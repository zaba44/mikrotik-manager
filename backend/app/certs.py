"""Certyfikat HTTPS panelu: własne mini-CA + certyfikat serwera, oba zarządzane z GUI.

DLACZEGO CA, A NIE ZWYKŁY SAMOPODPISANY: certyfikat trzeba będzie regenerować (dochodzi
adres huba w tunelu, potem adresy peerów administracyjnych). Przy zwykłym samopodpisanym
KAŻDA regeneracja unieważnia zaufanie i trzeba go instalować od nowa na wszystkich
maszynach. Przy własnym CA instalujesz raz sam certyfikat CA, a kolejne certyfikaty
serwera są przezroczyste — przeglądarka dalej pokazuje kłódkę.

JEDEN certyfikat obejmuje WIELE adresów (SubjectAlternativeName), więc nie trzeba
wybierać „ten czy tamten" — wpisuje się wszystkie, pod którymi panel bywa osiągalny.
Ma to znaczenie, bo przy wejściu po gołym IP przeglądarka nie wysyła SNI i serwer
zawsze poda ten sam, domyślny certyfikat.

UWAGA BEZPIECZEŃSTWA: klucz prywatny CA leży na portalu. Kto przejmie portal, może
wystawiać certyfikaty, którym zaufają maszyny z zainstalowanym CA. To ta sama własność,
którą ma każde prywatne CA — ale instalacja w systemie to realne rozszerzenie zaufania.
Klucz jedzie w kopii portalu razem z resztą sekretów.
"""
import datetime
import ipaddress
import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

TLS_DIR = "/data/tls"
CA_CERT = os.path.join(TLS_DIR, "ca.pem")
CA_KEY = os.path.join(TLS_DIR, "ca.key")
SERVER_CERT = os.path.join(TLS_DIR, "fullchain.pem")
SERVER_KEY = os.path.join(TLS_DIR, "cert.key")

_CA_YEARS = 10
_SERVER_YEARS = 5


def _san(value: str):
    """Adres IP -> IPAddress, reszta -> DNSName. Przeglądarki traktują je inaczej,
    więc wpisanie IP jako DNSName nie zadziała."""
    try:
        return x509.IPAddress(ipaddress.ip_address(value))
    except ValueError:
        return x509.DNSName(value)


def _write(path: str, data: bytes, mode: int = 0o600) -> None:
    os.makedirs(TLS_DIR, exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)
    os.chmod(path, mode)


def ensure_ca() -> None:
    """Tworzy CA raz. Nigdy nie nadpisuje istniejącego — nadpisanie unieważniłoby
    zaufanie na wszystkich maszynach, na których je zainstalowano."""
    if os.path.exists(CA_CERT) and os.path.exists(CA_KEY):
        return
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "MikroTik Manager Root CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "MikroTik Manager"),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject).issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365 * _CA_YEARS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, key_cert_sign=True, crl_sign=True,
            content_commitment=False, key_encipherment=False, data_encipherment=False,
            key_agreement=False, encipher_only=False, decipher_only=False), critical=True)
        .sign(key, hashes.SHA256())
    )
    _write(CA_KEY, key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    _write(CA_CERT, cert.public_bytes(serialization.Encoding.PEM), 0o644)


def issue_server_cert(addresses: list[str]) -> None:
    """Wystawia certyfikat serwera z podanego CA na WSZYSTKIE adresy naraz."""
    ensure_ca()
    with open(CA_KEY, "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)
    with open(CA_CERT, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())

    clean = [a.strip() for a in addresses if a and a.strip()]
    if not clean:
        clean = ["localhost", "127.0.0.1"]

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, clean[0][:64])]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365 * _SERVER_YEARS))
        .add_extension(x509.SubjectAlternativeName([_san(a) for a in clean]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    # fullchain: certyfikat serwera + CA (Caddy poda oba, klient zbuduje ścieżkę)
    _write(SERVER_CERT,
           cert.public_bytes(serialization.Encoding.PEM) + ca_cert.public_bytes(serialization.Encoding.PEM),
           0o644)
    _write(SERVER_KEY, key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))


def cert_info() -> dict:
    """Co jest teraz zainstalowane — do pokazania w panelu."""
    if not os.path.exists(SERVER_CERT):
        return {"present": False}
    try:
        with open(SERVER_CERT, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())
        try:
            sans = [str(v.value) for v in cert.extensions.get_extension_for_class(
                x509.SubjectAlternativeName).value]
        except x509.ExtensionNotFound:
            sans = []
        issuer = cert.issuer.rfc4514_string()
        return {
            "present": True,
            "addresses": sans,
            "not_after": cert.not_valid_after_utc,
            "issuer": issuer,
            "self_managed": "MikroTik Manager Root CA" in issuer,
            "own_ca_present": os.path.exists(CA_CERT),
        }
    except Exception as e:
        return {"present": True, "error": f"{type(e).__name__}: {e}"}


def install_uploaded(cert_pem: bytes, key_pem: bytes) -> str | None:
    """Wgranie własnego certyfikatu. Zwraca komunikat błędu albo None.
    Sprawdzamy, czy klucz pasuje do certyfikatu — inaczej Caddy nie wstanie po
    restarcie, a użytkownik zostałby bez panelu i bez podpowiedzi dlaczego."""
    try:
        cert = x509.load_pem_x509_certificate(cert_pem)
    except Exception:
        return "Plik certyfikatu nie jest poprawnym PEM-em."
    try:
        key = serialization.load_pem_private_key(key_pem, password=None)
    except Exception:
        return "Plik klucza nie jest poprawnym PEM-em (klucz nie może być zaszyfrowany hasłem)."

    if key.public_key().public_numbers() != cert.public_key().public_numbers():
        return "Klucz prywatny nie pasuje do tego certyfikatu."

    _write(SERVER_CERT, cert_pem, 0o644)
    _write(SERVER_KEY, key_pem)
    return None


def ca_pem() -> bytes | None:
    if not os.path.exists(CA_CERT):
        return None
    with open(CA_CERT, "rb") as f:
        return f.read()


def bootstrap(default_addresses: list[str]) -> None:
    """Wołane z entrypointu przed startem Caddy: jeśli nie ma certyfikatu, zrób CA
    i wystaw pierwszy. Świeża instalacja ma działać bez podkładania plików."""
    ensure_ca()
    if not (os.path.exists(SERVER_CERT) and os.path.exists(SERVER_KEY)):
        issue_server_cert(default_addresses)


if __name__ == "__main__":
    import sys

    bootstrap([a for a in sys.argv[1:] if a] + ["localhost", "127.0.0.1"])
    print("TLS gotowe:", cert_info().get("addresses"))
