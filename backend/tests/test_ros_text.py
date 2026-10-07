"""Tekst wysylany na router bez znakow diakrytycznych (app/ros_text.py)."""
import pytest

from app.ros_text import ros_ascii


@pytest.mark.parametrize("raw,ascii_", [
    ("SWITCH C 24P GÓRA", "SWITCH C 24P GORA"),          # przypadek z produkcji: terminal dal „GRA"
    ("Zażółć gęślą jaźń", "Zazolc gesla jazn"),
    ("ZAŻÓŁĆ GĘŚLĄ JAŹŃ", "ZAZOLC GESLA JAZN"),
    ("Łódź, ul. Świętego", "Lodz, ul. Swietego"),
    ("Café Müller, Straße", "Cafe Muller, Strasse"),
    ("Biuro \"Parter\" $5?", "Biuro \"Parter\" $5?"),    # ASCII bez zmian — cudzyslowy to sprawa ros_quote
    ("dwie\nlinie\t i  spacje", "dwie linie i spacje"),
    ("kamera 📷 hala", "kamera hala"),                    # czego sie nie da zamienic, to wypada
    ("Test GÓRA – hub „główny” … ok", 'Test GORA - hub "glowny" ... ok'),  # z Worda/maila
    ("twarda spacja", "twarda spacja"),
    ("", ""), (None, ""),
])
def test_ros_ascii(raw, ascii_):
    assert ros_ascii(raw) == ascii_
    assert ros_ascii(raw).isascii()


def test_registration_script_comment_is_ascii(monkeypatch):
    from app.routers import devices
    monkeypatch.setattr(devices.wg, "subnet", "10.77.0.0/22")
    monkeypatch.setattr(devices.wg, "server_ip", "10.77.0.1")
    monkeypatch.setattr(devices.wg, "hub_endpoint", "hub.example.org")
    monkeypatch.setattr(devices.wg, "server_public_key", "PUB=")
    s = devices.build_routeros_script(device_name="SWITCH C 24P GÓRA", client_private_key="P=",
                                      device_ip="10.77.0.5", api_username="mtm-api", api_password="x")
    assert 'comment="SWITCH C 24P GORA - hub"' in s and s.isascii()
