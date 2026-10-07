#!/bin/sh
set -e

# Trasa do podsieci WG jest dodawana przez aplikację po wczytaniu konfiguracji z bazy
# (świeża instalacja nie zna podsieci na tym etapie) — patrz app/wg_bringup.py.

mkdir -p /data/backups
if [ ! -f /data/backups/ssh_host_key ]; then
    echo "Generating backup SFTP server host key"
    ssh-keygen -t ed25519 -f /data/backups/ssh_host_key -N ""
fi

# Sekrety aplikacyjne na wolumenie. Zasada: jeśli plik nie istnieje, najpierw seeduj
# z wartości .env (istniejący stack — TEN SAM klucz Fernet, brak utraty danych),
# a dopiero przy jej braku generuj nowy (świeża instalacja). Po zaseedowaniu można
# wartości usunąć z .env.
mkdir -p /data/secrets
chmod 700 /data/secrets
if [ ! -f /data/secrets/fernet.key ]; then
    if [ -n "${FERNET_KEY}" ]; then
        printf '%s' "${FERNET_KEY}" > /data/secrets/fernet.key
        echo "Seeded fernet.key from FERNET_KEY env"
    else
        python3 -c "from cryptography.fernet import Fernet; open('/data/secrets/fernet.key','w').write(Fernet.generate_key().decode())"
        echo "Generated new fernet.key"
    fi
    chmod 600 /data/secrets/fernet.key
fi
if [ ! -f /data/secrets/session.secret ]; then
    if [ -n "${SESSION_SECRET}" ]; then
        printf '%s' "${SESSION_SECRET}" > /data/secrets/session.secret
    else
        python3 -c "import secrets; open('/data/secrets/session.secret','w').write(secrets.token_hex(32))"
    fi
    chmod 600 /data/secrets/session.secret
fi
if [ ! -f /data/secrets/backup_sftp.pw ]; then
    if [ -n "${BACKUP_SFTP_PASSWORD}" ]; then
        printf '%s' "${BACKUP_SFTP_PASSWORD}" > /data/secrets/backup_sftp.pw
    else
        python3 -c "import secrets; open('/data/secrets/backup_sftp.pw','w').write(secrets.token_hex(24))"
    fi
    chmod 600 /data/secrets/backup_sftp.pw
fi

# Token kanału sterującego do agenta WG. Generowany AUTOMATYCZNIE na współdzielonym
# wolumenie — gdyby siedział jako placeholder w .env.example, każda instalacja, w której
# nikt go nie zmieni, miałaby ten sam token. Kontener wireguard czyta ten sam plik.
mkdir -p /data/agent
if [ ! -f /data/agent/token ]; then
    if [ -n "${WG_AGENT_TOKEN}" ]; then
        printf '%s' "${WG_AGENT_TOKEN}" > /data/agent/token
        echo "Seeded agent token from WG_AGENT_TOKEN env"
    else
        python3 -c "import secrets; open('/data/agent/token','w').write(secrets.token_hex(32))"
        echo "Generated new agent token"
    fi
    chmod 600 /data/agent/token
fi
export WG_AGENT_TOKEN="$(cat /data/agent/token)"

# Token do uslugi aktualizacji (updater) — ten sam wzorzec co token agenta. Katalog istnieje
# zawsze (takze bez uslugi updater — wtedy portal po prostu jej nie znajdzie).
mkdir -p /data/updater
if [ ! -f /data/updater/token ]; then
    python3 -c "import secrets; open('/data/updater/token','w').write(secrets.token_hex(32))"
    chmod 600 /data/updater/token
    echo "Generated new updater token"
fi

# Certyfikat HTTPS panelu. Świeża instalacja MUSI mieć czym wstać — Caddy startuje po
# nas (depends_on) i bez plików certyfikatu nie podniósłby się w ogóle, czyli nie byłoby
# nawet kreatora. Własne mini-CA + certyfikat serwera; user może potem podmienić z GUI.
python3 -m app.certs "${HUB_ENDPOINT}" || echo "UWAGA: nie udało się przygotować certyfikatu TLS"

# Poczekaj aż Postgres przyjmuje połączenia (świeży `up` startuje kontenery równolegle —
# bez tego alembic potrafił wywalić się na pierwszej próbie i liczyć na restart).
echo "Czekam na Postgres..."
until python3 -c "import socket; s=socket.socket(); s.settimeout(2); s.connect(('postgres', 5432)); s.close()" 2>/dev/null; do
    sleep 1
done

alembic upgrade head
exec uvicorn app.main:app --host 0.0.0.0 --port 8000
