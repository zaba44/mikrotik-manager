# Scenariusze na żywym labie

Testy w `tests/` (pytest, CI) sprawdzają czystą logikę bez bazy i sprzętu. Tutaj leżą
scenariusze, które **wymagają działającego portalu i prawdziwych routerów** — dowody, że
funkcje działają na sprzęcie, a nie tylko w teorii. Każdy sprząta po sobie w `finally`.

Uruchamiane wewnątrz kontenera backendu, z danymi logowania w zmiennych środowiskowych
(nigdy w pliku — repozytorium jest publiczne). Nazwy urządzeń testowych też podajesz w zmiennych
(`MTM_LAB_WRITE_DEVICE`, `MTM_LAB_BTH_DEVICE`, `MTM_LAB_NO_BTH_DEVICE`) — bez wartości domyślnych:

```bash
docker exec -i -w /app -e MTM_LAB_USER=admin -e MTM_LAB_PASSWORD='...' mtm-backend python - < tests/lab/smoke_pages.py
```

| skrypt | co sprawdza | co zmienia |
|---|---|---|
| `smoke_pages.py` | każda strona i fragment portalu daje 200; flagi ciasteczka sesji | nic |
| `fixes_review.py` | poprawki po pierwszej recenzji: sesje, retencja, usuwanie urządzeń i lokalizacji, peery admina, eksport | tymczasowy operator, urządzenie, lokalizacja, peer — usuwane |
| `fixes_review2.py` | poprawki po drugiej recenzji: blokada puli IP przy równoległej rejestracji, cudzy cel pingu, restart bez połączenia, brak `confirm()` w handlerach | tymczasowe urządzenie (bez peera) i cel pingu — usuwane; ping na 192.0.2.1, restart na pusty adres w tunelu |
| `wireguard_write_import.py` | etapy 3–4 modułu WireGuard: nowy tunel, ZIP, dodawanie, ochrona przed zmianą routera, import `.conf` | tymczasowy interfejs `WG_TEST` na `MTM_LAB_WRITE_DEVICE` — usuwany |
| `bth_router.py` | Back To Home: włączenie, użytkownik, config w obu trybach, zrzuty; komunikat na routerze bez wsparcia (`MTM_LAB_NO_BTH_DEVICE`) | BTH na `MTM_LAB_BTH_DEVICE` — **przywracany do stanu sprzed testu**, DDNS porównywany |

Przed uruchomieniem czegokolwiek, co restartuje backend albo zmienia routery, sprawdź, czy nie
trwa aktualizacja (`update_runs.status = 'running'`) — lab bywa używany na żywo.

## Odtwarzanie kopii portalu — w odizolowanym środowisku

`restore_isolated.py` i `restore_identity.py` **nie mogą** działać na żywym portalu: odtwarzanie
kasuje bazę. Uruchamia się je w jednorazowym kontenerze z osobną bazą, z podmienionym tunelem
i peerami (nic nie dociera do agenta ani routerów):

```bash
# 1. eksport z żywego portalu (tylko odczyt) i jednorazowa baza
docker exec -w /app mtm-backend python -c "import asyncio; from app.portal_backup import export_portal; \
  open('/tmp/a.tgz','wb').write(asyncio.run(export_portal(False, True, True)))"
mkdir -p /tmp/rt && docker cp mtm-backend:/tmp/a.tgz /tmp/rt/archive.tgz && docker exec mtm-backend rm /tmp/a.tgz
cp tests/lab/restore_isolated.py /tmp/rt/rt.py
docker network create mtm-rt
docker run -d --name mtm-rt-pg --network mtm-rt -e POSTGRES_USER=rt -e POSTGRES_PASSWORD=rt -e POSTGRES_DB=rt postgres:16-alpine

# 2. odtworzenie w jednorazowym kontenerze z obrazu backendu
docker run --rm --network mtm-rt -e PYTHONPATH=/app -e DATABASE_URL=postgresql+asyncpg://rt:rt@mtm-rt-pg/rt \
  -e FERNET_KEY="$(docker run --rm --entrypoint python infra-backend -c 'from cryptography.fernet import Fernet;print(Fernet.generate_key().decode())')" \
  -e SESSION_SECRET=x -e BACKUP_SFTP_PASSWORD=x -v /tmp/rt:/work --entrypoint sh infra-backend \
  -c 'cd /app && alembic upgrade head && python /work/rt.py'

# 3. sprzątanie — archiwum zawiera klucze całej instalacji
docker rm -f mtm-rt-pg && docker network rm mtm-rt && docker run --rm -v /tmp:/t alpine rm -rf /t/rt
```

`restore_isolated.py` (asercje, kod wyjścia ≠ 0 przy pierwszej niezgodności) sprawdza:
zgodność liczby wierszy z manifestem; wycofanie przy błędzie w połowie zapisu; odrzucenie kopii
bez klucza huba i kopii z kluczem Fernet z innej instalacji — w obu przypadkach baza, sekrety
i katalogi bez zmian; **wznawianie** po niedostępnym agencie WireGuard i po błędzie podmiany
plików już po commicie bazy (dziennik + znacznik w bazie, klucz huba czeka na dysku, ponowienie
kończy i sprząta); zamknięcie przebiegu aktualizacji „running” z kopii; sprzątanie dziennika,
którego baza nie zatwierdziła; commit zapisany przy zgubionym potwierdzeniu (rozstrzyga znacznik
odczytany nowym połączeniem). `restore_identity.py` — że po odtworzeniu nowe wpisy syslog nie
kolidują z odtworzonymi identyfikatorami.

Przy dwóch skryptach podmień w pętli plik `rt.py` i wyczyść bazę między nimi
(`docker exec mtm-rt-pg psql -U rt -d rt -c "drop schema public cascade; create schema public;"`).
