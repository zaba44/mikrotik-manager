# Wdrożenie na darmowym VPS Oracle (ARM)

Instrukcja dla Oracle Cloud Always Free — kształt **VM.Standard.A1.Flex** (Ampere ARM,
do 4 rdzeni i 24 GB RAM). Obrazy portalu są budowane multi-arch, więc na ARM działają
natywnie, bez emulacji.

## Uwaga: prywatne repozytorium

Dopóki repozytorium jest prywatne, `curl` z `raw.githubusercontent.com` zwróci **404**
(nie 401 — GitHub nie zdradza, że plik istnieje). Token z uprawnieniem `read:packages`
tu nie wystarczy, bo to inny zakres niż `repo`. Najprościej skopiować pliki z maszyny
roboczej przez `scp`, zamiast pobierać je na serwerze.

## Dwie pułapki, przez które to zwykle nie działa

Oracle ma **dwie niezależne warstwy filtrowania ruchu**. Otwarcie tylko jednej z nich
to najczęstszy powód „port jest otwarty, a nic nie działa":

1. **Security List / NSG** w panelu Oracle — filtruje ruch na poziomie sieci wirtualnej.
2. **iptables w samym systemie** — obrazy Oracle Ubuntu mają domyślnie restrykcyjne
   reguły zapisane przez `netfilter-persistent`, niezależne od panelu.

Trzeba przejść obie.

## 1. Maszyna

Utwórz instancję: **Ubuntu 22.04 lub 24.04**, kształt **VM.Standard.A1.Flex**,
np. 2 rdzenie i 12 GB (portal spokojnie się zmieści; limit Always Free to łącznie
4 rdzenie i 24 GB). Zapisz klucz SSH przy tworzeniu.

## 2. Otwórz porty w panelu Oracle

Networking → Virtual Cloud Networks → twoja VCN → Security Lists → domyślna lista →
**Add Ingress Rules**:

| Source CIDR | Protokół | Port | Po co |
|---|---|---|---|
| `0.0.0.0/0` | **UDP** | port WireGuarda (np. `51820`) | tunel — jedyna rzecz naprawdę wystawiona na świat |
| twój adres IP `/32` | TCP | `8443` | panel; **ogranicz do swojego adresu**, nie do `0.0.0.0/0` |

Panel możesz też w ogóle nie wystawiać — patrz krok 6.

## 3. Otwórz porty w systemie

To ten krok, o którym wszyscy zapominają.

```bash
sudo iptables -I INPUT 1 -p udp --dport 51820 -j ACCEPT
sudo iptables -I INPUT 1 -p tcp --dport 8443 -j ACCEPT
sudo netfilter-persistent save
```

Podmień `51820` na port, który wybierzesz. Bez `netfilter-persistent save` reguły
znikną po restarcie maszyny.

## 4. Docker

```bash
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker $USER
newgrp docker
```

## 5. Obrazy

Dopóki repozytorium jest **prywatne**, obrazy też są prywatne i trzeba się zalogować.
Utwórz w GitHubie token (Settings → Developer settings → Personal access tokens →
Tokens (classic)) z uprawnieniem **`read:packages`**, a potem na serwerze:

```bash
docker login ghcr.io -u zaba44
```

Jako hasło podaj ten token. Po upublicznieniu repozytorium ten krok znika.

## 6. Portal

```bash
mkdir ~/mikrotik-manager && cd ~/mikrotik-manager
curl -fsSLO https://raw.githubusercontent.com/zaba44/mikrotik-manager/main/docker-compose.yml
curl -fsSLO https://raw.githubusercontent.com/zaba44/mikrotik-manager/main/Caddyfile
curl -fsSL -o .env https://raw.githubusercontent.com/zaba44/mikrotik-manager/main/.env.example
```

W `.env` ustaw:

```
WG_PORT=51820
HUB_ENDPOINT=<publiczny adres IP maszyny>
POSTGRES_PASSWORD=<wymyśl mocne hasło>
MTM_VERSION=0.1.0
```

`HUB_ENDPOINT` to adres, pod który będą dzwonić routery — musi być **publiczny adres
Oracle**, nie prywatny z podsieci.

**Bezpieczniejszy wariant panelu:** ustaw `CADDY_BIND=127.0.0.1`. Wtedy panel nie jest
wystawiony w ogóle, a dostajesz się do niego tunelem SSH:

```bash
ssh -L 8443:127.0.0.1:8443 ubuntu@<adres-oracle>
```

i wchodzisz na `https://localhost:8443/`. Przy takim wariancie nie musisz otwierać
portu 8443 ani w Security List, ani w iptables.

## 7. Start

```bash
docker compose up -d
docker compose logs -f backend
```

Poczekaj na `Application startup complete`, wejdź na panel i przejdź **kreator**:
konto administratora, adres huba w tunelu i maska podsieci.

## 8. Pierwsze urządzenie

Dodaj lokalizację i urządzenie. Portal wygeneruje skrypt RouterOS — wklej go
w terminalu Winboksa. Po chwili urządzenie powinno pokazać się jako osiągalne.

## Weryfikacja, gdy coś nie działa

```bash
# czy tunel nasłuchuje
docker exec mtm-wireguard wg show

# czy port UDP dochodzi z zewnątrz (z innej maszyny)
nc -zvu <adres-oracle> 51820

# czy backend widzi urządzenia
docker compose logs backend | tail -30
```

Jeśli router nie nawiązuje tunelu, a `wg show` na serwerze nie pokazuje handshake —
problem jest w warstwie sieciowej. Sprawdź **obie** warstwy z kroków 2 i 3.
