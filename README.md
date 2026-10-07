# MikroTik Manager

Portal do zarządzania flotą urządzeń MikroTik w modelu hub-and-spoke. Urządzenia
łączą się **wychodząco** przez WireGuard, a portal sięga do nich po REST API.
Panel jest dostępny przez tunel; czy także z sieci hosta — decydujesz sam
(zob. **Bezpieczeństwo**).

## Co potrafi

- **Stan floty**: handshake WireGuard, osiągalność REST, wersja RouterOS, uptime,
  port Winboksa (odczytywany na żywo — w praktyce bywa niestandardowy).
- **Rejestracja urządzenia**: portal generuje gotowy do wklejenia skrypt RouterOS
  (tunel, konto API o minimalnych uprawnieniach, firewall, usługa REST tylko na
  tunelu) i sam dodaje peera po stronie serwera.
- **Kopie zapasowe**: export tekstowy i backup binarny, szyfrowane, z harmonogramem
  i retencją. Transport „push" — router sam wysyła plik, więc nie trzeba dokładać
  reguł firewalla na już wdrożonym sprzęcie.
- **Aktualizacje** RouterOS i firmware: sprawdzanie w tle, ręczny trigger, sekwencyjnie
  po urządzeniach, z pomijaniem tych już aktualnych.
- **Diagnostyka**: ping z urządzenia, kondycja (CPU, RAM, temperatury, napięcia,
  prędkości linków), dzierżawy DHCP, raport zdarzeń z logów routera.
- **PoE per port**: stan, pobór mocy, napięcie i prąd na każdym porcie, zdalny restart
  zasilanego urządzenia (kamera, access point) i blokada portów uplinku.
- **Syslog**: urządzenia pushują zdarzenia do portalu, z retencją i limitami.
- **Powiadomienia e-mail** o zdarzeniach z całego portalu, z bezpiecznikami
  przeciw zalaniu skrzynki.
- **Kopia całego portalu** i odtworzenie na czystej maszynie — flota wraca sama,
  bez dotykania routerów.

## Uruchomienie

Potrzebujesz hosta z Dockerem i publicznego adresu (albo przekierowanego portu UDP).
Obrazy są budowane dla **amd64 i arm64**, więc działa też na Oracle Ampere,
Raspberry Pi i podobnych.

```bash
mkdir mikrotik-manager && cd mikrotik-manager
curl -fsSLO https://raw.githubusercontent.com/zaba44/mikrotik-manager/main/docker-compose.yml
curl -fsSLO https://raw.githubusercontent.com/zaba44/mikrotik-manager/main/Caddyfile
curl -fsSL -o .env https://raw.githubusercontent.com/zaba44/mikrotik-manager/main/.env.example
```

Otwórz `.env` i ustaw trzy rzeczy: **port WireGuarda**, **hasło do bazy** i — jeśli
już wiesz — **adres huba**. Reszta ma sensowne wartości domyślne.

```bash
docker compose up -d
```

Wejdź na `https://<adres-hosta>:8443/`. Przy pierwszym uruchomieniu zobaczysz
**kreator**: zakładasz konto administratora i wybierasz podsieć tunelu (adres huba
plus maska, z podglądem, ile urządzeń się zmieści). Klucze, token kanału sterującego
i certyfikat HTTPS portal generuje sam — nie ma nic do wymyślania ręcznie.

Kreator wymaga **tokenu instalacyjnego**, który portal wypisuje do logów przy starcie:

```bash
docker compose logs backend | grep TOKEN
```

Bez niego ktoś, kto dotarłby do panelu przed Tobą, mógłby założyć pierwsze konto
administratora i przejąć portal. Token działa tylko do momentu założenia portalu.

Przeglądarka ostrzeże o certyfikacie, bo pochodzi z wbudowanego urzędu certyfikacji
portalu. W zakładce **Ustawienia → Certyfikat** możesz pobrać ten urząd i zainstalować
w systemie (wtedy kłódka będzie zielona), wygenerować certyfikat na dodatkowe adresy
albo wgrać własny.

### Przypnij wersję

`latest` może się zmienić w dowolnym momencie, razem z migracją bazy. Na produkcji
ustaw w `.env` konkretną wersję:

```
MTM_VERSION=0.6.5
```

Aktualne wydania: zakładka *Releases* / tagi `v*` w repozytorium (w `.env` bez litery `v`).

## Aktualizacja

```bash
docker compose pull && docker compose up -d
```

Migracje bazy wykonują się automatycznie przy starcie. **Zrób wcześniej kopię portalu**
(Ustawienia → Kopie zapasowe → Pobierz kopię portalu) — to jeden plik, z którego
odtworzysz całość.

## Kopia zapasowa i odtwarzanie

Kopia portalu zawiera bazę, klucz szyfrujący, klucz prywatny huba, certyfikat wraz
z urzędem certyfikacji i opcjonalnie kopie urządzeń oraz zdarzenia. **Trzymaj ją poza
serwerem** — to komplet kluczy do całej instalacji.

Konfiguracja (w tym cele pingów i wyciszenia powiadomień) jest w kopii zawsze; kopie
urządzeń, zdarzenia syslog i historię (przebiegi aktualizacji, dziennik powiadomień)
dołączasz opcjonalnie. Jeśli kanał sterujący nie odda klucza huba, kopia **nie powstanie**
— lepiej dostać błąd teraz niż odkryć niekompletny plik w dniu awarii.

Odtworzenie: postaw czysty stack, a w kreatorze wybierz „Przywróć z kopii", wpisz token
instalacyjny z logów i wgraj plik. Tożsamość huba wraca, więc **urządzenia łączą się same**
— nie trzeba niczego wklejać na routerach.

Jak to jest zabezpieczone przed awarią w trakcie:
- **zanim cokolwiek się zmieni**, cała kopia jest sprawdzana — także to, czy klucz
  szyfrujący pasuje do danych; zła kopia jest odrzucana, a portal zostaje nietknięty,
- **baza** odtwarza się w jednej transakcji: albo cała, albo wcale,
- **pliki kluczy, tunel huba i peery** nie dają się zamknąć w transakcji, więc ta część jest
  **wznawialna**: jeśli się nie uda (np. kontener WireGuard nie odpowiada), portal ponawia
  ją sam co minutę i przy każdym starcie, aż hub potwierdzi tunel i trwały zapis wszystkich
  peerów. Do tego czasu w Ustawieniach widać baner „odtwarzanie niedokończone” z przyczyną
  i przyciskiem „Ponów teraz”.

## Nie pamiętam hasła

Hasło dowolnego konta zmienisz z serwera, bez logowania do panelu (w katalogu stacka):

```bash
docker compose exec backend python -m app.reset_password
```

Polecenie wypisze konta, zapyta o login i dwa razy o nowe hasło (wpisywane bez podglądu,
nie zostaje w historii poleceń). Rola konta się nie zmienia, a jego zalogowane sesje wygasają.
Login możesz podać od razu: `... python -m app.reset_password admin`.

Gdy nie zostało żadne konto administratora (np. zostali sami operatorzy), załóż je albo nadaj
istniejącemu kontu rolę administratora:

```bash
printf 'login\nhaslo\n' | docker compose exec -T backend python -m app.create_admin
```

Tu hasło zostaje w historii powłoki — potraktuj je jako tymczasowe i od razu zmień
poleceniem `app.reset_password` albo w panelu (Moje konto).

To jest uprawniona droga, nie furtka: kto ma dostęp do serwera, i tak ma pełną władzę nad
portalem. Dlatego tym bardziej pilnuj samego serwera (SSH tylko na klucz).

## Wymagania wobec urządzeń

RouterOS **7.15 lub nowszy** (nazwane peery WireGuard i spójne REST API). Konto API
zakładane przez portal ma minimalny działający zestaw uprawnień, ustalony
empirycznie na żywym sprzęcie: `read,write,test,sensitive,api,rest-api,reboot,policy`.

## Bezpieczeństwo

Klucze prywatne WireGuard, hasła API urządzeń i hasło SMTP są szyfrowane w bazie.
Sekrety powstają przy pierwszym starcie i żyją na wolumenie, nie w plikach
konfiguracyjnych. Panel wymaga logowania i ma role administratora oraz operatora
(ten drugi widzi tylko swoją lokalizację), a skrypty zawierające hasła są przed
operatorami ukryte.

**Port panelu.** Domyślnie (`CADDY_BIND=0.0.0.0`) panel jest publikowany na wszystkich
interfejsach hosta — inaczej nie dałoby się otworzyć kreatora przy pierwszym uruchomieniu.
Na hoście z publicznym adresem trzeba go więc ograniczyć. Uwaga na pułapkę: **Docker omija
łańcuch `INPUT`**, więc reguły w `iptables -L INPUT` nie chronią opublikowanego portu
kontenera, choć wydruk wygląda uspokajająco. Skuteczne są:

- firewall dostawcy chmury (lista bezpieczeństwa / security group) bez otwartego portu panelu,
- reguła w łańcuchu `DOCKER-USER`, np. odrzucająca port panelu na karcie publicznej:
  `iptables -I DOCKER-USER -i <karta-publiczna> -p tcp --dport 8443 -j DROP`,
- po przeklikaniu kreatora: `CADDY_BIND=127.0.0.1` — panel znika z sieci hosta,
  a dostęp zostaje przez tunel (peer administracyjny) albo SSH.

Przez tunel panel działa niezależnie od tych ustawień: adres huba, port 8443.

### Dostęp do panelu przez tunel

W **Ustawienia → Peery administracyjne** wygenerujesz konfigurację WireGuard dla
swojego komputera. Po połączeniu panel jest osiągalny pod **adresem huba wraz z portem**,
np. `https://10.22.20.1:8443/` — także wtedy, gdy panel nie jest wystawiony na
żadnym publicznym interfejsie. Warto potem w **Ustawienia → Certyfikat** wystawić
certyfikat na ten adres (jest już w podpowiedzi), żeby przeglądarka nie protestowała.

## Rozwój

Do pracy nad kodem służy `infra/docker-compose.yml`, który buduje obrazy ze źródeł:

```bash
cd infra && cp .env.example .env && docker compose up -d --build
```

Testy: `cd backend && python -m pytest tests` (czysta logika, bez bazy i sprzętu; to samo
uruchamia CI przed każdym wydaniem). Scenariusze wymagające działającego portalu i prawdziwych
routerów: [backend/tests/lab/](backend/tests/lab/README.md). Ustalenia empiryczne z żywego
sprzętu (zachowanie REST RouterOS, minimalne uprawnienia API) są opisane w komentarzach
przy kodzie, którego dotyczą.

## Licencja

MIT — patrz [LICENSE](LICENSE).
