"""WireGuard i Back To Home NA ZARZADZANYCH ROUTERACH.

Nie mylic z modulami `wg_config`, `wg_agent_client`, `wg_bringup` — tamte dotycza
WireGuarda HUBA (tunelu, ktorym portal laczy sie z flota). Ten pakiet obsluguje tunele,
ktore uzytkownik ma na swoich routerach: serwery dla klientow, site-to-site, uplinki.

Zasada nadrzedna: router jest jedynym zrodlem prawdy. Portal niczego tu nie przechowuje
— kazdy widok to swiezy odczyt.
"""
