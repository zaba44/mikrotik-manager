# Pliki obce w tym katalogu

Trzymamy je w repozytorium zamiast pobierać przy budowaniu obrazu, żeby awaria cudzego
CDN-u nie blokowała wydań ani budowania ze źródeł.

| plik | pochodzenie | licencja | pełny tekst |
|---|---|---|---|
| `htmx.min.js` | [htmx](https://htmx.org/) 1.9.12 | Zero-Clause BSD | `LICENSE-htmx.txt` |
| `inter-var.woff2`, `inter-var-ext.woff2` | [Inter](https://rsms.me/inter/) via `@fontsource-variable/inter` 5.0.18 | SIL Open Font License 1.1 | `LICENSE-Inter-OFL.txt` |

Teksty licencji są kopiami plików `LICENSE` z tych samych wydań paczek (jsDelivr), bez zmian.
Przy aktualizacji pliku podmień też jego licencję.

Aktualizacja: pobierz nową wersję i podmień plik, np.

```bash
curl -fsSL -o htmx.min.js https://cdn.jsdelivr.net/npm/htmx.org@<wersja>/dist/htmx.min.js
```
