# Usluga aktualizacji portalu: klient Dockera z wtyczka Compose + maly serwer HTTP.
# Oficjalny obraz docker:*-cli zawiera juz `docker compose`; dokladamy tylko Pythona.
FROM docker:29-cli

RUN apk add --no-cache python3 tzdata

COPY updater.py /updater.py

ARG MTM_BUILD_VERSION=dev
ARG MTM_BUILD_COMMIT=
ARG MTM_BUILD_DATE=
ENV MTM_BUILD_VERSION=$MTM_BUILD_VERSION MTM_BUILD_COMMIT=$MTM_BUILD_COMMIT MTM_BUILD_DATE=$MTM_BUILD_DATE

ENTRYPOINT ["python3", "-u", "/updater.py"]
