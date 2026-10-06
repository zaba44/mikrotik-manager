FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends iproute2 openssh-client \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# htmx i czcionka Inter leza w app/static i ida razem z reszta zrodel. Wczesniej
# sciagal je ADD z unpkg PRZY KAZDYM BUDOWANIU — awaria cudzego CDN-u blokowala
# wtedy nie tylko testy, ale i wydania na GitHubie oraz kazdego, kto buduje ze zrodel.
# (Zdarzylo sie 2026-09-25: unpkg odpowiadal 500, potem przestal odpowiadac w ogole.)
COPY app ./app
COPY alembic ./alembic
COPY alembic.ini .
COPY entrypoint.sh .
RUN chmod +x entrypoint.sh

EXPOSE 8000

ENTRYPOINT ["./entrypoint.sh"]
