"""Modem LTE/5G — odczyt `/interface/lte/monitor` przez REST i ocena sygnalu.

Ustalone na zywym sprzecie (hAP ax lite LTE6, modem Fibocom FG621-EA, RouterOS 7.24.5):
  * `GET /rest/interface/lte` -> lista modemow; urzadzenie BEZ modemu zwraca `[]` (sprawdzone
    na calym labie: wAP ax, hAP ac^2, hAP ax^2, mAP lite, CRS328) — tak rozpoznajemy modem,
  * `POST /rest/interface/lte/monitor {"numbers": "lte1", "once": ""}` -> lista z jednym
    slownikiem; liczby jako TEKST BEZ JEDNOSTEK ("-107", "-13.5" — jednostki dopisuje tylko
    terminal), `session-uptime` w formacie RouterOS ("3m54s"), `primary-band` jako jeden
    napis "B3@15Mhz earfcn: 1875 phy-cellid: 345",
  * zestaw pol zalezy od modemu i chwili (`ri` raz jest, raz nie; 5G ma pola, ktorych LTE6
    nie ma) — pokazujemy znane w czytelnej postaci, a pozostale w „Inne pola",
  * odpowiedz ZAWSZE zawiera IMEI, IMSI i ICCID — dane identyfikujace abonenta i karte.
    Odrzucamy je tu, przy odczycie: nie trafiaja do szablonu, bazy ani logow.

Progi ocen to powszechnie stosowane wartosci dla LTE (dla 5G NR podobne).
"""
import re

# Nigdy nie wychodza poza ten modul.
SECRET_KEYS = {"imei", "imsi", "iccid", "msisdn", "phone-number", "pin", "puk", "own-number"}

# (klucz, etykieta) — pola pokazywane w czytelnej kolejnosci; reszta trafia do „Inne pola".
KNOWN = [
    ("status", "Stan"), ("current-operator", "Operator"), ("data-class", "Technologia"),
    ("access-technology", "Technologia dostępu"), ("session-uptime", "Czas sesji"),
    ("model", "Model modemu"), ("revision", "Firmware modemu"),
    ("current-cellid", "Komórka (Cell ID)"), ("enb-id", "eNB ID"), ("sector-id", "Sektor"),
    ("phy-cellid", "PCI"), ("ri", "RI (strumienie MIMO)"), ("cqi", "CQI"),
]
SIGNAL = ("rssi", "rsrp", "rsrq", "sinr")
BANDS = ("primary-band", "ca-band")

# (prog, poziom, opis) od najlepszego; wartosc >= prog -> ten poziom.
_LEVELS = {
    "rsrp": [(-80, "ok", "doskonały"), (-90, "ok", "dobry"), (-100, "warn", "słaby"), (None, "bad", "bardzo słaby")],
    "sinr": [(20, "ok", "doskonały"), (13, "ok", "dobry"), (0, "warn", "słaby"), (None, "bad", "bardzo słaby")],
    "rsrq": [(-10, "ok", "doskonały"), (-15, "ok", "dobry"), (-20, "warn", "słaby"), (None, "bad", "bardzo słaby")],
}
UNITS = {"rssi": "dBm", "rsrp": "dBm", "rsrq": "dB", "sinr": "dB"}
LABELS = {"rssi": "RSSI", "rsrp": "RSRP (siła)", "rsrq": "RSRQ (jakość)", "sinr": "SINR (zakłócenia)"}

_NUMBER = re.compile(r"^\s*(-?\d+(?:\.\d+)?)")
_BAND = re.compile(r"(?<![A-Za-z0-9])([A-Za-z]{0,2}\d+)\s*@\s*(\d+(?:\.\d+)?)\s*mhz(?:[^@]*?earfcn:\s*(\d+))?", re.I)


def number(value) -> float | None:
    """"-107" / "-107dBm" / "-13.5" -> liczba; reszta -> None."""
    m = _NUMBER.match(str(value)) if value is not None else None
    return float(m.group(1)) if m else None


def rate(key: str, value: float | None) -> tuple[str, str] | None:
    """Poziom (ok/warn/bad) i opis slowny dla RSRP, SINR i RSRQ."""
    if value is None or key not in _LEVELS:
        return None
    for threshold, level, text in _LEVELS[key]:
        if threshold is None or value >= threshold:
            return level, text
    return None


def bands(value) -> list[dict]:
    """Wszystkie pasma z napisu RouterOS: "B3@15Mhz earfcn: 1875 phy-cellid: 345" ->
    [{band: B3, width: 15 MHz, earfcn: 1875}]. Format agregacji (ca-band) nie byl jeszcze
    widziany na sprzecie, wiec bez zalozen o separatorze: kazde wystapienie wzorca
    „pasmo@szerokosc" to jedno pasmo (dziala tez dla 5G NR, np. "n78@100Mhz")."""
    out = []
    for m in _BAND.finditer(str(value or "")):
        width = m.group(2)
        if "." in width:
            width = width.rstrip("0").rstrip(".")
        name = m.group(1)
        name = "n" + name[1:] if name[:1] in "nN" else name.upper()  # 5G NR: n78, LTE: B3
        out.append({"band": name, "width": f"{width} MHz", "earfcn": m.group(3)})
    if not out and value:
        out.append({"band": str(value), "width": None, "earfcn": None})  # nieznany format: pokaz jak jest
    return out


def parse_monitor(raw) -> dict:
    """Odpowiedz monitora (lista z jednym slownikiem albo slownik) -> dane do wyswietlenia,
    BEZ identyfikatorow abonenta."""
    row = raw[0] if isinstance(raw, list) and raw else raw if isinstance(raw, dict) else {}
    row = {k: v for k, v in row.items() if k.lower() not in SECRET_KEYS}
    signals = []
    for key in SIGNAL:
        if key in row:
            v = number(row[key])
            signals.append({"key": key, "label": LABELS[key], "value": v, "unit": UNITS[key],
                            "rating": rate(key, v)})
    known_keys = {k for k, _ in KNOWN} | set(SIGNAL) | set(BANDS)
    return {
        "fields": [(label, row[k]) for k, label in KNOWN if row.get(k) not in (None, "")],
        "signals": signals,
        "primary_band": (bands(row.get("primary-band")) or [None])[0],
        "ca_bands": bands(row.get("ca-band")),
        "other": sorted((k, v) for k, v in row.items() if k not in known_keys and v not in (None, "")),
        "worst": _worst(signals),
    }


def _worst(signals) -> str | None:
    order = {"bad": 0, "warn": 1, "ok": 2}
    rated = [s["rating"][0] for s in signals if s["rating"]]
    return min(rated, key=order.get) if rated else None
