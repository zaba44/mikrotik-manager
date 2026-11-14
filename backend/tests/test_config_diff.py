"""Porownanie eksportow konfiguracji: naglowek z data pomijany, sekrety ukryte."""
from app import config_diff

OLD = """# 2026-10-01 03:00:01 by RouterOS 7.24.5
# software id = ABCD-1234
/interface bridge
add name=LAN_BRIDGE
/ip address
add address=192.168.55.1/24 interface=LAN_BRIDGE
/interface wifi security
add name=sec1 passphrase="StareHaslo1"
/ppp secret
add name=jan password=tajne1 service=l2tp
"""
NEW = OLD.replace("2026-10-01 03:00:01", "2026-10-08 03:00:02") \
         .replace("192.168.55.1/24", "192.168.56.1/24") \
         .replace("StareHaslo1", "NoweHaslo2")


def test_identical_except_header_is_empty():
    assert config_diff.diff(OLD, OLD.replace("2026-10-01 03:00:01", "2026-10-09 04:00:00")) == []


def test_changes_shown_secrets_hidden():
    rows = config_diff.diff(OLD, NEW)
    text = "\n".join(r.text for r in rows)
    assert config_diff.stats(rows) == (2, 2)
    assert "192.168.55.1/24" in text and "192.168.56.1/24" in text
    assert "StareHaslo1" not in text and "NoweHaslo2" not in text and "tajne1" not in text
    changed = [r for r in rows if r.secret_changed]
    assert [r.kind for r in changed] == ["del", "add"] and "passphrase=" + config_diff.MASK in changed[0].text


def test_mask_keeps_non_secret_parts():
    assert config_diff.mask('add name=jan password=tajne1 service=l2tp') == f"add name=jan password={config_diff.MASK} service=l2tp"
    assert config_diff.mask('set private-key="abc def=" listen-port=13231') == f"set private-key={config_diff.MASK} listen-port=13231"
