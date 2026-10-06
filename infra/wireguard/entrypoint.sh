#!/bin/bash
set -e

# Cały cykl życia interfejsu wg-mt (podniesienie istniejącej konfiguracji albo
# oczekiwanie na /setup przy świeżej instalacji) obsługuje teraz agent.
mkdir -p /etc/wireguard

exec python3 -u /agent.py
