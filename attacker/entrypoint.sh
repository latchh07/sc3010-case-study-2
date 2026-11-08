#!/bin/sh
# SC3010 Log4Shell lab -- attacker entrypoint.
# Starts the HTTP codebase server and the LDAP referral server together.
set -e

echo "[ATTACKER] starting HTTP codebase server (:8000) and LDAP referral server (:1389)"

# HTTP server in the background (serves Exploit.class).
python3 /opt/attacker/http_server.py &
HTTP_PID=$!

# Clean shutdown of the background HTTP server when this script exits.
trap 'kill "$HTTP_PID" 2>/dev/null || true' INT TERM EXIT

# LDAP server in the foreground (keeps the container alive).
python3 /opt/attacker/ldap_server.py
