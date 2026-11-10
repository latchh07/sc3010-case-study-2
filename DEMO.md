# Log4Shell Lab — Demo Cheat-Sheet (SC3010)

Run everything in **PowerShell** from the repo folder. Keep this open while presenting.

```powershell
cd C:\Users\latch\OneDrive\Desktop\sc3010\log4shell-lab
```

---

## Before the demo (do it the night before)

1. Start **Docker Desktop**, wait until it says *Running*.
2. Pre-build the images (needs internet, takes a few min — cache it now):
   ```powershell
   docker compose build
   ```
3. Do one full practice run of the steps below.
4. **Record a screen capture of a successful run** as a backup.

> At demo time the containers have no internet — once built, wifi doesn't matter.

---

## The live demo

**0. Set the scene (optional)** — show the only difference is the Log4j version:
```powershell
python inspect_lab.py
```
*"Same app, same input. The only thing that changes is the library version."*

**1. Start the attacker's servers** (fake LDAP :1389 + web server :8000 holding Exploit.class):
```powershell
docker compose up -d attacker
```

**2. Run the VULNERABLE app — the money shot:**
```powershell
docker compose run --rm victim
```
Look for:
```
[EXPLOIT-PROOF] Arbitrary code executed inside victim JVM. id => uid=0(root) ...
```
*"The app only LOGGED the input — that alone made it fetch and run the attacker's code."*

> You'll also see a `ClassCastException` right after. **Expected and harmless** — the code already ran; the error is just the lookup failing afterwards. Don't panic.

**3. Show the attacker saw the whole chain:**
```powershell
docker compose logs attacker
```
*bindRequest → searchRequest returns the JNDI reference → GET /Exploit.class 200.*

**4. Run the PATCHED app with the SAME input:**
```powershell
docker compose run --rm victim-patched
```
No proof line — it logs `${jndi:...}` as plain text.
*"Same attack, patched Log4j, completely inert."*

**5. (Optional) Prove the lookup is on vs off:**
```powershell
docker compose run --rm victim '${java:version}'
docker compose run --rm victim-patched '${java:version}'
```
Vulnerable prints the real Java version; patched prints `${java:version}` literally.

**6. Clean up:**
```powershell
docker compose down --remove-orphans
```

---

## The flow in one breath

Crafted string is **logged** → vulnerable Log4j sees `${jndi:...}` and does a JNDI lookup → contacts the attacker's LDAP server → LDAP says "class is at http://attacker:8000/Exploit.class" → victim's JVM **downloads and runs** it → proof line prints. No "execute" call anywhere — logging it was enough.

## If asked about "getting admin"

Log4Shell = **code running as the app's user** (the break-in). Climbing to admin/root is a **separate** exploit (privilege escalation) we don't demo — our container just happens to run as root, which is why the proof shows `uid=0(root)`.

## Safety nets

- `python` not found? Try `python3`, or skip step 0 (it's optional).
- If Docker or wifi misbehaves live, play the backup recording instead of debugging on stage.
