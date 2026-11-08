# SC3010 Log4Shell lab -- attacker container (LDAP referral + HTTP codebase).
#
# --- build stage: compile the DEFANGED Exploit.class with JDK 8 bytecode ---
# -source 8 -target 8 guarantees the victim's JDK 8 can load the class.
FROM eclipse-temurin:8-jdk AS build
WORKDIR /build
COPY Exploit.java .
RUN javac -source 8 -target 8 Exploit.java && ls -l Exploit.class

# --- runtime stage: Python (stdlib only) serves LDAP + HTTP, no internet ---
FROM python:3.11-slim
WORKDIR /opt/attacker

# The compiled payload must sit in the HTTP server's working directory so it is
# served at http://attacker:8000/Exploit.class
COPY --from=build /build/Exploit.class /opt/attacker/Exploit.class
COPY ldap_server.py http_server.py entrypoint.sh /opt/attacker/
RUN chmod +x /opt/attacker/entrypoint.sh

EXPOSE 1389 8000
ENTRYPOINT ["/opt/attacker/entrypoint.sh"]
