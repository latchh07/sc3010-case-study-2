# SC3010 Log4Shell lab -- VULNERABLE victim (Log4j 2.14.1)
# --- build stage: needs internet to pull Maven deps (build time only) ---
FROM maven:3.8-eclipse-temurin-8 AS build
WORKDIR /src
COPY pom.xml .
# Pre-fetch dependencies for a faster, more reproducible build.
RUN mvn -q -B dependency:go-offline || true
COPY src ./src
RUN mvn -q -B clean package

# --- runtime stage: JDK 8, NO internet at runtime (compose network is internal) ---
FROM eclipse-temurin:8-jre
WORKDIR /app
COPY --from=build /src/target/vulnerable-app.jar /app/app.jar

# trustURLCodebase=true recreates the PRE-PATCH JDK default so the LDAP
# remote-codebase class load actually fires on a modern JDK 8 image.
# Keeping this false is itself one of the real-world mitigations (see README).
ENTRYPOINT ["java", "-Dcom.sun.jndi.ldap.object.trustURLCodebase=true", "-jar", "/app/app.jar"]
