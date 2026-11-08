# SC3010 Log4Shell lab -- PATCHED control (Log4j 2.17.1), identical in every
# other respect to the vulnerable image, INCLUDING the trustURLCodebase flag.
# This proves the fix is the library upgrade, not the JVM flag or config.
# --- build stage: needs internet to pull Maven deps (build time only) ---
FROM maven:3.8-eclipse-temurin-8 AS build
WORKDIR /src
COPY pom.xml .
RUN mvn -q -B dependency:go-offline || true
COPY src ./src
RUN mvn -q -B clean package

# --- runtime stage: JDK 8, NO internet at runtime (compose network is internal) ---
FROM eclipse-temurin:8-jre
WORKDIR /app
COPY --from=build /src/target/patched-app.jar /app/app.jar

# Same flag as the vulnerable image on purpose -- the patched library is
# inert regardless, because 2.16+ removed JNDI message lookups entirely.
ENTRYPOINT ["java", "-Dcom.sun.jndi.ldap.object.trustURLCodebase=true", "-jar", "/app/app.jar"]
