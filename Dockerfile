FROM maven:3-eclipse-temurin-24 AS build

ENV APP_HOME=/app
WORKDIR $APP_HOME


COPY pom.xml $APP_HOME
COPY src ./src
RUN mvn clean package -DskipTests=true

FROM eclipse-temurin:24-jre

ARG JAVA_OTEL_VERSION=2.24.0

WORKDIR /app-service

COPY --from=build \
    /app/target/ded-anonymizer-2.0.0.jar \
    ./app.jar

COPY config ./config    

ADD https://github.com/open-telemetry/opentelemetry-java-instrumentation/releases/download/v${JAVA_OTEL_VERSION}/opentelemetry-javaagent.jar /opentelemetry-javaagent.jar

EXPOSE 8000
CMD ["java", "-jar", "app.jar"]