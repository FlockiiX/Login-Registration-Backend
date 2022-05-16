FROM maven:3.8.5-openjdk-17 AS base
WORKDIR /app
COPY . .

FROM base AS test
CMD mvn test

FROM base AS build
RUN ["mvn", "install", "-Dmaven.test.skip=true"]

FROM openjdk:17-jdk-alpine AS execution
COPY --from=build /app/target/login-registration-backend.jar login-registration-backend.jar
ENTRYPOINT ["java","-jar","login-registration-backend.jar"]