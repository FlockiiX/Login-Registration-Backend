FROM openjdk:17-jdk-alpine as base

WORKDIR /app

COPY .mvn/ .mvn
COPY mvnw pom.xml ./
COPY src ./src

FROM base as test
CMD ["./mvnw", "test"]

FROM base as build
RUN ["./mvnw", "package"]

FROM base as buildSkipTests
RUN ["./mvnw", "package", "-Dmaven.test.skip=true"]

FROM openjdk:17-jdk-alpine as production
COPY --from=build /app/target/login-registration-backend.jar login-registration-backend.jar
ENTRYPOINT ["java","-jar","login-registration-backend.jar"]

FROM openjdk:17-jdk-alpine as development
COPY --from=buildSkipTests /app/target/login-registration-backend.jar login-registration-backend.jar
ENTRYPOINT ["java","-jar","login-registration-backend.jar"]