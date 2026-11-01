# Etapa 1: Build y empaquetado
FROM eclipse-temurin:25-jdk AS builder
WORKDIR /build

COPY .mvn/ .mvn/
COPY mvnw pom.xml ./
RUN chmod +x mvnw

COPY src/ ./src/
RUN ./mvnw clean package -DskipTests

# Etapa 2: Imagen final de ejecución
FROM eclipse-temurin:25-jre-noble
WORKDIR /app

RUN groupadd -r spring && useradd -r -g spring spring
USER spring:spring

COPY --from=builder /build/target/*.jar app.jar

ENV PORT=8066
EXPOSE 8066

ENTRYPOINT ["java", "-Dspring.classformat.ignore=true", "-jar", "app.jar"]