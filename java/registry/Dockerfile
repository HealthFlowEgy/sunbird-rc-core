FROM openjdk:8-jdk-alpine
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
ARG JAR_FILE=*.jar
COPY ${JAR_FILE} app.jar
HEALTHCHECK --interval=30s --timeout=3s CMD wget -q --spider http://localhost:8081/health || exit 1
USER appuser
ENTRYPOINT ["java","-jar","/app.jar"]