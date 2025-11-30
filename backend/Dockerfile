FROM postgres:15-alpine

ENV POSTGRES_USER=postgres
ENV POSTGRES_PASSWORD=postgres
ENV POSTGRES_DB=mail

EXPOSE 5432

COPY init.sql /docker-entrypoint-initdb.d/