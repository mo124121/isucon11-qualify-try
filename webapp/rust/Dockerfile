FROM ubuntu:22.04

WORKDIR /tmp
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
    apt-get -y upgrade && \
    apt-get install -y wget default-mysql-client

RUN useradd --uid=1100 --create-home isucon
USER isucon
