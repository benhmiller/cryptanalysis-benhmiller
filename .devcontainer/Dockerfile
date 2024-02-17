FROM ubuntu:jammy

RUN apt-get update && apt-get -y install --no-install-recommends build-essential \
    gcc gdb git libcurl4-gnutls-dev libgcrypt20-dev valgrind \
    gnupg2 openssh-client ca-certificates && \
    apt-get clean autoclean && \
    apt-get autoremove

RUN addgroup --gid 1000 vscode
RUN adduser --disabled-password --gecos "" --uid 1000 --gid 1000 vscode
USER vscode
ENV HOME /home/vscode
