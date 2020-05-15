FROM ubuntu:18.04 AS builder

RUN apt-get -y update
RUN apt-get install --fix-missing -y python3 python3-setuptools python3-dev build-essential git wget tar libusb-1.0-0.dev libudev-dev gcc-multilib g++-multilib

WORKDIR /
RUN git clone https://github.com/LedgerHQ/ledger-app-boilerplate.git
WORKDIR /ledger-app-boilerplate
RUN cd /ledger-app-boilerplate
RUN git checkout e84270ab07b276ad1c18370961d4efddc1058db4
WORKDIR /
RUN cd /

RUN apt-get install -y python3-venv

RUN apt-get update
RUN apt-get install -y emacs

WORKDIR /ledger-app-boilerplate
RUN cd /ledger-app-boilerplate
RUN ls
RUN ["/bin/bash", "-c", "source prepare-devenv.sh s"]

RUN apt-get install -y python3-pip
RUN pip3 install virtualenv

RUN pip3 install Pillow

RUN apt-get install -y gcc-multilib g++-multilib

ENV BOLOS_SDK /ledger-app-boilerplate/dev-env/SDK/nanos-secure-sdk/
ENV BOLOS_ENV /ledger-app-boilerplate/dev-env/CC/others/
ENV TARGET_NAME TARGET_NANOS

RUN pip3 install ledgerblue && touch .ledgerblue
RUN echo ledgerblue installed

WORKDIR /ledger-app-boilerplate
RUN cd /ledger-app-boilerplate
RUN sed -i 's/python /python3 /g' Makefile 
RUN make 

WORKDIR /
RUN cd /
RUN git clone https://github.com/LedgerHQ/ledger-app-sia.git
RUN cd /ledger-app-sia
WORKDIR /ledger-app-sia
RUN make

WORKDIR /
RUN cd /
COPY ledger-app-dgld /ledger-app-dgld
COPY apploader /apploader
WORKDIR /apploader

RUN rm -rf load_dgld

RUN ./build_dgld.sh

VOLUME /apploader


