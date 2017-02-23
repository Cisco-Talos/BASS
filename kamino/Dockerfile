# Copyright 2017 Cisco Systems

FROM ubuntu:16.04
MAINTAINER Jonas Zaddach <jzaddach@cisco.com>

ENV PREFIX /home
ENV KAMINO_VERSION 1.1.2
ENV JAVA_HOME /usr/lib/jvm/java-1.8.0-openjdk-amd64

RUN apt-get update
RUN apt-get install -y openjdk-8-jdk-headless curl git \
                       python build-essential unzip 
                       #msitools \
                       #bsdiff

RUN mkdir /data
RUN mkdir ${PREFIX}/packages
WORKDIR ${PREFIX}/packages

# Build and install Z3
RUN git clone https://github.com/Z3Prover/z3 z3
WORKDIR z3
RUN python scripts/mk_make.py --java
WORKDIR build
RUN make -j8
RUN make install

# Install kamino
WORKDIR ${PREFIX}/packages
RUN mkdir kamino
WORKDIR kamino
RUN curl -L https://github.com/McGill-DMaS/Kam1n0-Plugin-IDA-Pro/releases/download/${KAMINO_VERSION}/kam1n0_server_${KAMINO_VERSION}_linux_64.tar.gz | tar xz
WORKDIR ${PREFIX}/packages/kamino/lib
RUN cp ${PREFIX}/packages/z3/build/libz3.so liblibz3.so
RUN cp ${PREFIX}/packages/z3/build/libz3java.so liblibz3java.so

RUN apt-get install -y gdb


WORKDIR ${PREFIX}/packages/kamino
COPY files/server/start.sh .
RUN chmod +x start.sh

VOLUME /data
EXPOSE 9988

ENTRYPOINT ["./start.sh", "--architecture", "metapc.xml"]
#ENTRYPOINT ["./start.sh", "--architecture", "symbolic"]
