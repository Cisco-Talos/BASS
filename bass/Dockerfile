FROM ubuntu:16.04
MAINTAINER Jonas Zaddach <jzaddach@cisco.com>

ENV PREFIX /home

# Update packages
RUN apt-get update

# Install packages
RUN apt-get install -y git python clamav-daemon clamav-freshclam python-pyclamd \
                       curl python-dev python-setuptools build-essential \
                       python-flask libssl-dev thrift-compiler \
                       swig python-pip libffi-dev cmake
RUN mkdir -p ${PREFIX}/packages

# Update signatures (this speeds up later updates)
RUN freshclam

# Stuff needed for ClamAV
RUN mkdir /var/run/clamav
RUN chown clamav:clamav /var/run/clamav

# Configure crontab to update signatures
RUN echo "23 0,6,12,18 * * * root /usr/bin/freshclam" >> /etc/cron.d/freshclam

# Install VRT certificate
RUN curl http://www.talosintelligence.com/downloads/ca.pem > /usr/local/share/ca-certificates/vrt.crt
RUN update-ca-certificates

# Install sdhash
ENV PROTOBUF_VERSION 2.5.0
WORKDIR ${PREFIX}/packages
# Build protobuf library. sdhash needs version 2.5.
RUN curl -L "https://github.com/google/protobuf/releases/download/v${PROTOBUF_VERSION}/protobuf-${PROTOBUF_VERSION}.tar.bz2" | tar xj
WORKDIR protobuf-${PROTOBUF_VERSION}
RUN ./configure
RUN make
RUN make install
# Build sdhash
WORKDIR ..
RUN git clone https://github.com/sdhash/sdhash sdhash
WORKDIR sdhash
RUN make
RUN make install
RUN install libsdbf.a /usr/local/lib
RUN ldconfig
WORKDIR swig/python
COPY files/sdhash/__init__.py .
COPY files/sdhash/setup.py .
RUN python setup.py install

# Install TLSH
WORKDIR ${PREFIX}/packages
RUN git clone https://github.com/trendmicro/tlsh tlsh
WORKDIR tlsh
COPY files/patches/0001-Changed-parameters-to-values-for-maximum-precision.patch .
RUN git apply 0001-Changed-parameters-to-values-for-maximum-precision.patch
RUN cmake -G "Unix Makefiles" .
RUN make -j8
RUN make install
RUN install bin/tlsh_unittest /usr/local/bin/
RUN install bin/tlsh_version /usr/local/bin/
WORKDIR py_ext
RUN python setup.py build
RUN python setup.py install

# Install ssdeep (we don't plan to use it, but since VT and everybody ssdeeps, maybe we'll need it)
WORKDIR ${PREFIX}/packages
ENV SSDEEP_VERSION 2.13
RUN curl -L https://downloads.sourceforge.net/project/ssdeep/ssdeep-${SSDEEP_VERSION}/ssdeep-${SSDEEP_VERSION}.tar.gz | tar xz
WORKDIR ssdeep-${SSDEEP_VERSION}
RUN ./configure
RUN make
RUN make install
RUN ldconfig
RUN pip install ssdeep

RUN mkdir /logs
RUN apt-get install -y sqlite3 libgraphviz-dev

# Install BASS
WORKDIR ${PREFIX}/packages
COPY python/ bass/
WORKDIR bass
RUN python setup.py install

WORKDIR ${PREFIX}
RUN mkdir server
WORKDIR server
COPY files/server/server.py .
COPY files/server/start.sh .
COPY files/json/api_db.json .
RUN chmod +x start.sh

ENTRYPOINT ["./start.sh"]
