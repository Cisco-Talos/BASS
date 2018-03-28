############################################
### Container to build BinExport plugins ###
############################################

FROM centos:7.3.1611 as pluginbuilder
MAINTAINER Jonas Zaddach <jzaddach@cisco.com>

ARG IDA_WEB_PASSWORD
ENV PREFIX /home

RUN yum -y update && yum clean all
RUN yum -y install gcc-c++ autoconf automake libtool curl unzip git make wget zlib-devel libcurl-devel

# Install cmake 3.7.1
RUN wget https://cmake.org/files/v3.7/cmake-3.7.1.tar.gz
RUN tar xvfz cmake-3.7.1.tar.gz
WORKDIR cmake-3.7.1 
RUN ./bootstrap --system-curl && make && make install
WORKDIR ${PREFIX}

# Download IDA Pro 7.0 SDK. Needed for building BinExport plugin
RUN curl -L --user "idauser:${IDA_WEB_PASSWORD}" -o /tmp/ida-sdk.zip https://www.hex-rays.com/products/ida/support/ida/idasdk70.zip
WORKDIR ${PREFIX}
RUN unzip /tmp/ida-sdk.zip

# Download, build and install BinExport plugin
WORKDIR ${PREFIX}
RUN git clone https://github.com/google/binexport
WORKDIR ${PREFIX}/binexport
RUN mkdir -p build_linux
WORKDIR build_linux
RUN cmake -DCMAKE_BUILD_TYPE=Release -DIdaSdk_ROOT_DIR=${PREFIX}/idasdk70 ../cmake
RUN cmake --build .

#################################################
### Actual container with IDA Pro and service ###
#################################################

FROM centos:7.3.1611
MAINTAINER Jonas Zaddach <jzaddach@cisco.com>

ARG IDA_INSTALLATION_FILE=ida.run
ARG IDA_PASSWORD
ENV PREFIX /home

RUN yum -y update && yum clean all
RUN yum -y install python python-flask python-gunicorn \
    glib2 libXext libXi dbus-libs fontconfig \
    libSM libxcb python-libs

COPY $IDA_INSTALLATION_FILE /installation/

# Install IDA
RUN mkdir /ida
# ida.run is the IDA installation executable file
RUN chmod +x \
    /installation/$IDA_INSTALLATION_FILE

# Run IDA installation - echo keyboard input including installation password and "yes" commands
RUN printf "\n\n\n\n\n\ny\n$IDA_PASSWORD\n/ida\ny\ny\n" | /installation/ida.run

# Create a special file in order to prevent IDA to ask for license acceptance before executing IDA
RUN touch /ida/license.displayed

# Copy Binexport plugins
COPY --from=pluginbuilder /home/binexport/build_linux/binexport-prefix/binexport.so /ida/plugins
COPY --from=pluginbuilder /home/binexport/build_linux/binexport-prefix/binexport64.so /ida/plugins

# Install BinDiff
RUN curl -o /tmp/bindiff.deb https://dl.google.com/dl/zynamics/bindiff_4.3.0_amd64.deb
WORKDIR /tmp/bindiff
RUN ar x /tmp/bindiff.deb && tar xf data.tar.xz
RUN cp opt/zynamics/BinDiff/bin/differ ${PREFIX}
WORKDIR ${PREFIX}
RUN rm -Rf /tmp/bindiff /tmp/bindiff.deb

# Install BinExport and pickle service
WORKDIR ${PREFIX}
COPY files/service/ida_service.py .
COPY files/service/ida_service.sh /usr/local/bin
RUN chmod +x /usr/local/bin/ida_service.sh
COPY files/ida/export_binexport_pickle.py .

RUN mkdir /shared
WORKDIR /shared

RUN mkdir /logs

ENV PATH /ida:$PATH
ENV TERM xterm
ENV PYTHONPATH /usr/local/lib/python2.7/dist-packages:/usr/local/lib/python2.7/site-packages:/usr/lib/python2.7/:$PYTHONPATH
ENV BINDIFF_DIFFER ${PREFIX}/differ

VOLUME /logs

ENTRYPOINT ["/usr/local/bin/ida_service.sh"]
