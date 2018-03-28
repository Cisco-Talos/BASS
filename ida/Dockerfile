#################################################
### Actual container with IDA Pro and service ###
#################################################

FROM centos:7.3.1611
MAINTAINER Jonas Zaddach <jzaddach@cisco.com>

ARG IDA_INSTALLATION_FILE=ida.run
ARG IDA_PASSWORD

ENV PREFIX /home

RUN yum -y update && yum clean all
RUN yum -y install python python.i386 python-flask.i386 python-gunicorn.i386 \
    glib2.i386 libXext.i386 libXi.i386 dbus-libs.i386 fontconfig.i386 \
    libSM.i386 libxcb.i386 python-libs.i386

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

ADD https://github.com/google/binexport/releases/download/v9-20170303/zynamics_binexport_9.plx /ida/plugins
ADD https://github.com/google/binexport/releases/download/v9-20170303/zynamics_binexport_9.plx64 /ida/plugins

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

VOLUME /logs

ENTRYPOINT ["/usr/local/bin/ida_service.sh"]
