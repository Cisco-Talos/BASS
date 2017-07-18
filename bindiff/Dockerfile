#TODO: Base this container on the IDA Pro container 
FROM ida
MAINTAINER Jonas Zaddach <jzaddach@cisco.com>

ENV PREFIX /home

# Add repository for JDK 8
RUN echo "deb http://httpredir.debian.org/debian jessie-backports main" >> /etc/apt/sources.list

# Update packages
RUN apt-get update

# Workaround for a stupid Debian bug
RUN apt install -t jessie-backports -y ca-certificates-java
# Install packages
RUN apt-get install -y curl openjdk-8-jre

# Get and install BinDiff package
WORKDIR ${PREFIX}
RUN mkdir -p packages/bindiff
WORKDIR packages/bindiff
RUN curl -o bindiff.deb https://dl.google.com/dl/zynamics/bindiff_4.3.0_amd64.deb
RUN echo "debconf bindiff/accepted-bindiff-license boolean true" | debconf-set-selections
#TODO: Specify good IDA Path from the parent container here
RUN echo "debconf zynamics/ida_location string /ida" | debconf-set-selections
RUN apt-get install -y xdg-utils lib32gcc1 lib32stdc++6 libc6-i386

RUN DEBIAN_FRONTEND=noninteractive dpkg -i bindiff.deb

# Update Java version - Bindiff needs JDK 8
RUN update-java-alternatives -s java-1.8.0-openjdk-amd64 2>&1

RUN mkdir -p ${PREFIX}/packages/bindiff/ida
COPY files/ida/export_bindiff.py ${PREFIX}/packages/bindiff/ida/
COPY files/ida/export_pickle.py ${PREFIX}/packages/bindiff/ida/
COPY files/ida/export_bindiff_pickle.py ${PREFIX}/packages/bindiff/ida/
RUN mkdir -p ${PREFIX}/packages/bindiff/service
COPY files/service/bindiff_service.sh ${PREFIX}/packages/bindiff/service/
COPY files/service/flask_service.py ${PREFIX}/packages/bindiff/service/

# This dictates how many workers will be spawned by the web server
ENV CORES 8
# This is the longest time (in seconds) that an IDA or bindiff job can take 
# before the web server restarts the worker thread
ENV TIMEOUT 300

RUN mkdir /logs
VOLUME /logs
WORKDIR ${PREFIX}/packages/bindiff/service
EXPOSE 80
ENTRYPOINT ["./bindiff_service.sh"]
#ENTRYPOINT ["/bin/bash"]
#ENV FLASK_APP /home/packages/bindiff/service/flask_service.py
#ENV FLASK_DEBUG 1
#ENTRYPOINT flask run --port 4000
