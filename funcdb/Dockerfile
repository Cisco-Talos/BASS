FROM ubuntu:16.04
MAINTAINER Jonas Zaddach <jzaddach@cisco.com>

ARG KERBEROS_REALM
ARG GIT_TOKEN
ENV PREFIX /home

RUN apt-get update
RUN apt-get install -y python python-sqlalchemy \
                              python-flask \
                              python-psycopg2

WORKDIR ${PREFIX}
COPY server.py .
COPY python python


ENV PYTHONPATH ${PREFIX}/python
EXPOSE 80

ENTRYPOINT ["/usr/bin/python", "server.py", "-v"]
