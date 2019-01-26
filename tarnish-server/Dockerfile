# Use phusion/baseimage as base image. To make your builds
# reproducible, make sure you lock down to a specific version, not
# to `latest`! See
# https://github.com/phusion/baseimage-docker/blob/master/Changelog.md
# for a list of version numbers.
FROM phusion/baseimage:0.9.22

# Use baseimage-docker's init system.
#CMD ["/sbin/my_init"]

# Get dependencies
RUN apt-get update && apt-get install -y python python-virtualenv python-pip libcurl4-openssl-dev libssl-dev

# Clean up APT when done.
RUN apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

RUN mkdir /tarnish_server/

# Install dependencies
COPY [ "requirements.txt", "/tarnish_server/" ]
WORKDIR /tarnish_server/
RUN /usr/bin/pip install -r requirements.txt

# Move actually source over
COPY [ "server.py", "/tarnish_server/" ]
COPY [ "celerylib.py", "/tarnish_server/" ]
COPY [ "__init__.py", "/tarnish_server/" ]
COPY [ "tarnishworker", "/tarnish_server/tarnishworker/" ]
COPY [ "tornado-celery/", "/tarnish_server/tornado-celery/" ]

# Update tornado-celery
WORKDIR /tarnish_server/tornado-celery/
RUN /usr/bin/python /tarnish_server/tornado-celery/setup.py install
WORKDIR /tarnish_server/

EXPOSE 80

ENTRYPOINT ["/usr/bin/python", "/tarnish_server/server.py"]