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

RUN mkdir /tarnish_worker/

# Install dependencies
COPY [ "requirements.txt", "/tarnish_worker/" ]
WORKDIR /tarnish_worker/
RUN /usr/bin/pip install -r requirements.txt

# Move actually source over
COPY [ "tasks.py", "/tarnish_worker/" ]
COPY [ "start_workers.sh", "/tarnish_worker/" ]
COPY [ "celerylib.py", "/tarnish_worker/" ]
COPY [ "__init__.py", "/tarnish_worker/" ]
COPY [ "libs/", "/tarnish_worker/libs/" ]
COPY [ "chromium-docs/", "/tarnish_worker/chromium-docs/" ]
COPY [ "snippets/", "/tarnish_worker/snippets/" ]
COPY [ "configs/", "/tarnish_worker/configs/" ]

EXPOSE 80

ENTRYPOINT [ "/tarnish_worker/start_workers.sh" ]