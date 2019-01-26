#!/usr/bin/env bash
# Due to docker limitations we have to do this :(
rm -rf tarnish-server/tarnishworker/
mkdir tarnish-server/tarnishworker/
cp -r tarnish-worker/* tarnish-server/tarnishworker/
docker-compose up --build
