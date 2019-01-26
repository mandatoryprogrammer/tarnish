#!/usr/bin/env bash
rm elb_config.zip
mkdir tmp/
cd tarnish-worker/
zip -r elb_config.zip * .ebextensions/
mv elb_config.zip ..
cd ..
rm -rf tmp/
