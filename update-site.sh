#!/usr/bin/env bash
#s3cmd --guess-mime-type --delete-removed sync site/* s3://thehackerblog.com/tarnish/
s3cmd --no-mime-magic --guess-mime-type --delete-removed sync site/* s3://thehackerblog.com/tarnish/
