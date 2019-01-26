#!/usr/bin/env bash
s3cmd --no-mime-magic --guess-mime-type --delete-removed sync site/* s3://yourwebsite.com/tarnish/
