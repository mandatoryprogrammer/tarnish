#!/usr/bin/env bash
#source env/bin/activate
ls -lisah
celery -A tasks worker --loglevel=debug