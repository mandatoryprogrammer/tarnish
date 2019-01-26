from __future__ import absolute_import
from celery import Celery
import os

app = Celery(
	"tasks",
	broker=os.environ.get( "redis_backend" )
)
app.conf.CELERY_RESULT_BACKEND = os.environ.get( "redis_backend" )
app.conf.CELERY_IGNORE_RESULT = False
app.conf.CELERY_TASK_RESULT_EXPIRES = ( 1 * 60 ) # How long to hold the result in memory
app.conf.CELERYD_TASK_TIME_LIMIT = ( 10 * 60 ) # Max task execution time