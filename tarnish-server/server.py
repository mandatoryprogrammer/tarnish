#!/usr/bin/env python
# coding=utf8
# -*- coding: utf8 -*-
# vim: set fileencoding=utf8 :
import tornado.escape
import tornado.ioloop
import tornado.web
import functools
import logging
import pycurl
import boto3
import string
import json
import yaml
import time
import sys
import os

from tornado import gen
from datetime import timedelta
from tornado.web import asynchronous
from expiringdict import ExpiringDict
from botocore.exceptions import ClientError
from tornado.concurrent import run_on_executor, futures
from tornado.httpclient import AsyncHTTPClient, HTTPRequest

from celerylib import app
import tcelery
from tarnishworker import tasks

tcelery.setup_nonblocking_producer()

reload( sys )  
sys.setdefaultencoding( "utf8" )

TARNISH_VERSION = "1.0"

S3_CLIENT = boto3.client(
    "s3",
    aws_access_key_id=os.environ.get( "aws_access_key" ),
    aws_secret_access_key=os.environ.get( "aws_secret_key" ),
)

AsyncHTTPClient.configure( "tornado.curl_httpclient.CurlAsyncHTTPClient" )

"""
Automatically expiring cache of extension metadata.

TODO: Write metadata to S3 for archival reasons.
"""
METADATA_CACHE = ExpiringDict(
	max_len=400,
	max_age_seconds=( 60 * 5 )
)

"""
Extension job table stores all of the extension IDs and
keeps track of whether or not we're processing them currently.

This prevents people double/oversubmitting extensions which are massive
and end up clogging up our cluster with unnecessary work.
"""
EXTENSION_JOB_TABLE = ExpiringDict(
	max_len=400,
	max_age_seconds=( 60 * 20 )
)

def pprint( input_dict ):
    print( json.dumps( input_dict, sort_keys=True, indent=4, separators=( ",", ": " ) ) )

class TaskSpawner(object):
	def __init__(self, loop=None):
		self.executor = futures.ThreadPoolExecutor( 60 )
		self.loop = loop or tornado.ioloop.IOLoop.current()

	@run_on_executor
	def get_s3_object( self, remote_path ):
		try:
			response = S3_CLIENT.get_object(
				Bucket=os.environ.get( "extension_s3_bucket" ),
				Key=remote_path
			)
		except ClientError as e:
			return False

		return response[ "Body" ].read()

	@run_on_executor
	def does_s3_object_exist( self, remote_path ):
		try:
			response = S3_CLIENT.head_object(
				Bucket=os.environ.get( "extension_s3_bucket" ),
				Key=remote_path
			)
		except ClientError as e:
			if int( e.response["Error"]["Code"] ) == 404:
				return False
		return True
        
	@run_on_executor
	def upload_to_s3( self, content_type, remote_path, body ):
		object_exists = True
		try:
			response = S3_CLIENT.head_object(
				Bucket=os.environ.get( "extension_s3_bucket" ),
				Key=remote_path
			)
		except ClientError as e:
			if int( e.response["Error"]["Code"] ) == 404:
				object_exists = False

		if object_exists:
			print( "It already exists, not uploading..." )
			return os.environ.get( "extension_s3_bucket" ) + "/" + remote_path

		print( "Uploading to: " + os.environ.get( "extension_s3_bucket" ) + "/" + remote_path )
		S3_CLIENT.put_object(
			ACL="public-read",
			ContentType=content_type,
			Bucket=os.environ.get( "extension_s3_bucket" ),
			Key=remote_path,
			Body=body
		)
		print( "Upload finished!" )
		return os.environ.get( "extension_s3_bucket" ) + "/" + remote_path

	"""
	@run_on_executor
	def get_report_data( self, chrome_extension_id, chrome_extension_zip ):
		return _get_report_data( chrome_extension_id, chrome_extension_zip )
	"""

class BaseHandler(tornado.web.RequestHandler):
    def __init__(self, *args, **kwargs):
		super(BaseHandler, self).__init__(*args, **kwargs)
		self.set_header("Access-Control-Allow-Origin", "https://thehackerblog.com")
		self.set_header("Access-Control-Allow-Headers", "Content-Type")
		self.set_header("X-Frame-Options", "deny")
		self.set_header("Content-Security-Policy", "default-src 'self'")
		self.set_header("X-XSS-Protection", "1; mode=block")
		self.set_header("X-Content-Type-Options", "nosniff")
		self.set_header("Cache-Control", "no-cache, no-store, must-revalidate")
		self.set_header("Pragma", "no-cache")
		self.set_header("Expires", "0")

    def logit( self, message, message_type="info" ):
        message = "[" + self.request.remote_ip + "] " + message

        if message_type == "info":
            logging.info( message )
        elif message_type == "warn":
            logging.warn( message )
        elif message_type == "debug":
            logging.debug( message )
        else:
            logging.info( message )

    def options(self):
        pass

    # Hack to stop Tornado from sending the Etag header
    def compute_etag( self ):
        return None

    def throw_404( self ):
        self.set_status(404)
        self.write("Resource not found")

    def error( self, error_message ):
        self.write(json.dumps({
            "success": False,
            "error": error_message
        }))

class MainHandler(BaseHandler):
	@gen.coroutine
	def options(self):
		self.write("")

	@gen.coroutine
	def post(self):
		try:
			request_data = tornado.escape.json_decode(
				self.request.body
			)
		except:
			print( "Error decoding body!" )
			raise gen.Return(False)

		if not "extension_id" in request_data:
			print( "No extension ID provided!" )
			raise gen.Return(False)

		local_tasks = TaskSpawner()

		chrome_extension_id = request_data[ "extension_id" ]

		chrome_extension_metadata = False
		metadata_attempts = 0
		while not chrome_extension_metadata:
			# Limit outselves to five tries
			if metadata_attempts > 5:
				print( "Attempts exhausted, quitting out!" )
				self.write()
				self.finish()
				raise gen.Return( false );
				break

			print( "Grabbing metadata for " + chrome_extension_id + "..." )
			sys.stdout.flush()

			if chrome_extension_id in METADATA_CACHE:
				chrome_extension_metadata = METADATA_CACHE[ chrome_extension_id ]
			else:
				chrome_extension_metadata = yield yield_on_complete(
					tasks.get_chrome_extension_metadata.apply_async(
						args=[ chrome_extension_id ],
					)
				)

				print( "Metadata: " )
				print( chrome_extension_metadata )

				if chrome_extension_metadata:
					METADATA_CACHE[ chrome_extension_id ] = chrome_extension_metadata

			metadata_attempts += 1

		print( "Extension metadata: " )
		pprint(
			chrome_extension_metadata
		)

		previous_report_data = yield local_tasks.get_s3_object(
			"reports/" + TARNISH_VERSION + "/" + chrome_extension_id + "/" + chrome_extension_id + "_" + chrome_extension_metadata[ "version" ] + ".json"
		)

		if previous_report_data:
			print( "Previous report exists!" )
			previous_report_data = json.loads( previous_report_data )
			self.write(
				previous_report_data
			)
			self.finish()
			raise gen.Return()

		print( "Analyzing extension ID " + chrome_extension_id + "..." )
		sys.stdout.flush()

		# Check if we're already analyzing this extension
		# If we are, then yield till that finishes and return result
		# Else throw it in the queue.
		if chrome_extension_id in EXTENSION_JOB_TABLE:
			chrome_extension_report = yield EXTENSION_JOB_TABLE[ chrome_extension_id ]
		else:
			EXTENSION_JOB_TABLE[ chrome_extension_id ] = yield_on_complete(
				tasks.get_report_data.apply_async(
					args=[
						chrome_extension_id,
						chrome_extension_metadata[ "name" ]
					],
				)
			)
			chrome_extension_report = yield EXTENSION_JOB_TABLE[ chrome_extension_id ]

		print( "Report generated for " + chrome_extension_id + "!" )

		chrome_extension_report[ "metadata" ] = chrome_extension_metadata

		# No yield, this shouldn't hold us up.
		local_tasks.upload_to_s3(
			"application/json",
			"reports/" + TARNISH_VERSION + "/" + chrome_extension_id + "/" + chrome_extension_id + "_" + chrome_extension_metadata[ "version" ] + ".json",
			json.dumps(
				chrome_extension_report,
				sort_keys=True,
				indent=4,
				separators=(",", ": ")
			)
		)

		self.write(
			chrome_extension_report
		)

		self.finish()

@gen.coroutine
def yield_on_complete( task_ref ):
	while True:
		if task_ref.status == "SUCCESS":
			raise gen.Return( task_ref.result )
		elif task_ref.status == "FAILURE":
			raise gen.Return( False )
		yield gen.Task(
			tornado.ioloop.IOLoop.current().add_timeout,
			time.time() + 1
		)

def make_app( is_debug ):
	# Convert to bool
	is_debug = ( is_debug.lower() == "true" )
	return tornado.web.Application([
		(r"/", MainHandler),
	], debug=is_debug)

if __name__ == "__main__":
	print( "Starting server..." )
	app = make_app( os.environ.get( "debugging" ) )
	server = tornado.httpserver.HTTPServer(
		app
	)
	server.bind(80)
	server.start()
	tornado.ioloop.IOLoop.current().start()