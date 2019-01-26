#!/usr/bin/env python
# coding=utf8
# -*- coding: utf8 -*-
# vim: set fileencoding=utf8 :
import re
import os
import sys
import uuid
import time
import json
import yaml
import boto3
import requests
import jsbeautifier
import zipfile
import StringIO
import hashlib
import string

from celerylib import app
from celery.result import AsyncResult
from celery.result import allow_join_result
from bs4 import BeautifulSoup
from celery import Task
from io import BytesIO
from libs.cspparse import *
from botocore.exceptions import ClientError
from distutils.version import LooseVersion, StrictVersion

reload( sys )  
sys.setdefaultencoding( "utf8" )

S3_CLIENT = boto3.client(
    "s3",
    aws_access_key_id=os.environ.get( "aws_access_key" ),
    aws_secret_access_key=os.environ.get( "aws_secret_key" ),
)

# Taken from https://stackoverflow.com/questions/2319019/using-regex-to-remove-comments-from-source-files
def remove_comments(string):
	pattern = r"(\".*?(?<!\\)\"|\'.*?(?<!\\)\')|(/\*.*?\*/|//[^\r\n]*$)"
	# first group captures quoted strings (double or single)
	# second group captures comments (//single-line or /* multi-line */)
	regex = re.compile(pattern, re.MULTILINE|re.DOTALL)
	def _replacer(match):
		# if the 2nd group (capturing comments) is not None,
		# it means we have captured a non-quoted (real) comment string.
		if match.group(2) is not None:
			return "" # so we will return empty to remove the comment
		else: # otherwise, we will return the 1st group
			return match.group(1) # captured quoted-string
	return regex.sub(_replacer, string)


#https://gist.github.com/seanh/93666
def format_filename(s):
	valid_chars = "-_.() %s%s" % (string.ascii_letters, string.digits)
	filename = ''.join(c for c in s if c in valid_chars)
	filename = filename.replace(' ','_') # I don't like spaces in filenames.
	return filename

def get_json_from_file( filename, should_remove_comments=False ):
	"""
	Turn a JSON file into a dict
	"""
	with open( filename, "r" ) as file_handler:
		file_contents = file_handler.read()

	if should_remove_comments:
		file_contents = remove_comments( file_contents )

	return json.loads( file_contents )

current_dir = os.path.dirname(
	os.path.realpath(
		__file__
	)
)
RETIRE_JS_DEFINITIONS = get_json_from_file( current_dir + "/configs/jsrepository.json", False )
PERMISSIONS_DATA = get_json_from_file( current_dir + "/configs/permissions.json", False )
JAVASCRIPT_INDICATORS = get_json_from_file( current_dir + "/configs/javascript_indicators.json", False )
FINGERPRINT_BASE_JS = ""

with open( current_dir + "/snippets/fingerprinting.js", "r" ) as js_handler:
	FINGERPRINT_BASE_JS = js_handler.read()

CSP_KNOWN_BYPASSES = {
	"script-src": [
		# (DOMAIN, DESCRIPTION/EXAMPLE,)
		# Pulled from various sources:
		# https://github.com/GoSecure/csp-auditor/blob/master/csp-auditor-core/src/main/resources/resources/data/csp_host_vulnerable_js.txt
		# https://github.com/mozilla/http-observatory/blob/5c52b6bfdfc0a2f1f83b38fd097c5f8cbeef3e6d/httpobs/conf/bypasses/jsonp.json
		("ajax.googleapis.com", '''
Additional information is available here:  https://github.com/cure53/XSSChallengeWiki/wiki/H5SC-Minichallenge-3:-%22Sh*t,-it%27s-CSP!%22

Example Payload:
"><script src=//ajax.googleapis.com/ajax/services/feed/find?v=1.0%26callback=alert%26context=1337></script>
		'''),
		( "raw.githubusercontent.com", """
This is a hostname of which anyone can upload content. This host is used when viewing uploaded Github repo files in "raw".

Example:
https://github.com/mandatoryprogrammer/sonar.js/blob/master/sonar.js -> https://raw.githubusercontent.com/mandatoryprogrammer/sonar.js/master/sonar.js
		""" ),
		( "github.io", """
This is a shared hostname of which anyone can upload content. This domain for Github pages (https://pages.github.com/) which allows you to host content on github.io via repo commits.
		""" ),
		( "*.s3.amazonaws.com", """
This is a shared hostname of which anyone can upload content. Any user can add content to this host via Amazon AWS's S3 offering (https://aws.amazon.com/s3/).
		""" ),
		( "*.cloudfront.com", """
This is a shared hostname of which anyone can upload content. Any user can add content to this host via Amazon's Cloudfront CDN offering (https://aws.amazon.com/cloudfront/).
		""" ),
		( "*.herokuapp.com", """
This is a shared hostname of which anyone can upload content. Any user can add content to this host via Heroku's app offering (https://www.heroku.com/platform).
		""" ),
		( "dl.dropboxusercontent.com", """
This is a shared hostname of which anyone can upload content. Any user can add content to this host via uploading content to their Dropbox account (https://www.dropbox.com/) and getting the web download link for it.
		""" ),
		( "*.appspot.com", """
This is a shared hostname of which anyone can upload content. Any user can add content to this host via creating a Google AppEngine app (https://cloud.google.com/appengine/).
		""" ),
		( "*.googleusercontent.com", """
This is a shared hostname of which anyone can upload content. Any user can add content to this host via uploading to various Google services. 
		""" ),
		( "cdn.jsdelivr.net", """
This is a shared hostname of which anyone can upload content. Any user can add content to this host via uploading a package to npm (https://www.npmjs.com/) which will then be proxy hosted on this host (https://www.jsdelivr.com/features).
		""" ),
		( "cdnjs.cloudflare.com", """
This host serves old version of the Angular library. Hosts that serve old Angular libraries can be used to bypass Content Security Policy (CSP) in ways similar to the following:
<body class="ng-app"ng-csp ng-click=$event.view.alert(1337)>

<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.0.8/angular.js"></script>

More information about older Angular version sandboxing (or lack of) and various escapes can be read about here:
http://blog.portswigger.net/2017/05/dom-based-angularjs-sandbox-escapes.html
		""" ),
		( "code.angularjs.org", """
This host serves old version of the Angular library. Hosts that serve old Angular libraries can be used to bypass Content Security Policy (CSP) in ways similar to the following:
<body class="ng-app"ng-csp ng-click=$event.view.alert(1337)>

<script src="https://code.angularjs.org/1.0.8/angular.js"></script>

More information about older Angular version sandboxing (or lack of) and various escapes can be read about here:
http://blog.portswigger.net/2017/05/dom-based-angularjs-sandbox-escapes.html
		""" ),
		( "d.yimg.com", """
This host contains a JSONP endpoint which can be used to bypass Content Security Policy (CSP):
<script src="http://d.yimg.com/autoc.finance.yahoo.com/autoc?callback=alert&query=yah&lang=en&region=us"></script>
		""" ),
		( "www.linkedin.com", """
This host contains a JSONP endpoint which can be used to bypass Content Security Policy (CSP):
<script src="https://www.linkedin.com/countserv/count/share?url=https://example.com&format=jsonp&callback=test"></script>
		""" ),
		( "*.wikipedia.org", """
This host contains a JSONP endpoint which can be used to bypass Content Security Policy (CSP):
<script src="https://en.wikipedia.org/w/api.php?action=opensearch&format=json&limit=5&callback=test&search=test"></script>
<script src="https://se.wikipedia.org/w/api.php?action=opensearch&format=json&limit=5&callback=test&search=test"></script>
<script src="https://ru.wikipedia.org/w/api.php?action=opensearch&format=json&limit=5&callback=test&search=test"></script>
		""" ),
		#( "", """
		#""" ),
	]
}

# First load all JSON files into a tree structure for future use
CHROME_DOC_DIR = "./chromium-docs/"

def get_chrome_doc_dict( path_to_docs_dir ):
	"""
	Grab the JSON files in Chromium source and parse them into a tree for autodoc
	https://github.com/chromium/chromium/tree/master/chrome/common/extensions/api
	"""
	chrome_doc_dict = {}
	for root, dirnames, filenames in os.walk( path_to_docs_dir ):
		for filename in filenames:
			if filename.endswith( ".json" ) and not filename.startswith( "_" ):
				file_path = os.path.join( root, filename )
				api_function_list = get_json_from_file(
					file_path,
					True
				)
				
				for api_function in api_function_list:
					chrome_doc_dict[ api_function[ "namespace" ] ] = api_function

	return chrome_doc_dict

def get_api_call_targets( chrome_doc_dict ):
	"""
	Now generate a list of target strings

	[
		{
			"match_string": "",
			"comment": "",
		}
	]
	"""
	api_call_targets = []
	for api_name, api_data in chrome_doc_dict.iteritems():
		if "functions" in api_data and not "Private" in api_name:
			combined_list = []

			if "events" in api_data:
				combined_list = combined_list + api_data[ "events" ]
			if "functions" in api_data:
				combined_list = combined_list + api_data[ "functions" ]

			for function_data in combined_list:
				comment_data = "{{WHITESPAE_PLACEHOLDER}}// chrome." + api_name + "." + function_data[ "name" ] + "("

				if "parameters" in function_data:
					parameter_list = []
					for parameter in function_data[ "parameters" ]:
						parameter_list.append( parameter[ "name" ] )

					comment_data += ", ".join( parameter_list )
					comment_data += ")\n"

					for parameter in function_data[ "parameters" ]:
						if "type" in parameter:
							comment_data += "{{WHITESPAE_PLACEHOLDER}}// @param " + parameter[ "type" ] + " {" + parameter[ "name" ] + "} "
						else:
							comment_data += "{{WHITESPAE_PLACEHOLDER}}// @param unknown {" + parameter[ "name" ] + "} "

						if "description" in parameter:
							comment_data += parameter[ "description" ]

						comment_data += "\n"

						if "type" in parameter and parameter[ "type" ] == "object" and "properties" in parameter:
							for object_name, object_value in parameter[ "properties" ].iteritems():
								comment_data += "{{WHITESPAE_PLACEHOLDER}}// -> @property "
								if "type" in parameter:
									comment_data += "{" + parameter[ "type" ] + "} "
								else:
									comment_data += "{unknown} "

								comment_data += object_name + " "

								if "description" in object_value:
									comment_data += object_value[ "description" ]

								comment_data += "\n"

						if "type" in parameter and parameter[ "type" ] == "function" and "parameters" in parameter:
							for function_value in parameter[ "parameters" ]:
								comment_data += "{{WHITESPAE_PLACEHOLDER}}// -> @argument "
								
								if "type" in function_value:
									comment_data += "{" + parameter[ "type" ] + "} "
								else:
									comment_data += "{unknown} "

								comment_data += function_value[ "name" ] + " "

								if "description" in function_value:
									comment_data += function_value[ "description" ]

								comment_data += "\n"

				else:
					comment_data += ")\n"

				if "description" in function_data:
					comment_data += "{{WHITESPAE_PLACEHOLDER}}// Description: " + re.sub( "<[^<]+?>", "", function_data[ "description" ] ) + "\n"

				comment_data += "{{WHITESPAE_PLACEHOLDER}}// https://developer.chrome.com/extensions/" + api_name + "#method-" + function_data[ "name" ]

				api_call_targets.append({
					"match_string": "chrome." + api_name + "." + function_data[ "name" ] + "(",
					"comment": comment_data,
				})

	return api_call_targets

CHROME_DOC_LIST = get_chrome_doc_dict(
	CHROME_DOC_DIR
)

# Now convert the tree into a call target list
API_CALL_TARGETS = get_api_call_targets( CHROME_DOC_LIST )

class RetireJS( object ):
	"""
	Scan a given JavaScript file for Retire.js matches.
	"""
	def __init__( self, definitions ):
		cleaned_definitions = {}

		# Clean up dirty definitions
		for definition_name, definition_value in definitions.iteritems():
			is_useful = True
			if not "vulnerabilities" in definition_value or len( definition_value[ "vulnerabilities" ] ) == 0:
				is_useful = False
			if is_useful:
				cleaned_definitions[ definition_name ] = definition_value

		self.definitions = cleaned_definitions

	def regex_version_match( self, definition_name, regex_list, target_string ):
		"""
		Check a given target string for a version match, return a list of matches
		and their respective versions.
		"""
		matching_definitions = []
		for filecontent_matcher in regex_list	:
			matcher_parts = filecontent_matcher.split( "(§§version§§)" )
			filecontent_matcher = filecontent_matcher.replace( "(§§version§§)", "[a-z0-9\.\-]+" )
			match = re.search( filecontent_matcher, target_string )
			if match:
				version_match = str( match.group() )
				for matcher_part in matcher_parts:
					matcher_match = re.search( matcher_part, version_match )
					if matcher_match:
						version_match = version_match.replace( str( matcher_match.group() ), "" )

				matching_definitions.append({
					"definition_name": definition_name,
					"version": version_match
				})

		return matching_definitions

	def get_libraries( self, filename, file_data ):
		"""
		Find libraries and their versions and return a list of match(s):

		[{
			"definition_name": "jquery",
			"version": "1.1.1"
		}]
		"""
		matching_definitions = []

		# In this first iteration we simply attempt to extract version numbers
		for definition_name, definition_value in self.definitions.iteritems():
			# File contents match
			if "filecontent" in definition_value[ "extractors" ]:
				filecontent_matches = self.regex_version_match(
					definition_name,
					definition_value[ "extractors" ][ "filecontent" ],
					file_data
				)
				matching_definitions = filecontent_matches + matching_definitions

			# URI name match
			if "uri" in definition_value[ "extractors" ]:
				uri_matches = self.regex_version_match(
					definition_name,
					definition_value[ "extractors" ][ "uri" ],
					file_data
				)
				matching_definitions = uri_matches + matching_definitions

			# Filename
			if "filename" in definition_value[ "extractors" ]:
				filename_matches = self.regex_version_match(
					definition_name,
					definition_value[ "extractors" ][ "filename" ],
					file_data
				)
				matching_definitions = filename_matches + matching_definitions

			# Hash matching
			if "hashes" in definition_value[ "extractors" ]:
				hasher = hashlib.sha1()
				hasher.update( file_data )
				js_hash = hasher.hexdigest()
				if js_hash in definition_value[ "extractors" ][ "hashes" ]:
					matching_definitions.append({
						"definition_name": definition_name,
						"version": definition_value[ "extractors" ][ "hashes" ][ js_hash ]
					})

		# De-duplicate matches via hashing
		match_hash = {}
		for matching_definition in matching_definitions:
			match_hash[ matching_definition[ "definition_name" ] + matching_definition[ "version" ] ] = {
				"definition_name": matching_definition[ "definition_name" ],
				"version": matching_definition[ "version" ]
			}

		matching_definitions = []

		for key, value in match_hash.iteritems():
			matching_definitions.append( value )

		return matching_definitions

	def check_file( self, filename, file_data ):
		"""
		Check a given file
		@filename: Name of the file
		@file_data: Contents of the JavaScript
		"""
		matching_definitions = self.get_libraries(
			filename,
			file_data
		)

		vulnerability_match_hash = {}
		vulnerability_match = []

		for matching_definition in matching_definitions:
			vulnerabilities = self.definitions[ matching_definition[ "definition_name" ] ][ "vulnerabilities" ]

			for vulnerability in vulnerabilities:
				match = False
				if matching_definition[ "version" ].strip() == "":
					match = False
				elif "atOrAbove" in vulnerability and "below" in vulnerability:
					if LooseVersion( matching_definition[ "version" ] ) >= LooseVersion( vulnerability[ "atOrAbove" ] ) and LooseVersion( matching_definition[ "version" ] ) < LooseVersion( vulnerability[ "below" ] ):
						match = True
				elif "above" in vulnerability and "below" in vulnerability:
					if LooseVersion( matching_definition[ "version" ] ) > LooseVersion( vulnerability[ "above" ] ) and LooseVersion( matching_definition[ "version" ] ) < LooseVersion( vulnerability[ "below" ] ):
						match = True
				elif "below" in vulnerability:
					if LooseVersion( matching_definition[ "version" ] ) < LooseVersion( vulnerability[ "below" ] ):
						match = True
				elif "above" in vulnerability:
					if LooseVersion( matching_definition[ "version" ] ) > LooseVersion( vulnerability[ "above" ] ):
						match = True
				elif "atOrAbove" in vulnerability:
					if LooseVersion( matching_definition[ "version" ] ) >= LooseVersion( vulnerability[ "atOrAbove" ] ):
						match = True
				elif "atOrBelow" in vulnerability:
					if LooseVersion( matching_definition[ "version" ] ) <= LooseVersion( vulnerability[ "atOrBelow" ] ):
						match = True

				if match:
					vulnerability_match_hash[ matching_definition[ "definition_name" ] + matching_definition[ "version" ] ] = {
						"version": matching_definition[ "version" ],
						"definition_name": matching_definition[ "definition_name" ],
						"vulnerability": vulnerability
					}

		# De-duplicate
		for key, value in vulnerability_match_hash.iteritems():
			vulnerability_match.append(
				value
			)

		return vulnerability_match

RETIRE_JS = RetireJS( RETIRE_JS_DEFINITIONS )

def prettify_json( input_dict ):
    return json.dumps( input_dict, sort_keys=True, indent=4, separators=( ",", ": " ) )

def pprint( input_dict ):
    print( json.dumps( input_dict, sort_keys=True, indent=4, separators=( ",", ": " ) ) )

def upload_to_s3( content_type, remote_path, body ):
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

@app.task(
	name="tarnishworker.tasks.get_chrome_extension_metadata",
    time_limit=( 30 * 1 ), # Don't wait more then 30 minutes.
)
def get_chrome_extension_metadata( extension_id ):
	"""
	Get Chrome extension metadata from the Chrome store.
	"""
	return_metadata = {}

	headers = {
		"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:49.0) Gecko/20100101 Firefox/49.0",
		"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		"Accept-Language": "en-US,en;q=0.5",
		"Accept-Encoding": "gzip, deflate, br",
		"X-Same-Domain": "1",
		"Content-Type": "application/x-www-form-urlencoded;charset=utf-8",
		"Referer": "https://chrome.google.com/",
	}

	try:
		response = requests.get(
			"https://chrome.google.com/webstore/detail/extension-name/" + extension_id + "?hl=en",
			headers=headers,
			timeout=( 15 ),
		)
	except:
		raise self.retry()

	soup = BeautifulSoup(
		response.text,
		"html.parser"
	)

	version_element = soup.find(
		"meta",
		{ "itemprop": "version" }
	)
	return_metadata[ "version" ] = str( version_element.get( "content" ) )

	name_element = soup.find(
		"meta",
		{ "itemprop": "name" }
	)
	return_metadata[ "name" ] = str( name_element.get( "content" ) )

	url_element = soup.find(
		"meta",
		{ "itemprop": "url" }
	)
	return_metadata[ "url" ] = str( url_element.get( "content" ) )

	image_element = soup.find(
		"meta",
		{ "itemprop": "image" }
	)
	return_metadata[ "image" ] = str( image_element.get( "content" ) )

	download_count_element = soup.find(
		"meta",
		{ "itemprop": "interactionCount" }
	)
	return_metadata[ "download_count" ] = int(
		str(
			download_count_element.get( "content" )
		).replace(
			"UserDownloads:",
			""
		).replace(
			",",
			""
		).replace(
			"+",
			""
		)
	)

	os_element = soup.find(
		"meta",
		{ "itemprop": "operatingSystem" }
	)
	return_metadata[ "os" ] = str( os_element.get( "content" ) )

	rating_element = soup.find(
		"meta",
		{ "itemprop": "ratingValue" }
	)
	return_metadata[ "rating" ] = float( rating_element.get( "content" ) )

	rating_count_element = soup.find(
		"meta",
		{ "itemprop": "ratingCount" }
	)
	return_metadata[ "rating_count" ] = int( rating_count_element.get( "content" ) )

	description_element = soup.find(
		"div",
		{ "itemprop": "description" }
	)
	return_metadata[ "short_description" ] = str( description_element.text )

	return return_metadata


def get_uuid():
	return str( uuid.uuid4() )

def pprint( input_dict ):
    print( json.dumps(input_dict, sort_keys=True, indent=4, separators=(',', ': ')) )

def beautified_js( input_js ):
	options = jsbeautifier.default_options()
	options.indent_size = 4
	return jsbeautifier.beautify(
		input_js,
		options
	)

def ends_in_ext_list( target_string, ext_list ):
	for ext in ext_list:
		if target_string.endswith( ext ):
			return True

	return False

def get_csp_report( csp_object ):
	"""
	Much of this is taken from: https://github.com/moloch--/CSP-Bypass/
	Credits to moloch--, he can't hang but he can code :)

	return_data = [
		{
			"name": "",
			"description": "",
			"risk": "",
		}
	]
	"""
	return_data = []

	""" Checks the current CSP header for unsafe content sources """
	for directive in [SCRIPT_SRC]:
		if UNSAFE_EVAL in csp_object[directive]:
			return_data.append({
				"name": "Unsafe Eval",
				"description": "Extension allows unsafe evaluation of JavaScript via eval().",
				"risk": "high"
			})
		if UNSAFE_INLINE in csp_object[directive]:
			return_data.append({
				"name": "Unsafe Inline",
				"description": "Extension allows unsafe evaluation of JavaScript via inline <script>, and event handlers.",
				"risk": "high"
			})

	"""
	Check content sources for wildcards '*' note that wilcard subdomains
	are checked by `wildcardSubdomainContentSourceCheck'
	"""
	for directive, sources in csp_object.iteritems():
		if sources is None:
			continue  # Skip unspecified directives in NO_FALLBACK
		if any( src == "*" for src in sources ):
			return_data.append({
				"name": "Wildcard Source for Directive '" + directive + "'",
				"description": "Wildcard sources specified for directive " + directive,
				"risk": "medium",
			})

	""" Check content sources for wildcards subdomains '*.foo.com' """
	for directive, sources in csp_object.iteritems():
		if sources is None:
			continue
		# This check is a little hacky but should work well
		# the shortest subdomain string should be like *.a.bc
		if any("*" in src and 5 <= len(src) for src in sources):
			return_data.append({
				"name": "Wildcard Source for Directive '" + directive + "'",
				"description": "Wildcard sources specified for directive " + directive,
				"risk": "medium",
			})

	"""
	Check for missing directives that do not inherit from `default-src'
	"""
	for directive in ContentSecurityPolicy.NO_FALLBACK:
		if directive not in csp_object:
			return_data.append({
				"name": "Missing CSP Directive '" + directive + "'",
				"description": "Lack of CSP directive '" + directive + "', which does not inherit from default-src.",
				"risk": "low",
			})

	"""
	Parses the CSP for known bypasses, this check is a little more
	complicated, and calls into other subroutines.
	"""
	for directive, known_bypasses in CSP_KNOWN_BYPASSES.iteritems():
		bypasses = _bypassCheckDirective( csp_object, directive, known_bypasses )
		for bypass in bypasses:
			return_data.append({
				"name": "CSP Bypass Possible",
				"description": "CSP allows a script source with known bypasses: '" + bypass[0] + "'.",
				"risk": "high",
				"bypass": bypass[1],
			})

	return return_data

def _bypassCheckDirective(csp, directive, known_bypasses):
	"""
	Check an individual directive (e.g. `script-src') to see if it contains
	any domains that host known CSP bypasses.
	"""
	bypasses = []
	for src in csp[directive]:
		if src.startswith("'") or src in [HTTP, HTTPS, DATA, BLOB]:
			continue  # We only care about domains

		# Iterate over all bypasses and check if `src' allows loading
		# content from `domain' if so, we have a bypass!
		for domain, payload in known_bypasses:
			if csp_match_domains(src, domain):
				bypasses.append((domain, payload,))
	return bypasses

def get_lowercase_list( input_list ):
	return_list = []
	for item in input_list:
		return_list.append( item.lower() )
	return return_list

@app.task(
	name="tarnishworker.tasks.get_report_data",
    time_limit=( 60 * 30 ), # Don't wait more then 30 minutes.
)
def get_report_data( chrome_extension_id, chrome_extension_name ):
	report_data = {
		"extension_id": chrome_extension_id,
		"manifest": {},
		"fingerprintable": False,
		"web_accessible_resources": [],
		"web_accessible_html": [],
		"web_accessible_image": [],
		"web_accessible_other": [],
		"active_pages": [],
		"scripts_scan_results": {},
		"s3_extension_download_link": "",
		"s3_beautified_extension_download_link": "",
		#"s3_autodoc_extension_download_link": "",
		"metadata": {},
		"permissions_info": [],
	}

	print( "Downloading extension ID " + chrome_extension_id + "..." )
	chrome_extension_handler = get_chrome_extension(
		chrome_extension_id
	)

	chrome_extension_zip = zipfile.ZipFile(
		chrome_extension_handler
	)

	# Create a new .zip for the beautified version
	beautified_zip_handler = StringIO.StringIO()
	#autodoc_zip_handler = StringIO.StringIO()
	regular_zip_handler = StringIO.StringIO()
	beautified_extension = zipfile.ZipFile( beautified_zip_handler, mode="w" )
	#autodoc_extension = zipfile.ZipFile( autodoc_zip_handler, mode="w" )
	regular_extension = zipfile.ZipFile( regular_zip_handler, mode="w" )

	# List of file extensions that will be written (prettified) later.
	prettified_exts = [
		".html",
		".htm",
		".js"
	]

	for file_path in chrome_extension_zip.namelist():
		file_data = chrome_extension_zip.read( file_path )
		if not ends_in_ext_list( file_path, prettified_exts ):
			beautified_extension.writestr(
				file_path,
				file_data
			)
			"""
			autodoc_extension.writestr(
				file_path,
				file_data
			)
			"""

		# Create a valid regular .zip file of the extension as well
		regular_extension.writestr(
			file_path,
			file_data
		)

	manifest_data = json.loads(
		chrome_extension_zip.read(
			"manifest.json"
		)
	)

	# Upload manifest.json to S3 for later aggregation
	upload_to_s3(
		"application/json",
		"manifests/" + chrome_extension_id + ".json",
		prettify_json( manifest_data )
	)

	# Parse CSP policy
	if "content_security_policy" in manifest_data:
		csp_object = ContentSecurityPolicy( "content-security-policy", manifest_data[ "content_security_policy" ] )
		report_data[ "content_security_policy" ] = manifest_data[ "content_security_policy" ]
	else:
		csp_object = ContentSecurityPolicy( "content-security-policy", "script-src 'self'; object-src 'self'" )
		report_data[ "content_security_policy" ] = "script-src 'self'; object-src 'self'"

	# Scan for CSP bypasses and other issues
	csp_report = get_csp_report( csp_object )

	report_data[ "csp_report" ] = csp_report

	# Go through permission(s) and return info about them.
	permissions_info = []

	if "permissions" in manifest_data:
		extension_permissions = manifest_data[ "permissions" ]
	else:
		extension_permissions = False

	if extension_permissions:
		for permission in extension_permissions:
			if type( permission ) == dict:
				permission = next( iter( permission ) )
			if permission in PERMISSIONS_DATA[ "permissions_metadata" ]:
				permissions_info.append({
					"permission": permission,
					"warning_text": PERMISSIONS_DATA[ "permissions_metadata" ][ permission ][ "warning_text" ],
					"notes": PERMISSIONS_DATA[ "permissions_metadata" ][ permission ][ "notes" ]
				})
			elif "://" in permission:
				permissions_info.append({
					"permission": permission,
					"warning_text": "Read and modify your data on " + permission,
					"notes": ""
				})

	report_data[ "permissions_info" ] = permissions_info

	report_data[ "manifest" ] = manifest_data
	report_data[ "manifest_text" ] = json.dumps(
		manifest_data,
		sort_keys=True,
		indent=4,
		separators=(",", ": ")
	)

	chrome_ext_file_list = chrome_extension_zip.namelist()

	"""
	Pull out browser_action
	"""
	report_data[ "browser_action" ] = False
	if "browser_action" in manifest_data and "default_popup" in manifest_data[ "browser_action" ]:
		report_data[ "browser_action" ] = manifest_data[ "browser_action" ][ "default_popup" ]

	"""
	Pull out background page
	"""
	report_data[ "background_page" ] = False
	if "background" in manifest_data and "page" in manifest_data[ "background" ]:
		report_data[ "background_page" ] = manifest_data[ "background" ][ "page" ]

	"""
	Get background script(s) and create a list of them.

	Note this does not include scripts included by HTML background
	page(s).

	report_data[ "background_scripts" ] = [
		"main.js"
	] 
	"""
	report_data[ "background_scripts" ] = []
	if "background" in manifest_data and "scripts" in manifest_data[ "background" ]:
		report_data[ "background_scripts" ] = manifest_data[ "background" ][ "scripts" ]

	"""
	Iterate over content script(s) and create a reverse map of them.

	report_data[ "content_scripts" ][ "scripts/lib/intercom-snippet.js" ] = [
		"https://mail.google.com/*",
		"https://inbox.google.com/*"
	]
	"""
	report_data[ "content_scripts" ] = {}
	if "content_scripts" in manifest_data:
		for content_script_data in manifest_data[ "content_scripts" ]:
			if "js" in content_script_data:
				for javascript_path in content_script_data[ "js" ]:
					if not javascript_path in report_data[ "content_scripts" ]:
						report_data[ "content_scripts" ][ javascript_path ] = []

					for match_uri in content_script_data[ "matches" ]:
						if not match_uri in report_data[ "content_scripts" ][ javascript_path ]:
							report_data[ "content_scripts" ][ javascript_path ].append(
								match_uri
							)
					for web_origin_match_string in content_script_data[ "matches" ]:
						already_exists = False

						for permission in report_data[ "permissions_info" ]:
							if permission[ "permission" ] == web_origin_match_string:
								already_exists = True

						if not already_exists:
							report_data[ "permissions_info" ].append({
								"permission": web_origin_match_string,
								"warning_text": "Read and modify your data on " + web_origin_match_string,
								"notes": ""
							})

	"""
	Scan for web accessible resources which can be used for extension fingerprinting
	and possibly for exploitation.
	"""
	web_accessible_resources_paths = []
	if "web_accessible_resources" in manifest_data:
		report_data[ "web_accessible_resources" ] = manifest_data[ "web_accessible_resources" ]
		for web_accessible_resource in manifest_data[ "web_accessible_resources" ]:
			"""
			Wildcard expansion
			"""
			if "*" in web_accessible_resource:
				pre_regex = web_accessible_resource.replace( "*", "starplaceholderstring" )
				pre_regex = pre_regex.lower()
				regex_web_accessible_resource = re.compile( re.escape( pre_regex ).replace( "starplaceholderstring", ".*" ) )
				for chrome_extension_path in chrome_ext_file_list:
					if regex_web_accessible_resource.search( "\/" + chrome_extension_path.lower() ):
						web_accessible_resources_paths.append(
							chrome_extension_path
						)
			elif web_accessible_resource.lower() in get_lowercase_list( chrome_ext_file_list ):
				web_accessible_resources_paths.append(
					web_accessible_resource
				)

	# Remove duplicates
	web_accessible_resources_paths = list( set( web_accessible_resources_paths ) )
	web_accessible_resources_paths = [resource for resource in web_accessible_resources_paths if not resource.endswith( "/" )]

	# Generate the fingerprinting code
	report_data[ "web_accessible_resources_paths" ] = web_accessible_resources_paths
	report_data[ "fingerprint_html" ] = ""
	report_data[ "fingerprint_js" ] = FINGERPRINT_BASE_JS
	report_data[ "fingerprint_json" ] = []

	# Seperate out different web_accessible_resource types
	for web_accessible_resource in web_accessible_resources_paths:
		# Lowercase to make better matching since Chrome ignores casing in URLs
		lowercase_web_accessible_resource = web_accessible_resource.lower()

		if ends_in_ext_list( lowercase_web_accessible_resource, [ ".html", ".htm" ] ):
			report_data[ "web_accessible_html" ].append(
				web_accessible_resource
			)
			report_data[ "fingerprint_json" ].append({
				"type": "web",
				"resource": "chrome-extension://" + chrome_extension_id + "/" + web_accessible_resource
			})
		elif ends_in_ext_list( lowercase_web_accessible_resource, [ ".jpg", ".gif", ".jpeg", ".gif", ".ico", ".png" ] ):
			report_data[ "web_accessible_image" ].append(
				web_accessible_resource
			)
			report_data[ "fingerprint_json" ].append({
				"type": "image",
				"resource": "chrome-extension://" + chrome_extension_id + "/" + web_accessible_resource
			})
		else:
			# Do nothing with this for now, to keep away unknown unknowns
			report_data[ "web_accessible_other" ].append(
				web_accessible_resource
			)
			report_data[ "fingerprint_json" ].append({
				"type": "other",
				"resource": "chrome-extension://" + chrome_extension_id + "/" + web_accessible_resource
			})

	report_data[ "fingerprint_js" ] = "var extension_fingerprint_resources = " + json.dumps({
		"extension_id": chrome_extension_id,
		"resources": report_data[ "fingerprint_json" ],
		"callback": "{{REPLACE_ME_CALLBACK_HOLDER}}"
	}, indent=4) + ";\n" + report_data[ "fingerprint_js" ]

	report_data[ "fingerprint_js" ] = report_data[ "fingerprint_js" ].replace(
		"\"{{REPLACE_ME_CALLBACK_HOLDER}}\"",
		"""function () {
        // Add custom callback here for when extension is found.
    }"""
	)

	if len( web_accessible_resources_paths ) > 0:
		report_data[ "fingerprintable" ] = True

	"""
	Scan over scripts embedded in HTML and add them to the report.
	"""
	html_files = []
	for chrome_file_path in chrome_ext_file_list:
		if ends_in_ext_list( chrome_file_path, [ ".html", ".htm" ] ):
			html_files.append( chrome_file_path )

	script_to_page_map = {}
	active_pages = []
	for html_file_path in html_files:
		is_web_accessible = False

		# Get HTML file root directory
		html_file_base_dir = ""
		html_file_path_parts = html_file_path.split( "/" )
		if len( html_file_path_parts ) > 1:
			html_file_path_parts.pop()
			html_file_base_dir = "/".join( html_file_path_parts )
			html_file_base_dir = html_file_base_dir + "/"

		if html_file_path in report_data[ "web_accessible_html" ]:
			is_web_accessible = True

		page_contents = chrome_extension_zip.read(
			html_file_path
		)

		soup = BeautifulSoup(
			page_contents,
			"html.parser"
		)

		# As long as we have the .html file open, let's update the prettified extension
		bytes_beautified = bytes(
			soup.prettify()
		)
		beautified_extension.writestr(
			html_file_path,
			bytes_beautified
		)
		"""
		autodoc_extension.writestr(
			html_file_path,
			bytes_beautified
		)
		"""

		script_tags = soup.find_all(
			"script"
		)

		included_script_paths = []

		for script_tag in script_tags:
			if script_tag.has_attr( "src" ):
				script_tag_src = script_tag.get( "src" )
				script_tag_src = script_tag_src.replace( "chrome-extension://", "" )
				relative_script_path = "/" + html_file_base_dir + script_tag_src
				normalized_script_path = os.path.normpath( relative_script_path )[1:] # Remove leading /
				included_script_paths.append(
					normalized_script_path
				)
				# Append a reverse map of the JS -> page so we can use it later
				if not normalized_script_path in script_to_page_map:
					script_to_page_map[ normalized_script_path ] = []
				if not html_file_path in script_to_page_map[ normalized_script_path ]:
					script_to_page_map[ normalized_script_path ].append(
						html_file_path
					)

		active_pages.append({
			"is_web_accessible": is_web_accessible,
			"path": html_file_path,
			"original_html": page_contents,
			"included_script_paths": included_script_paths,
			"prettified_html": soup.prettify()
		})

	"""
	Now we link the JavaScript files to the web_accessible_resources HTML
	so that we can better screen our entry points (e.g. location.hash only
	matters for web_accessible_resources pages).

	report_data[ "web_accessible_javascript" ] = {
		"example.js": [
			"example.html",
			"pew.html"
		]
	}
	"""
	report_data[ "web_accessible_javascript" ] = {}
	for active_page in active_pages:
		if active_page[ "is_web_accessible" ]:
			for included_script_path in active_page[ "included_script_paths" ]:
				if not ( included_script_path in report_data[ "web_accessible_javascript" ] ):
					report_data[ "web_accessible_javascript" ][ included_script_path ] = []
				report_data[ "web_accessible_javascript" ][ included_script_path ].append( active_page[ "path" ] )

	# Check if the JS is in any web_resource_accessible pages

	print( "HTML beautified..." )

	report_data[ "script_to_page_map" ] = script_to_page_map
	report_data[ "active_pages" ] = active_pages

	"""
	Parse through active page(s) and add included <script>s
	to the background scripts if they exist.
	"""
	report_data[ "browser_action_scripts" ] = []

	if report_data[ "background_page" ] or report_data[ "browser_action" ]:
		for active_page in report_data[ "active_pages" ]:
			if active_page[ "path" ] == report_data[ "background_page" ]:
				report_data[ "background_scripts" ] = active_page[ "included_script_paths" ]
			if active_page[ "path" ] == report_data[ "browser_action" ]:
				report_data[ "browser_action_scripts" ] = active_page[ "included_script_paths" ]

	"""
	Go over all JavaScript and look for interesting indicators.

	This means things like dangerous function calls, Chrome API
	calls, etc.

	Don't scan files which match the blacklist (e.g. jquery.js).
	"""
	report_data[ "risky_javascript_functions" ] = []
	report_data[ "web_entrypoints" ] = []
	report_data[ "retirejs" ] = []
	for chrome_file_path in chrome_ext_file_list:
		if ends_in_ext_list( chrome_file_path, [ ".js" ] ):
			javascript_data = chrome_extension_zip.read( chrome_file_path )

			print( "Retire.js scan...")
			vulnerability_results = RETIRE_JS.check_file(
				chrome_file_path,
				javascript_data
			)

			if vulnerability_results:
				for i in range( 0, len( vulnerability_results ) ):
					vulnerability_results[ i ][ "file_path" ] = chrome_file_path
					report_data[ "retirejs" ].append( vulnerability_results[i] )

			print( "Beautifying some JS..." + chrome_file_path )

			# Beautify JS
			new_beautified_js = beautified_js( javascript_data )
			print( "JS beautified!" )

			"""
			print( "Autodocing some JS..." )

			# AutoDoc JS
			autodoc_js = get_autodoc_js(
				new_beautified_js,
				API_CALL_TARGETS
			)
			print( "Autodoc-ed some js!" )
			"""

			# As long was we have it, write the beautified JS to the beautified extension .zip
			beautified_extension.writestr(
				chrome_file_path,
				bytes( new_beautified_js )
			)

			# Write the AutoDoc version as well
			"""
			autodoc_extension.writestr(
				chrome_file_path,
				bytes( autodoc_js )
			)
			"""

			"""
			If we have a blacklisted word in our filename skip the JavaScript file.

			This is to prevent noise/false positives.
			"""
			scan_file = True
			for blacklist_filename_string in JAVASCRIPT_INDICATORS[ "js_filename_blacklist" ]:
				if blacklist_filename_string in chrome_file_path:
					scan_file = False

			if scan_file:
				print( "Scanning for risky functions..." )
				is_content_script = ( chrome_file_path in report_data[ "content_scripts" ] )
				is_web_accessible_resource = ( chrome_file_path in report_data[ "web_accessible_javascript" ] )

				risky_javascript_functions = scan_javascript(
					chrome_file_path,
					new_beautified_js,
					"risky_functions",
					is_content_script,
					is_web_accessible_resource
				)
				report_data[ "risky_javascript_functions" ] = report_data[ "risky_javascript_functions" ] + risky_javascript_functions

				print( "Scanning for entry points..." )
				web_entrypoints = scan_javascript(
					chrome_file_path,
					new_beautified_js,
					"web_entrypoints",
					is_content_script,
					is_web_accessible_resource
				)
				report_data[ "web_entrypoints" ] = report_data[ "web_entrypoints" ] + web_entrypoints

	print( "Extension analysis finished." )

	# S3 download link(s) for the extension
	beautified_end_url = "/" + format_filename( chrome_extension_name ) + "_beautified_" + chrome_extension_id + "_" + report_data[ "manifest" ][ "version" ] + ".zip"
	report_data[ "s3_extension_download_link" ] = "https://" + os.environ.get( "extension_s3_bucket" ) + ".s3.amazonaws.com/crx/" + chrome_extension_id + "/" + chrome_extension_id + "_" + report_data[ "manifest" ][ "version" ] + ".zip"
	#autodoc_end_url = "/" + format_filename( chrome_extension_name ) + "_autodoc_" + chrome_extension_id + "_" + report_data[ "manifest" ][ "version" ] + ".zip"

	# Format filename for beautified extension
	report_data[ "s3_beautified_extension_download_link" ] = "https://" + os.environ.get( "extension_s3_bucket" ) + ".s3.amazonaws.com/crx/" + chrome_extension_id + beautified_end_url
	#report_data[ "s3_autodoc_extension_download_link" ] = "https://" + os.environ.get( "extension_s3_bucket" ) + ".s3.amazonaws.com/crx/" + chrome_extension_id + autodoc_end_url

	# Close up handlers
	beautified_extension.close()
	#autodoc_extension.close()
	regular_extension.close()

	# Backup Chrome extensions to S3
	upload_to_s3(
		"application/zip",
		"crx/" + chrome_extension_id + "/" + chrome_extension_id + "_" + report_data[ "manifest" ][ "version" ] + ".zip",
		regular_zip_handler.getvalue()
	)
	upload_to_s3(
		"application/zip",
		"crx/" + chrome_extension_id + beautified_end_url,
		beautified_zip_handler.getvalue()
	)
	"""
	upload_to_s3(
		"application/zip",
		"crx/" + chrome_extension_id + autodoc_end_url,
		autodoc_zip_handler.getvalue()
	)
	"""

	chrome_extension_handler.close()

	return report_data

def get_autodoc_js( input_js, api_call_targets ):
	"""
	Get the final autodoc data for some given JS
	"""
	input_js = unicode( input_js, errors="ignore" )

	autodoc_js = ""
	# Optimization
	trimmed_api_call_targets = []
	for api_call_target in api_call_targets:
		if api_call_target[ "match_string" ] in input_js:
			trimmed_api_call_targets.append( api_call_target )

	for line in input_js.split( "\n" ):
		first_comment = True
		for api_call_target in api_call_targets:
			if api_call_target[ "match_string" ] in line:

				# Get whitespace of line to use for comments
				whitespace_match = re.search( "[ ]+", line )
				if whitespace_match:
					whitespace = whitespace_match.group()
				else:
					whitespace = ""

				if first_comment:
					first_comment = False
					autodoc_js += api_call_target[ "comment" ].replace( "{{WHITESPAE_PLACEHOLDER}}", whitespace ) + "\n"
				else:
					autodoc_js += "\n" + api_call_target[ "comment" ].replace( "{{WHITESPAE_PLACEHOLDER}}", whitespace ) + "\n"
		autodoc_js += line + "\n"
		
	return autodoc_js

def get_context_block( javascript_lines_array, i ):
	# TODO make this code less shit
	context_block = javascript_lines_array[i]
	if i > 5 and ( ( i + 5 ) < len( javascript_lines_array ) ):
		context_block = ( "/*" + str( i - 5 ) + "*/" + javascript_lines_array[ i - 5 ] + "\n" +
		"/*" + str( i - 4 ) + "*/" + javascript_lines_array[ i - 4 ] + "\n" +
		"/*" + str( i - 3 ) + "*/" + javascript_lines_array[ i - 3 ] + "\n" +
		"/*" + str( i - 2 ) + "*/" + javascript_lines_array[ i - 2 ] + "\n" +
		"/*" + str( i - 1 ) + "*/" + javascript_lines_array[ i - 1 ] + "\n" + 
		"/*" + str( i ) + "*/" + javascript_lines_array[ i ] + " /* LINE OF INTEREST */\n" + 
		"/*" + str( i + 1 ) + "*/" + javascript_lines_array[ i + 1 ] + "\n" + 
		"/*" + str( i + 2 ) + "*/" + javascript_lines_array[ i + 2 ] + "\n" + 
		"/*" + str( i + 3 ) + "*/" + javascript_lines_array[ i + 3 ] + "\n" +
		"/*" + str( i + 4 ) + "*/" + javascript_lines_array[ i + 4 ] + "\n" +
		"/*" + str( i + 5 ) + "*/" + javascript_lines_array[ i + 5 ] + "\n" )
	return context_block

def check_indicators( i, javascript_file_path, indicator_type, javascript_lines, matches, is_content_script, is_web_accessible_resource ):
	for indicator_data in JAVASCRIPT_INDICATORS[ indicator_type ]:
		# Make sure it's not a JavaScript comment
		if javascript_lines[i].strip().startswith( "//" ) or javascript_lines[i].strip().startswith( "*" ):
			continue

		# Make sure it's the right type of script (e.g. Content Script, Background Script, etc)
		if "type" in indicator_data and indicator_data[ "type" ]:
			# If it's not a Content Script and we require that, skip it.
			if ( indicator_data[ "type" ] == "content_script" and not is_content_script ):
				continue

		# If it's not web accessible and we require that, skip it.
		# IMPORTANT: Content Scripts are ASSUMED to be "web accessible"
		if ( "web_accessible" in indicator_data and indicator_data[ "web_accessible" ] ) and ( is_web_accessible_resource == False or is_content_script ):
			continue

		# Regex indicator
		if indicator_data[ "regex" ]:
			regex = re.compile( indicator_data[ "regex" ], re.IGNORECASE )
			if regex.search( javascript_lines[i] ):
				context_block = get_context_block( javascript_lines, i )
				matches.append({
					"javascript_path": javascript_file_path,
					"context_block": context_block,
					"indicator": indicator_data,
				})

		# String indicator
		if indicator_data[ "string" ] and indicator_data[ "string" ] in javascript_lines[i]:
			context_block = get_context_block( javascript_lines, i )

			matches.append({
				"javascript_path": javascript_file_path,
				"context_block": context_block,
				"indicator": indicator_data,
			})

	return matches

def scan_javascript( javascript_file_path, input_javascript, indicator_type, is_content_script, is_web_accessible_resource ):
	input_javascript = unicode( input_javascript, errors="ignore" )
	matches = []
	javascript_lines = input_javascript.splitlines()
	for i in range( 0, len( javascript_lines ) ):
		matches = check_indicators(
			i,
			javascript_file_path,
			indicator_type,
			javascript_lines,
			matches,
			is_content_script,
			is_web_accessible_resource
		)

	return matches


def get_chrome_extension( extension_id ):
	"""
	Download given extension ID and return a Zip object of the resulting file.
	"""
	headers = {
		"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:49.0) Gecko/20100101 Firefox/49.0",
		"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		"Accept-Language": "en-US,en;q=0.5",
		"Accept-Encoding": "gzip, deflate, br",
		"X-Same-Domain": "1",
		"Content-Type": "application/x-www-form-urlencoded;charset=utf-8",
		"Referer": "https://chrome.google.com/",
	}

	response = requests.get(
		"https://clients2.google.com/service/update2/crx?response=redirect&prodversion=49.0&x=id%3D~~~~%26installsource%3Dondemand%26uc".replace(
			"~~~~",
			extension_id
		),
		headers=headers,
		timeout=( 60 * 2 ),
	)
	chrome_extension_handler = BytesIO(
		response.content
	)

	return chrome_extension_handler
