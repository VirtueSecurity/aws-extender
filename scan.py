# -*- coding: utf-8 -*-
from __future__ import absolute_import, print_function
import re
from ssl import SSLError
import time
import warnings
try:
    import urllib2 as urllib_req
    from urllib2 import HTTPError, URLError, unquote
except ImportError:
    import urllib.request as urllib_req
    from urllib.error import HTTPError, URLError
    from urllib.parse import unquote
from xml.dom.minidom import parse
from datetime import datetime
try:
    import boto3
    from botocore.exceptions import ClientError
    from botocore.handlers import disable_signing
    from botocore.parsers import ResponseParserError
    from boto.s3.connection import S3Connection
    from boto.exception import S3ResponseError
    RUN_TESTS = True
except ImportError:
    RUN_TESTS = False
from array import array
from burp import IScanIssue
from cf_checks import check_cf

IDENTIFIED_VALUES = set()
warnings.filterwarnings('ignore', message='Unverified HTTPS request')


class BucketScan(object):
    def __init__(self, request_response, callbacks, opts, SSL_VERIFICATION):
        self.request_response = request_response
        self.callbacks = callbacks
        self.helpers = self.callbacks.getHelpers()
        self.ssl_verification = SSL_VERIFICATION
        bytesToString = self.helpers.bytesToString
        self.request = self.request_response.getRequest()
        self.request_str = bytesToString(self.request)
        self.request_len = len(self.request_str)
        self.request_str = self.request_str.encode('utf-8', 'replace')
        self.response = self.request_response.getResponse()
        self.response_str = bytesToString(self.response)
        self.response_len = len(self.response_str)
        self.response_str = self.response_str.encode('utf-8', 'replace')
        self.offset = array('i', [0, 0])
        self.current_url = self.helpers.analyzeRequest(self.request_response).getUrl()
        self.scan_issues = []
        self.aws_access_key = opts['aws_access_key']
        self.aws_secret_key = opts['aws_secret_key']
        self.aws_session_token = opts['aws_session_token']
        self.gs_access_key = opts['gs_access_key']
        self.gs_secret_key = opts['gs_secret_key']
        self.wordlist_path = opts['wordlist_path']
        try:
            self.boto3_client = boto3.client('s3',
                                             aws_access_key_id=self.aws_access_key,
                                             aws_secret_access_key=self.aws_secret_key,
                                             aws_session_token=self.aws_session_token, verify=SSL_VERIFICATION)
            self.boto_s3_con = S3Connection(
                aws_access_key_id=self.aws_access_key,
                aws_secret_access_key=self.aws_secret_key,
                host='s3.amazonaws.com',
                is_secure=SSL_VERIFICATION
            )
            self.boto_gs_con = S3Connection(
                aws_access_key_id=self.gs_access_key,
                aws_secret_access_key=self.gs_secret_key,
                host='storage.googleapis.com',
                is_secure=SSL_VERIFICATION
            )

            if not (self.aws_access_key and self.aws_secret_key):
                self.boto3_client.meta.events.register('choose-signer.s3.*', disable_signing)
                self.boto_s3_con = S3Connection(anon=True)

            if not (self.gs_access_key and self.gs_secret_key):
                self.boto_gs_con = S3Connection(anon=True, host='storage.googleapis.com')
        except NameError:
            pass

    def bucket_exists(self, bucket_name, bucket_type):
        try:
            if bucket_type == 'S3':
                try:
                    self.boto3_client.head_bucket(Bucket=bucket_name)
                except ClientError as error:
                    error_code = int(error.response['Error']['Code'])
                    if error_code == 404:
                        return False
            elif bucket_type == 'GS':
                try:
                    self.boto_gs_con.head_bucket(bucket_name)
                except S3ResponseError as error:
                    if error.error_code == 'NoSuchBucket':
                        return False
            elif bucket_type == 'Azure':
                try:
                    bucket_url = 'https://' + bucket_name + '?comp=list&maxresults=10'
                    urllib_req.urlopen(urllib_req.Request(bucket_url), timeout=20)
                except (HTTPError, URLError):
                    if not self.wordlist_path:
                        return False
        except SSLError:
            print("Bucket ({}) could not be scanned due to SSL errors. SSL verification can be disabled in settings.".format(bucket_name))
            return None
        return True

    def test_bucket(self, bucket_name, bucket_type):
        """Test for buckets misconfiguration issues."""
        grants = []
        issues = []
        keys = []

        def enumerate_keys(bucket, bucket_name, bucket_type):
            """Enumerate bucket keys."""
            try:
                with open(self.wordlist_path) as wordlist:
                    wordlist_keys = wordlist.read()
                    key_list = wordlist_keys.split('\n')
            except IOError:
                return

            if bucket_type != 'Azure':
                for key in key_list:
                    try:
                        key = bucket.get_key(key).key
                        self.test_object(bucket_name, bucket_type, key, False)
                    except (S3ResponseError, AttributeError):
                        continue
            else:
                bucket = bucket if bucket.endswith('/') else bucket + '/'
                for key in key_list:
                    try:
                        request = urllib_req.Request(bucket + key)
                        urllib_req.urlopen(request, timeout=20)
                        keys.append(key)
                    except (HTTPError, URLError):
                        continue

        if bucket_type == 'S3':
            bucket = self.boto_s3_con.get_bucket(bucket_name, validate=False)
            try:
                bucket_acl = bucket.get_acl().acl
                for grant in bucket_acl.grants:
                    grants.append((grant.display_name or grant.uri or grant.id or
                                   grant.email_address) + '->' + grant.permission)
                issues.append('s3:GetBucketAcl<ul><li>%s</li></ul>' % '</li><li>'.join(grants))
            except S3ResponseError as error:
                print('Error Code (get_bucket_acl): ' + str(error.error_code))

            try:
                self.boto3_client.get_bucket_cors(Bucket=bucket_name)
                issues.append('s3:GetBucketCORS')
            except ClientError as error:
                error_code = error.response['Error']['Code']
                print('Error Code (get_bucket_cors): ' + str(error_code))
            except ResponseParserError:
                issues.append('s3:GetBucketCORS')

            try:
                self.boto3_client.get_bucket_lifecycle(Bucket=bucket_name)
                issues.append('s3:GetLifecycleConfiguration')
            except ClientError as error:
                error_code = error.response['Error']['Code']
                print('Error Code (get_bucket_lifecycle): ' + str(error_code))
            except ResponseParserError:
                issues.append('s3:GetLifecycleConfiguration')

            try:
                self.boto3_client.get_bucket_notification(Bucket=bucket_name)
                issues.append('s3:GetBucketNotification')
            except ClientError as error:
                error_code = error.response['Error']['Code']
                print('Error Code (get_bucket_notification): ' + str(error_code))
            except ResponseParserError:
                issues.append('s3:GetBucketNotification')

            try:
                self.boto3_client.get_bucket_policy(Bucket=bucket_name)
                issues.append('s3:GetBucketPolicy')
            except ClientError as error:
                error_code = error.response['Error']['Code']
                print('Error Code (get_bucket_policy): ' + str(error_code))
            except ResponseParserError:
                issues.append('s3:GetBucketPolicy')

            try:
                self.boto3_client.get_bucket_tagging(Bucket=bucket_name)
                issues.append('s3:GetBucketTagging')
            except ClientError as error:
                error_code = error.response['Error']['Code']
                print('Error Code (get_bucket_tagging): ' + str(error_code))
            except ResponseParserError:
                issues.append('s3:GetBucketTagging')

            try:
                self.boto3_client.get_bucket_website(Bucket=bucket_name)
                issues.append('s3:GetBucketWebsite')
            except ClientError as error:
                error_code = error.response['Error']['Code']
                print('Error Code (get_bucket_website): ' + str(error_code))
            except ResponseParserError:
                issues.append('s3:GetBucketWebsite')

            try:
                self.boto3_client.list_multipart_uploads(Bucket=bucket_name)
                issues.append('s3:ListMultipartUploadParts')
            except ClientError as error:
                error_code = error.response['Error']['Code']
                print('Error Code (list_multipart_uploads): ' + str(error_code))
            except ResponseParserError:
                issues.append('s3:ListMultipartUploadParts')

            try:
                i = 0
                for k in bucket.list():
                    i = i + 1
                    keys.append(k.key)
                    if i == 10:
                        break
                issues.append('s3:ListBucket<ul><li>%s</li></ul>' % '</li><li>'.join(keys))
            except S3ResponseError as error:
                print('Error Code (list): ' + str(error.error_code))
                if self.wordlist_path:
                    enumerate_keys(bucket, bucket_name, 'S3')

            try:
                self.boto3_client.put_bucket_cors(
                    Bucket=bucket_name,
                    CORSConfiguration={
                        'CORSRules': [
                            {
                                'AllowedMethods': [
                                    'GET'
                                ],
                                'AllowedOrigins': [
                                    '*'
                                ]
                            }
                        ]
                    }
                )
                issues.append('s3:PutBucketCORS')
            except ClientError as error:
                error_code = error.response['Error']['Code']
                print('Error Code (put_bucket_cors): ' + str(error_code))
            except ResponseParserError:
                issues.append('s3:PutBucketCORS')

            try:
                self.boto3_client.put_bucket_lifecycle_configuration(
                    Bucket=bucket_name,
                    LifecycleConfiguration={
                        'Rules': [
                            {
                                'Status': 'Disabled',
                                'Prefix': 'test'
                            }
                        ]
                    }
                )
                issues.append('s3:PutLifecycleConfiguration')
            except ClientError as error:
                error_code = error.response['Error']['Code']
                print('Error Code (put_bucket_lifecycle_configuration): ' + str(error_code))
            except ResponseParserError:
                issues.append('s3:PutLifecycleConfiguration')

            try:
                self.boto3_client.put_bucket_logging(
                    Bucket=bucket_name,
                    BucketLoggingStatus={}
                )
                issues.append('s3:PutBucketLogging')
            except ClientError as error:
                error_code = error.response['Error']['Code']
                print('Error Code (put_bucket_logging): ' + str(error_code))
            except ResponseParserError:
                issues.append('s3:PutBucketLogging')

            try:
                self.boto3_client.put_bucket_notification(
                    Bucket=bucket_name,
                    NotificationConfiguration={
                        'TopicConfiguration': {
                            'Events': ['s3:ReducedRedundancyLostObject'],
                            'Topic': 'arn:aws:sns:us-west-2:444455556666:sns-topic-one'
                        }
                    }
                )
                issues.append('s3:PutBucketNotification')
            except ClientError as error:
                error_code = error.response['Error']['Code']
                print('Error Code (put_bucket_notification): ' + str(error_code))
            except ResponseParserError:
                issues.append('s3:PutBucketNotification')

            try:
                self.boto3_client.put_bucket_tagging(
                    Bucket=bucket_name,
                    Tagging={
                        'TagSet': [
                            {
                                'Key': 'test',
                                'Value': 'test'
                            }
                        ]
                    }
                )
                issues.append('s3:PutBucketTagging')
            except ClientError as error:
                error_code = error.response['Error']['Code']
                print('Error Code (put_bucket_tagging): ' + str(error_code))
            except ResponseParserError:
                issues.append('s3:PutBucketTagging')

            try:
                self.boto3_client.put_bucket_website(
                    Bucket=bucket_name,
                    WebsiteConfiguration={
                        'ErrorDocument': {
                            'Key': 'test'
                        },
                        'IndexDocument': {
                            'Suffix': 'test'
                        }
                    }
                )
                issues.append('s3:PutBucketWebsite')
            except ClientError as error:
                error_code = error.response['Error']['Code']
                print('Error Code (put_bucket_website): ' + str(error_code))
            except ResponseParserError:
                issues.append('s3:PutBucketWebsite')

            try:
                self.boto3_client.put_object(
                    Body=b'test',
                    Bucket=bucket_name,
                    Key='test.txt'
                )
                issues.append('s3:PutObject<ul><li>test.txt</li></ul>')
            except ClientError as error:
                error_code = error.response['Error']['Code']
                print('Error Code (put_object): ' + str(error_code))
            except ResponseParserError:
                issues.append('s3:PutObject')

            if '.' in bucket_name:
                try:
                    self.boto3_client.put_bucket_acl(
                        GrantFullControl='uri="http://acs.amazonaws.com/groups/global/AllUsers"',
                        Bucket=bucket_name
                    )
                    issues.append('s3:PutBucketAcl')
                except ClientError as error:
                    error_code = error.response['Error']['Code']
                    print('Error Code (put_bucket_acl): ' + str(error_code))
                except ResponseParserError:
                    issues.append('s3:PutBucketAcl')
            else:
                try:
                    bucket.add_email_grant('FULL_CONTROL', 0)
                    issues.append('s3:PutBucketAcl')
                except S3ResponseError as error:
                    if error.error_code == 'UnresolvableGrantByEmailAddress':
                        issues.append('s3:PutBucketAcl')

            try:
                self.boto3_client.put_bucket_policy(
                    Bucket=bucket_name,
                    Policy='''
                        {
                            "Version":"2012-10-17",
                            "Statement": [
                                {
                                    "Effect":"Allow",
                                    "Principal": "*",
                                    "Action":["s3:GetBucketPolicy"],
                                    "Resource":["arn:aws:s3:::%s/*"]
                                }
                            ]
                        } ''' % bucket_name
                )
                issues.append('s3:PutBucketPolicy')
            except ClientError as error:
                error_code = error.response['Error']['Code']
                print('Error Code (put_bucket_policy): ' + str(error_code))
            except ResponseParserError:
                issues.append('s3:PutBucketPolicy')
        elif bucket_type == 'GS':
            bucket = self.boto_gs_con.get_bucket(bucket_name, validate=False)

            try:
                i = 0
                for k in bucket.list():
                    i = i + 1
                    keys.append(k.key)
                    if i == 10:
                        break
                issues.append('READ<ul><li>%s</li></ul>' % '</li><li>'.join(keys))
            except S3ResponseError as error:
                print('Error Code (list): ' + str(error.error_code))
                if self.wordlist_path:
                    enumerate_keys(bucket, bucket_name, 'GS')
            try:
                key = bucket.new_key('test.txt')
                key.set_contents_from_string('')
                issues.append('WRITE<ul><li>test.txt</li></ul>')
            except S3ResponseError as error:
                print('Error Code (set_contents_from_string): ' + str(error.error_code))

            try:
                bucket.add_email_grant('FULL_CONTROL', 0)
                issues.append('FULL_CONTROL')
            except S3ResponseError as error:
                if error.error_code == 'UnresolvableGrantByEmailAddress':
                    issues.append('FULL_CONTROL')
                else:
                    print('Error Code (add_email_grant): ' + str(error.error_code))
            except AttributeError as error:
                if error.message.startswith("'Policy'"):
                    issues.append('FULL_CONTROL')
                else:
                    raise
        elif bucket_type == 'Azure':
            bucket_url = 'https://' + bucket_name
            try:
                request = urllib_req.Request(bucket_url + '?comp=list&maxresults=10')
                response = urllib_req.urlopen(request, timeout=20)
                blobs = parse(response).documentElement.getElementsByTagName('Name')
                for blob in blobs:
                    keys.append(blob.firstChild.nodeValue.encode('utf-8'))
                issues.append('Full public read access<ul><li>%s</li></ul>' %
                              '</li><li>'.join(keys))
            except (AttributeError, HTTPError, URLError):
                if self.wordlist_path:
                    enumerate_keys(bucket_url, bucket_name, 'Azure')
                    if keys:
                        issues.append('Public read access for blobs only<ul><li>%s</li></ul>' %
                                      '</li><li>'.join(keys))

        if not issues:
            return False
        if ('s3:PutBucketAcl' in issues or 'FULL_CONTROL' in issues) or len(issues) > 4:
            issue_level = 'High'
        elif len(issues) > 2 or ('READ' in issues and
                                 'WRITE<ul><li>test.txt</li></ul>' in issues):
            issue_level = 'Medium'
        else:
            issue_level = 'Low'

        issue_name = '%s Bucket Misconfiguration' % bucket_type
        issue_detail = '''The "%s" %s bucket grants the following permissions:<br>
                         <li>%s</li><br><br>''' % (bucket_name, bucket_type,
                                                   '</li><li>'.join(issues))

        return {'issue_name': issue_name, 'issue_detail': issue_detail,
                'issue_level': issue_level}

    def check_timestamp(self, bucket_url, bucket_type, timestamp):
        timestamp_raw = timestamp
        offsets = []
        mark_request = False
        start = 0

        try:
            if bucket_type != 'Azure':
                now = int(time.time())
                diff = (int(timestamp) - now) / 3600
            else:
                timestamp = unquote(timestamp)
                timestamp = datetime.strptime(timestamp, '%Y-%m-%dT%H:%M:%S%fZ')
                diff = int((timestamp - datetime.now()).total_seconds()) / 3600
        except ValueError:
            return

        if diff > 24:
            start = self.helpers.indexOf(self.response,
                                         timestamp_raw, True, 0, self.response_len)
            if start < 0:
                start = self.helpers.indexOf(self.request,
                                             timestamp_raw, True, 0, self.request_len)
                mark_request = True
            self.offset[0] = start
            self.offset[1] = start + len(timestamp_raw)
            offsets.append(self.offset)
            if mark_request:
                markers = [self.callbacks.applyMarkers(self.request_response, offsets, None)]
            else:
                markers = [self.callbacks.applyMarkers(self.request_response, None, offsets)]
            issue_name = '%s Signed URL Excessive Expiration Time' % bucket_type
            issue_level = 'Information'
            issue_detail = '''The following %s signed URL was found to be valid for more than
                24 hours (expires in %sh):<br><li>%s</li>''' % (bucket_type, diff, bucket_url)
            self.scan_issues.append(
                ScanIssue(self.request_response.getHttpService(),
                          self.current_url, markers, issue_name, issue_level, issue_detail)
            )

    def test_object(self, bucket_name, bucket_type, key, mark=True):
        issues = []
        grants = []
        markers = []
        offsets = []
        issue_name = ''
        permission = ''
        mark_request = False
        norm_key = key.replace('\\', '')

        if bucket_type == 'S3':
            bucket = self.boto_s3_con.get_bucket(bucket_name, validate=False)
        else:
            bucket = self.boto_gs_con.get_bucket(bucket_name, validate=False)

        try:
            key_obj = bucket.get_key(norm_key)
        except:
            return

        if not key_obj:
            return
        issues.append('READ')

        try:
            key_acl = key_obj.get_acl().acl
            for grant in key_acl.grants:
                grants.append((grant.display_name or grant.uri or grant.id or
                               grant.email_address) + '->' + grant.permission)
            permission = 's3:GetObjectAcl' if bucket_type == 'S3' else 'getIamPolicy'
            issues.append('%s<ul><li>%s</li></ul>' % (permission, '</li><li>'.join(grants)))
        except S3ResponseError:
            pass

        if '.' in bucket_name and bucket_type == 'S3':
            try:
                self.boto3_client.put_object_acl(
                    GrantFullControl='uri="http://acs.amazonaws.com/groups/global/AllUsers"',
                    Bucket=bucket_name,
                    Key=norm_key
                )
                issues.append('s3:PutObjectAcl')
            except ClientError as error:
                error_code = error.response['Error']['Code']
                print('Error Code (put_object_acl): ' + str(error_code))
            except ResponseParserError:
                issues.append('s3:PutObjectAcl')
        else:
            try:
                key_obj.add_email_grant('FULL_CONTROL', 0)
                permission = 's3:PutObjectAcl' if bucket_type == 'S3' else 'FULL_CONTROL'
                issues.append(permission)
            except S3ResponseError as error:
                if error.error_code == 'UnresolvableGrantByEmailAddress':
                    permission = 's3:PutObjectAcl' if bucket_type == 'S3' else 'FULL_CONTROL'
                    issues.append(permission)

        if not issues:
            return
        if 'READ' in issues and len(issues) < 2:
            issue_level = 'Information'
            issue_name = '%s Object Publicly Accessible' % bucket_type
        elif 's3:PutObjectAcl' in issues or 'FULL_CONTROL' in issues:
            issue_level = 'High'
        else:
            issue_level = 'Low'

        start = self.helpers.indexOf(self.response,
                                     key, True, 0, self.response_len)

        if start < 0 and mark:
            start = self.helpers.indexOf(self.request,
                                         key, True, 0, self.request_len)
            mark_request = True

        self.offset[0] = start
        self.offset[1] = start + len(key)
        offsets.append(self.offset)

        if mark_request:
            markers = [self.callbacks.applyMarkers(self.request_response, offsets, None)]
        elif mark:
            markers = [self.callbacks.applyMarkers(self.request_response, None, offsets)]

        if not issue_name:
            issue_name = '%s Object Misconfiguration' % bucket_type
        issue_detail = '''The following ACL grants were found set on the "%s" object of
            the "%s" %s bucket:<br><li>%s</li>''' % (norm_key, bucket_name, bucket_type,
                                                     '</li><li>'.join(issues))
        self.scan_issues.append(
            ScanIssue(self.request_response.getHttpService(),
                      self.current_url, markers, issue_name, issue_level, issue_detail)
        )

    def check_buckets(self):
        current_url_str = str(unicode(self.current_url, 'utf-8', 'ignore'))
        host, path = re.findall(r'\w+://([\w.-]+)(?::\d+)?(?:/([^\s?#]*))?', current_url_str)[0]

        s3_buckets_regex = re.compile(
            r'((?:\w+://)?(?:([\w.-]+)\.s3[\w.-]*\.amazonaws\.com(?:\.cn)?|s3(?:[\w.-]*\.amazonaws\.com(?:\.cn)?(?:\\?/)*|://)([\w.-]+))(?:\\?/([^\s?#]*))?(?:.*?\?.*?Expires=(\d+))?)',
            re.I)
        s3_bucket_matches = re.findall(s3_buckets_regex, current_url_str)
        s3_bucket_matches += re.findall(s3_buckets_regex, self.request_str)
        s3_bucket_matches += re.findall(s3_buckets_regex, self.response_str)

        cf_regex = re.compile(r'\w+\.cloudfront\.net', re.I)
        cf_endpoints = re.findall(cf_regex, self.request_str)
        cf_endpoints += re.findall(cf_regex, self.response_str)
        if cf_endpoints:
            for cf_bucket_match in check_cf(cf_endpoints):
                s3_bucket_matches.append(cf_bucket_match + ('', '', ''))

        gs_buckets_regex = re.compile(
            r'((?:\w+://)?(?:([\w.-]+)\.storage[\w-]*\.googleapis\.com|(?:(?:console\.cloud\.google\.com/storage/browser/|storage[\w-]*\.googleapis\.com)(?:(?::\d+)?\\?/)*|gs://)([\w.-]+))(?:(?::\d+)?\\?/([^\s?#]*))?(?:.*\?.*Expires=(\d+))?)',
            re.I)
        gs_bucket_matches = re.findall(gs_buckets_regex, current_url_str)
        gs_bucket_matches += re.findall(gs_buckets_regex, self.request_str)
        gs_bucket_matches += re.findall(gs_buckets_regex, self.response_str)

        az_buckets_regex = re.compile(
            r'(([\w.-]+\.blob\.core\.windows\.net(?:\\?/[\w.-]+)?(?:.*?\?.*se=([\w%-]+))?))',
            re.I)
        az_bucket_matches = re.findall(az_buckets_regex, current_url_str)
        az_bucket_matches += re.findall(az_buckets_regex, self.request_str)
        az_bucket_matches += re.findall(az_buckets_regex, self.response_str)

        if RUN_TESTS:
            s3_bucket_matches.append(('', host, '', path))
            gs_bucket_matches.append(('', host, '', path))

        def assess_buckets(bucket_matches, bucket_type):
            """Assess identified buckets."""
            test_flag = RUN_TESTS
            mark_request = False
            markers = []
            for i in xrange(0, len(bucket_matches)):
                issues = []
                offsets = []
                bucket_match = bucket_matches[i]
                bucket_url = bucket_match[0]
                bucket_name = bucket_match[1] or bucket_match[2]
                timestamp = bucket_match[-1]
                bucket_tuple = (bucket_name, host)
                timestamp_tuple = (timestamp, bucket_url, host)
                if '.' in bucket_name and self.ssl_verification and bucket_type != 'Azure':
                    if not bucket_url:
                        continue
                    else:
                        test_flag = False
                if test_flag and not self.bucket_exists(bucket_name, bucket_type):
                    continue
                try:
                    key = bucket_match[3]
                    key_tuple = (key, bucket_name, host)
                    if key and key_tuple not in IDENTIFIED_VALUES and test_flag:
                        self.test_object(bucket_name, bucket_type, key)
                    IDENTIFIED_VALUES.add(key_tuple)
                except IndexError:
                    pass
                if timestamp and timestamp_tuple not in IDENTIFIED_VALUES:
                    self.check_timestamp(bucket_url, bucket_type, timestamp)
                IDENTIFIED_VALUES.add(timestamp_tuple)
                if bucket_tuple in IDENTIFIED_VALUES:
                    continue
                IDENTIFIED_VALUES.add(bucket_tuple)
                start = self.helpers.indexOf(self.response,
                                             bucket_name, True, 0, self.response_len)
                if start < 0:
                    start = self.helpers.indexOf(self.request,
                                                 bucket_name, True, 0, self.request_len)
                    mark_request = True
                self.offset[0] = start
                self.offset[1] = start + len(bucket_name)
                offsets.append(self.offset)
                if mark_request:
                    markers = [self.callbacks.applyMarkers(self.request_response, offsets, None)]
                else:
                    markers = [self.callbacks.applyMarkers(self.request_response, None, offsets)]
                if test_flag:
                    issues = self.test_bucket(bucket_name, bucket_type)
                    if issues:
                        self.scan_issues.append(
                            ScanIssue(self.request_response.getHttpService(),
                                      self.helpers.analyzeRequest(self.request_response).getUrl(),
                                      markers, issues['issue_name'], issues['issue_level'], issues['issue_detail']
                                     )
                        )
                if not issues:
                    issue_name = '%s Bucket Detected' % bucket_type
                    issue_level = 'Information'
                    issue_detail = '''The following %s bucket has been identified:<br>
                        <li>%s</li>''' % (bucket_type, bucket_name)
                    self.scan_issues.append(
                        ScanIssue(self.request_response.getHttpService(),
                                  self.current_url, markers, issue_name, issue_level, issue_detail)
                    )
        if s3_bucket_matches:
            assess_buckets(s3_bucket_matches, 'S3')

        if gs_bucket_matches:
            assess_buckets(gs_bucket_matches, 'GS')

        if az_bucket_matches:
            assess_buckets(az_bucket_matches, 'Azure')

        return self.scan_issues


class ScanIssue(IScanIssue):
    def __init__(self, http_service, url, request_response, name, severity, detail_msg):
        self.url_ = url
        self.http_service = http_service
        self.request_response = request_response
        self.name_ = name
        self.severity_ = severity
        self.detail_msg = detail_msg

    def getUrl(self):
        return self.url_

    def getHttpMessages(self):
        return self.request_response

    def getHttpService(self):
        return self.http_service

    @staticmethod
    def getRemediationDetail():
        return None

    def getIssueDetail(self):
        return self.detail_msg

    @staticmethod
    def getIssueBackground():
        return None

    @staticmethod
    def getRemediationBackground():
        return None

    @staticmethod
    def getIssueType():
        return 0

    def getIssueName(self):
        return self.name_

    def getSeverity(self):
        return self.severity_

    @staticmethod
    def getConfidence():
        return 'Certain'


class CognitoScan(object):
    def __init__(self, request_response, callbacks):
        self.request_response = request_response
        self.callbacks = callbacks
        self.helpers = self.callbacks.getHelpers()
        self.current_url = self.helpers.analyzeRequest(self.request_response).getUrl()
        self.scan_issues = []

    def obtain_unauth_token(self, identity_pool_id, identity_id, region, markers):
        """Obtain an unauthenticated identity token."""
        client = boto3.client('cognito-identity', region_name=region)
        try:
            token = client.get_open_id_token(IdentityId=identity_id)['Token']
        except (ClientError, KeyError):
            return
        issue_name = 'Cognito Unauthenticated Identities Enabled'
        issue_level = 'Information'
        issue_detail = '''The following identity pool allows unauthenticated identities:
            <br><ul><li>%s</li></ul><br>The following identity ID has been obtained:
            <ul><li>%s</li></ul><br>The following token has been obtained:
            <ul><li>%s</li></ul>''' % (identity_pool_id, identity_id, token)
        self.scan_issues.append(
            ScanIssue(self.request_response.getHttpService(),
                      self.current_url, markers, issue_name, issue_level, issue_detail)
        )

    def identify_identity_pools(self):
        bytesToString = self.helpers.bytesToString
        request = self.request_response.getRequest()
        request_str = bytesToString(request)
        request_len = len(request_str)
        request_str = request_str.encode('utf-8', 'replace')
        response = self.request_response.getResponse()
        response_str = bytesToString(response)
        response_len = len(response_str)
        response_str = response_str.encode('utf-8', 'replace')
        identity_pool_regex = re.compile(
            r'((\w+-[\w-]+):[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})',
            re.I)
        identity_pools = re.findall(identity_pool_regex, request_str)
        identity_pools += re.findall(identity_pool_regex, response_str)

        def verify_identity_pools(identity_pool_ids):
            """Verify identity pools."""
            offset = array('i', [0, 0])
            host = re.search(r'\w+://([\w.-]+)', str(self.current_url)).group(1)
            for i in xrange(0, len(identity_pool_ids)):
                offsets = []
                identity_id = ''
                mark_request = False
                identity_pool_id = identity_pool_ids[i]
                region = identity_pool_id[1]
                identity_pool_id = identity_pool_id[0]
                identity_pool_tuple = (identity_pool_id, host)
                if identity_pool_id and identity_pool_tuple in IDENTIFIED_VALUES:
                    continue
                try:
                    client = boto3.client('cognito-identity', region_name=region)
                    identity_id = client.get_id(IdentityPoolId=identity_pool_id)
                    identity_id = identity_id['IdentityId'].encode('utf-8')
                except NameError:
                    pass
                except ClientError:
                    continue
                start = self.helpers.indexOf(response,
                                             identity_pool_id, True, 0, response_len)
                if start < 0:
                    start = self.helpers.indexOf(request,
                                                 identity_pool_id, True, 0, request_len)
                    mark_request = True
                offset[0] = start
                offset[1] = start + len(identity_pool_id)
                offsets.append(offset)
                if mark_request:
                    markers = [self.callbacks.applyMarkers(self.request_response, offsets, None)]
                else:
                    markers = [self.callbacks.applyMarkers(self.request_response, None, offsets)]
                issue_name = 'Cognito Identity Pool Detected'
                issue_level = 'Information'
                issue_detail = '''The following identity pool ID has been identified:<br>
                    <li>%s</li>''' % identity_pool_id
                self.scan_issues.append(
                    ScanIssue(self.request_response.getHttpService(),
                              self.current_url, markers, issue_name, issue_level, issue_detail)
                )
                IDENTIFIED_VALUES.add(identity_pool_tuple)
                if identity_id and RUN_TESTS:
                    self.obtain_unauth_token(identity_pool_id, identity_id, region, markers)

        if identity_pools:
            verify_identity_pools(identity_pools)

        return self.scan_issues
