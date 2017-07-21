# -*- coding: utf-8 -*-
# Version 0.9
import re
import urllib2
import xml.etree.cElementTree as CET
from xml.dom.minidom import parse
from array import array
from datetime import datetime
try:
    import boto3
    from botocore.exceptions import ClientError
    from botocore.handlers import disable_signing
    from botocore.compat import XMLParseError
    from botocore.parsers import ResponseParserError
    from boto.s3.connection import S3Connection
    from boto.exception import S3ResponseError
    RUN_TESTS = True
except ImportError:
    RUN_TESTS = False
from burp import IBurpExtender
from burp import IScanIssue
from burp import IScannerCheck
from burp import ITab
from javax.swing import JTextField
from javax.swing import JLabel
from javax.swing import JFrame
from javax.swing import JPanel
from javax.swing import JButton
from javax.swing.border import EmptyBorder
from java.awt import BorderLayout
from java.awt import GridLayout
from org.xml.sax import SAXException

identified_s3_buckets = set()
identified_gs_buckets = set()
identified_az_buckets = set()
tested_uris = set()


class BurpExtender(IBurpExtender, IScannerCheck, ITab):
    def __init__(self):
        self.ext_name = 'AWS Extender'
        self.callbacks = None
        self.gui_elements = None
        self.aws_access_key_inpt = None
        self.aws_secret_key_inpt = None
        self.aws_session_token_inpt = None
        self.gs_access_key_inpt = None
        self.gs_secret_key_inpt = None
        self.aws_access_key = ''
        self.aws_secret_key = ''
        self.aws_session_token = ''
        self.gs_access_key = ''
        self.gs_secret_key = ''

    def registerExtenderCallbacks(self, callbacks):
        """Register extender callbacks."""
        self.callbacks = callbacks

        # Set the name of the extension
        self.callbacks.setExtensionName(self.ext_name)

        # Register the extension as a scanner check
        self.callbacks.registerScannerCheck(self)

        # Build GUI elements
        self.gui_elements = self.build_gui()

        callbacks.customizeUiComponent(self.gui_elements)
        callbacks.addSuiteTab(self)
        self.reload_config()
        self.show_errors()
        return

    def show_errors(self):
        """Display loading errors."""
        missing_libs = []
        tips = []
        label = """<html>
              <body style='margin: 10px'>
                <b>The following dependencies could not be loaded successfully:</b><br>
                <ul><li>%s</li></ul><br>
                <b>Tips:</b><br>
                <ul><li>%s</li><br></ul>
                <b>For detailed information on how to load the plugin, see:</b><br>
                <ul>
                  <li>
                    <a href='#'>https://github.com/VirtueSecurity/aws-extender#getting-started</a>
                  </li>
                </ul>
              </body>
            </html>"""

        if not RUN_TESTS:
            missing_libs.append('boto3')
            tips.append('Make sure that the boto3 library is installed properly, and\
                the right path is specified in the "Folder for loading modules" setting.')
        try:
            CET.fromstring('<test></test>')
        except SAXException:
            # Try to workaround "http://bugs.jython.org/issue1127"
            try:
                def xml_parser(**kwargs):
                    class Parser(object):
                        def feed(*args):
                            raise XMLParseError
                        def close(*args):
                            return None
                    return Parser()
                CET.XMLParser = xml_parser
            except TypeError:
                missing_libs.append('SAXParser')
                tips.append("""Run Burp Suite using the following command:
                   <br><code style='background: #f7f7f9; color: red'>$ java -classpath 
                   xercesImpl.jar;burpsuite_pro.jar burp.StartBurp</code>""")

        if not missing_libs:
            return

        label %= ('</li><li>'.join(missing_libs), '</li><li>'.join(tips))
        top_label = JLabel(label, JLabel.CENTER)

        frame = JFrame(self.ext_name)
        frame.setSize(550, 300)
        frame.setLayout(GridLayout(1, 1))

        frame.add(top_label)
        frame.setLocationRelativeTo(None)
        frame.setVisible(True)

    def build_gui(self):
        """Construct GUI elements."""
        creds_panel = JPanel(BorderLayout(3, 3))
        creds_panel.setBorder(EmptyBorder(200, 200, 200, 200))

        self.aws_access_key_inpt = JTextField(10)
        self.aws_secret_key_inpt = JTextField(10)
        self.aws_session_token_inpt = JTextField(10)
        self.gs_access_key_inpt = JTextField(10)
        self.gs_secret_key_inpt = JTextField(10)
        save_btn = JButton('Save', actionPerformed=self.save_config)

        labels = JPanel(GridLayout(0, 1))
        inputs = JPanel(GridLayout(0, 1))
        creds_panel.add(labels, BorderLayout.WEST)
        creds_panel.add(inputs, BorderLayout.CENTER)

        top_label = JLabel('<html><b>Account Credentials</b><br><br></html>')
        top_label.setHorizontalAlignment(JLabel.CENTER)
        creds_panel.add(top_label, BorderLayout.NORTH)
        labels.add(JLabel('AWS Access Key: '))
        inputs.add(self.aws_access_key_inpt)
        labels.add(JLabel('AWS Secret Key: '))
        inputs.add(self.aws_secret_key_inpt)
        labels.add(JLabel('AWS Session Key (optional): '))
        inputs.add(self.aws_session_token_inpt)
        labels.add(JLabel('GS Access Key: '))
        inputs.add(self.gs_access_key_inpt)
        labels.add(JLabel('GS Secret Key: '))
        inputs.add(self.gs_secret_key_inpt)
        creds_panel.add(save_btn, BorderLayout.SOUTH)
        return creds_panel

    def save_config(self, _):
        """Save settings."""
        save_setting = self.callbacks.saveExtensionSetting
        save_setting('aws_access_key', self.aws_access_key_inpt.getText())
        save_setting('aws_secret_key', self.aws_secret_key_inpt.getText())
        save_setting('aws_session_token', self.aws_session_token_inpt.getText())
        save_setting('gs_access_key', self.gs_access_key_inpt.getText())
        save_setting('gs_secret_key', self.gs_secret_key_inpt.getText())

        self.reload_config()
        return

    def reload_config(self):
        """Reload saved settings."""
        load_setting = self.callbacks.loadExtensionSetting
        aws_access_key_val = load_setting('aws_access_key')
        aws_secret_key_val = load_setting('aws_secret_key')
        aws_session_token_val = load_setting('aws_session_token')
        gs_access_key_val = load_setting('gs_access_key')
        gs_secret_key_val = load_setting('gs_secret_key')

        self.aws_access_key = aws_access_key_val
        self.aws_secret_key = aws_secret_key_val
        self.aws_session_token = aws_session_token_val
        self.gs_access_key = gs_access_key_val
        self.gs_secret_key = gs_secret_key_val
        self.aws_access_key_inpt.setText(aws_access_key_val)
        self.aws_secret_key_inpt.setText(aws_secret_key_val)
        self.aws_session_token_inpt.setText(aws_session_token_val)
        self.gs_access_key_inpt.setText(gs_access_key_val)
        self.gs_secret_key_inpt.setText(gs_secret_key_val)

        return

    def getTabCaption(self):
        """Return tab caption."""
        return self.ext_name

    def getUiComponent(self):
        """Return GUI elements."""
        return self.gui_elements

    def doPassiveScan(self, request_response):
        """Perform a passive scan."""
        keys = {'aws_access_key': self.aws_access_key,
                'aws_secret_key': self.aws_secret_key,
                'aws_session_token': self.aws_session_token,
                'gs_access_key': self.gs_access_key,
                'gs_secret_key': self.gs_secret_key}
        bucket_scan = BucketScan(request_response, self.callbacks, keys)
        scan_issues = bucket_scan.identify_buckets()

        if len(scan_issues) > 0:
            return scan_issues
        return None

    @staticmethod
    def doActiveScan(*args):
        pass

    @staticmethod
    def consolidateDuplicateIssues(existing_issue, new_issue):
        """Eliminate duplicate issues."""
        if existing_issue.getIssueDetail() == new_issue.getIssueDetail():
            return -1
        else:
            return 0


class BucketScan(object):
    def __init__(self, request_response, callbacks, keys):
        self.request_response = request_response
        self.callbacks = callbacks
        self.helpers = self.callbacks.getHelpers()
        self.scan_issues = []
        self.aws_access_key = keys['aws_access_key']
        self.aws_secret_key = keys['aws_secret_key']
        self.aws_session_token = keys['aws_session_token']
        self.gs_access_key = keys['gs_access_key']
        self.gs_secret_key = keys['gs_secret_key']
        if RUN_TESTS:
            self.boto3_client = boto3.client('s3',
                                             aws_access_key_id=self.aws_access_key,
                                             aws_secret_access_key=self.aws_secret_key,
                                             aws_session_token=self.aws_session_token)
            self.boto_s3_con = S3Connection(
                aws_access_key_id=self.aws_access_key,
                aws_secret_access_key=self.aws_secret_key,
                host='s3.amazonaws.com'
            )
            self.boto_gs_con = S3Connection(
                aws_access_key_id=self.gs_access_key,
                aws_secret_access_key=self.gs_secret_key,
                host='storage.googleapis.com'
            )

            if not (self.aws_access_key and self.aws_secret_key):
                self.boto3_client.meta.events.register('choose-signer.s3.*', disable_signing)
                self.boto_s3_con = S3Connection(anon=True)

            if not (self.gs_access_key and self.gs_secret_key):
                self.boto_gs_con = S3Connection(anon=True, host='storage.googleapis.com')
        return

    def bucket_exists(self, bucket_name, bucket_type):
        """Confirm if an S3 bucket exists."""
        if bucket_type == 'S3':
            try:
                self.boto3_client.head_bucket(Bucket=bucket_name)
            except ClientError as error:
                error_code = int(error.response['Error']['Code'])
                if error_code == 404:
                    return False
        elif bucket_type == 'GS':
            bucket_exists = self.boto_gs_con.lookup(bucket_name)
            if not bucket_exists:
                return False
        elif bucket_type == 'Azure':
            try:
                bucket_url = 'https://' + bucket_name + '?comp=list&maxresults=10'
                urllib2.urlopen(urllib2.Request(bucket_url), timeout=10)
            except (urllib2.HTTPError, urllib2.URLError):
                return False
        return True

    def test_bucket(self, bucket_name, bucket_type):
        """Test for buckets misconfiguration issues."""
        grants = []
        issues = []
        keys = []

        if bucket_type == 'S3':
            bucket = self.boto_s3_con.get_bucket(bucket_name, validate=False)
            try:
                bucket_acl = bucket.get_acl().acl
                for grant in bucket_acl.grants:
                    grants.append((grant.display_name or grant.uri) + '->' + grant.permission)
                issues.append('s3:GetBucketAcl<ul><li>%s</li></ul>' % '</li><li>'.join(grants))
            except S3ResponseError as error:
                print 'Error Code (get_bucket_acl): ' + str(error.error_code)

            try:
                self.boto3_client.get_bucket_cors(Bucket=bucket_name)
                issues.append('s3:GetBucketCORS')
            except ClientError as error:
                error_code = error.response['Error']['Code']
                print 'Error Code (get_bucket_cors): ' + str(error_code)
            except ResponseParserError:
                issues.append('s3:GetBucketCORS')

            try:
                self.boto3_client.get_bucket_lifecycle(Bucket=bucket_name)
                issues.append('s3:GetLifecycleConfiguration')
            except ClientError as error:
                error_code = error.response['Error']['Code']
                print 'Error Code (get_bucket_lifecycle): ' + str(error_code)
            except ResponseParserError:
                issues.append('s3:GetLifecycleConfiguration')

            try:
                self.boto3_client.get_bucket_notification(Bucket=bucket_name)
                issues.append('s3:GetBucketNotification')
            except ClientError as error:
                error_code = error.response['Error']['Code']
                print 'Error Code (get_bucket_notification): ' + str(error_code)
            except ResponseParserError:
                issues.append('s3:GetBucketNotification')

            try:
                self.boto3_client.get_bucket_policy(Bucket=bucket_name)
                issues.append('s3:GetBucketPolicy')
            except ClientError as error:
                error_code = error.response['Error']['Code']
                print 'Error Code (get_bucket_policy): ' + str(error_code)
            except ResponseParserError:
                issues.append('s3:GetBucketPolicy')

            try:
                self.boto3_client.get_bucket_tagging(Bucket=bucket_name)
                issues.append('s3:GetBucketTagging')
            except ClientError as error:
                error_code = error.response['Error']['Code']
                print 'Error Code (get_bucket_tagging): ' + str(error_code)
            except ResponseParserError:
                issues.append('s3:GetBucketTagging')

            try:
                self.boto3_client.get_bucket_website(Bucket=bucket_name)
                issues.append('s3:GetBucketWebsite')
            except ClientError as error:
                error_code = error.response['Error']['Code']
                print 'Error Code (get_bucket_website): ' + str(error_code)
            except ResponseParserError:
                issues.append('s3:GetBucketWebsite')

            try:
                self.boto3_client.list_multipart_uploads(Bucket=bucket_name)
                issues.append('s3:ListMultipartUploadParts')
            except ClientError as error:
                error_code = error.response['Error']['Code']
                print 'Error Code (list_multipart_uploads): ' + str(error_code)
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
                print 'Error Code (list): ' + str(error.error_code)

            try:
                self.boto3_client.put_bucket_cors(
                    Bucket=bucket_name,
                    CORSConfiguration={
                        'CORSRules': [
                            {
                                'ExposeHeaders': [
                                    'Authorization',
                                ],
                                'AllowedMethods': [
                                    'GET',
                                ],
                                'AllowedOrigins': [
                                    '*',
                                ],
                                'MaxAgeSeconds': 123
                            }
                        ]
                    }
                )
                issues.append('s3:PutBucketCORS')
            except ClientError as error:
                error_code = error.response['Error']['Code']
                print 'Error Code (put_bucket_cors): ' + str(error_code)
            except ResponseParserError:
                issues.append('s3:PutBucketCORS')

            try:
                self.boto3_client.put_bucket_lifecycle_configuration(
                    Bucket=bucket_name,
                    LifecycleConfiguration={
                        'Rules': [
                            {
                                'Expiration': {
                                    'Date': datetime(2015, 1, 1),
                                    'Days': 123,
                                    'ExpiredObjectDeleteMarker': True|False
                                },
                                'ID': 'test',
                                'Prefix': 'test',
                                'Filter': {
                                    'Prefix': 'test',
                                    'Tag': {
                                        'Key': 'test',
                                        'Value': 'test'
                                    },
                                    'And': {
                                        'Prefix': 'test',
                                        'Tags': [
                                            {
                                                'Key': 'test',
                                                'Value': 'test'
                                            },
                                        ]
                                    }
                                },
                                'Status': 'Enabled'
                            }
                        ]
                    }
                )
                issues.append('s3:PutLifecycleConfiguration')
            except ClientError as error:
                error_code = error.response['Error']['Code']
                print 'Error Code (put_bucket_lifecycle_configuration): ' + str(error_code)
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
                print 'Error Code (put_bucket_logging): ' + str(error_code)
            except ResponseParserError:
                issues.append('s3:PutBucketLogging')

            try:
                self.boto3_client.put_bucket_notification(
                    Bucket=bucket_name,
                    NotificationConfiguration={
                        'TopicConfiguration': {
                            'Id': 'string',
                            'Events': [
                                's3:ReducedRedundancyLostObject',
                            ],
                            'Event': 's3:ReducedRedundancyLostObject',
                            'Topic': 'test'
                        }
                    }
                )
                issues.append('s3:PutBucketNotification')
            except ClientError as error:
                error_code = error.response['Error']['Code']
                print 'Error Code (put_bucket_notification): ' + str(error_code)
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
                            },
                        ]
                    }
                )
                issues.append('s3:PutBucketTagging')
            except ClientError as error:
                error_code = error.response['Error']['Code']
                print 'Error Code (put_bucket_tagging): ' + str(error_code)
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
                print 'Error Code (put_bucket_website): ' + str(error_code)
            except ResponseParserError:
                issues.append('s3:PutBucketWebsite')

            try:
                self.boto3_client.put_object(
                    ACL='public-read-write',
                    Body=b'test',
                    Bucket=bucket_name,
                    Key='test.txt'
                )
                issues.append('s3:PutObject<ul><li>test.txt</li></ul>')
            except ClientError as error:
                error_code = error.response['Error']['Code']
                print 'Error Code (put_object): ' + str(error_code)
            except ResponseParserError:
                issues.append('s3:PutObject')

            try:
                self.boto3_client.put_bucket_acl(
                    GrantFullControl='uri="http://acs.amazonaws.com/groups/global/AllUsers"',
                    Bucket=bucket_name
                )
                issues.append('s3:PutBucketAcl')
            except ClientError as error:
                error_code = error.response['Error']['Code']
                print 'Error Code (put_bucket_acl): ' + str(error_code)
            except ResponseParserError:
                issues.append('s3:PutBucketAcl')

            try:
                self.boto3_client.put_bucket_policy(
                    Bucket='string',
                    Policy='''
                        {
                        "Version":"2008-10-17",
                        "Id":"aaaa-bbbb-cccc-dddd",
                        "Statement" : [
                            {
                                "Effect":"Allow",
                                "Sid":"1", 
                                "Principal" : {
                                    "AWS":["111122223333","444455556666"]
                                },
                                "Action":["s3:*"],
                                "Resource":"arn:aws:s3:::%s/*"
                            }
                         ] 
                        } ''' % bucket_name
                )
                issues.append('s3:PutBucketPolicy')
            except ClientError as error:
                error_code = error.response['Error']['Code']
                print 'Error Code (put_bucket_policy): ' + str(error_code)
            except ResponseParserError:
                issues.append('s3:PutBucketPolicy')
        elif bucket_type == 'GS':
            try:
                bucket = self.boto_gs_con.get_bucket(bucket_name, validate=False)
            except S3ResponseError as error:
                return False

            try:
                i = 0
                for k in bucket.list():
                    i = i + 1
                    keys.append(k.key)
                    if i == 10:
                        break
                issues.append('READ<ul><li>%s</li></ul>' % '</li><li>'.join(keys))
            except S3ResponseError as error:
                print 'Error Code (list): ' + str(error.error_code)

            try:
                key = bucket.new_key('test.txt')
                key.set_contents_from_string('')
                issues.append('WRITE<ul><li>test.txt</li></ul>')
            except S3ResponseError as error:
                print 'Error Code (set_contents_from_string): ' + str(error.error_code)

            try:
                bucket.add_email_grant('FULL_CONTROL', '')
            except S3ResponseError as error:
                if error.error_code == 'MalformedACLError':
                    issues.append('FULL_CONTROL')
                else:
                    print 'Error Code (add_email_grant): ' + str(error.error_code)
            except AttributeError as error:
                if error.message.startswith("'Policy'"):
                    issues.append('FULL_CONTROL')
                else:
                    raise
        elif bucket_type == 'Azure':
            try:
                bucket_url = 'https://' + bucket_name + '?comp=list&maxresults=10'
                request = urllib2.Request(bucket_url)
                response = urllib2.urlopen(request, timeout=10)
                blobs = parse(response).documentElement.getElementsByTagName('Name')
                for blob in blobs:
                    keys.append(blob.firstChild.nodeValue.encode('utf-8'))
                issues.append('Full public read access<ul><li>%s</li></ul>' %
                              '</li><li>'.join(keys))
            except (AttributeError, urllib2.HTTPError, urllib2.URLError):
                pass

        if not issues:
            return False
        if ('s3:PutBucketAcl' in issues or 'FULL_CONTROL' in issues) or len(issues) > 5:
            issuelevel = 'High'
        elif ('s3:ListBucket' in issues and 's3:PutObject' in issues) or\
            ('READ' in issues and 'WRITE' in issues) or len(issues) > 2:
            issuelevel = 'Medium'
        else:
            issuelevel = 'Low'

        issuename = '%s Bucket Misconfiguration' % bucket_type
        issuedetail = '''The "%s" %s bucket grants the following permissions:<br>
                         <li>%s</li><br><br>''' % (bucket_name, bucket_type, '</li><li>'.join(issues))

        return {'issuename': issuename, 'issuedetail': issuedetail,
                'issuelevel': issuelevel}

    def identify_buckets(self):
        """Identify S3 buckets."""
        scan_issues = []
        s3_bucket_names = []
        gs_bucket_names = []
        az_bucket_uris = []
        response = self.request_response.getResponse()
        response_str = self.helpers.bytesToString(response)
        response_len = len(response_str)
        response_str = response_str.encode('utf-8', 'replace')
        current_url = self.helpers.analyzeRequest(self.request_response).getUrl()
        current_url_str = re.search(r'\w+://[^/]+', str(current_url)).group(0)
        host = host = re.search(r'\w+://([\w.-]+)', current_url_str).group(1)

        if RUN_TESTS:
            s3_bucket_names.append((host, ''))
            gs_bucket_names.append((host, ''))

        # Matches S3 bucket names
        s3_buckets_regex = re.compile(
            r'(?:([\w.-]+)\.s3[\w.-]*\.amazonaws\.com|s3(?:[\w.-]*\.amazonaws\.com(?:\\?/)*|://)([\w.-]+))',
            re.I)
        s3_bucket_names += re.findall(s3_buckets_regex, response_str)

        # Matches GS bucket names
        gs_buckets_regex = re.compile(
            r'(?:([\w.-]+)\.storage[\w-]*\.googleapis\.com|(?:(?:console\.cloud\.google\.com/storage/browser/|storage[\w-]*\.googleapis\.com)(?:\\?/)*|gs://)([\w.-]+))',
            re.I)
        gs_bucket_names += re.findall(gs_buckets_regex, response_str)

        # Matches Azure container URIs
        az_buckets_regex = re.compile(
            r'[\w.-]+[\w.-]*\.blob\.core\.windows\.net(?:/|\\/)[\w.-]+',
            re.I)
        az_bucket_uris = re.findall(az_buckets_regex, response_str)

        def handle_buckets(bucket_names, bucket_type):
            """Handle identified buckets."""
            request = self.request_response.getRequest()
            request_str = self.helpers.bytesToString(request)
            request_len = len(request_str)
            offset = array('i', [0, 0])
            markers = []
            mark_request = False
            for i in xrange(0, len(bucket_names)):
                offsets = []
                bucket_name = bucket_names[i]
                if not isinstance(bucket_name, str):
                    bucket_name = bucket_name[0] or bucket_name[1]
                if bucket_type == 'S3':
                    if bucket_name in identified_s3_buckets and current_url_str in tested_uris:
                        continue
                    identified_s3_buckets.add(bucket_name)
                elif bucket_type == 'GS':
                    if bucket_name in identified_gs_buckets and current_url_str in tested_uris:
                        continue
                    identified_gs_buckets.add(bucket_name)
                elif bucket_type == 'Azure':
                    if bucket_name in identified_az_buckets and current_url_str in tested_uris:
                        continue
                    identified_az_buckets.add(bucket_name)
                tested_uris.add(current_url_str)
                if RUN_TESTS and not self.bucket_exists(bucket_name, bucket_type):
                    continue
                if bucket_name == host:
                    mark_request = True
                    start = self.helpers.indexOf(request,
                                                 bucket_name, True, 0, request_len)
                else:
                    start = self.helpers.indexOf(response,
                                                 bucket_name, True, 0, response_len)
                offset[0] = start
                offset[1] = start + len(bucket_name)
                offsets.append(offset)
                if mark_request:
                    markers = [self.callbacks.applyMarkers(self.request_response, offsets, None)]
                else:
                    markers = [self.callbacks.applyMarkers(self.request_response, None, offsets)]
                issuename = '%s Bucket Detected' % bucket_type
                issuelevel = 'Information'
                issuedetail = '''The following %s bucket has been identified:<br>
                    <li>$bucket_name$</li>''' % bucket_type
                scan_issues.append(
                    ScanIssue(self.request_response.getHttpService(),
                              current_url, markers, issuename, issuelevel,
                              issuedetail.replace('$bucket_name$', bucket_name)
                             )
                )
                if RUN_TESTS:
                    issues = self.test_bucket(bucket_name, bucket_type)
                    if issues:
                        scan_issues.append(
                            ScanIssue(self.request_response.getHttpService(),
                                      self.helpers.analyzeRequest(self.request_response).getUrl(),
                                      markers, issues['issuename'], issues['issuelevel'], issues['issuedetail']
                                     )
                        )

        if s3_bucket_names:
            handle_buckets(s3_bucket_names, 'S3')

        if gs_bucket_names:
            handle_buckets(gs_bucket_names, 'GS')

        if az_bucket_uris:
            handle_buckets(az_bucket_uris, 'Azure')

        return scan_issues


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
