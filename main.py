# -*- coding: utf-8 -*-
# Version 1.1
import os.path
import xml.etree.cElementTree as CET
from botocore.compat import XMLParseError
from burp import IBurpExtender
from burp import IScannerCheck
from burp import ITab
from javax.swing import JTextField
from javax.swing import JLabel
from javax.swing import JFrame
from javax.swing import JPanel
from javax.swing import JButton
from javax.swing import JCheckBox
from javax.swing.border import EmptyBorder
from java.awt import BorderLayout
from java.awt import GridLayout
from org.xml.sax import SAXException
from scan import BucketScan, CognitoScan, RUN_TESTS
SSL_VERIFICATION = True

class BurpExtender(IBurpExtender, IScannerCheck, ITab):
    def __init__(self):
        self.ext_name = 'Cloud Storage Tester'
        self.callbacks = None
        self.gui_elements = None
        self.aws_access_key_inpt = None
        self.aws_secret_key_inpt = None
        self.aws_session_token_inpt = None
        self.gs_access_key_inpt = None
        self.gs_secret_key_inpt = None
        self.wordlist_path_inpt = None
        self.passive_mode = None
        self.ssl_verification = None
        self.aws_access_key = ''
        self.aws_secret_key = ''
        self.aws_session_token = ''
        self.gs_access_key = ''
        self.gs_secret_key = ''
        self.wordlist_path = ''

    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks

        self.callbacks.setExtensionName(self.ext_name)

        self.callbacks.registerScannerCheck(self)

        self.gui_elements = self.build_gui()

        callbacks.customizeUiComponent(self.gui_elements)
        callbacks.addSuiteTab(self)
        self.check_loading_issues()
        self.reload_config()

    def show_errors(self, label):
        """Display error messages."""
        top_label = JLabel(label, JLabel.CENTER)

        frame = JFrame(self.ext_name)
        frame.setSize(550, 300)
        frame.setLayout(GridLayout(1, 1))

        frame.add(top_label)
        frame.setLocationRelativeTo(None)
        frame.setVisible(True)

    def check_loading_issues(self):
        """Check for any loading issues."""
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
            missing_libs.append('boto/boto3')
            tips.append('Make sure that the boto/boto3 library is installed properly, and\
                the right path is specified in the "Folder for loading modules" setting.')
        try:
            CET.fromstring('<test></test>')
        except SAXException:
            # a workaround for "http://bugs.jython.org/issue1127"
            try:
                def xml_parser(**_):
                    class Parser(object):
                        def feed(*_):
                            raise XMLParseError
                        @staticmethod
                        def close(*_):
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

        self.show_errors(label)

    def build_gui(self):
        """Construct GUI elements."""
        panel = JPanel(BorderLayout(3, 3))
        panel.setBorder(EmptyBorder(160, 160, 160, 160))

        self.aws_access_key_inpt = JTextField(10)
        self.aws_secret_key_inpt = JTextField(10)
        self.aws_session_token_inpt = JTextField(10)
        self.gs_access_key_inpt = JTextField(10)
        self.gs_secret_key_inpt = JTextField(10)
        self.wordlist_path_inpt = JTextField(10)
        self.passive_mode = JCheckBox('Enabled')
        self.ssl_verification = JCheckBox('Enabled')

        save_btn = JButton('Save', actionPerformed=self.save_config)

        labels = JPanel(GridLayout(0, 1))
        inputs = JPanel(GridLayout(0, 1))
        panel.add(labels, BorderLayout.WEST)
        panel.add(inputs, BorderLayout.CENTER)

        top_label = JLabel('<html><b>Settings</b><br><br></html>')
        top_label.setHorizontalAlignment(JLabel.CENTER)
        panel.add(top_label, BorderLayout.NORTH)
        labels.add(JLabel('AWS Access Key:'))
        inputs.add(self.aws_access_key_inpt)
        labels.add(JLabel('AWS Secret Key:'))
        inputs.add(self.aws_secret_key_inpt)
        labels.add(JLabel('AWS Session Key (optional):'))
        inputs.add(self.aws_session_token_inpt)
        labels.add(JLabel('GS Access Key:'))
        inputs.add(self.gs_access_key_inpt)
        labels.add(JLabel('GS Secret Key:'))
        inputs.add(self.gs_secret_key_inpt)
        labels.add(JLabel('Wordlist Filepath (optional):'))
        inputs.add(self.wordlist_path_inpt)
        labels.add(JLabel('Passive Mode:'))
        inputs.add(self.passive_mode)
        labels.add(JLabel('SSL Verification:'))
        inputs.add(self.ssl_verification)
        panel.add(save_btn, BorderLayout.SOUTH)
        return panel

    def save_config(self, _):
        """Save settings."""
        error_message = ''
        wordlist_path = self.wordlist_path_inpt.getText()
        save_setting = self.callbacks.saveExtensionSetting
        save_setting('aws_access_key', self.aws_access_key_inpt.getText())
        save_setting('aws_secret_key', self.aws_secret_key_inpt.getText())
        save_setting('aws_session_token', self.aws_session_token_inpt.getText())
        save_setting('gs_access_key', self.gs_access_key_inpt.getText())
        save_setting('gs_secret_key', self.gs_secret_key_inpt.getText())
        save_setting('wordlist_path', wordlist_path)

        if self.passive_mode.isSelected():
            save_setting('passive_mode', 'True')
        else:
            save_setting('passive_mode', '')

        if self.ssl_verification.isSelected():
            save_setting('SSL_VERIFICATION', '')
        else:
            save_setting('SSL_VERIFICATION', 'False')

        if wordlist_path and not os.path.isfile(wordlist_path):
            error_message = 'Error: Invalid filepath for the "Wordlist Filepath" setting.'
            self.show_errors(error_message)

        self.reload_config()

    def reload_config(self):
        """Reload saved settings."""
        global RUN_TESTS
        global SSL_VERIFICATION
        load_setting = self.callbacks.loadExtensionSetting
        aws_access_key_val = load_setting('aws_access_key') or ''
        aws_secret_key_val = load_setting('aws_secret_key') or ''
        aws_session_token_val = load_setting('aws_session_token') or ''
        gs_access_key_val = load_setting('gs_access_key') or ''
        gs_secret_key_val = load_setting('gs_secret_key') or ''
        wordlist_path_val = load_setting('wordlist_path') or ''
        passive_mode_val = load_setting('passive_mode')
        passive_mode_val = True if passive_mode_val else False
        ssl_verification_val = load_setting('SSL_VERIFICATION')
        ssl_verification_val = False if ssl_verification_val == 'False' else True

        if passive_mode_val:
            RUN_TESTS = False

        if not ssl_verification_val:
            SSL_VERIFICATION = False

        self.aws_access_key = aws_access_key_val
        self.aws_secret_key = aws_secret_key_val
        self.aws_session_token = aws_session_token_val
        self.gs_access_key = gs_access_key_val
        self.gs_secret_key = gs_secret_key_val
        self.wordlist_path = wordlist_path_val
        self.aws_access_key_inpt.setText(aws_access_key_val)
        self.aws_secret_key_inpt.setText(aws_secret_key_val)
        self.aws_session_token_inpt.setText(aws_session_token_val)
        self.gs_access_key_inpt.setText(gs_access_key_val)
        self.gs_secret_key_inpt.setText(gs_secret_key_val)
        self.wordlist_path_inpt.setText(wordlist_path_val)
        self.passive_mode.setSelected(passive_mode_val)
        self.ssl_verification.setSelected(ssl_verification_val)

    def getTabCaption(self):
        """Return tab caption."""
        return self.ext_name

    def getUiComponent(self):
        """Return GUI elements."""
        return self.gui_elements

    def doPassiveScan(self, request_response):
        """Perform a passive scan."""
        scan_issues = []
        opts = {'aws_access_key': self.aws_access_key,
                'aws_secret_key': self.aws_secret_key,
                'aws_session_token': self.aws_session_token,
                'gs_access_key': self.gs_access_key,
                'gs_secret_key': self.gs_secret_key,
                'wordlist_path': self.wordlist_path}
        bucket_scan = BucketScan(request_response, self.callbacks, opts, SSL_VERIFICATION)
        bucket_issues = bucket_scan.check_buckets()
        cognito_scan = CognitoScan(request_response, self.callbacks)
        cognito_issues = cognito_scan.identify_identity_pools()

        scan_issues = bucket_issues + cognito_issues
        return scan_issues

    @staticmethod
    def doActiveScan(*_):
        pass

    @staticmethod
    def consolidateDuplicateIssues(existing_issue, new_issue):
        """Eliminate duplicate issues."""
        if existing_issue.getIssueDetail() == new_issue.getIssueDetail():
            return -1
        return 0
