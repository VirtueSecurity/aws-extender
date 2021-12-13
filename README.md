# AWS Extender

This Burp Suite extension can identify and test S3 buckets as well as Google Storage buckets and Azure Storage containers for common misconfiguration issues using the boto/boto3 SDK library.


## How to install
You can install this extension directly from the BApp Store or manually by cloning this repo and following these steps:

1. Open the Burp Suite Extender tab.
2. Open the "Options" subtab.
3. Set the "Folder for loading modules" setting to the pathname of the "BappModules" folder.
4. Open the "Extensions" subtab.
5. Click "Add" and set "Extension type" to "Python".
6. Set "Extension file (.py)" to the pathname of the "main.py" file and click Next. 


#### Extension Settings
The settings tab provides the following settings:

<a href="/screenshots/settings.png?raw=true" target="_blank"><img src="/screenshots/settings_thumb.png?raw=true" alt="Settings Tab"></a>

Below is a description of each:

| Setting   |      Description      |      Required      |
|----------|:-------------:|:-------------:|
| AWS Access Key |  Your AWS account access key ID |  True |
| AWS Secret Key |    Your AWS account secret key   |    True   |
| AWS Session Key | A temporary session token | False |
| GS Access Key | Your Google account access key ID | True |
| GS Secret Key | Your Google account secret key | True |
| Wordlist Filepath | A filepath for a wordlist of filenames | False |
| Passive Mode | Perform passive checks only | N/A |
| SSL Verification | Enable/disable SSL verification | N/A |

**Notes:**
* AWS keys can be obtained from your [AWS Management Console](https://console.aws.amazon.com/iam/home?#/security_credential). For Google Cloud, see [the documentation](https://cloud.google.com/storage/docs/migrating#keys). Note that AWS/GS keys are only required for authenticated tests; if no keys are provided, only unauthenticated tests will run.

* When SSL verification is enabled, buckets with a dot in their name will not be thoroughly tested due to SSL verification errors in boto (see: [/boto/boto/issues/2836](https://github.com/boto/boto/issues/2836)). You can either disable SSL Verification to test these (not recommended) or use this command-line script to test such buckets ([/VirtueSecurity/aws-extender-cli](https://github.com/VirtueSecurity/aws-extender-cli)).

## Screenshots
<a href="/screenshots/S3_bucket_misconfiguration.png?raw=true" target="_blank"><img src="/screenshots/S3_bucket_misconfiguration.png?raw=true" alt="S3 Bucket Misconfiguration"></a>

<a href="/screenshots/excessive_signed_url.png?raw=true" target="_blank"><img src="/screenshots/excessive_signed_url.png?raw=true" alt="S3 Signed URL Excessive Expiration Time"></a>

<a href="/screenshots/GS_bucket_misconfiguration.png?raw=true" target="_blank"><img src="/screenshots/GS_bucket_misconfiguration.png?raw=true" alt="GS Bucket Misconfiguration"></a>

#### Disclaimer:
Developers assume no liability and are not responsible for any misuse or damage caused by this tool. Usage of this tool for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws.
