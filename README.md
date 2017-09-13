# AWS Extender

AWS Extender is a [BurpSuite](https://portswigger.net/burp/) extension to identify and test S3 buckets as well as Google Storage buckets and Azure Storage containers for common misconfiguration issues using the boto/boto3 SDK library.


## Getting Started
##### For general instructions on how to load BurpSuite extensions, please visit this [URL](https://support.portswigger.net/customer/portal/articles/1965930-how-to-install-an-extension-in-burp-suite).

#### Installing Dependencies
Both of [boto](https://github.com/boto/boto) and [boto3](https://github.com/boto/boto3) are required. You can install them using [pip](https://en.wikipedia.org/wiki/Pip_\(package_manager\)):

    $ pip install -r requirements.txt

#### Custom Environment Settings
1. Open the BurpSuite Extender tab.
2. Click "Options".
3. Set the "Folder for loading modules" setting to the path of your Python installation's [site-packages directory](https://docs.python.org/2/install/#how-installation-works).

#### Extension Settings
The settings tab provides the following settings:

<a href="https://github.com/VirtueSecurity/aws-extender/blob/master/screenshots/settings.png?raw=true" target="_blank"><img src="https://github.com/VirtueSecurity/aws-extender/blob/master/screenshots/settings_thumb.png?raw=true" alt="Settings Tab"></a>

Below is a description of each:

| Setting   |      Description      |      Required      |
|----------|:-------------:|:-------------:|
| AWS Access Key |  Your AWS account access key ID |  True |
| AWS Secret Key |    Your AWS account secret key   |    True   |
| AWS Session Key | A temporary session token | False |
| GS Access Key | Your Google account access key ID | True |
| GS Secret Key | Your Google account secret key | True |
| Wordlist Filepath | A filepath to a list of filenames | False |
| Passive Mode | Perform passive checks only | N/A |

**Notes:**
* AWS keys can be obtained from your [AWS Management Console](https://console.aws.amazon.com/iam/home?#/security_credential). For Google Cloud, see [the documentation](https://cloud.google.com/storage/docs/migrating#keys).

* The extension will still provide minimal functionality (e.g., identifying buckets) even if none of the above requirements are satisfied.


## Screenshots
<a href="https://github.com/VirtueSecurity/aws-extender/blob/master/screenshots/S3_bucket_misconfiguration.png?raw=true" target="_blank"><img src="https://github.com/VirtueSecurity/aws-extender/blob/master/screenshots/S3_bucket_misconfiguration.png?raw=true" alt="S3 Bucket Misconfiguration"></a>

<a href="https://github.com/VirtueSecurity/aws-extender/blob/master/screenshots/excessive_signed_url.png?raw=true" target="_blank"><img src="https://github.com/VirtueSecurity/aws-extender/blob/master/screenshots/excessive_signed_url.png?raw=true" alt="S3 Signed URL Excessive Expiration Time"></a>

<a href="https://github.com/VirtueSecurity/aws-extender/blob/master/screenshots/GS_bucket_misconfiguration.png?raw=true" target="_blank"><img src="https://github.com/VirtueSecurity/aws-extender/blob/master/screenshots/GS_bucket_misconfiguration.png?raw=true" alt="GS Bucket Misconfiguration"></a>


