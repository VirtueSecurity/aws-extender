# AWS Extender

AWS Extender is a [Burpsuite](https://portswigger.net/burp/) plugin to identify and test AWS assets for common misconfigurations. Many AWS services such as S3 expose an attack surface not accessible directly over HTTP/HTTPS. AWS Extender uses the AWS SDK Boto3 to connect to S3 buckets and test for misconfigurations.


## Getting Started
##### For general instructions on how to load Burp Suite plugins, please visit the following [URL](https://support.portswigger.net/customer/portal/articles/1965930-how-to-install-an-extension-in-burp-suite).

#### Installing Dependency Librarires
1. Download the file "[requirements.txt](/requirements.txt)".
1. Run the following command `pip install -r requirements.txt`.

#### Custom Environment Settings
1. Open the Burp Suite Extender tab.
2. Click "Options".
3. Set the "Folder for loading modules" setting to the path of your Python installation's [site-packages directory](https://docs.python.org/2/install/#how-installation-works).

#### Config Options
In order to make full use of AWS Extender, you will need an AWS access key as well as a secret key. if you don't have an account, one can be obtained for free at "[https://aws.amazon.com/free/](https://aws.amazon.com/free/)".

After obtaining your AWS credentials, you will need to add them through the "AWS Extender" tab as shown below:
<a href="https://github.com/VirtueSecurity/aws-extender/blob/master/screenshots/config-tab.png?raw=true" target="_blank"><img src="https://github.com/VirtueSecurity/aws-extender/blob/master/screenshots/config-tab-thumb.png?raw=true" alt="Congig Tab"></a>

## Tests Covered

### S3

 - List Bucket (s3:ListBucket)
 - List Multipart Uploads (s3:ListMultipartUploadParts)
 - Get Bucket ACL (s3:GetBucketAcl)
 - Set Bucket ACL (s3:PutBucketAcl)
 - Upload File (s3:PutObject)
 - Get Bucket Event Notifications (s3:GetBucketNotification)
 - Set Bucket Event Notifications (s3:PutBucketNotification)
 - Get Bucket Policy (s3:GetBucketPolicy)
 - Set Bucket Policy (s3:PutBucketPolicy)
 - Get Bucket Tagging (s3:GetBucketTagging)
 - Set Bucket Tagging (s3:PutBucketTagging)
 - Get Bucket Website (s3:GetBucketWebsite)
 - Set Bucket Website (s3:PutBucketWebsite)
 - Get Bucket CORS (s3:GetBucketCORS)
 - Set Bucket CORS (s3:PutBucketCORS)
 - GET Life Cycle Configuration (s3:GetLifecycleConfiguration)
 - Set Life Cycle Configuration (s3:PutLifecycleConfiguration)
 - Set Bucket Logging (s3:PutBucketLogging)

## Screenshots
<a href="https://github.com/VirtueSecurity/aws-extender/blob/master/screenshots/bucket_identified.png?raw=true" target="_blank"><img src="https://github.com/VirtueSecurity/aws-extender/blob/master/screenshots/bucket_identified.png?raw=true" alt="Bucket Identified"></a>

<a href="https://github.com/VirtueSecurity/aws-extender/blob/master/screenshots/bucket-readable.png?raw=true" target="_blank"><img src="https://github.com/VirtueSecurity/aws-extender/blob/master/screenshots/bucket-readable.png?raw=true" alt="Bucket Readable"></a>

## Todo
* Cover more AWS services.
* Add more tests.
