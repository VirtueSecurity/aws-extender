# AWS Extender

AWS Extender is a [Burpsuite](https://portswigger.net/burp/) plugin to identify and test AWS assets for common misconfigurations. Many AWS services such as S3 expose an attack surface not accessible directly over HTTP/HTTPS. AWS Extender uses the AWS SDK Boto3 to connect to S3 buckets and test for misconfigurations.


## Getting Started
Because of longstanding Jython bugs, this extension requires -- libraries to be loaded at the commandline. This can be doen with the following:
```
java -classpath xercesImpl.jar;burpsuite_pro.jar burp.StartBurp
```
To make full use of AWS Extender you will need an AWS Secret key, if you don't have an account, one can be obtained for free: https://aws.amazon.com/free/

## Vulnerabilities Covered

### S3

 - Bucket Directory Listing
 - Bucket ACL Exposed
 - Unauthenticated File Upload
 - Authenticated File Upload
 
### General AWS

 - Reference to AWS Metadata IP
 






