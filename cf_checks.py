# -*- coding: utf-8 -*-

try:
    import urllib2 as urllib_req
    from urllib2 import HTTPError, URLError
except ImportError:
    import urllib.request as urllib_req
    from urllib.error import HTTPError, URLError
from xml.dom.minidom import parse

def check_cf(cf_endpoints):
    """Check if a CloudFront URL points to an S3 bucket"""
    if not cf_endpoints:
        return None
    bucket_names = []
    for endpoint in cf_endpoints:
        if not endpoint.startswith('https://'):
            endpoint = 'https://' + endpoint
        request = urllib_req.Request(endpoint)
        try:
            response = urllib_req.urlopen(request, timeout=20)
            if 'AmazonS3' in dict(response.info())['server']:
                bucket_name = parse(response).documentElement.getElementsByTagName('Name')[0]
                bucket_names.append((endpoint,
                                     bucket_name.firstChild.nodeValue.encode('utf-8'))
                                   )
        except (AttributeError, HTTPError, URLError):
            continue
    return bucket_names
