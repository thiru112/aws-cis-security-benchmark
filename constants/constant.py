from boto3 import client
import time
"""To declate global level constants
"""

AWS_CIS_BENCHMARK_VERSION = "v 1.2.0 05-23-2018"

CLOUDTRAIL_CLIENT = client('cloudtrail')

CLOUDWATCH_CLIENT = client('cloudwatch')

CONFIG_SERVICE_CLIENT = client('config')

EC2_CLIENT = client('ec2')

IAM_CLIENT = client('iam')

KMS_CLIENT = client('kms')

LOGS_CLIENT = client('logs')

S3_CLIENT = client('s3')

SNS_CLIENT = client('sns')

TOOL_VERSION = "v 0.1"

now = time.strftime('%Y-%m-%dT%H:%M:%S+00:00',
                    time.gmtime(time.time()))
fmt = "%Y-%m-%dT%H:%M:%S+00:00"
