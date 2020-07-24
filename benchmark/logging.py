from constants.constant import CLOUDTRAIL_CLIENT, S3_CLIENT, CONFIG_SERVICE_CLIENT, KMS_CLIENT, now
from constants.controls import Control

from datetime import datetime, timedelta, timezone
from dateutil import tz
from json import loads

cloudtrial_describe_trails = CLOUDTRAIL_CLIENT.describe_trails()['trailList']


def control_2_1_cloudtrail_enabled_all_regions():
    cont = Control('2.1', 'Ensure CloudTrail is enabled in all regions', True)
    for each_trail in cloudtrial_describe_trails:
        if each_trail['IsMultiRegionTrail'] is True:
            if CLOUDTRAIL_CLIENT.get_trail_status(Name=each_trail['TrailARN'])['IsLogging'] is True:
                resp = CLOUDTRAIL_CLIENT.get_event_selectors(
                    TrailName=each_trail['TrailARN'])['EventSelectors']
                flag = False
                for each_event_selectors in resp:
                    if each_event_selectors['IncludeManagementEvents'] is True and each_event_selectors['ReadWriteType'] == 'All':
                        flag = True
                        break
                if flag is False:
                    cont.fail_reason = 'Event selectors are not properly enabled'
                    cont.offenders = each_trail['TrailARN']
            else:
                cont.fail_reason = 'Logging is not enabled'
                cont.offenders = each_trail['TrailARN']
        else:
            cont.fail_reason = 'MultiregionTrial is not enabled'
            cont.offenders = each_trail['TrailARN']

    if not cont.offenders:
        cont.result = True

    return {'control_id': cont.id, 'scored': cont.scored, 'desc': cont.desc, 'result': cont.result, 'fail_reason': cont.fail_reason, 'offenders': cont.offenders}


def control_2_2_cloudtrail_log_file_validation():
    cont = Control(
        '2.2', 'Ensure CloudTrail log file validation is enabled', True)
    if not cloudtrial_describe_trails:
        cont.fail_reason = 'CloudTrail is not created'
        cont.offenders = 'CloudTrail is not created'
    else:
        for each_trail in cloudtrial_describe_trails:
            if each_trail['LogFileValidationEnabled'] is False:
                if 'Logfile Validation is not enabled' not in cont.fail_reason:
                    cont.fail_reason = 'Logfile Validation is not enabled'
                cont.offenders = each_trail['TrailARN']
    if not cont.offenders:
        cont.result = True

    return {'control_id': cont.id, 'scored': cont.scored, 'desc': cont.desc, 'result': cont.result, 'fail_reason': cont.fail_reason, 'offenders': cont.offenders}


def control_2_3_cloudtrail_s3_not_public_accessable():
    cont = Control(
        '2.3', 'Ensure the S3 bucket used to store CloudTrail logs is not publicly accessible', True)
    for each_trail_bucket in cloudtrial_describe_trails:
        s3_grants = S3_CLIENT.get_bucket_acl(
            Bucket=each_trail_bucket['S3BucketName'])['Grants']
        for grant in s3_grants:
            if 'URI' in grant:
                if grant['URI'] == 'http://acs.amazonaws.com/groups/global/AuthenticatedUsers' or grant['URI'] == 'http://acs.amazonaws.com/groups/global/AllUsers':
                    fail_res = 'All Users or Authenticated Users are granted privelge to the bucket'
                    if fail_res not in cont.fail_reason:
                        cont.fail_reason = fail_res
                    cont.offenders = each_trail_bucket['S3BucketName']

        bucket_policy = loads(S3_CLIENT.get_bucket_policy(
            Bucket=each_trail_bucket['S3BucketName'])['Policy'])['Statement']
        for policy in bucket_policy:
            if policy['Effect'] == 'Allow' and ('*' in policy['Principal'] or 'AWS' in policy['Principal']):
                fail_res = 'Bucket policy is set for Public access'
                if fail_res not in cont.fail_reason:
                    cont.fail_reason = fail_res
                cont.offenders = each_trail_bucket['S3BucketName']

    if not cont.offenders:
        cont.result = True

    return {'control_id': cont.id, 'scored': cont.scored, 'desc': cont.desc, 'result': cont.result, 'fail_reason': cont.fail_reason, 'offenders': cont.offenders}


def control_2_4_cloudtrail_integrated_cloudwatch():
    cont = Control(
        '2.4', 'Ensure CloudTrail trails are integrated with CloudWatch Logs', True)
    for each_trail in cloudtrial_describe_trails:
        if 'CloudWatchLogsLogGroupArn' in each_trail or 'LatestCloudWatchLogsDeliveryTime' in CLOUDTRAIL_CLIENT.get_trail_status(Name=each_trail['Name']):
            if not each_trail['CloudWatchLogsLogGroupArn']:
                fail_res = 'CloudWatch Logs Group Arn is empty'
                if fail_res not in cont.fail_reason:
                    cont.fail_reason = fail_res
                cont.offenders = each_trail['TrailARN']
            a = datetime.now(tz=tz.tzlocal()) - timedelta(days=1)
            delivery_time = CLOUDTRAIL_CLIENT.get_trail_status(Name=each_trail['Name'])[
                'LatestCloudWatchLogsDeliveryTime']
            if delivery_time <= datetime.now(tz=tz.tzlocal()) - timedelta(days=1):
                fail = 'Latest CloudWatch Logs Delivery Time is greater than one day'
                if fail not in cont.fail_reason:
                    cont.fail_reason = fail
                cont.offenders = each_trail['TrailARN']
        else:
            if "CloudTrail logs doesn't attached to CloudWatch Logs log group" not in cont.fail_reason:
                cont.fail_reason = "CloudTrail logs doesn't attached to CloudWatch Logs log group" 
            cont.offenders = each_trail['TrailARN']

    if not cont.offenders:
        cont.result = True

    return {'control_id': cont.id, 'scored': cont.scored, 'desc': cont.desc, 'result': cont.result, 'fail_reason': cont.fail_reason, 'offenders': cont.offenders}


def control_2_5_aws_config_enabled_all_regions():
    cont = Control('2.5', 'Ensure AWS Config is enabled in all regions', True)
    flag = False
    configuration_recorders = CONFIG_SERVICE_CLIENT.describe_configuration_recorders()[
        'ConfigurationRecorders']
    recorders = list()
    for each_recorder in configuration_recorders:
        if each_recorder['recordingGroup']['allSupported'] is True and each_recorder['recordingGroup']['includeGlobalResourceTypes'] is True:
            flag = True
            recorders.append(each_recorder['name'])

    if not recorders:
        cont.fail_reason = 'No Configservice recorders found'
        cont.offenders = 'No recoders found!.'
    else:
        flg = False
        for recoder_status in CONFIG_SERVICE_CLIENT.describe_configuration_recorder_status(ConfigurationRecorderNames=recorders)['ConfigurationRecordersStatus']:
            if recoder_status['recording'] is True and recoder_status['lastStatus'] == 'Success':
                flg = True
                break
        if flg is False:
            cont.fail_reason = 'No recorders is recording or and State is not success'

    if flag is True:
        cont.result = True
    else:
        cont.fail_reason = 'The Recording group does not suport all regions and resources'
        cont.offenders = 'Configuration Recorders'

    return {'control_id': cont.id, 'scored': cont.scored, 'desc': cont.desc, 'result': cont.result, 'fail_reason': cont.fail_reason, 'offenders': cont.offenders}


def control_2_6_s3_logging_enabled_cts3_bucket():
    cont = Control(
        '2.6', 'Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket', True)
    for each_trail in cloudtrial_describe_trails:
        if 'LoggingEnabled' in S3_CLIENT.get_bucket_logging(Bucket=each_trail['S3BucketName']):
            continue
        else:
            if 'CloudTrail Bucket logging is not enabled' not in cont.fail_reason:
                cont.fail_reason = 'CloudTrail Bucket logging is not enabled'
            cont.offenders = each_trail['Name'] + \
                ' => ' + each_trail['S3BucketName']

    if not cont.offenders:
        cont.result = True

    return {'control_id': cont.id, 'scored': cont.scored, 'desc': cont.desc, 'result': cont.result, 'fail_reason': cont.fail_reason, 'offenders': cont.offenders}


def control_2_7_cloudtrail_logs_encrypted_kms():
    cont = Control(
        '2.7', 'Ensure CloudTrail logs are encrypted at rest using KMS CMKs', True)
    for each_trail in cloudtrial_describe_trails:
        if not 'KmsKeyId' in each_trail:
            if not cont.fail_reason:
                cont.fail_reason = 'CloudTrail Logs are not encrypted at rest using CMK'
            cont.offenders = each_trail['TrailARN']
    if not cont.offenders:
        cont.result = True

    return {'control_id': cont.id, 'scored': cont.scored, 'desc': cont.desc, 'result': cont.result, 'fail_reason': cont.fail_reason, 'offenders': cont.offenders}


def control_2_8_key_rotation_enabled():
    cont = Control(
        '2.8', 'Ensure rotation for customer created CMKs is enabled', True)
    kms_paginator = KMS_CLIENT.get_paginator('list_keys')
    for keys in kms_paginator.paginate():
        for each_key in keys['Keys']:
            if KMS_CLIENT.get_key_rotation_status(KeyId=each_key['KeyId'])['KeyRotationEnabled'] is False:
                if not cont.fail_reason:
                    cont.fail_reason = 'Key Rotation is not enabled for the CMKs'
                cont.offenders = each_key['KeyId']

    if not cont.offenders:
        cont.result = True

    return {'control_id': cont.id, 'scored': cont.scored, 'desc': cont.desc, 'result': cont.result, 'fail_reason': cont.fail_reason, 'offenders': cont.offenders}


def control_2_9_vpc_logging_enabled():
    cont = Control(
        '2.9', 'Ensure VPC flow logging is enabled in all VPCs', True)
    cont.fail_reason = 'API is not available to perform this action'
    cont.offenders = 'Cannot perform this action'
    cont.result = None

    return {'control_id': cont.id, 'scored': cont.scored, 'desc': cont.desc, 'result': cont.result, 'fail_reason': cont.fail_reason, 'offenders': cont.offenders}
