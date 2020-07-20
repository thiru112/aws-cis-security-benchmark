from constants.constant import CLOUDTRAIL_CLIENT, CLOUDWATCH_CLIENT, LOGS_CLIENT, SNS_CLIENT
from constants.controls import Control

from re import search

cloudtrials = CLOUDTRAIL_CLIENT.describe_trails()['trailList']


def find_patterns_in_string(patterns, string):
    """To find pattern in given string

    Args:
        pattern (list): A set of pattern
        string (string): String that pattern needed to be finded

    Returns:
        bool (bool): Returns True if condition pass, else False
    """
    result = True
    for pattern in patterns:
        if not search(pattern, string):
            result = False
            break

    return result


def monitoring_common_function(patterns, cloudtrial_trails):
    """A function for common monitoring benchmark

    Args:
        patterns (list): Pattern in benchmark
        cloudtrial_trails (list): Entire trail list

    Returns:
        result (int) : Returns integer based on conditions
    """
    result = 0
    for trail in cloudtrial_trails:
        if 'CloudWatchLogsLogGroupArn' in trail:
            log_group = search('log-group:(.+?):',
                               trail['CloudWatchLogsLogGroupArn']).group(1)
            if LOGS_CLIENT.describe_metric_filters(logGroupName=log_group)['metricFilters']:
                for each_metric in LOGS_CLIENT.describe_metric_filters(logGroupName=log_group)['metricFilters']:
                    if find_patterns_in_string(patterns, str(each_metric['filterPattern'])):
                        try:
                            response = CLOUDWATCH_CLIENT.describe_alarms_for_metric(
                                MetricName=each_metric['metricTransformations'][0]['metricName'],
                                Namespace=each_metric['metricTransformations'][0]['metricNamespace']
                            )
                            subscribers = SNS_CLIENT.list_subscriptions_by_topic(
                                TopicArn=response['MetricAlarms'][0]['AlarmActions'][0]
                            )['Subscriptions']
                            if not len(subscribers) == 0:
                                result = 4
                                break
                        except:
                            result = 3
                    else:
                        result = 2
            else:
                result = 1

    return result


def control_3_1_log_metric_alarm_for_unauthorized_API():
    cont = Control(
        '3.1', 'Ensure a log metric filter and alarm exist for unauthorized API calls', True)
    res = monitoring_common_function(
        ["\$\.errorCode\s*=\s*\"?\*UnauthorizedOperation(\"|\)|\s)", "\$\.errorCode\s*=\s*\"?AccessDenied\*(\"|\)|\s)"], cloudtrials)
    if res == 0:
        cont.fail_reason = 'No trail found'
    elif res == 1:
        cont.fail_reason = 'No metric filter found from Log group'
    elif res == 2:
        cont.fail_reason = 'Pattern not found in the metric filter'
    elif res == 3:
        cont.fail_reason = 'No alarm is found for the metric filter'
    else:
        cont.result = True

    return {'control_id': cont.id, 'scored': cont.scored, 'desc': cont.desc, 'result': cont.result, 'fail_reason': cont.fail_reason, 'offenders': cont.offenders}


def control_3_2_log_metric_alarm_for_signin_without_MFA():
    cont = Control(
        '3.2', 'Ensure a log metric filter and alarm exist for Management Console sign-in without MFA', True)
    res = monitoring_common_function(
        ["\$\.eventName\s*=\s*\"?ConsoleLogin(\"|\)|\s)", "\$\.additionalEventData\.MFAUsed\s*\!=\s*\"?Yes"], cloudtrials)
    if res == 0:
        cont.fail_reason = 'No trail found'
    elif res == 1:
        cont.fail_reason = 'No metric filter found from Log group'
    elif res == 2:
        cont.fail_reason = 'Pattern not found in the metric filter'
        cont.offenders = 'No alarm exist for Sign-in without MFA'
    elif res == 3:
        cont.fail_reason = 'No alarm is found for the metric filter'
    else:
        cont.result = True

    return {'control_id': cont.id, 'scored': cont.scored, 'desc': cont.desc, 'result': cont.result, 'fail_reason': cont.fail_reason, 'offenders': cont.offenders}


def control_3_3_log_metric_alarm_for_usage_root_account():
    cont = Control(
        '3.3', 'Ensure a log metric filter and alarm exist for usage of "root" account', True)
    res = monitoring_common_function(
        ["\$\.userIdentity\.type\s*=\s*\"?Root", "\$\.userIdentity\.invokedBy\s*NOT\s*EXISTS", "\$\.eventType\s*\!=\s*\"?AwsServiceEvent(\"|\)|\s)"], cloudtrials)
    if res == 0:
        cont.fail_reason = 'No trail found'
    elif res == 1:
        cont.fail_reason = 'No metric filter found from Log group'
    elif res == 2:
        cont.fail_reason = 'Pattern not found in the metric filter'
        cont.offenders = 'No alarm exist for usage of root account'
    elif res == 3:
        cont.fail_reason = 'No alarm is found for the metric filter'
    else:
        cont.result = True

    return {'control_id': cont.id, 'scored': cont.scored, 'desc': cont.desc, 'result': cont.result, 'fail_reason': cont.fail_reason, 'offenders': cont.offenders}


def control_3_4_log_metric_alarm_for_IAM_policy_changes():
    cont = Control(
        '3.4', 'Ensure a log metric filter and alarm exist for IAM policy changes', True)
    res = monitoring_common_function(
        ["\$\.eventName\s*=\s*\"?DeleteGroupPolicy(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DeleteRolePolicy(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DeleteUserPolicy(\"|\)|\s)", "\$\.eventName\s*=\s*\"?PutGroupPolicy(\"|\)|\s)", "\$\.eventName\s*=\s*\"?PutRolePolicy(\"|\)|\s)", "\$\.eventName\s*=\s*\"?PutUserPolicy(\"|\)|\s)", "\$\.eventName\s*=\s*\"?CreatePolicy(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DeletePolicy(\"|\)|\s)", "\$\.eventName\s*=\s*\"?CreatePolicyVersion(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DeletePolicyVersion(\"|\)|\s)", "\$\.eventName\s*=\s*\"?AttachRolePolicy(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DetachRolePolicy(\"|\)|\s)", "\$\.eventName\s*=\s*\"?AttachUserPolicy(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DetachUserPolicy(\"|\)|\s)", "\$\.eventName\s*=\s*\"?AttachGroupPolicy(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DetachGroupPolicy(\"|\)|\s)"], cloudtrials)
    if res == 0:
        cont.fail_reason = 'No trail found'
    elif res == 1:
        cont.fail_reason = 'No metric filter found from Log group'
    elif res == 2:
        cont.fail_reason = 'Pattern not found in the metric filter'
        cont.offenders = 'No alarm exist for usage of root account'
    elif res == 3:
        cont.fail_reason = 'No alarm is found for the metric filter'
    else:
        cont.result = True

    return {'control_id': cont.id, 'scored': cont.scored, 'desc': cont.desc, 'result': cont.result, 'fail_reason': cont.fail_reason, 'offenders': cont.offenders}


def control_3_5_log_metric_alarm_for_cloudtrail_config_changes():
    cont = Control(
        '3.5', 'Ensure a log metric filter and alarm exist for CloudTrail configuration changes', True)
    res = monitoring_common_function(
        ["\$\.eventName\s*=\s*\"?CreateTrail(\"|\)|\s)", "\$\.eventName\s*=\s*\"?UpdateTrail(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DeleteTrail(\"|\)|\s)", "\$\.eventName\s*=\s*\"?StartLogging(\"|\)|\s)", "\$\.eventName\s*=\s*\"?StopLogging(\"|\)|\s)"], cloudtrials)
    if res == 0:
        cont.fail_reason = 'No trail found'
    elif res == 1:
        cont.fail_reason = 'No metric filter found from Log group'
    elif res == 2:
        cont.fail_reason = 'Pattern not found in the metric filter'
        cont.offenders = 'No alarm exist for Cloudtrail configuration changes'
    elif res == 3:
        cont.fail_reason = 'No alarm is found for the metric filter'
    else:
        cont.result = True

    return {'control_id': cont.id, 'scored': cont.scored, 'desc': cont.desc, 'result': cont.result, 'fail_reason': cont.fail_reason, 'offenders': cont.offenders}


def control_3_6_log_metric_alarm_for_aws_console_auth_failures():
    cont = Control(
        '3.6', 'Ensure a log metric filter and alarm exist for AWS Management Console authentication failures', True)
    res = monitoring_common_function(
        ["\$\.eventName\s*=\s*\"?ConsoleLogin(\"|\)|\s)", "\$\.errorMessage\s*=\s*\"?Failed authentication(\"|\)|\s)"], cloudtrials)
    if res == 0:
        cont.fail_reason = 'No trail found'
    elif res == 1:
        cont.fail_reason = 'No metric filter found from Log group'
    elif res == 2:
        cont.fail_reason = 'Pattern not found in the metric filter'
        cont.offenders = 'No alarm exist for AWS Console authentication failures'
    elif res == 3:
        cont.fail_reason = 'No alarm is found for the metric filter'
    else:
        cont.result = True

    return {'control_id': cont.id, 'scored': cont.scored, 'desc': cont.desc, 'result': cont.result, 'fail_reason': cont.fail_reason, 'offenders': cont.offenders}


def control_3_7_log_metric_alarm_for_disable_deletion_CMK():
    cont = Control(
        '3.7', 'Ensure a log metric filter and alarm exist for disabling or scheduled deletion of customer created CMKs', True)
    res = monitoring_common_function(
        ["\$\.eventSource\s*=\s*\"?kms\.amazonaws\.com(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DisableKey(\"|\)|\s)", "\$\.eventName\s*=\s*\"?ScheduleKeyDeletion(\"|\)|\s)"], cloudtrials)
    if res == 0:
        cont.fail_reason = 'No trail found'
    elif res == 1:
        cont.fail_reason = 'No metric filter found from Log group'
    elif res == 2:
        cont.fail_reason = 'Pattern not found in the metric filter'
        cont.offenders = 'No alarm exist for disabling or scheduled deletion of Customer Managed keys'
    elif res == 3:
        cont.fail_reason = 'No alarm is found for the metric filter'
    else:
        cont.result = True

    return {'control_id': cont.id, 'scored': cont.scored, 'desc': cont.desc, 'result': cont.result, 'fail_reason': cont.fail_reason, 'offenders': cont.offenders}


def control_3_8_log_metric_alarm_for_S3_bucket_policy_changes():
    cont = Control(
        '3.8', 'Ensure a log metric filter and alarm exist for S3 bucket policy changes', True)
    res = monitoring_common_function(
        ["\$\.eventSource\s*=\s*\"?s3\.amazonaws\.com(\"|\)|\s)", "\$\.eventName\s*=\s*\"?PutBucketAcl(\"|\)|\s)", "\$\.eventName\s*=\s*\"?PutBucketPolicy(\"|\)|\s)", "\$\.eventName\s*=\s*\"?PutBucketCors(\"|\)|\s)", "\$\.eventName\s*=\s*\"?PutBucketLifecycle(\"|\)|\s)", "\$\.eventName\s*=\s*\"?PutBucketReplication(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DeleteBucketPolicy(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DeleteBucketCors(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DeleteBucketLifecycle(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DeleteBucketReplication(\"|\)|\s)"], cloudtrials)
    if res == 0:
        cont.fail_reason = 'No trail found'
    elif res == 1:
        cont.fail_reason = 'No metric filter found from Log group'
    elif res == 2:
        cont.fail_reason = 'Pattern not found in the metric filter'
        cont.offenders = 'No alarm exist for S3 Bucket policy changes'
    elif res == 3:
        cont.fail_reason = 'No alarm is found for the metric filter'
    else:
        cont.result = True

    return {'control_id': cont.id, 'scored': cont.scored, 'desc': cont.desc, 'result': cont.result, 'fail_reason': cont.fail_reason, 'offenders': cont.offenders}


def control_3_9_log_metric_alarm_for_awsconfig_config_changes():
    cont = Control(
        '3.9', 'Ensure a log metric filter and alarm exist for AWS Config configuration changes', True)
    res = monitoring_common_function(
        ["\$\.eventSource\s*=\s*\"?config\.amazonaws\.com(\"|\)|\s)", "\$\.eventName\s*=\s*\"?StopConfigurationRecorder(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DeleteDeliveryChannel(\"|\)|\s)", "\$\.eventName\s*=\s*\"?PutDeliveryChannel(\"|\)|\s)", "\$\.eventName\s*=\s*\"?PutConfigurationRecorder(\"|\)|\s)"], cloudtrials)
    if res == 0:
        cont.fail_reason = 'No trail found'
    elif res == 1:
        cont.fail_reason = 'No metric filter found from Log group'
    elif res == 2:
        cont.fail_reason = 'Pattern not found in the metric filter'
        cont.offenders = 'No alarm exist for AWSConfig configuration changes'
    elif res == 3:
        cont.fail_reason = 'No alarm is found for the metric filter'
    else:
        cont.result = True

    return {'control_id': cont.id, 'scored': cont.scored, 'desc': cont.desc, 'result': cont.result, 'fail_reason': cont.fail_reason, 'offenders': cont.offenders}


def control_3_10_log_metric_alarm_for_security_group_changes():
    cont = Control(
        '3.10', 'Ensure a log metric filter and alarm exist for security group changes', True)
    res = monitoring_common_function(
        ["\$\.eventName\s*=\s*\"?AuthorizeSecurityGroupIngress(\"|\)|\s)", "\$\.eventName\s*=\s*\"?AuthorizeSecurityGroupEgress(\"|\)|\s)", "\$\.eventName\s*=\s*\"?RevokeSecurityGroupIngress(\"|\)|\s)", "\$\.eventName\s*=\s*\"?RevokeSecurityGroupEgress(\"|\)|\s)", "\$\.eventName\s*=\s*\"?CreateSecurityGroup(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DeleteSecurityGroup(\"|\)|\s)"], cloudtrials)
    if res == 0:
        cont.fail_reason = 'No trail found'
    elif res == 1:
        cont.fail_reason = 'No metric filter found from Log group'
    elif res == 2:
        cont.fail_reason = 'Pattern not found in the metric filter'
        cont.offenders = 'No alarm exist for Security group changes'
    elif res == 3:
        cont.fail_reason = 'No alarm is found for the metric filter'
    else:
        cont.result = True

    return {'control_id': cont.id, 'scored': cont.scored, 'desc': cont.desc, 'result': cont.result, 'fail_reason': cont.fail_reason, 'offenders': cont.offenders}


def control_3_11_log_metric_alarm_for_NACL_changes():
    cont = Control(
        '3.11', 'Ensure a log metric filter and alarm exist for changes to Network Access Control Lists (NACL)', True)
    res = monitoring_common_function(
        ["\$\.eventName\s*=\s*\"?CreateNetworkAcl(\"|\)|\s)", "\$\.eventName\s*=\s*\"?CreateNetworkAclEntry(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DeleteNetworkAcl(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DeleteNetworkAclEntry(\"|\)|\s)", "\$\.eventName\s*=\s*\"?ReplaceNetworkAclEntry(\"|\)|\s)", "\$\.eventName\s*=\s*\"?ReplaceNetworkAclAssociation(\"|\)|\s)"], cloudtrials)
    if res == 0:
        cont.fail_reason = 'No trail found'
    elif res == 1:
        cont.fail_reason = 'No metric filter found from Log group'
    elif res == 2:
        cont.fail_reason = 'Pattern not found in the metric filter'
        cont.offenders = 'No alarm exist for Network Access Control Lists (NACL) changes'
    elif res == 3:
        cont.fail_reason = 'No alarm is found for the metric filter'
    else:
        cont.result = True

    return {'control_id': cont.id, 'scored': cont.scored, 'desc': cont.desc, 'result': cont.result, 'fail_reason': cont.fail_reason, 'offenders': cont.offenders}


def control_3_12_log_metric_alarm_for_network_gateway_changes():
    cont = Control(
        '3.12', 'Ensure a log metric filter and alarm exist for changes to network gateways', True)
    res = monitoring_common_function(
        ["\$\.eventName\s*=\s*\"?CreateCustomerGateway(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DeleteCustomerGateway(\"|\)|\s)", "\$\.eventName\s*=\s*\"?AttachInternetGateway(\"|\)|\s)", "\$\.eventName\s*=\s*\"?CreateInternetGateway(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DeleteInternetGateway(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DetachInternetGateway(\"|\)|\s)"], cloudtrials)
    if res == 0:
        cont.fail_reason = 'No trail found'
    elif res == 1:
        cont.fail_reason = 'No metric filter found from Log group'
    elif res == 2:
        cont.fail_reason = 'Pattern not found in the metric filter'
        cont.offenders = 'No alarm exist for Network Gateway changes'
    elif res == 3:
        cont.fail_reason = 'No alarm is found for the metric filter'
    else:
        cont.result = True

    return {'control_id': cont.id, 'scored': cont.scored, 'desc': cont.desc, 'result': cont.result, 'fail_reason': cont.fail_reason, 'offenders': cont.offenders}


def control_3_13_log_metric_alarm_for_route_table_changes():
    cont = Control(
        '3.13', 'Ensure a log metric filter and alarm exist for route table changes', True)
    res = monitoring_common_function(
        ["\$\.eventName\s*=\s*\"?CreateRoute(\"|\)|\s)", "\$\.eventName\s*=\s*\"?CreateRouteTable(\"|\)|\s)", "\$\.eventName\s*=\s*\"?ReplaceRoute(\"|\)|\s)", "\$\.eventName\s*=\s*\"?ReplaceRouteTableAssociation(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DeleteRouteTable(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DeleteRoute(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DisassociateRouteTable(\"|\)|\s)"], cloudtrials)
    if res == 0:
        cont.fail_reason = 'No trail found'
    elif res == 1:
        cont.fail_reason = 'No metric filter found from Log group'
    elif res == 2:
        cont.fail_reason = 'Pattern not found in the metric filter'
        cont.offenders = 'No alarm exist for Route table changes'
    elif res == 3:
        cont.fail_reason = 'No alarm is found for the metric filter'
    else:
        cont.result = True

    return {'control_id': cont.id, 'scored': cont.scored, 'desc': cont.desc, 'result': cont.result, 'fail_reason': cont.fail_reason, 'offenders': cont.offenders}


def control_3_14_log_metric_alarm_for_VPC_changes():
    cont = Control(
        '3.14', 'Ensure a log metric filter and alarm exist for VPC changes', True)
    res = monitoring_common_function(
        ["\$\.eventName\s*=\s*\"?CreateVpc(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DeleteVpc(\"|\)|\s)", "\$\.eventName\s*=\s*\"?ModifyVpcAttribute(\"|\)|\s)", "\$\.eventName\s*=\s*\"?AcceptVpcPeeringConnection(\"|\)|\s)", "\$\.eventName\s*=\s*\"?CreateVpcPeeringConnection(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DeleteVpcPeeringConnection(\"|\)|\s)", "\$\.eventName\s*=\s*\"?RejectVpcPeeringConnection(\"|\)|\s)", "\$\.eventName\s*=\s*\"?AttachClassicLinkVpc(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DetachClassicLinkVpc(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DisableVpcClassicLink(\"|\)|\s)", "\$\.eventName\s*=\s*\"?EnableVpcClassicLink(\"|\)|\s)"], cloudtrials)
    if res == 0:
        cont.fail_reason = 'No trail found'
    elif res == 1:
        cont.fail_reason = 'No metric filter found from Log group'
    elif res == 2:
        cont.fail_reason = 'Pattern not found in the metric filter'
        cont.offenders = 'No alarm exist for VPC changes'
    elif res == 3:
        cont.fail_reason = 'No alarm is found for the metric filter'
    else:
        cont.result = True

    return {'control_id': cont.id, 'scored': cont.scored, 'desc': cont.desc, 'result': cont.result, 'fail_reason': cont.fail_reason, 'offenders': cont.offenders}
