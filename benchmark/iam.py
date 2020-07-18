from boto3 import resource
from constants.constant import IAM_CLIENT, now, fmt
from constants.controls import Control
from csv import DictReader
from datetime import datetime
import time


def get_cred_report():
    """[summary]
    """
    x = 0
    status = ''
    while IAM_CLIENT.generate_credential_report()['State'] != "COMPLETE":
        time.sleep(2)
        x = x + 1
        if x == 5:
            status = "Failure"
            break
    if "Fail" in status:
        return status
    cred_response = IAM_CLIENT.get_credential_report()
    reader = DictReader(cred_response['Content'].decode(
        'utf-8').splitlines(), delimiter=',')
    report = list()
    for row in reader:
        report.append(row)
    return report


def get_password_policy():
    while True:
        if IAM_CLIENT.get_account_password_policy()['ResponseMetadata']['HTTPStatusCode'] == 200:
            return IAM_CLIENT.get_account_password_policy()['PasswordPolicy']


CRED_REPORT = get_cred_report()

ACCOUNT_PASSWORD_POLICY = get_password_policy()


def control_1_1_no_root_account_use():
    cont = Control("1.1", 'Avoid the use of the "root" account', True)
    report = CRED_REPORT[0]
    if report['user'] == '<root_account>' and report['access_key_1_last_used_date'] == 'N/A' and report['access_key_2_last_used_date'] == 'N/A':
        try:
            pwd_used_time = (datetime.strptime(
                now, fmt) - datetime.strptime(report['password_last_used'], fmt))
            if pwd_used_time.days == 0:
                cont.fail_reason(
                    "Password has been used within last 24 hours")
            else:
                cont.result = True
        except Exception:
            pass
    else:
        try:
            access_key_1_time = (datetime.strptime(
                now, fmt) - datetime.strptime(report['access_key_1_last_used_date'], fmt))
            access_key_2_time = (datetime.strptime(
                now, fmt) - datetime.strptime(report['access_key_2_last_used_date'], fmt))
            if access_key_1_time.days == 0 or access_key_2_time.days == 0:
                cont.fail_reason(
                    "Access keys have been used within last 24 hours.")
        except Exception:
            pass
    return {'control_id': cont.id, 'scored': cont.scored, 'desc': cont.desc, 'result': cont.result, 'fail_reason': cont._fail_reason, 'offenders': []}


def control_1_2_mfa_all_users():
    cont = Control("1.2", 'Ensure multi-factor authentication (MFA) is enabled for all IAM users that have a console password',
                   True)
    report = CRED_REPORT
    for each_cred in report:
        username = each_cred['user']
        if each_cred['password_enabled'] == 'true':
            if each_cred['mfa_active'] == 'false':
                fail_reason = "Some users don't have MFA enabled."
                cont.offenders = each_cred['arn']
    if not cont._offenders:
        cont.result = True

    return {'control_id': cont.id, 'scored': cont.scored, 'desc': cont.desc, 'result': cont.result, 'fail_reason': cont.fail_reason, 'offenders': cont.offenders}


def control_1_3_creds_unused_90_days():
    cont = Control("1.3", 'Ensure credentials unused for 90 days or greater are disabled',
                   True)
    report = CRED_REPORT

    for each_report in report:
        try:
            if each_report['password_enabled'] == 'true':
                passd_date = (datetime.strptime(
                    now, fmt) - datetime.strptime(each_report['password_last_used'], fmt))
                if passd_date.days > 90:
                    cont.fail_reason = 'Password unused more than 90 days.'
                    cont.offenders = each_report['arn'] + "=>:password"
        except:
            pass

        try:
            if each_report['access_key_1_active'] == 'true':
                access_key_1_date = (datetime.strptime(
                    now, fmt) - datetime.strptime(each_report['access_key_1_last_used_date'], fmt))
                if access_key_1_date.days > 90:
                    cont.fail_reason = 'Access key unused more than 90 days.'
                    cont.offenders = each_report['arn'] + "=>:access_key_1"
        except:
            pass

        try:
            if each_report['access_key_2_active'] == 'true':
                access_key_1_date = (datetime.strptime(
                    now, fmt) - datetime.strptime(each_report['access_key_2_last_used_date'], fmt))
                if access_key_1_date.days > 90:
                    cont.fail_reason = 'Access key unused more than 90 days.'
                    cont.offenders = each_report['arn'] + "=>:access_key_2"
        except:
            pass
    if not cont.offenders:
        cont.result = True

    return {'control_id': cont.id, 'scored': cont.scored, 'desc': cont.desc, 'result': cont.result, 'fail_reason': cont.fail_reason, 'offenders': cont.offenders}


def control_1_4_access_key_rotated():
    cont = Control(
        '1.4', 'Ensure access keys are rotated every 90 days or less', True)
    report = CRED_REPORT
    for each_report in report:
        if each_report['access_key_1_active'] == 'true':
            access_key_1_date = (datetime.strptime(
                now, fmt) - datetime.strptime(each_report['access_key_1_last_used_date'], fmt))
            if access_key_1_date.days > 90:
                cont.fail_reason = 'Access key unused more than 90 days.'
                cont.offenders = each_report['arn'] + "=>:access_key_1"

        if each_report['access_key_2_active'] == 'true':
            access_key_1_date = (datetime.strptime(
                now, fmt) - datetime.strptime(each_report['access_key_2_last_used_date'], fmt))
            if access_key_1_date.days > 90:
                cont.fail_reason = 'Access key unused more than 90 days.'
                cont.offenders = each_report['arn'] + "=>:access_key_2"
    if not cont.offenders:
        cont.result = True

    return {'control_id': cont.id, 'scored': cont.scored, 'desc': cont.desc, 'result': cont.result, 'fail_reason': cont.fail_reason, 'offenders': cont.offenders}


def control_1_5_passwd_policy_uppercase():
    cont = Control('1.5', 'Ensure IAM password policy requires at least one uppercase letter',
                   True)
    if ACCOUNT_PASSWORD_POLICY is False:
        cont.fail_reason = "Account does not have a IAM password policy"
    else:
        if ACCOUNT_PASSWORD_POLICY['RequireUppercaseCharacters'] is True:
            cont.result = True
        else:
            cont.fail_reason = 'Require uppercase characters is not set.'

    return {'control_id': cont.id, 'scored': cont.scored, 'desc': cont.desc, 'result': cont.result, 'fail_reason': cont.fail_reason, 'offenders': cont.offenders}


def control_1_6_passwd_policy_lowercase():
    cont = Control('1.6', 'Ensure IAM password policy require at least one lowercase letter',
                   True)
    if ACCOUNT_PASSWORD_POLICY is False:
        cont.fail_reason = "Account does not have a IAM password policy"
    else:
        if ACCOUNT_PASSWORD_POLICY['RequireLowercaseCharacters'] is True:
            cont.result = True
        else:
            cont.fail_reason = 'Require lowercase characters is not set.'

    return {'control_id': cont.id, 'scored': cont.scored, 'desc': cont.desc, 'result': cont.result, 'fail_reason': cont.fail_reason, 'offenders': cont.offenders}


def control_1_7_passwd_policy_one_symbol():
    cont = Control('1.7', 'Ensure IAM password policy require at least one symbol',
                   True)
    if ACCOUNT_PASSWORD_POLICY is False:
        cont.fail_reason = "Account does not have a IAM password policy"
    else:
        if ACCOUNT_PASSWORD_POLICY['RequireSymbols'] is True:
            cont.result = True
        else:
            cont.fail_reason = 'Require atleast one symbol is not set.'

    return {'control_id': cont.id, 'scored': cont.scored, 'desc': cont.desc, 'result': cont.result, 'fail_reason': cont.fail_reason, 'offenders': cont.offenders}


def control_1_8_passwd_policy_one_number():
    cont = Control('1.8', 'Ensure IAM password policy require at least one number',
                   True)
    if ACCOUNT_PASSWORD_POLICY is False:
        cont.fail_reason = "Account does not have a IAM password policy"
    else:
        if ACCOUNT_PASSWORD_POLICY['RequireNumbers'] is True:
            cont.result = True
        else:
            cont.fail_reason = 'Require atleast one number is not set.'

    return {'control_id': cont.id, 'scored': cont.scored, 'desc': cont.desc, 'result': cont.result, 'fail_reason': cont.fail_reason, 'offenders': cont.offenders}


def control_1_9_passwd_policy_passd_length():
    cont = Control('1.9', 'Ensure IAM password policy requires minimum length of 14 or greater',
                   True)
    if ACCOUNT_PASSWORD_POLICY is False:
        cont.fail_reason = "Account does not have a IAM password policy"
    else:
        if ACCOUNT_PASSWORD_POLICY['MinimumPasswordLength'] >= 14:
            cont.result = True
        else:
            cont.fail_reason = 'Requires minimum password length is 14.'
            cont.offenders = 'The current password length policy is {0}'.format(
                ACCOUNT_PASSWORD_POLICY['MinimumPasswordLength'])

    return {'control_id': cont.id, 'scored': cont.scored, 'desc': cont.desc, 'result': cont.result, 'fail_reason': cont.fail_reason, 'offenders': cont.offenders}


def control_1_10_passwd_policy_passd_reuse():
    cont = Control('1.10', 'Ensure IAM password policy prevents password reuse',
                   True)
    if ACCOUNT_PASSWORD_POLICY is False:
        cont.fail_reason = "Account does not have a IAM password policy"
    else:
        if ACCOUNT_PASSWORD_POLICY['PasswordReusePrevention'] == 24:
            cont.result = True
        else:
            cont.fail_reason = 'Requires minimum password reuse is 24.'
            cont.offenders = 'The current password resuse policy is {0}'.format(
                ACCOUNT_PASSWORD_POLICY['PasswordReusePrevention'])

    return {'control_id': cont.id, 'scored': cont.scored, 'desc': cont.desc, 'result': cont.result, 'fail_reason': cont.fail_reason, 'offenders': cont.offenders}


def control_1_11_passwd_policy_passd_expiry_age():
    cont = Control('1.11', 'Ensure IAM password policy expires passwords within 90 days or less',
                   True)
    if ACCOUNT_PASSWORD_POLICY is False:
        cont.fail_reason = "Account does not have a IAM password policy"
    else:
        if ACCOUNT_PASSWORD_POLICY['MaxPasswordAge'] <= 90:
            cont.result = True
        else:
            cont.fail_reason = 'Requires minimum password expires less or equal to 90.'
            cont.offenders = 'The current password expiry policy is {0}'.format(
                ACCOUNT_PASSWORD_POLICY['PasswordReusePrevention'])

    return {'control_id': cont.id, 'scored': cont.scored, 'desc': cont.desc, 'result': cont.result, 'fail_reason': cont.fail_reason, 'offenders': cont.offenders}


def control_1_12_no_root_account_key():
    cont = Control('1.12', 'Ensure no root account access key exists', True)
    root_access_key = CRED_REPORT[0]
    try:
        if root_access_key['user'] == '<root_account>':
            if root_access_key['access_key_1_active'] == 'false' and root_access_key['access_key_2_active'] == 'false':
                cont.result = True
            else:
                cont.fail_reason = 'The root account access key exists'
    except:
        pass

    return {'control_id': cont.id, 'scored': cont.scored, 'desc': cont.desc, 'result': cont.result, 'fail_reason': cont.fail_reason, 'offenders': cont.offenders}


def control_1_13_mfa_enabled_root():
    cont = Control(
        '1.13', 'Ensure MFA is enabled for the "root" account', True)
    root_account_MFA = IAM_CLIENT.get_account_summary()[
        'SummaryMap']['AccountMFAEnabled']
    if root_account_MFA == 1:
        cont.result = True
    else:
        cont.fail_reason = 'The root account does not have MFA enabled'

    return {'control_id': cont.id, 'scored': cont.scored, 'desc': cont.desc, 'result': cont.result, 'fail_reason': cont.fail_reason, 'offenders': cont.offenders}


def control_1_14_hardware_mfa_enabled_root():
    cont = Control(
        '1.14', 'Ensure hardware MFA is enabled for the "root" account', True)
    root_account_MFA = IAM_CLIENT.get_account_summary()[
        'SummaryMap']['AccountMFAEnabled']
    if root_account_MFA == 1:
        hardware_MFA_paginator = IAM_CLIENT.get_paginator(
            'list_virtual_mfa_devices')
        for resp in hardware_MFA_paginator.paginate(AssignmentStatus='Any'):
            for hardware_MFA in resp['VirtualMFADevices']:
                if "mfa/root-account-mfa-device" in hardware_MFA['SerialNumber']:
                    cont.result = True
                    break
        if cont.result is False:
            cont.fail_reason = 'The root account does not have Hardware MFA'
    else:
        cont.fail_reason = 'The root account does not have MFA enabled'

    return {'control_id': cont.id, 'scored': cont.scored, 'desc': cont.desc, 'result': cont.result, 'fail_reason': cont.fail_reason, 'offenders': cont.offenders}


def control_1_15_security_question():
    cont = Control(
        '1.15', 'Ensure security questions are registered in the AWS account', False)
    cont.fail_reason = 'No API available to perform this action'
    cont.offenders = 'Check it manually using the AWS console'

    return {'control_id': cont.id, 'scored': cont.scored, 'desc': cont.desc, 'result': cont.result, 'fail_reason': cont.fail_reason, 'offenders': cont.offenders}


def control_1_16_policy_attached_grp_roles():
    cont = Control(
        '1.16', 'Ensure IAM policies are attached only to groups or roles', True)
    all_users_paginator = IAM_CLIENT.get_paginator('list_users')
    for users in all_users_paginator.paginate():
        for user in users['Users']:
            if user is None:
                continue
            if IAM_CLIENT.list_attached_user_policies(UserName=user['UserName'])['AttachedPolicies']:
                cont.fail_reason = "Managed Policies attached directly to user."
                cont.offenders = user['Arn'] + ":=> Managed policy"
            if IAM_CLIENT.list_user_policies(UserName=user['UserName'])['PolicyNames']:
                cont.fail_reason = "Inline Policies are attached directly to user."
                cont.offenders = user['Arn'] + ":=> Inline policy"
    if not cont.offenders:
        cont.result = True

    return {'control_id': cont.id, 'scored': cont.scored, 'desc': cont.desc, 'result': cont.result, 'fail_reason': cont.fail_reason, 'offenders': cont.offenders}


def control_1_17_current_contact_details():
    cont = Control('1.17', 'Maintain current contact details', False)
    cont.offenders = 'Check manually in AWS console'
    cont.fail_reason = 'No API available to perform this action'

    return {'control_id': cont.id, 'scored': cont.scored, 'desc': cont.desc, 'result': cont.result, 'fail_reason': cont.fail_reason, 'offenders': cont.offenders}


def control_1_18_security_contact_info():
    cont = Control(
        '1.18', 'Ensure security contact information is registered', False)
    cont.fail_reason = 'Check manually in AWS console'
    cont.fail_reason = 'No API available to perform this action'

    return {'control_id': cont.id, 'scored': cont.scored, 'desc': cont.desc, 'result': cont.result, 'fail_reason': cont.fail_reason, 'offenders': cont.offenders}


def control_1_19_iam_instance_roles():
    cont = Control(
        '1.19', 'Ensure IAM instance roles are used for AWS resource access from instances', False)
    cont.fail_reason = 'Check manually in AWS console'
    cont.fail_reason = 'No API available to perform this action'

    return {'control_id': cont.id, 'scored': cont.scored, 'desc': cont.desc, 'result': cont.result, 'fail_reason': cont.fail_reason, 'offenders': cont.offenders}


def control_1_20_support_role_manage_incident():
    cont = Control(
        '1.20', 'Ensure a support role has been created to manage incidents with AWS Support', True)
    entities = IAM_CLIENT.list_entities_for_policy(
        PolicyArn='arn:aws:iam::aws:policy/AWSSupportAccess'
    )
    if entities['PolicyGroups'] or entities['PolicyUsers'] or entities['PolicyRoles']:
        cont.result = True
    else:
        cont.fail_reason = 'AWSSupportAccess is not attached to any IAM user,group or role'
        cont.offenders = 'AWSSupportAccess should be attached to IAM user,group or role in order to manage incidents'

    return {'control_id': cont.id, 'scored': cont.scored, 'desc': cont.desc, 'result': cont.result, 'fail_reason': cont.fail_reason, 'offenders': cont.offenders}


def control_1_21_intial_access_keys_setup():
    cont = Control(
        '1.21', 'Do not setup access keys during initial user setup for all IAM users that have a console password', False)
    users_paginate = IAM_CLIENT.get_paginator('list_users')
    for users in users_paginate.paginate():
        for user in users['Users']:
            for access_time in IAM_CLIENT.list_access_keys(UserName=user['UserName'])['AccessKeyMetadata']:
                if access_time['CreateDate'] == access_time['CreateDate']:
                    cont.fail_reason = 'Keys that were created at the same time as the user profile'
                    cont.offenders = user['UserName']
    if not cont.offenders:
        cont.result = True

    return {'control_id': cont.id, 'scored': cont.scored, 'desc': cont.desc, 'result': cont.result, 'fail_reason': cont.fail_reason, 'offenders': cont.offenders}


def control_1_22_iam_full_admin_privileges():
    cont = Control(
        '1.22', 'Ensure IAM policies that allow full "*:*" administrative privileges are not created', True)
    policies_paginator = IAM_CLIENT.get_paginator('list_policies')
    for policies in policies_paginator.paginate(Scope='Local', OnlyAttached=False):
        for each_policy in policies['Policies']:
            statements = IAM_CLIENT.get_policy_version(
                PolicyArn=each_policy['Arn'], VersionId=each_policy['DefaultVersionId'])['PolicyVersion']['Document']['Statement']
            if isinstance(statements, list):
                for each_statement in statements:
                    if 'Action' in each_statement.keys() and each_statement['Effect'] == 'Allow':
                        if isinstance(each_statement['Action'], str) or isinstance(each_statement['Resource'], str):
                            if each_statement['Action'] == '*' and each_statement['Resource'] == '*':
                                cont.fail_reason = 'IAM policies has full "*:*" administrative privilege'
                                cont.offenders = each_policy['Arn']

    if not cont.offenders:
        cont.result = True

    return {'control_id': cont.id, 'scored': cont.scored, 'desc': cont.desc, 'result': cont.result, 'fail_reason': cont.fail_reason, 'offenders': cont.offenders}


def main():
    control_1_1_no_root_account_use()
