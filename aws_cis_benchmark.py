from constants.argumentsparser import arg_parse

import json
import csv


def main():
    parsed = arg_parse.parse_args()

    from benchmark import iam, logging, monitoring, networking

    def benchmark():
        return [iam.control_1_1_no_root_account_use(), iam.control_1_2_mfa_all_users(),
                              iam.control_1_3_creds_unused_90_days(), iam.control_1_4_access_key_rotated(),
                              iam.control_1_5_passwd_policy_uppercase(), iam.control_1_6_passwd_policy_lowercase(),
                              iam.control_1_7_passwd_policy_one_symbol(), iam.control_1_8_passwd_policy_one_number(),
                              iam.control_1_9_passwd_policy_passd_length(), iam.control_1_10_passwd_policy_passd_reuse(),
                              iam.control_1_11_passwd_policy_passd_expiry_age(), iam.control_1_12_no_root_account_key(),
                              iam.control_1_13_mfa_enabled_root(), iam.control_1_14_hardware_mfa_enabled_root(),
                              iam.control_1_15_security_question(), iam.control_1_16_policy_attached_grp_roles(),
                              iam.control_1_17_current_contact_details(),iam.control_1_18_security_contact_info(),
                              iam.control_1_19_iam_instance_roles(),iam.control_1_20_support_role_manage_incident(),
                              iam.control_1_21_intial_access_keys_setup(), iam.control_1_22_iam_full_admin_privileges(),
                              logging.control_2_1_cloudtrail_enabled_all_regions(), logging.control_2_2_cloudtrail_log_file_validation(),
                              logging.control_2_3_cloudtrail_s3_not_public_accessable(), logging.control_2_4_cloudtrail_integrated_cloudwatch(),
                              logging.control_2_5_aws_config_enabled_all_regions(), logging.control_2_6_s3_logging_enabled_cts3_bucket(),
                              logging.control_2_7_cloudtrail_logs_encrypted_kms(), logging.control_2_8_key_rotation_enabled(),
                              logging.control_2_9_vpc_logging_enabled(),
                              monitoring.control_3_1_log_metric_alarm_for_unauthorized_API(), monitoring.control_3_2_log_metric_alarm_for_signin_without_MFA(),
                              monitoring.control_3_3_log_metric_alarm_for_usage_root_account(), monitoring.control_3_4_log_metric_alarm_for_IAM_policy_changes(),
                              monitoring.control_3_5_log_metric_alarm_for_cloudtrail_config_changes(), monitoring.control_3_6_log_metric_alarm_for_aws_console_auth_failures(),
                              monitoring.control_3_7_log_metric_alarm_for_disable_deletion_CMK(), monitoring.control_3_8_log_metric_alarm_for_S3_bucket_policy_changes(),
                              monitoring.control_3_9_log_metric_alarm_for_awsconfig_config_changes(), monitoring.control_3_10_log_metric_alarm_for_security_group_changes(),
                              monitoring.control_3_11_log_metric_alarm_for_NACL_changes(), monitoring.control_3_12_log_metric_alarm_for_network_gateway_changes(),
                              monitoring.control_3_13_log_metric_alarm_for_route_table_changes(), monitoring.control_3_14_log_metric_alarm_for_VPC_changes(),
                              networking.control_4_1_no_security_ingress_port_22(), networking.control_4_2_no_security_ingress_port_3389(),
                              networking.control_4_3_security_group_vpc_restricts(), networking.control_4_4_vpc_peering_least_access()
        ]


    def each_res(each_section):
        passed, fail, not_assessed = 0, 0, 0
        for each in each_section:
            if each['result'] is True:
                passed += 1
            elif each['result'] is False:
                fail += 1
            else:
                not_assessed += 1
        return [passed, fail, not_assessed]

    if parsed.json:
        try:
            if '.' in parsed.path:
                with open('{}.json'.format(parsed.file_name), 'w') as json_out:
                    json.dump(benchmark(), json_out)
            else:
                with open('{}/{}.json'.format(parsed.path, parsed.file_name), 'x') as json_out:
                    json.dump(benchmark(), json_out)
        except FileExistsError:
            print('The given file name is already exists in ', parsed.path)
        except Exception as e:
            print(e)
    elif parsed.csv:
        try:
            field_names = ['control_id', 'scored', 'desc', 'result', 'fail_reason', 'offenders']
            if '.' in parsed.path:
                with open('{}.csv'.format(parsed.file_name), 'w') as csv_out:
                    dict_writer = csv.writer(csv_out, delimiter=';', quotechar='`', quoting=csv.QUOTE_MINIMAL)
                    dict_writer.writerow(field_names)
                    for data in benchmark():
                        dict_writer.writerow(data.values())
            else:
                with open('{}/{}.csv'.format(parsed.file_name), 'x') as csv_out:
                    dict_writer = csv.writer(csv_out, delimiter=';', quotechar='`', quoting=csv.QUOTE_MINIMAL)
                    dict_writer.writerow(field_names)
                    for data in benchmark():
                        dict_writer.writerow(data.values())
        except FileExistsError:
            print('The given file name is already exists in ', parsed.path)
        except Exception as e:
            print(e)
    elif parsed.html:
        from constants.report_html import html, html2
        output = benchmark()
        iam_res, log_res, mon_res, net_res = each_res(output[0:21]), each_res(output[22:30]), each_res(output[31:44]), each_res(output[45:])
        res_html = html + str({'iam_res': iam_res, 'log_res': log_res, 'mon_res': mon_res, 'net_res': net_res}) + "; var output="+ json.dumps(output) + ";"+ html2
        try:
            if '.' in parsed.path:
                with open('{}.html'.format(parsed.file_name), 'w') as html_out:
                    html_out.write(res_html)
            else:
                with open('{}/{}.html'.format(parsed.path, parsed.file_name), 'x') as html_out:
                    html_out.write(res_html)
        except FileExistsError:
            print('The given file name is already exists in ', parsed.path)
        except Exception as e:
            print(e)        

if __name__ == "__main__":
    main()
