from constants.constant import EC2_CLIENT
from constants.controls import Control


def control_4_1_no_security_ingress_port_22():
    cont = Control(
        '4.1', 'Ensure no security groups allow ingress from 0.0.0.0/0 to port 22', True)
    security_groups_iterator = EC2_CLIENT.get_paginator(
        'describe_security_groups')
    for groups in security_groups_iterator.paginate():
        for group in groups['SecurityGroups']:
            if '0.0.0.0/0' in str(group['IpPermissions']):
                for each_ip_perm in group['IpPermissions']:
                    try:
                        if int(each_ip_perm['FromPort']) <= 22 <= int(each_ip_perm['ToPort']) and '0.0.0.0/0' in str(each_ip_perm['IpRanges']):
                            cont.fail_reason = 'Found Security Group with port 22 open to the internet (0.0.0.0/0)'
                            cont.offenders = group['GroupId']
                    except:
                        if str(each_ip_perm['IpProtocol']) == '-1' and '0.0.0.0/0' in str(each_ip_perm['IpRanges']):
                            cont.fail_reason = 'Found Security Group with port 22 open to the internet (0.0.0.0/0)'
                            cont.offenders = group['GroupId']
    if not cont.offenders:
        cont.result = True

    return {'control_id': cont.id, 'scored': cont.scored, 'desc': cont.desc, 'result': cont.result, 'fail_reason': cont.fail_reason, 'offenders': cont.offenders}


def control_4_2_no_security_ingress_port_3389():
    cont = Control(
        '4.2', 'Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389', True)
    security_groups_iterator = EC2_CLIENT.get_paginator(
        'describe_security_groups')
    for groups in security_groups_iterator.paginate():
        for group in groups['SecurityGroups']:
            if '0.0.0.0/0' in str(group['IpPermissions']):
                for each_ip_perm in group['IpPermissions']:
                    try:
                        if int(each_ip_perm['FromPort']) <= 3389 <= int(each_ip_perm['ToPort']) and '0.0.0.0/0' in str(each_ip_perm['IpRanges']):
                            cont.fail_reason = 'Found Security Group with port 3389 open to the internet (0.0.0.0/0)'
                            cont.offenders = group['GroupId']
                    except:
                        if str(each_ip_perm['IpProtocol']) == '-1' and '0.0.0.0/0' in str(each_ip_perm['IpRanges']):
                            cont.fail_reason = 'Found Security Group with port 3389 open to the internet (0.0.0.0/0)'
                            cont.offenders = group['GroupId']
    if not cont.offenders:
        cont.result = True

    return {'control_id': cont.id, 'scored': cont.scored, 'desc': cont.desc, 'result': cont.result, 'fail_reason': cont.fail_reason, 'offenders': cont.offenders}


def control_4_3_security_group_vpc_restricts():
    cont = Control(
        '4.3', 'Ensure the default security group of every VPC restricts all traffic', True)
    security_groups_iterator = EC2_CLIENT.get_paginator(
        'describe_security_groups')
    for groups in security_groups_iterator.paginate(Filters=[{'Name': 'group-name', 'Values': ['default', ]}, ]):
        for group in groups['SecurityGroups']:
            if not (len(group['IpPermissions']) + len(group['IpPermissionsEgress'])) == 0:
                cont.fail_reason = 'Default security groups with ingress or egress rules discovered'
                cont.offenders = group['GroupId']
    if not cont.offenders:
        cont.result = True

    return {'control_id': cont.id, 'scored': cont.scored, 'desc': cont.desc, 'result': cont.result, 'fail_reason': cont.fail_reason, 'offenders': cont.offenders}


def control_4_4_vpc_peering_least_access():
    cont = Control(
        '4.4', 'Ensure routing tables for VPC peering are "least access', False)
    vpc_paginator = EC2_CLIENT.get_paginator('describe_route_tables')
    for route_tables in vpc_paginator.paginate():
        for routes in route_tables['RouteTables']:
            for route in routes['Routes']:
                if 'VpcPeeringConnectionId' in route:
                    if int(str(route['DestinationCidrBlock']).split('/', 1)[1]) < 24:
                        if not cont.fail_reason:
                            cont.fail_reason = 'Large CIDR block routed to peer discovered'
                            cont.offenders = routes['RouteTableId']

    if not cont.offenders:
        cont.result = True

    return {'control_id': cont.id, 'scored': cont.scored, 'desc': cont.desc, 'result': cont.result, 'fail_reason': cont.fail_reason, 'offenders': cont.offenders}
