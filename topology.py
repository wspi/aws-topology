#!/usr/bin/env python
import boto3
import botocore
from py2neo import Graph, Node, Relationship, NodeSelector


def check_key(dictionary, key):
    if key in dictionary.keys():
        return dictionary[key]
    else:
        return "Unknown"


def find_name_tag(tags):
    for tag in tags:
        if tag['Key'] == 'Name':
            return tag['Value']
    return ""


def find_tags(structure):
    if structure.__contains__('Tags'):
        name = find_name_tag(structure['Tags'])
    else:
        name = ""
    return name


def find_node(**kwargs):
    return graph.find_one(**kwargs)


def create_node(args, **kwargs):
    tx = graph.begin()
    graph_node = Node(args, **kwargs)
    tx.merge(graph_node)
    tx.commit()
    return graph_node


def create_relationship(*args, **kvargs):
    tx = graph.begin()
    if len(kvargs) > 0:
        relationship = Relationship(*args, **kvargs)
    else:
        relationship = Relationship(*args)
    tx.merge(relationship)
    tx.commit()
    return relationship


def create_subnets(graph_region, vpc_id):
    subnets_array = []
    subnets = ec2.describe_subnets(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])
    if subnets['Subnets']:
        for subnet in subnets['Subnets']:
            graph_az = create_node("AvailabilityZone", name=subnet['AvailabilityZone'],
                                   AvailabilityZoneId=subnet['AvailabilityZoneId'])
            name = find_tags(subnet)
            graph_subnet = create_node("Subnet", SubnetId=subnet['SubnetId'], name=name, az=subnet['AvailabilityZone'],
                                       cidr=subnet['CidrBlock'], VpcId=subnet['VpcId'])
            if graph_subnet is not None:
                create_relationship(graph_subnet, "BELONGS", graph_az)
            if graph_az is not None:
                create_relationship(graph_az, "BELONGS", graph_region)
            subnets_array.append(graph_subnet)
    return subnets_array


def create_igws(vpc_id):
    igws_array = []
    igws = ec2.describe_internet_gateways(Filters=[{'Name': 'attachment.vpc-id', 'Values': [vpc_id]}])
    if igws['InternetGateways']:
        for igw in igws['InternetGateways']:
            name = find_tags(igw)
            graph_igw = create_node("IGW", igwId=igw['InternetGatewayId'], VpcId=igw['Attachments'][0]['VpcId'],
                                    name=name)
            igws_array.append(graph_igw)
    return igws_array


def create_nat_gws(vpc_id):
    ngws_array = []
    ngws = ec2.describe_nat_gateways(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])
    if ngws['NatGateways']:
        for ngw in ngws['NatGateways']:
            name_tag = find_tags(ngw)
            if name_tag == '':
                name_tag = ngw['NatGatewayId']
            graph_ngw = create_node("NATGW", ngwId=ngw['NatGatewayId'], SubnetId=ngw['SubnetId'], name=name_tag)
            ngws_array.append(graph_ngw)
            find_eip = find_node(label="EIP", property_key='AllocationId',
                                 property_value=ngw['NatGatewayAddresses'][0]['AllocationId'])
            if find_eip is not None:
                create_relationship(find_eip, "BELONGS", graph_ngw)
    return ngws_array


def create_vpc(graph_region):
    vpcs = ec2.describe_vpcs()
    if vpcs['Vpcs']:
        for vpc in vpcs['Vpcs']:
            name = find_tags(vpc)
            subnets = create_subnets(graph_region, vpc['VpcId'])
            igws = create_igws(vpc['VpcId'])
            ngws = create_nat_gws(vpc['VpcId'])
            graph_vpc = create_node("VPC", vpcId=vpc['VpcId'], name=name, cidr=vpc['CidrBlock'])
            create_relationship(graph_vpc, "BELONGS", graph_region)
            for subnet in subnets:
                create_relationship(subnet, "BELONGS", graph_vpc)
            for igw in igws:
                create_relationship(igw, "ATTACHED", graph_vpc)
            for ngw in ngws:
                graph_subnet = find_node(label="Subnet", property_key='SubnetId', property_value=ngw['SubnetId'])
                create_relationship(ngw, "BELONGS", graph_subnet)


def find_attachments(volume):
    attachments = []
    for attachment in volume['Attachments']:
        attachments.append(attachment)
    return attachments


def create_ec2_volumes():
    volumes = ec2.describe_volumes()
    for volume in volumes['Volumes']:
        attachments = find_attachments(volume)
        name_tag = find_tags(volume)
        if name_tag == '':
            name_tag = volume['VolumeId']
        if len(attachments) >= 1:
            create_node("Volumes", name=name_tag, AvailabilityZone=volume['AvailabilityZone'], Size=volume['Size'],
                        VolumeId=volume['VolumeId'], VolumeType=volume['VolumeType'], Encrypted=volume['Encrypted'],
                        DeviceName=volume['Attachments'][0]['Device'], InstanceId=volume['Attachments'][0]['InstanceId'])
        else:
            create_node("Volumes", name=name_tag, AvailabilityZone=volume['AvailabilityZone'], Size=volume['Size'],
                        VolumeId=volume['VolumeId'], VolumeType=volume['VolumeType'], Encrypted=volume['Encrypted'])


def create_reservations():
    reservations = ec2.describe_instances()
    if reservations['Reservations']:
        for reservation in reservations['Reservations']:
            create_ec2(reservation)


def create_ec2(reservation):
    for instance in reservation['Instances']:
        if not instance['State']['Code'] == 48:
            name = find_tags(instance)
            network_interface_id = instance['NetworkInterfaces'][0]['NetworkInterfaceId']
            graph_ec2 = create_node("EC2", InstanceId=instance['InstanceId'], name=name,
                                    state=instance['State']['Name'], SubnetId=instance['SubnetId'],
                                    NetworkInterfaceId=network_interface_id, type=instance['InstanceType']
                                    )
            graph_subnet = find_node(label="Subnet", property_key='SubnetId', property_value=instance['SubnetId'])
            if graph_subnet is not None:
                create_relationship(graph_ec2, "ATTACHED", graph_subnet)
            graph_eip = find_node(label="EIP", property_key='NetworkInterfaceId', property_value=network_interface_id)
            if graph_eip is not None:
                create_relationship(graph_eip, "ASSOCIATION", graph_ec2)
            graph_volume = find_node(label="Volumes", property_key='InstanceId', property_value=instance['InstanceId'])
            if graph_volume is not None:
                create_relationship(graph_ec2, "ATTACHED", graph_volume)


def create_rds():
    databases = rds.describe_db_instances()
    for db in databases['DBInstances']:
        create_node("RDS", rdsId=db['DBInstanceIdentifier'], DBInstanceClass=db['DBInstanceClass'], Engine=db['Engine'],
                    EngineVersion=db['EngineVersion'], MultiAZ=db['MultiAZ'], AllocatedStorage=db['AllocatedStorage'])


def create_elc():
    elcs = elasticache.describe_cache_clusters()['CacheClusters']
    for elc in elcs:
        create_node("ElastiCache", elcId=elc['CacheClusterId'])


def create_elb():
    elbs = loadbalancer.describe_load_balancers()['LoadBalancerDescriptions']
    for elb in elbs:
        graph_elb = create_node("ELB", name=elb['LoadBalancerName'],
                                CanonicalHostedZoneName=elb['CanonicalHostedZoneName']
                                )
        for subnet in elb['Subnets']:
            graph_subnet = find_node(label="Subnet", property_key='SubnetId', property_value=subnet)
            if graph_subnet is not None:
                create_relationship(graph_elb, "BELONGS", graph_subnet)
        for instance in elb["Instances"]:
            graph_instance = find_node(label="EC2", property_key='InstanceId', property_value=instance['InstanceId'])
            if graph_instance is not None:
                create_relationship(graph_instance, "BELONGS", graph_elb)


def create_eip():
    eips = ec2.describe_addresses()
    for eip in eips['Addresses']:
        network_interface_id = check_key(eip, 'NetworkInterfaceId')
        create_node("EIP", AllocationId=eip['AllocationId'], PublicIp=eip['PublicIp'], Domain=eip['Domain'],
                    PublicIpv4Pool=eip['PublicIpv4Pool'], AssociationId=check_key(eip, 'AssociationId'),
                    NetworkInterfaceId=network_interface_id
                    )


def create_network_interfaces():
    interfaces = ec2.describe_network_interfaces()
    for interface in interfaces['NetworkInterfaces']:
        create_node("Interfaces", Description=interface['Description'], RequesterId=check_key(interface, 'RequesterId'),
                    NetworkInterfaceId=interface['NetworkInterfaceId']
                    )


def create_topics(sns):
    topics = sns.list_topics()
    for topic in topics['Topics']:
        topic_attributes = sns.get_topic_attributes(TopicArn=topic['TopicArn'])
        create_node("Topic", Name=topic_attributes['Attributes']['DisplayName'],
                    TopicArn=topic_attributes['Attributes']['TopicArn'],
                    Owner=topic_attributes['Attributes']['Owner'],
                    EffectiveDeliveryPolicy=topic_attributes['Attributes']['EffectiveDeliveryPolicy'],
                    SubscriptionsPending=topic_attributes['Attributes']['SubscriptionsPending'],
                    SubscriptionsConfirmed=topic_attributes['Attributes']['SubscriptionsConfirmed']
                    )


def create_sns():
    sns = boto3.client('sns', region_name=region)

    # Potential verbs
    #
    # list_endpoints_by_platform_application
    # list_phone_numbers_opted_out
    # list_platform_applications
    # list_subscriptions
    # list_subscriptions_by_topic
    # list_tags_for_resource
    # list_topics
    # https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/sns.html#SNS.Client.get_platform_application_attributes

    create_topics(sns)
    subscriptions = sns.list_subscriptions()
    for subscription in subscriptions['Subscriptions']:
        graph_subscription = create_node("SNS_Subscriptions",
                                         Name=subscription['SubscriptionArn'],
                                         SubscriptionArn=subscription['SubscriptionArn'],
                                         Owner=subscription['Owner'],
                                         Protocol=subscription['Protocol'],
                                         Endpoint=subscription['Endpoint'],
                                         TopicArn=subscription['TopicArn']
                                         )
        graph_topic = find_node(label="Topic", property_key='TopicArn',
                                property_value=subscription['TopicArn'])
        if graph_topic is not None:
            create_relationship(graph_subscription, "SUBSCRIBED", graph_topic)

    try:
        platform_applications = sns.list_platform_applications()
        for application in platform_applications['PlatformApplications']:
            create_node("PlatformApplications",
                        PlatformApplicationArn=application['PlatformApplicationArn'],
                        Attributes=application['Attributes']
                        )
    # botocore.exceptions.ClientError: An error occurred (InvalidAction) when calling the ListPlatformApplications
    # operation: Operation (ListPlatformApplications) is not supported in this region
    except sns.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'InvalidAction':
            print("sns.list_platform_applications: " + e.response['Error']['Message'])
        else:
            print("Unexpected error: %s" % e)

    try:
        phone_numbers_opted_out = sns.list_phone_numbers_opted_out()
    except (sns.exceptions.ClientError, sns.exceptions.AuthorizationErrorException) as e:
        if e.response['Error']['Code'] == 'AuthorizationError':
            print("sns.list_phone_numbers_opted_out: " + e.response['Error']['Message'])
        elif e.response['Error']['Code'] == 'InvalidAction':
            print("sns.list_phone_numbers_opted_out: " + e.response['Error']['Message'])
        else:
            print("Unexpected error: %s" % e)
    # tags_for_resource = sns.list_tags_for_resource()


def create_target_groups(alb_arn, graph_alb):
    tgs = elbv2.describe_target_groups(LoadBalancerArn=alb_arn)['TargetGroups']
    for tg in tgs:
        tg_arn = tg['TargetGroupArn']
        targets = elbv2.describe_target_health(TargetGroupArn=tg_arn)['TargetHealthDescriptions']
        graph_tg = create_node("Target Group", name=tg['TargetGroupName'])
        create_relationship(graph_tg, "ATTACHED", graph_alb)
        for target in targets:
            graph_instance = find_node(label="EC2", property_key='instanceId', property_value=target['Target']['Id'])
            if graph_instance is not None:
                create_relationship(graph_instance, "ATTACHED", graph_tg)


def create_alb():
    albs = elbv2.describe_load_balancers()['LoadBalancers']
    for alb in albs:
        graph_alb = create_node("ALB", name=alb['LoadBalancerName'], dnsname=alb['DNSName'], scheme=alb['Scheme'],
                                VpcId=alb['VpcId'])
        alb_arn = alb['LoadBalancerArn']

        for azs in alb['AvailabilityZones']:
            graph_subnet = find_node(label="Subnet", property_key='SubnetId', property_value=azs['SubnetId'])
            if graph_subnet is not None:
                create_relationship(graph_alb, "ATTACHED", graph_subnet)
        create_target_groups(alb_arn, graph_alb)


def create_lambda():
    lambdas = lambdaFunctions.list_functions()['Functions']
    for l in lambdas:
        create_node("Lambda", name=l['FunctionName'])
    global has_lambda
    has_lambda = False


def create_sg():
    security_groups = ec2.describe_security_groups()
    for sg in security_groups['SecurityGroups']:
        graph_sg = create_node("SecurityGroup", securityGroupId=sg['GroupId'], name=sg['GroupName'], VpcId=sg['VpcId'])
        graph_vpc = find_node(label="Subnet", property_key='VpcId', property_value=sg['VpcId'])
        if graph_vpc is not None:
            create_relationship(graph_sg, "BELONGS", graph_vpc)


def create_dynamodb():
    dynamo_tables = dynamodb.list_tables()['TableNames']
    for table_name in dynamo_tables:
        table_info = dynamodb.describe_table(TableName=table_name)['Table']
        create_node("DynamoDB", name=table_name,
                    write_capacity=table_info['ProvisionedThroughput']['WriteCapacityUnits'],
                    read_capacity=table_info['ProvisionedThroughput']['ReadCapacityUnits'])


def create_instance_relationships(graph_sg, sg):
    instances = ec2.describe_instances(Filters=[{'Name': 'instance.group-id', 'Values': [sg['GroupId']]}])
    if instances['Reservations']:
        for instance in instances['Reservations']:
            instance_id = instance['Instances'][0]['InstanceId']
            graph_ec2 = find_node(label="EC2", property_key='instanceId', property_value=instance_id)
            if graph_ec2 is not None:
                create_relationship(graph_ec2, "ATTACHED", graph_sg)


def create_database_sg_relationships(graph_sg, sg):
    databases = rds.describe_db_instances()['DBInstances']
    for db in databases:
        db_sgs = db['VpcSecurityGroups']
        for db_sg in db_sgs:
            if db_sg['VpcSecurityGroupId'] == sg['GroupId']:
                graph_rds = find_node(label="RDS", property_key='rdsId', property_value=db['DBInstanceIdentifier'])
                if graph_rds is not None:
                    create_relationship(graph_rds, "ATTACHED", graph_sg)


def create_database_subnet_relationships(graph_sg, sg):
    databases = rds.describe_db_instances()['DBInstances']
    for db_subnets in databases['DBSubnetGroup']['Subnets']:
        graph_rds = find_node(label="Subnets", property_key='SubnetId', property_value=db['SubnetIdentifier'])
        if graph_rds is not None:
            create_relationship(graph_rds, "ATTACHED", graph_sg)


def create_elasticache_relationships(graph_sg, sg):
    elcs = elasticache.describe_cache_clusters()['CacheClusters']
    for elc in elcs:
        elc_sgs = elc['SecurityGroups']
        for elc_sg in elc_sgs:
            if elc_sg['SecurityGroupId'] == sg['GroupId']:
                graph_elc = find_node(label="ElastiCache", property_key='elcId', property_value=elc['CacheClusterId'])
                if graph_elc is not None:
                    create_relationship(graph_elc, "ATTACHED", graph_sg)


def create_elb_relationships(graph_sg, sg):
    elbs = loadbalancer.describe_load_balancers()['LoadBalancerDescriptions']
    for elb in elbs:
        elb_sgs = elb['SecurityGroups']
        for elb_sg in elb_sgs:
            if elb_sg == sg['GroupId']:
                graph_elb = find_node(label="ELB", property_key='name', property_value=elb['LoadBalancerName'])
                if graph_elb is not None:
                    create_relationship(graph_elb, "ATTACHED", graph_sg)


def create_lamda_relationships(graph_sg, sg):
    lambdas = lambdaFunctions.list_functions()['Functions']
    for l in lambdas:
        if l.__contains__('VpcConfig') and l['VpcConfig'] != []:
            for lambda_sg in l['VpcConfig']['SecurityGroupIds']:
                if lambda_sg == sg['GroupId']:
                    graph_lambda = find_node(label="Lambda", property_key='name', property_value=l['FunctionName'])
                    create_relationship(graph_lambda, "ATTACHED", graph_sg)


def create_useridgrouppairs_relationships(rule, graph_sg):
    for group in rule['UserIdGroupPairs']:
        graph_from_sg = find_node(label="SecurityGroup", property_key='securityGroupId', property_value=group['GroupId'])
        if graph_from_sg is not None:
            if rule['IpProtocol'] == '-1':
                protocol = 'All'
                port_range = '0 - 65535'
            else:
                protocol = rule['IpProtocol']
                if rule['FromPort'] == rule['ToPort']:
                    port_range = rule['FromPort']
                else:
                    port_range = "%d - %d" % (rule['FromPort'], rule['ToPort'])
            create_relationship(graph_from_sg, "ATTACHED", graph_sg, protocol=protocol, port=port_range)


def create_ipranges_relationships(rule, graph_sg):
    for cidr in rule['IpRanges']:
        try:
            graph_cidr = find_node(label="IP", property_key='cidr', property_value=cidr['CidrIp'])
        except:
            graph_cidr = create_node("IP", cidr=cidr['CidrIp'])
        if rule['IpProtocol'] == '-1':
            protocol = 'All'
            port_range = '0 - 65535'
        else:
            protocol = rule['IpProtocol']
            if rule['FromPort'] == rule['ToPort']:
                port_range = rule['FromPort']
            else:
                port_range = "%d - %d" % (rule['FromPort'], rule['ToPort'])
        if graph_cidr is not None:
            create_relationship(graph_cidr, "ATTACHED", graph_sg, protocol=protocol, port=port_range)


def create_sg_relationships():
    security_groups = ec2.describe_security_groups()
    for sg in security_groups['SecurityGroups']:
        graph_sg = find_node(label="SecurityGroup", property_key='securityGroupId', property_value=sg['GroupId'])
        if graph_sg is not None:
            ingress_rules = sg['IpPermissions']
            for rule in ingress_rules:
                if rule['UserIdGroupPairs']:
                    create_useridgrouppairs_relationships(rule, graph_sg)
                elif rule['IpRanges']:
                    create_ipranges_relationships(rule, graph_sg)

        create_instance_relationships(graph_sg, sg)
        create_database_sg_relationships(graph_sg, sg)
        create_elasticache_relationships(graph_sg, sg)
        create_elb_relationships(graph_sg, sg)
        if has_lambda:
            create_lamda_relationships(graph_sg, sg)


graph = Graph(user="neo4j", password="letmein", host="localhost")

graph.delete_all()
has_lambda = True
regions = ["eu-central-1", "eu-west-1", "eu-west-2", "eu-west-3", "eu-north-1"]
sts = boto3.client('sts')
caller_identify = sts.get_caller_identity()

graph_provider = create_node("Provider", name='AWS', Account=caller_identify['Account'])

for region in regions:
    print("Querying region: " + region)
    ec2 = boto3.client('ec2', region_name=region)
    rds = boto3.client('rds', region_name=region)
    elasticache = boto3.client('elasticache', region_name=region)
    loadbalancer = boto3.client('elb', region_name=region)
    elbv2 = boto3.client('elbv2', region_name=region)
    lambdaFunctions = boto3.client('lambda', region_name=region)
    dynamodb = boto3.client('dynamodb', region_name=region)

    graph_region = create_node("Region", name=region)
    create_relationship(graph_region, "BELONGS", graph_provider)

    create_eip()
    create_vpc(graph_region)
    create_sg()
    # create_network_interfaces()
    create_sns()
    # create_sqs()
    create_ec2_volumes()
    create_reservations()
    create_rds()
    create_elb()
    create_alb()
    create_elc()
    if has_lambda:
        create_lambda()
        create_dynamodb()
    create_sg_relationships()
