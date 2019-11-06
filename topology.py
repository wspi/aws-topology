#!/usr/bin/env python
import boto3
import botocore
from py2neo import Graph, Node, Relationship, NodeSelector


def check_key(dict, key):
    if key in dict.keys():
        return dict[key]
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


def create_relationship(source, type, destination):
    tx = graph.begin()
    relationship = Relationship(source, type, destination)
    tx.merge(relationship)
    tx.commit()
    return relationship


def create_subnets(graph_region, vpc_id):
    subnets_array = []
    subnets = ec2.describe_subnets(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])
    if not subnets['Subnets']:
        pass
    else:
        for subnet in subnets['Subnets']:
            graph_az = create_node("AvailabilityZone", name=subnet['AvailabilityZone'],
                        AvailabilityZoneId=subnet['AvailabilityZoneId'])
            name = find_tags(subnet)

            graph_subnet = create_node("Subnet", SubnetId=subnet['SubnetId'], name=name, az=subnet['AvailabilityZone'],
                                cidr=subnet['CidrBlock'], VpcId=subnet['VpcId'])

            create_relationship(graph_subnet, "BELONGS", graph_az)
            create_relationship(graph_az, "BELONGS", graph_region)

            subnets_array.append(graph_subnet)
    return subnets_array


def create_igws(vpc_id):
    igws_array = []
    igws = ec2.describe_internet_gateways(Filters=[{'Name': 'attachment.vpc-id', 'Values': [vpc_id]}])
    if not igws['InternetGateways']:
        pass
    else:
        for igw in igws['InternetGateways']:
            name = find_tags(igw)
            graph_igw = create_node("IGW", igwId=igw['InternetGatewayId'], VpcId=igw['Attachments'][0]['VpcId'],
                                    name=name)
            igws_array.append(graph_igw)
    return igws_array


def create_nat_gws(vpc_id):
    ngws_array = []
    ngws = ec2.describe_nat_gateways(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])
    if not ngws['NatGateways']:
        pass
    else:
        for ngw in ngws['NatGateways']:
            name_tag = find_tags(ngw)
            if name_tag is '':
                name_tag = ngwId=ngw['NatGatewayId']

            graph_ngw = create_node("NATGW", ngwId=ngw['NatGatewayId'], SubnetId=ngw['SubnetId'], name=name_tag)
            ngws_array.append(graph_ngw)
            find_eip = find_node(label="EIP", property_key='AllocationId', property_value=ngw['NatGatewayAddresses'][0]['AllocationId'])
            relationship = create_relationship(find_eip, "BELONGS", graph_ngw)
    return ngws_array


def create_vpc(graph_region):
    vpcs = ec2.describe_vpcs()
    if not vpcs['Vpcs']:
        pass
    else:
        for vpc in vpcs['Vpcs']:
            name = find_tags(vpc)
            subnets = create_subnets(graph_region, vpc['VpcId'])
            igws = create_igws(vpc['VpcId'])
            ngws = create_nat_gws(vpc['VpcId'])

            graph_vpc = create_node("VPC", vpcId=vpc['VpcId'], name=name, cidr=vpc['CidrBlock'])

            relationship = create_relationship(graph_vpc, "BELONGS", graph_region)
            for subnet in subnets:
                relationship = create_relationship(subnet, "BELONGS", graph_vpc)
            for igw in igws:
                relationship = create_relationship(igw, "ATTACHED", graph_vpc)
            for ngw in ngws:
                graph_subnet = find_node(label="Subnet", property_key='SubnetId', property_value=ngw['SubnetId'])
                relationship = create_relationship(ngw, "BELONGS", graph_subnet)


def create_ec2():
    reservations = ec2.describe_instances()
    if not reservations['Reservations']:
        pass
    else:
        for reservation in reservations['Reservations']:
            for instance in reservation['Instances']:
                if not instance['State']['Code'] == 48:
                    name = find_tags(instance)
                    network_interface_id = instance['NetworkInterfaces'][0]['NetworkInterfaceId']
                    graph_ec2 = create_node("EC2", InstanceId=instance['InstanceId'], name=name,
                                     state=instance['State']['Name'], SubnetId=instance['SubnetId'],
                                     NetworkInterfaceId=network_interface_id, type=instance['InstanceType']
                                     )
                    graph_subnet = find_node(label="Subnet", property_key='SubnetId', property_value=instance['SubnetId'])
                    relationship = create_relationship(graph_ec2, "ATTACHED", graph_subnet)
                    graph_eip = find_node(label="EIP", property_key='NetworkInterfaceId', property_value=network_interface_id)
                    if graph_eip is not None:
                        rel = create_relationship(graph_eip, "ASSOCIATION", graph_ec2)
                    #     tx.merge(rel)
                    #     check_key(instance['NetworkInterfaces'][0], 'PublicIp')


def create_rds():
    databases = rds.describe_db_instances()['DBInstances']
    for db in databases:
        graph_rds = create_node("RDS", rdsId=db['DBInstanceIdentifier'], DBInstanceClass=db['DBInstanceClass'])


def create_elc():
    elcs = elasticache.describe_cache_clusters()['CacheClusters']
    for elc in elcs:
        graph_elc = create_node("ElastiCache", elcId=elc['CacheClusterId'])


def create_elb():
    elbs = loadbalancer.describe_load_balancers()['LoadBalancerDescriptions']
    for elb in elbs:
        graph_elb = create_node("ELB",
                         name=elb['LoadBalancerName'],
                         CanonicalHostedZoneName=elb['CanonicalHostedZoneName']
                         )
        for subnet in elb['Subnets']:
            tx = graph.begin()
            graph_subnet = find_node(label="Subnet", property_key='SubnetId', property_value=subnet)
            relationship = create_relationship(graph_elb, "BELONGS", graph_subnet)

        for instance in elb["Instances"]:
            try:
                tx = graph.begin()
                graph_instance = find_node(label="EC2",
                                                property_key='InstanceId',
                                                property_value=instance['InstanceId']
                                                )
                relationship = create_relationship(graph_instance, "BELONGS", graph_elb)
            except:
                pass


def create_eip():
    eips = ec2.describe_addresses()
    for eip in eips['Addresses']:
        network_interface_id = check_key(eip, 'NetworkInterfaceId')
        graph_eip = create_node("EIP",
                         AllocationId=eip['AllocationId'],
                         PublicIp=eip['PublicIp'],
                         Domain=eip['Domain'],
                         PublicIpv4Pool=eip['PublicIpv4Pool'],
                         AssociationId=check_key(eip, 'AssociationId'),
                         NetworkInterfaceId=network_interface_id
                         )
        # if network_interface_id != "Unknown":
        #     graph_interface = find_node(label="Interfaces",
        #                                       property_key='NetworkInterfaceId',
        #                                       property_value=network_interface_id
        #                                       )
        #     relationship = create_relationship(graph_eip, "ATTACHED", graph_interface)


def create_network_interfaces():
    interfaces = ec2.describe_network_interfaces()
    for interface in interfaces['NetworkInterfaces']:
        graph_interfaces = create_node("Interfaces",
                                Description=interface['Description'],
                                RequesterId=check_key(interface, 'RequesterId'),
                                NetworkInterfaceId=interface['NetworkInterfaceId']
                                )


def create_alb():
    albs = elbv2.describe_load_balancers()['LoadBalancers']
    for alb in albs:
        graph_alb = create_node("ALB", name=alb['LoadBalancerName'], dnsname=alb['DNSName'], scheme=alb['Scheme'],
                         VpcId=alb['VpcId'])
        alb_arn = alb['LoadBalancerArn']
        for azs in alb['AvailabilityZones']:
            graph_subnet = find_node(label="Subnet", property_key='SubnetId', property_value=azs['SubnetId'])
            rel = create_relationship(graph_alb, "ATTACHED", graph_subnet)
            # graph_zone = find_node(label="Subnet", property_key='ZoneName', property_value=azs['ZoneName'])

        tgs = elbv2.describe_target_groups(LoadBalancerArn=alb_arn)['TargetGroups']
        for tg in tgs:
            tg_arn = tg['TargetGroupArn']
            targets = elbv2.describe_target_health(TargetGroupArn=tg_arn)['TargetHealthDescriptions']
            graph_tg = create_node("Target Group", name=tg['TargetGroupName'])
            rel = create_relationship(graph_tg, "ATTACHED", graph_alb)
            for target in targets:
                try:
                    graph_instance = find_node(label="EC2", property_key='instanceId', property_value=target['Target']['Id'])
                    rel = create_relationship(graph_instance, "ATTACHED", graph_tg)
                except:
                    pass

        for instance in alb["AvailabilityZones"]:
            try:
                graph_subnet = find_node(label="Subnet",property_key='SubnetId', property_value=instance['SubnetId'])
                rel = create_relationship(graph_alb, "BELONGS", graph_subnet)
            except:
                pass


def create_lambda():
    try:
        lambdas = lambdaFunctions.list_functions()['Functions']
        for l in lambdas:
            graph_lambda = create_node("Lambda", name=l['FunctionName'])
    except botocore.exceptions.EndpointConnectionError as e:
        global has_lambda
        has_lambda = False


def create_sg():
    security_groups = ec2.describe_security_groups()
    for sg in security_groups['SecurityGroups']:
        graph_sg = create_node("SecurityGroup", securityGroupId=sg['GroupId'], name=sg['GroupName'], VpcId=sg['VpcId'])
        graph_vpc = find_node(label="Subnet", property_key='VpcId', property_value=sg['VpcId'])
        rel = create_relationship(graph_sg, "BELONGS", graph_vpc)

def create_dynamodb():
    dynamo_tables = dynamodb.list_tables()['TableNames']
    for tableName in dynamo_tables:
        table_info = dynamodb.describe_table(TableName=tableName)['Table']
        graph_table = create_node("DynamoDB", name=tableName,
                           write_capacity=table_info['ProvisionedThroughput']['WriteCapacityUnits'],
                           read_capacity=table_info['ProvisionedThroughput']['ReadCapacityUnits'])


def create_sg_relationships():
    try:
        security_groups = ec2.describe_security_groups()

        for sg in security_groups['SecurityGroups']:
            graph_sg = find_node(label="SecurityGroup", property_key='securityGroupId', property_value=sg['GroupId'])
            ingress_rules = sg['IpPermissions']
            for rule in ingress_rules:
                if rule['UserIdGroupPairs']:
                    for group in rule['UserIdGroupPairs']:
                        tx = graph.begin()
                        graph_from_sg = find_node(label="SecurityGroup", property_key='securityGroupId',
                                                        property_value=group['GroupId'])
                        if rule['IpProtocol'] == '-1':
                            protocol = 'All'
                            port_range = '0 - 65535'
                        else:
                            protocol = rule['IpProtocol']
                            if rule['FromPort'] == rule['ToPort']:
                                port_range = rule['FromPort']
                            else:
                                port_range = "%d - %d" % (rule['FromPort'], rule['ToPort'])
                        rel = create_relationship(graph_from_sg, "ATTACHED", graph_sg, protocol=protocol, port=port_range)
                if rule['IpRanges']:
                    for cidr in rule['IpRanges']:
                        tx = graph.begin()
                        try:
                            graph_cidr = find_node(label="IP", property_key='cidr', property_value=cidr['CidrIp'])
                        except:
                            graph_cidr =  create_node("IP", cidr=cidr['CidrIp'])
                        if rule['IpProtocol'] == '-1':
                            protocol = 'All'
                            port_range = '0 - 65535'
                        else:
                            protocol = rule['IpProtocol']
                            if rule['FromPort'] == rule['ToPort']:
                                port_range = rule['FromPort']
                            else:
                                port_range = "%d - %d" % (rule['FromPort'], rule['ToPort'])
                        rel = create_relationship(graph_cidr, "ATTACHED", graph_sg, protocol=protocol, port=port_range)

            instances = ec2.describe_instances(Filters=[{'Name': 'instance.group-id', 'Values': [sg['GroupId']]}])
            if not instances['Reservations']:
                pass
            else:
                for instance in instances['Reservations']:
                    tx = graph.begin()
                    instance_id = instance['Instances'][0]['InstanceId']
                    graph_ec2 = find_node(label="EC2", property_key='instanceId', property_value=instance_id)
                    rel = create_relationship(graph_ec2, "ATTACHED", graph_sg)

            databases = rds.describe_db_instances()['DBInstances']
            for db in databases:
                db_sgs = db['VpcSecurityGroups']
                for db_sg in db_sgs:
                    if (db_sg['VpcSecurityGroupId'] == sg['GroupId']):
                        graph_rds = find_node(label="RDS", property_key='rdsId', property_value=db['DBInstanceIdentifier'])
                        rel = create_relationship(graph_rds, "ATTACHED", graph_sg)

            elcs = elasticache.describe_cache_clusters()['CacheClusters']
            for elc in elcs:
                elc_sgs = elc['SecurityGroups']
                for elc_sg in elc_sgs:
                    if (elc_sg['SecurityGroupId'] == sg['GroupId']):
                        graph_elc = find_node(label="ElastiCache", property_key='elcId', property_value=elc['CacheClusterId'])
                        rel = create_relationship(graph_elc, "ATTACHED", graph_sg)

            elbs = loadbalancer.describe_load_balancers()['LoadBalancerDescriptions']
            for elb in elbs:
                elb_sgs = elb['SecurityGroups']
                for elb_sg in elb_sgs:
                    if (elb_sg == sg['GroupId']):
                        graph_elb = find_node(label="ELB", property_key='name', property_value=elb['LoadBalancerName'])
                        rel = create_relationship(graph_elb, "ATTACHED", graph_sg)

            if (has_lambda):
                lambdas = lambdaFunctions.list_functions()['Functions']
                for l in lambdas:
                    if l.__contains__('VpcConfig') and l['VpcConfig'] != []:
                        for lambda_sg in l['VpcConfig']['SecurityGroupIds']:
                            if lambda_sg == sg['GroupId']:
                                graph_lambda = find_node(label="Lambda", property_key='name', property_value=l['FunctionName'])
                                rel = create_relationship(graph_lambda, "ATTACHED", graph_sg)
    except:
        pass


graph = Graph(user="neo4j", password="letmein", host="localhost")
graph.delete_all()

has_lambda = False
regions = ["eu-central-1", "eu-west-1", "eu-west-2", "eu-west-3", "eu-north-1"]

graph_provider = create_node("Provider", name='AWS')

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
    rel = create_relationship(graph_region, "BELONGS", graph_provider)

    create_eip()
    create_vpc(graph_region)
    create_sg()
    # create_network_interfaces()

    create_ec2()
    # create_rds()
    create_elb()
    create_alb()
    create_elc()
    if (has_lambda):
        create_lambda()
        create_dynamodb()
    create_sg_relationships()
