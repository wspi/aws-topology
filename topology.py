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


def create_vpc(graph_region):
    vpcs = ec2.describe_vpcs()
    if not vpcs['Vpcs']:
        pass
    else:
        for vpc in vpcs['Vpcs']:
            if vpc.__contains__('Tags'):
                name = find_name_tag(vpc['Tags'])
            else:
                name = ""
            subnets = create_subnets(vpc['VpcId'])
            igws = create_igws(vpc['VpcId'])
            ngws = create_nat_gws(vpc['VpcId'])

            tx = graph.begin()
            graph_vpc = Node("VPC", vpcId=vpc['VpcId'], name=name, cidr=vpc['CidrBlock'])
            tx.merge(graph_vpc)
            rel = Relationship(graph_vpc, "BELONGS", graph_region)
            tx.create(rel)
            for subnet in subnets:
                rel = Relationship(subnet, "BELONGS", graph_vpc)
                tx.create(rel)
            for igw in igws:
                rel = Relationship(igw, "ATTACHED", graph_vpc)
                tx.create(rel)
            for ngw in ngws:
                graph_subnet = next(graph.find(label="Subnet", property_key='SubnetId', property_value=ngw['SubnetId']))
                rel = Relationship(ngw, "BELONGS", graph_subnet)
                tx.create(rel)
            tx.commit()


def create_subnets(vpc_id):
    subnets_array = []
    subnets = ec2.describe_subnets(Filters=[{'Name': 'vpc-id','Values':[vpc_id]}])
    if not subnets['Subnets']:
        pass
    else:
        for subnet in subnets['Subnets']:
            if subnet.__contains__('Tags'):
                name = find_name_tag(subnet['Tags'])
            else:
                name = ""
            tx = graph.begin()
            graph_subnet = Node("Subnet", SubnetId=subnet['SubnetId'], name=name, az=subnet['AvailabilityZone'], cidr=subnet['CidrBlock'])
            tx.merge(graph_subnet)
            tx.commit()
            subnets_array.append(graph_subnet)
    return subnets_array


def create_igws(vpc_id):
    igws_array = []
    igws = ec2.describe_internet_gateways(Filters=[{'Name': 'attachment.vpc-id', 'Values':[vpc_id]}])
    if not igws['InternetGateways']:
        pass
    else:
        for igw in igws['InternetGateways']:
            if igw.__contains__('Tags'):
                name = find_name_tag(igw['Tags'])
            else:
                name = ""
            tx = graph.begin()
            graph_igw = Node("IGW", igwId=igw['InternetGatewayId'], VpcId=igw['Attachments'][0]['VpcId'], name=name)
            tx.merge(graph_igw)
            tx.commit()
            igws_array.append(graph_igw)
    return igws_array


def create_nat_gws(vpc_id):
    ngws_array = []
    ngws = ec2.describe_nat_gateways(Filters=[{'Name': 'vpc-id', 'Values':[vpc_id]}])
    if not ngws['NatGateways']:
        pass
    else:
        for ngw in ngws['NatGateways']:
            if ngw.__contains__('Tags'):
                name = find_name_tag(ngw['Tags'])
            else:
                name = ""
            tx = graph.begin()
            graph_ngw = Node("NATGW", ngwId=ngw['NatGatewayId'], SubnetId=ngw['SubnetId'], name=name)
            tx.merge(graph_ngw)
            tx.commit()
            ngws_array.append(graph_ngw)
    return ngws_array


def create_ec2():
    reservations = ec2.describe_instances()
    if not reservations['Reservations']:
        pass
    else:
        for reservation in reservations['Reservations']:
            for instance in reservation['Instances']:
                tx = graph.begin()
                if not instance['State']['Code'] == 48:
                    if instance.__contains__('Tags'):
                        name = find_name_tag(instance['Tags'])
                    else:
                        name = ""
                    network_interface_id = instance['NetworkInterfaces'][0]['NetworkInterfaceId']
                    graph_ec2 = Node("EC2",
                                     InstanceId=instance['InstanceId'],
                                     name=name,
                                     state=instance['State']['Name'],
                                     SubnetId=instance['SubnetId'],
                                     NetworkInterfaceId=instance['NetworkInterfaces'][0]['NetworkInterfaceId'],
                                     type=instance['InstanceType']
                                     )
                    graph_subnet = next(graph.find(label="Subnet", property_key='SubnetId',
                                                   property_value=instance['SubnetId']))
                    rel = Relationship(graph_ec2, "BELONGS", graph_subnet)
                    tx.create(rel)
                    # graph_eip = graph.find_one(label="EIP",
                    #                             property_key='NetworkInterfaceId',
                    #                             property_value=network_interface_id)
                    # if graph_eip is not None:
                    #     rel = Relationship(graph_eip, "ASSOCIATION", graph_ec2)
                    #     tx.create(rel)
                    #     check_key(instance['NetworkInterfaces'][0], 'PublicIp')
                tx.commit()


def create_rds():
    databases = rds.describe_db_instances()['DBInstances']
    for db in databases:
        tx = graph.begin()
        graph_rds = Node("RDS", rdsId=db['DBInstanceIdentifier'], DBInstanceClass=db['DBInstanceClass'])
        tx.merge(graph_rds)
        tx.commit()


def create_elc():
    elcs = elasticache.describe_cache_clusters()['CacheClusters']
    for elc in elcs:
        tx = graph.begin()
        graph_elc = Node("ElastiCache", elcId=elc['CacheClusterId'])
        tx.merge(graph_elc)
        tx.commit()


def create_elb():
    elbs = loadbalancer.describe_load_balancers()['LoadBalancerDescriptions']
    for elb in elbs:
        tx = graph.begin()
        graph_elb = Node("ELB",
                         name=elb['LoadBalancerName'],
                         CanonicalHostedZoneName=elb['CanonicalHostedZoneName']
                         )
        tx.merge(graph_elb)
        tx.commit()
        for subnet in elb['Subnets']:
            tx = graph.begin()
            graph_subnet = next(graph.find(label="Subnet", property_key='SubnetId', property_value=subnet))
            rel = Relationship(graph_elb, "BELONGS", graph_subnet)
            tx.create(rel)
            tx.commit()

        for instance in elb["Instances"]:
            try:
                tx = graph.begin()
                graph_instance = graph.find_one(label="EC2",
                                                property_key='InstanceId',
                                                property_value=instance['InstanceId']
                                                )
                rel = Relationship(graph_instance, "BELONGS", graph_elb)
                tx.create(rel)
                tx.commit()
            except:
                pass


def create_eip():
    eips = ec2.describe_addresses()
    for eip in eips['Addresses']:
        tx = graph.begin()
        network_interface_id = check_key(eip, 'NetworkInterfaceId')
        graph_eip = Node("EIP",
                         AllocationId=eip['AllocationId'],
                         PublicIp=eip['PublicIp'],
                         Domain=eip['Domain'],
                         PublicIpv4Pool=eip['PublicIpv4Pool'],
                         AssociationId=check_key(eip, 'AssociationId'),
                         NetworkInterfaceId=network_interface_id
                         )
        tx.merge(graph_eip)
        # if network_interface_id != "Unknown":
        #     graph_interface = next(graph.find(label="Interfaces", property_key='NetworkInterfaceId', property_value=network_interface_id))
        #     rel = Relationship(graph_eip, "ATTACHED", graph_interface)
        #     tx.create(rel)

        tx.commit()

def create_network_interfaces():
    interfaces = ec2.describe_network_interfaces()
    for interface in interfaces['NetworkInterfaces']:
        tx = graph.begin()
        graph_interfaces = Node("Interfaces",
                         Description=interface['Description'],
                         RequesterId=check_key(interface, 'RequesterId'),
                         NetworkInterfaceId=interface['NetworkInterfaceId']
                         )
        tx.merge(graph_interfaces)
        tx.commit()

def create_alb():
    albs = elbv2.describe_load_balancers()['LoadBalancers']
    for alb in albs:
        tx = graph.begin()
        graph_alb = Node("ALB", name=alb['LoadBalancerName'])
        tx.merge(graph_alb)
        tx.commit()
        alb_arn = alb['LoadBalancerArn']
        for subnet in alb['AvailabilityZones']:
            tx = graph.begin()
            graph_subnet = next(graph.find(label="Subnet",property_key='SubnetId',property_value=subnet['SubnetId']))
            rel = Relationship(graph_alb, "BELONGS", graph_subnet)
            tx.create(rel)
            tx.commit()

        tgs = elbv2.describe_target_groups(LoadBalancerArn=alb_arn)['TargetGroups']
        for tg in tgs:
            tg_arn = tg['TargetGroupArn']
            targets = elbv2.describe_target_health(TargetGroupArn=tg_arn)['TargetHealthDescriptions']
            tx = graph.begin()
            graph_tg = Node("Target Group", name=tg['TargetGroupName'])
            tx.merge(graph_tg)
            rel = Relationship(graph_tg, "BELONGS", graph_alb)
            tx.create(rel)
            tx.commit()
            for target in targets:
                try:
                    tx = graph.begin()
                    graph_instance = next(graph.find(label="EC2",property_key='instanceId',property_value=target['Target']['Id']))
                    rel = Relationship(graph_instance, "BELONGS", graph_tg)
                    tx.create(rel)
                    tx.commit()
                except:
                    pass

        # for instance in alb["Instances"]:
        #     try:
        #         tx = graph.begin()
        #         next(graphInstance = graph.find(label="EC2",property_key='instanceId',
        #         property_value=instance['InstanceId']))
        #         rel = Relationship(graphInstance, "BELONGS", graphAlb)
        #         tx.create(rel)
        #         tx.commit()
        #     except:
        #         pass


def create_lambda():
    try:
        lambdas = lambdaFunctions.list_functions()['Functions']
        for l in lambdas:
            tx = graph.begin()
            graph_lambda = Node("Lambda", name=l['FunctionName'])
            tx.merge(graph_lambda)
            tx.commit()
    except botocore.exceptions.EndpointConnectionError as e:
        global has_lambda
        has_lambda = False


def create_sg():
    security_groups = ec2.describe_security_groups()
    for sg in security_groups['SecurityGroups']:
        tx = graph.begin()
        graph_sg = Node("SecurityGroup", securityGroupId=sg['GroupId'], name=sg['GroupName'], VpcId=sg['VpcId'])
        tx.merge(graph_sg)
        tx.commit()


def create_dynamodb():
    dynamo_tables = dynamodb.list_tables()['TableNames']
    for tableName in dynamo_tables:
        table_info = dynamodb.describe_table(TableName=tableName)['Table']
        tx = graph.begin()
        graph_table = Node("DynamoDB", name=tableName, write_capacity=table_info['ProvisionedThroughput']['WriteCapacityUnits'], read_capacity=table_info['ProvisionedThroughput']['ReadCapacityUnits'])
        tx.merge(graph_table)
        tx.commit()


def create_sg_relationships():
    try:
        security_groups = ec2.describe_security_groups()

        for sg in security_groups['SecurityGroups']:
            graph_sg = next(graph.find(label="SecurityGroup",property_key='securityGroupId',property_value=sg['GroupId']))
            ingress_rules = sg['IpPermissions']
            for rule in ingress_rules:
                if rule['UserIdGroupPairs']:
                    for group in rule['UserIdGroupPairs']:
                        tx = graph.begin()
                        graph_from_sg = next(graph.find(label="SecurityGroup",property_key='securityGroupId',property_value=group['GroupId']))
                        if rule['IpProtocol'] == '-1':
                            protocol = 'All'
                            port_range = '0 - 65535'
                        else:
                            protocol = rule['IpProtocol']
                            if rule['FromPort'] == rule['ToPort']:
                                port_range = rule['FromPort']
                            else:
                                port_range = "%d - %d" %(rule['FromPort'], rule['ToPort'])
                        rel = Relationship(graph_from_sg, "ATTACHED", graph_sg, protocol=protocol,port=port_range)
                        tx.create(rel)
                        tx.commit()
                if rule['IpRanges']:
                    for cidr in rule['IpRanges']:
                        tx = graph.begin()
                        try:
                            graph_cidr = next(graph.find(label="IP",property_key='cidr',property_value=cidr['CidrIp']))
                        except:
                            graph_cidr = Node("IP", cidr=cidr['CidrIp'])
                            tx.create(graph_cidr)
                        if rule['IpProtocol'] == '-1':
                            protocol = 'All'
                            port_range = '0 - 65535'
                        else:
                            protocol = rule['IpProtocol']
                            if rule['FromPort'] == rule['ToPort']:
                                port_range = rule['FromPort']
                            else:
                                port_range = "%d - %d" %(rule['FromPort'], rule['ToPort'])
                        rel = Relationship(graph_cidr, "ATTACHED", graph_sg, protocol=protocol,port=port_range)
                        tx.create(rel)
                        tx.commit()

            instances = ec2.describe_instances(Filters=[{'Name': 'instance.group-id','Values':[sg['GroupId']]}])
            if not instances['Reservations']:
                pass
            else:
                for instance in instances['Reservations']:
                    tx = graph.begin()
                    instance_id = instance['Instances'][0]['InstanceId']
                    graph_ec2 = next(graph.find(label="EC2",property_key='instanceId',property_value=instance_id))
                    rel = Relationship(graph_ec2, "ATTACHED", graph_sg)
                    tx.create(rel)
                    tx.commit()

            databases = rds.describe_db_instances()['DBInstances']
            for db in databases:
                db_sgs = db['VpcSecurityGroups']
                for db_sg in db_sgs:
                    if (db_sg['VpcSecurityGroupId'] == sg['GroupId']):
                        tx = graph.begin()
                        graph_rds = next(graph.find(label="RDS",property_key='rdsId',property_value=db['DBInstanceIdentifier']))
                        rel = Relationship(graph_rds, "ATTACHED", graph_sg)
                        tx.create(rel)
                        tx.commit()

            elcs = elasticache.describe_cache_clusters()['CacheClusters']
            for elc in elcs:
                elc_sgs = elc['SecurityGroups']
                for elc_sg in elc_sgs:
                    if (elc_sg['SecurityGroupId'] == sg['GroupId']):
                        tx = graph.begin()
                        graph_elc = next(graph.find(label="ElastiCache",property_key='elcId',property_value=elc['CacheClusterId']))
                        rel = Relationship(graph_elc, "ATTACHED", graph_sg)
                        tx.create(rel)
                        tx.commit()

            elbs = loadbalancer.describe_load_balancers()['LoadBalancerDescriptions']
            for elb in elbs:
                elb_sgs = elb['SecurityGroups']
                for elb_sg in elb_sgs:
                    if (elb_sg == sg['GroupId']):
                        tx = graph.begin()
                        graph_elb = next(graph.find(label="ELB",property_key='name',property_value=elb['LoadBalancerName']))
                        rel = Relationship(graph_elb, "BELONGS", graph_sg)
                        tx.create(rel)
                        tx.commit()

            if (has_lambda):
                lambdas = lambdaFunctions.list_functions()['Functions']
                for l in lambdas:
                    if l.__contains__('VpcConfig') and l['VpcConfig'] != []:
                        for lambda_sg in l['VpcConfig']['SecurityGroupIds']:
                            if lambda_sg == sg['GroupId']:
                                tx = graph.begin()
                                graph_lambda = next(graph.find(label="Lambda",property_key='name',property_value=l['FunctionName']))
                                rel = Relationship(graph_lambda, "BELONGS", graph_sg)
                                tx.create(rel)
                                tx.commit()
    except:
        pass


graph = Graph(user="neo4j", password="letmein", host="localhost")
graph.delete_all()

has_lambda = False
regions = ["eu-central-1", "eu-west-1", "eu-west-2", "eu-west-3", "eu-north-1"]

for region in regions:
    print("Querying region: " + region)
    ec2 = boto3.client('ec2', region_name=region)
    rds = boto3.client('rds', region_name=region)
    elasticache = boto3.client('elasticache', region_name=region)
    loadbalancer = boto3.client('elb', region_name=region)
    elbv2 = boto3.client('elbv2', region_name=region)
    lambdaFunctions = boto3.client('lambda', region_name=region)
    dynamodb = boto3.client('dynamodb', region_name=region)
    
    tx = graph.begin()
    graph_region = Node("Region", name=region)
    tx.merge(graph_region)
    tx.commit()

    create_vpc(graph_region)
    create_sg()
    # create_network_interfaces()
    create_eip()
    create_ec2()
    create_rds()
    create_elb()
    create_alb()
    create_elc()
    if (has_lambda):
        create_lambda()
    create_dynamodb()
    create_sg_relationships()
