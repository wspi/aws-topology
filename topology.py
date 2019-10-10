#!/usr/bin/env python
import boto3
import botocore
from py2neo import Graph, Node, Relationship, NodeSelector

graph = Graph(user="neo4j", password="letmein", host="localhost")

has_lambda = True


def check_key(dict, key):
    if key in dict.keys():
        return dict[key]
    else:
        return "Unknown"


def create_subnets(vpc_id):
    subnets_array = []
    subnets = ec2.describe_subnets(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])
    if not subnets['Subnets']:
        pass
    else:
        for subnet in subnets['Subnets']:
            name = "Unknown"
            if subnet.__contains__('Tags'):
                for tag in subnet['Tags']:
                    if tag['Key'] == 'Name':
                        name = tag['Value']
            Graph = graph.begin()
            graph_subnet = Node("Subnet", subnetId=subnet['SubnetId'], name=name, availabilityZone=subnet['AvailabilityZone'], availabilityZoneId=subnet['AvailabilityZoneId'],
                                cidr=subnet['CidrBlock'], vpcId=subnet['VpcId'])
            Graph.merge(graph_subnet)
            Graph.commit()
            subnets_array.append(graph_subnet)
    return subnets_array


def create_igws(vpc_id):
    igws_array = []
    igws = ec2.describe_internet_gateways(Filters=[{'Name': 'attachment.vpc-id', 'Values': [vpc_id]}])
    if not igws['InternetGateways']:
        pass
    else:
        for igw in igws['InternetGateways']:
            name = "Unknown"
            if igw.__contains__('Tags'):
                for tag in igw['Tags']:
                    if tag['Key'] == 'Name':
                        name = tag['Value']
            Graph = graph.begin()
            graph_igw = Node("IGW", igwId=igw['InternetGatewayId'], name=name)
            Graph.merge(graph_igw)
            Graph.commit()
            igws_array.append(graph_igw)
    return igws_array


def create_vpc(graph_region):
    vpcs = ec2.describe_vpcs()
    if not vpcs['Vpcs']:
        pass
    else:
        for vpc in vpcs['Vpcs']:
            name = "Unknown"
            if vpc.__contains__('Tags'):
                for tag in vpc['Tags']:
                    if tag['Key'] == 'Name':
                        name = tag['Value']
            
            subnets = create_subnets(vpc['VpcId'])
            igws = create_igws(vpc['VpcId'])

            Graph = graph.begin()
            graph_vpc = Node("VPC", vpcId=vpc['VpcId'], name=name, cidr=vpc['CidrBlock'])
            Graph.merge(graph_vpc)
            rel = Relationship(graph_vpc, "BELONGS", graph_region)
            Graph.create(rel)
            for subnet in subnets:
                rel = Relationship(subnet, "ATTACHED", graph_vpc)
                Graph.create(rel)
            for igw in igws:
                rel = Relationship(igw, "ATTACHED", graph_vpc)
                Graph.create(rel)
            Graph.commit()


def create_reservations(reservations):
    Graph = graph.begin()
    graph_reservations = Node("Reservations", OwnerId=reservations['OwnerId'],
                              ReservationId=reservations['ReservationId'])
    Graph.merge(graph_reservations)
    Graph.commit()
    return graph_reservations['ReservationId']


def create_ec2():
    describe_instances = ec2.describe_instances()
    if not describe_instances['Reservations']:
        pass
    else:
        for reservations in describe_instances['Reservations']:
            reservation_id = create_reservations(reservations)
            for instance in reservations['Instances']:
                Graph = graph.begin()
                if not instance['State']['Code'] == 48:
                    subnet_id = check_key(instance, 'SubnetId')
                    name = "Unknown"
                    if instance.__contains__('Tags'):
                        for tag in instance['Tags']:
                            if tag['Key'] == 'Name':
                                name = tag['Value']
                    
                    graph_ec2 = Node(
                            "EC2", instanceId=instance['InstanceId'], imageId=instance['ImageId'],
                            name=name, state=instance['State']['Name'], type=instance['InstanceType'],
                            platform=check_key(instance, 'Platform'), private_ip_address=instance['PrivateIpAddress'],
                            subnet_id = check_key(instance, 'SubnetId')
                            )
                    selector = NodeSelector(graph)
                    graph_subnet = selector.select(
                            "Subnet", subnetId=subnet_id
                            )
                    rel = Relationship(
                            graph_ec2, "ATTACHED", graph_subnet
                            )
                    Graph.create(rel)
                    Graph.commit()
                    
                    # Graph = graph.begin()
                    # graph_reservation = selector.select(
                    #         "Reservations", ReservationId=reservation_id
                    #         )
                    # rel = Relationship(
                    #         graph_reservation, "BELONGS", graph_ec2
                    #         )
                    # Graph.create(rel)
                    # Graph.commit()


def create_rds():
    databases = rds.describe_db_instances()['DBInstances']
    for db in databases:
        Graph = graph.begin()
        graph_rds = Node("RDS", rdsId=db['DBInstanceIdentifier'], Engine=db['Engine'], Version=db['EngineVersion'],
                         InstanceStatus=db['DBInstanceStatus'], AllocatedStorage=db['AllocatedStorage'],
                         MultiAZ=db['MultiAZ'], AZ=db['AvailabilityZone'], SecondaryAAZ=db[
                'SecondaryAvailabilityZone'])
        Graph.merge(graph_rds)
        Graph.commit()


def create_elc():
    elcs = elasticache.describe_cache_clusters()['CacheClusters']
    for elc in elcs:
        Graph = graph.begin()
        graph_elc = Node("ElastiCache", elcId=elc['CacheClusterId'])
        Graph.merge(graph_elc)
        Graph.commit()


def create_elb():
    elbs = loadbalancer.describe_load_balancers()['LoadBalancerDescriptions']
    for elb in elbs:
        Graph = graph.begin()
        graph_elb = Node("ELB", name=elb['LoadBalancerName'])
        Graph.merge(graph_elb)
        Graph.commit()
        for subnet_id in elb['Subnets']:
            Graph = graph.begin()
            selector = NodeSelector(graph)
            graph_subnet = selector.select("Subnet", subnetId=subnet_id)
            rel = Relationship(graph_elb, "BELONGS", graph_subnet)
            Graph.create(rel)
            Graph.commit()
        
        for instance in elb["Instances"]:
            try:
                Graph = graph.begin()
                selector = NodeSelector(graph)
                graph_instance = next(selector.select("EC2", instanceId=instance['InstanceId']))
                rel = Relationship(graph_instance, "BELONGS", graph_elb)
                Graph.create(rel)
                Graph.commit()
            except:
                pass


def create_alb():
    albs = elbv2.describe_load_balancers()['LoadBalancers']
    for alb in albs:
        Graph = graph.begin()
        graph_alb = Node("ALB", name=alb['LoadBalancerName'])
        Graph.merge(graph_alb)
        Graph.commit()
        alb_arn = alb['LoadBalancerArn']
        for subnet in alb['AvailabilityZones']:
            Graph = graph.begin()
            selector = NodeSelector(graph)
            graph_subnet = next(selector.select("Subnet", subnetId=subnet_id))
            rel = Relationship(graph_alb, "BELONGS", graph_subnet)
            Graph.create(rel)
            Graph.commit()
        
        tgs = elbv2.describe_target_groups(LoadBalancerArn=alb_arn)['TargetGroups']
        for tg in tgs:
            tg_arn = tg['TargetGroupArn']
            targets = elbv2.describe_target_health(TargetGroupArn=tg_arn)['TargetHealthDescriptions']
            Graph = graph.begin()
            graph_tg = Node("Target Group", name=tg['TargetGroupName'])
            Graph.merge(graph_tg)
            rel = Relationship(graph_tg, "BELONGS", graph_alb)
            Graph.create(rel)
            Graph.commit()
            for target in targets:
                try:
                    Graph = graph.begin()
                    selector = NodeSelector(graph)
                    graph_instance = next(selector.select("EC2", instanceId=target['Target']['Id']))
                    rel = Relationship(graph_instance, "BELONGS", graph_tg)
                    Graph.create(rel)
                    Graph.commit()
                except:
                    pass
        
        # Comment out if issues
        
        for instance in alb["Instances"]:
            try:
                Graph = graph.begin()
                selector = NodeSelector(graph)
                graph_instance = next(selector.select("EC2", instanceId=instance['InstanceId']))
                rel = Relationship(graph_instance, "BELONGS", graph_alb)
                Graph.create(rel)
                Graph.commit()
            except:
                pass


def create_lambda():
    try:
        lambdas = lambdaFunctions.list_functions()['Functions']
        for l in lambdas:
            Graph = graph.begin()
            graph_lambda = Node("Lambda", name=l['FunctionName'])
            Graph.merge(graph_lambda)
            Graph.commit()
    except botocore.exceptions.EndpointConnectionError as e:
        global has_lambda
        has_lambda = False


def create_sg():
    security_groups = ec2.describe_security_groups()
    for sg in security_groups['SecurityGroups']:
        Graph = graph.begin()
        graph_sg = Node("SecurityGroup", securityGroupId=sg['GroupId'], name=sg['GroupName'], description=sg['Description'], vpcId=sg['VpcId'], ownerId=sg['OwnerId'])
        Graph.merge(graph_sg)
        Graph.commit()


def create_dynamodb():
    dynamo_tables = dynamodb.list_tables()['TableNames']
    for table_name in dynamo_tables:
        table_info = dynamodb.describe_table(TableName=table_name)['Table']
        Graph = graph.begin()
        graph_table = Node(
                "DynamoDB", name=table_name,
                write_capacity=table_info['ProvisionedThroughput']['WriteCapacityUnits'],
                read_capacity=table_info['ProvisionedThroughput']['ReadCapacityUnits']
                )
        Graph.merge(graph_table)
        Graph.commit()


def create_relationships():
    try:
        security_groups = ec2.describe_security_groups()
        for sg in security_groups['SecurityGroups']:
            selector = NodeSelector(graph)
            graph_sg = next(selector.select("SecurityGroup", securityGroupId=sg['GroupId']))
            ingress_rules = sg['IpPermissions']
            for rule in ingress_rules:
                if rule['UserIdGroupPairs'] != []:
                    for group in rule['UserIdGroupPairs']:
                        Graph = graph.begin()
                        graph_from_sg = next(graph.find(label="SecurityGroup", property_key='securityGroupId',
                                                        property_value=group['GroupId']))
                        if rule['IpProtocol'] == '-1':
                            protocol = 'All'
                            port_range = '0 - 65535'
                        else:
                            protocol = rule['IpProtocol']
                            if rule['FromPort'] == rule['ToPort']:
                                port_range = rule['FromPort']
                            else:
                                port_range = "%d - %d" % (rule['FromPort'], rule['ToPort'])
                        rel = Relationship(graph_from_sg, "CONNECTS", graph_sg, protocol=protocol, port=port_range)
                        Graph.create(rel)
                        Graph.commit()
                if rule['IpRanges']:
                    for cidr in rule['IpRanges']:
                        Graph = graph.begin()
                        try:
                            selector = NodeSelector(graph)
                            graph_cidr = next(selector.select("IP", cidr=cidr['CidrIp']))
                        except:
                            graph_cidr = Node("IP", cidr=cidr['CidrIp'])
                            Graph.create(graph_cidr)
                        if rule['IpProtocol'] == '-1':
                            protocol = 'All'
                            port_range = '0 - 65535'
                        else:
                            protocol = rule['IpProtocol']
                            if rule['FromPort'] == rule['ToPort']:
                                port_range = rule['FromPort']
                            else:
                                port_range = "%d - %d" % (rule['FromPort'], rule['ToPort'])
                        rel = Relationship(graph_cidr, "CONNECTS", graph_sg, protocol=protocol, port=port_range)
                        Graph.create(rel)
                        Graph.commit()
            
            instances = ec2.describe_instances(Filters=[{'Name': 'instance.group-id', 'Values': [sg['GroupId']]}])
            if not instances['Reservations']:
                pass
            else:
                for instance in instances['Reservations']:
                    Graph = graph.begin()
                    instance_id = instance['Instances'][0]['InstanceId']
                    selector = NodeSelector(graph)
                    graph_ec2 = next(selector.select("EC2", instanceId=instance_id))
                    rel = Relationship(graph_ec2, "BELONGS", graph_sg)
                    Graph.create(rel)
                    Graph.commit()
            
            databases = rds.describe_db_instances()['DBInstances']
            for db in databases:
                db_sgs = db['VpcSecurityGroups']
                for db_sg in db_sgs:
                    if (db_sg['VpcSecurityGroupId'] == sg['GroupId']):
                        Graph = graph.begin()
                        selector = NodeSelector(graph)
                        graph_rds = next(selector.select("RDS", rdsId=db['DBInstanceIdentifier']))
                        rel = Relationship(graph_rds, "BELONGS", graph_sg)
                        Graph.create(rel)
                        Graph.commit()
            
            elcs = elasticache.describe_cache_clusters()['CacheClusters']
            for elc in elcs:
                elc_sgs = elc['SecurityGroups']
                for elc_sg in elc_sgs:
                    if (elc_sg['SecurityGroupId'] == sg['GroupId']):
                        Graph = graph.begin()
                        selector = NodeSelector(graph)
                        graph_elc = next(selector.select("ElastiCache", elcId=elc['CacheClusterId']))
                        rel = Relationship(graph_elc, "BELONGS", graph_sg)
                        Graph.create(rel)
                        Graph.commit()
            
            elbs = loadbalancer.describe_load_balancers()['LoadBalancerDescriptions']
            for elb in elbs:
                elb_sgs = elb['SecurityGroups']
                for elb_sg in elb_sgs:
                    if (elb_sg == sg['GroupId']):
                        Graph = graph.begin()
                        selector = NodeSelector(graph)
                        graph_elb = next(selector.select("ELB", name=elb['LoadBalancerName']))
                        rel = Relationship(graph_elb, "BELONGS", graph_sg)
                        Graph.create(rel)
                        Graph.commit()
            
            if (has_lambda):
                lambdas = lambdaFunctions.list_functions()['Functions']
                for l in lambdas:
                    if l.__contains__('VpcConfig') and l['VpcConfig'] != []:
                        for lambda_sg in l['VpcConfig']['SecurityGroupIds']:
                            if lambda_sg == sg['GroupId']:
                                Graph = graph.begin()
                                selector = NodeSelector(graph)
                                graph_lambda = next(selector.select("Lambda", name=l['FunctionName']))
                                rel = Relationship(graph_lambda, "BELONGS", graph_sg)
                                Graph.create(rel)
                                Graph.commit()
    except:
        pass


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
    
    Graph = graph.begin()
    graphRegion = Node("Region", name=region)
    Graph.merge(graphRegion)
    Graph.commit()
    
    create_vpc(graphRegion)
    create_ec2()
    # create_sg()
    # create_rds(graphRegion)
    # create_elb(graphRegion)
    # create_alb(graphRegion)
    # create_elc(graphRegion)
    # create_lambda(graphRegion)
    # create_dynamodb(graphRegion)
    # create_relationships()
