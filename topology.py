#!/usr/bin/env python
import boto3, traceback, sys, botocore
from py2neo import Graph, Node, Relationship

graph = Graph("http://localhost:7474")
ec2 = boto3.client('ec2')
rds = boto3.client('rds')
elasticache = boto3.client('elasticache')
loadbalancer = boto3.client('elb')
lambdaFunctions = boto3.client('lambda')
dynamodb = boto3.client('dynamodb')

hasLambda = True

def create_vpc():
    vpcs = ec2.describe_vpcs()
    if vpcs['Vpcs'] == []:
        pass
    else:
        for vpc in vpcs['Vpcs']:
            name = ""
            if (vpc.__contains__('Tags')):
                for tag in vpc['Tags']:
                    if tag['Key'] == 'Name':
                        name = tag['Value']

            subnets = create_subnets(vpc['VpcId'])
            igws = create_igws(vpc['VpcId'])

            tx = graph.begin()
            graphVpc = Node("VPC", vpcId=vpc['VpcId'], name=name, cidr=vpc['CidrBlock'])
            tx.merge(graphVpc)
            for subnet in subnets:
                rel = Relationship(subnet, "BELONGS", graphVpc)
                tx.create(rel)
            for igw in igws:
                rel = Relationship(igw, "ATTACHED", graphVpc)
                tx.create(rel)
            tx.commit()

def create_subnets(vpc_id):
    subnetsArray = []
    subnets = ec2.describe_subnets(Filters=[{'Name': 'vpc-id','Values':[vpc_id]}])
    if subnets['Subnets'] == []:
        pass
    else:
        for subnet in subnets['Subnets']:
            name = ""
            if (subnet.__contains__('Tags')):
                for tag in subnet['Tags']:
                    if tag['Key'] == 'Name':
                        name = tag['Value']
            tx = graph.begin()
            graphSubnet = Node("Subnet", subnetId=subnet['SubnetId'], name=name, az=subnet['AvailabilityZone'], cidr=subnet['CidrBlock'])
            tx.merge(graphSubnet)
            tx.commit()
            subnetsArray.append(graphSubnet)
    return subnetsArray

def create_igws(vpc_id):
    igwsArray = []
    igws = ec2.describe_internet_gateways(Filters=[{'Name': 'attachment.vpc-id', 'Values':[vpc_id]}])
    if igws['InternetGateways'] == []:
        pass
    else:
        for igw in igws['InternetGateways']:
            name = ""
            if (igw.__contains__('Tags')):
                for tag in igw['Tags']:
                    if tag['Key'] == 'Name':
                        name = tag['Value']
            tx = graph.begin()
            graphIgw = Node("IGW", igwId=igw['InternetGatewayId'], name=name)
            tx.merge(graphIgw)
            tx.commit()
            igwsArray.append(graphIgw)
    return igwsArray


def create_ec2():
    instances = ec2.describe_instances()
    if instances['Reservations'] == []:
        pass
    else:
        for instance in instances['Reservations']:
            tx = graph.begin()
            instanceId = instance['Instances'][0]['InstanceId']
            state = instance['Instances'][0]['State']['Name']
            instanceType = instance['Instances'][0]['InstanceType']
            subnetId = instance['Instances'][0]['SubnetId']
            name = ""
            if (instance['Instances'][0].__contains__('Tags')):
                for tag in instance['Instances'][0]['Tags']:
                    if tag['Key'] == 'Name':
                        name = tag['Value']
            graphEc2 = Node("EC2", instanceId=instanceId, name=name, state=state, type=instanceType)
            graphSubnet = graph.find(label="Subnet",property_key='subnetId',property_value=subnetId).next()
            rel = Relationship(graphEc2, "BELONGS", graphSubnet)
            tx.create(rel)
            tx.commit()

def create_rds():
    databases = rds.describe_db_instances()['DBInstances']
    for db in databases:
        tx = graph.begin()
        graphRds = Node("RDS", rdsId=db['DBInstanceIdentifier'])
        tx.merge(graphRds)
        tx.commit()

def create_elc():
    elcs = elasticache.describe_cache_clusters()['CacheClusters']
    for elc in elcs:
        tx = graph.begin()
        graphElc = Node("ElastiCache", elcId=elc['CacheClusterId'])
        tx.merge(graphElc)
        tx.commit()

def create_elb():
    elbs = loadbalancer.describe_load_balancers()['LoadBalancerDescriptions']
    for elb in elbs:
        tx = graph.begin()
        graphElb = Node("ELB", name=elb['LoadBalancerName'])
        tx.merge(graphElb)
        tx.commit()
        for subnet in elb['Subnets']:
            tx = graph.begin()
            graphSubnet = graph.find(label="Subnet",property_key='subnetId',property_value=subnet).next()
            rel = Relationship(graphElb, "BELONGS", graphSubnet)
            tx.create(rel)
            tx.commit()

        for instance in elb["Instances"]:
            tx = graph.begin()
            graphInstance = graph.find(label="EC2",property_key='instanceId',property_value=instance['InstanceId']).next()
            rel = Relationship(graphInstance, "BELONGS", graphElb)
            tx.create(rel)
            tx.commit()

def create_lambda():
    try:
        lambdas = lambdaFunctions.list_functions()['Functions']
        for l in lambdas:
            tx = graph.begin()
            graphLambda = Node("Lambda", name=l['FunctionName'])
            tx.merge(graphLambda)
            tx.commit()
    except botocore.exceptions.EndpointConnectionError as e:
        global hasLambda
        hasLambda = False

def create_sg():
    securityGroups = ec2.describe_security_groups()
    for sg in securityGroups['SecurityGroups']:
        tx = graph.begin()
        graphSg = Node("SecurityGroup", securityGroupId=sg['GroupId'], name=sg['GroupName'])
        tx.merge(graphSg)
        tx.commit()

def create_dynamodb():
    dynamoTables = dynamodb.list_tables()['TableNames']
    for tableName in dynamoTables:
        tableInfo = dynamodb.describe_table(TableName=tableName)['Table']
        tx = graph.begin()
        graphTable = Node("DynamoDB", name=tableName, write_capacity=tableInfo['ProvisionedThroughput']['WriteCapacityUnits'], read_capacity=tableInfo['ProvisionedThroughput']['ReadCapacityUnits'])
        tx.merge(graphTable)
        tx.commit()

def create_relationships():
    securityGroups = ec2.describe_security_groups()

    for sg in securityGroups['SecurityGroups']:
        graphSg = graph.find(label="SecurityGroup",property_key='securityGroupId',property_value=sg['GroupId']).next()
        ingressRules = sg['IpPermissions']
        for rule in ingressRules:
            if (rule['UserIdGroupPairs'] != []):
                for group in rule['UserIdGroupPairs']:
                    tx = graph.begin()
                    graphFromSg = graph.find(label="SecurityGroup",property_key='securityGroupId',property_value=group['GroupId']).next()
                    if rule['IpProtocol'] == '-1':
                        protocol = 'All'
                        portRange = '0 - 65535'
                    else:
                        protocol = rule['IpProtocol']
                        if rule['FromPort'] == rule['ToPort']:
                            portRange = rule['FromPort']
                        else:
                            portRange = "%d - %d" %(rule['FromPort'], rule['ToPort'])
                    rel = Relationship(graphFromSg, "CONNECTS", graphSg, protocol=protocol,port=portRange)
                    tx.create(rel)
                    tx.commit()
            if (rule['IpRanges'] != []):
                for cidr in rule['IpRanges']:
                    tx = graph.begin()
                    try:
                        graphCidr = graph.find(label="IP",property_key='cidr',property_value=cidr['CidrIp']).next()
                    except:
                        graphCidr = Node("IP", cidr=cidr['CidrIp'])
                        tx.create(graphCidr)
                    if rule['IpProtocol'] == '-1':
                        protocol = 'All'
                        portRange = '0 - 65535'
                    else:
                        protocol = rule['IpProtocol']
                        if rule['FromPort'] == rule['ToPort']:
                            portRange = rule['FromPort']
                        else:
                            portRange = "%d - %d" %(rule['FromPort'], rule['ToPort'])
                    rel = Relationship(graphCidr, "CONNECTS", graphSg, protocol=protocol,port=portRange)
                    if(sg['GroupId'] == 'sg-02e57866'):
                        print(sg['GroupId'])
                        print(graphSg)
                        print(cidr['CidrIp'])
                        print(graphCidr)
                        print(rel)
                    tx.create(rel)
                    tx.commit()

        instances = ec2.describe_instances(Filters=[{'Name': 'instance.group-id','Values':[sg['GroupId']]}])
        if instances['Reservations'] == []:
            pass
        else:
            for instance in instances['Reservations']:
                tx = graph.begin()
                instanceId = instance['Instances'][0]['InstanceId']
                graphEc2 = graph.find(label="EC2",property_key='instanceId',property_value=instanceId).next()
                rel = Relationship(graphEc2, "BELONGS", graphSg)
                tx.create(rel)
                tx.commit()

        databases = rds.describe_db_instances()['DBInstances']
        for db in databases:
            dbSgs = db['VpcSecurityGroups']
            for dbSg in dbSgs:
                if (dbSg['VpcSecurityGroupId'] == sg['GroupId']):
                    tx = graph.begin()
                    graphRds = graph.find(label="RDS",property_key='rdsId',property_value=db['DBInstanceIdentifier']).next()
                    rel = Relationship(graphRds, "BELONGS", graphSg)
                    tx.create(rel)
                    tx.commit()

        elcs = elasticache.describe_cache_clusters()['CacheClusters']
        for elc in elcs:
            elcSgs = elc['SecurityGroups']
            for elcSg in elcSgs:
                if (elcSg['SecurityGroupId'] == sg['GroupId']):
                    tx = graph.begin()
                    graphElc = graph.find(label="ElastiCache",property_key='elcId',property_value=elc['CacheClusterId']).next()
                    rel = Relationship(graphElc, "BELONGS", graphSg)
                    tx.create(rel)
                    tx.commit()

        elbs = loadbalancer.describe_load_balancers()['LoadBalancerDescriptions']
        for elb in elbs:
            elbSgs = elb['SecurityGroups']
            for elbSg in elbSgs:
                if (elbSg == sg['GroupId']):
                    tx = graph.begin()
                    graphElb = graph.find(label="ELB",property_key='name',property_value=elb['LoadBalancerName']).next()
                    rel = Relationship(graphElb, "BELONGS", graphSg)
                    tx.create(rel)
                    tx.commit()

        try:
            if (hasLambda):
                lambdas = lambdaFunctions.list_functions()['Functions']
                for l in lambdas:
                    if (l.__contains__('VpcConfig') and l['VpcConfig'] != []):
                        for lambdaSg in l['VpcConfig']['SecurityGroupIds']:
                            if (lambdaSg == sg['GroupId']):
                                tx = graph.begin()
                                graphLambda = graph.find(label="Lambda",property_key='name',property_value=l['FunctionName']).next()
                                rel = Relationship(graphLambda, "BELONGS", graphSg)
                                tx.create(rel)
                                tx.commit()
        except:
            pass

create_vpc()
create_sg()
create_ec2()
create_rds()
create_elb()
create_elc()
create_lambda()
create_dynamodb()
create_relationships()
