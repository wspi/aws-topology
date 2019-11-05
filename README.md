# Customer's Graph Topology

## Under the Hood
### Neo4j
Graph database, used for visualize and query customer graph

### py2neo
Neo4j driver for python, used to store the data into Neo4j
### Boto3
AWS SDK for python, used to get customer info

## Supported Services
* VPC
* Subnet
* Internet Gateway
* EC2
* ELB
* Security Group
* ElastiCache
* RDS
* DynamoDB
* Lambda

## Relationships
![Alt text](https://github.com/wspi/aws-topology/blob/master/topology.png)


## Running
### Neo4j
```docker run --publish=7474:7474 --publish=7687:7687 --env=NEO4J_AUTH=none neo4j```

### Script
```
pip install -r requirements.txt
export AWS_PROFILE=XYZ
python topology.py
```

### Queries
To get all nodes and relationships in neo4j web interface
```
MATCH (n) return n
```
To get all nodes of type EC2 that connects to an specific RDS (does not check ports yet)
```
MATCH (a:EC2)-[:BELONGS]->(b:SecurityGroup)-[:CONNECTS]->(c:SecurityGroup)<-[:BELONGS]-(d:RDS {rdsId:'rds-identifier'})
RETURN a,b,c,d
```

To get all nodes of type EC2 showing the subnet, vpc and region they belong to
```
MATCH (a:EC2)-[:BELONGS]->(b:Subnet)-[:BELONGS]->(c:VPC)-[:BELONGS]->(d:Region)
RETURN a,b,c,d
```
To list all EIPS without associationa
```
MATCH (o:EIP) WHERE NOT (o.AssociationId) contains "eipassoc-" RETURN o
```
To delete all nodes and relationships
```
MATCH (n)
DETACH DELETE n
```