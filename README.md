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
![Alt text](https://bytebucket.org/credibilit/aws-topology/raw/306ecc1f23ff63acaadb5d347ec33e631d246096/topology.png?token=01195b0fc1b34e2e096519381228d41b8193dc5a)

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
