# Topologia de Clientes em Grafos

## Under the Hood
### Neo4j
Banco de dados de grafos rodando em docker para visualizar e realizar queries na arquitetura do cliente

### py2neo
Driver do Neo4j para Python

### Boto3
SDK da AWS para Python utilizada para coletar as informações da conta do cliente

## Serviços Suportados
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

## Relacionamentos
![Alt text](https://g.gravizo.com/source/svg/thiisthemark?http%3A%2F%2Fwww.gravizo.com)
![Alt text](http://www.gravizo.com/img/1x1.png#


thiisthemark        
@startuml
object VPC
object Subnet
object InternetGateway
object EC2
object ELB
object SecurityGroup
object ElastiCache
object RDS
object DynamoDB
object Lambda

VPC <|-- Subnet
VPC <|-- InternetGateway
Subnet <|-- EC2
Subnet <|-- ELB
SecurityGroup <|-- EC2
SecurityGroup <|-- ElastiCache
SecurityGroup <|-- RDS
SecurityGroup <|-- Lambda

@enduml
thiisthemark        
)

## Execução
### Neo4j
```docker run --publish=7474:7474 --publish=7687:7687 --env=NEO4J_AUTH=none neo4j```

### Função
```
pip install -r requirements.txt
export AWS_PROFILE=XYZ
python topology.py
```
