from typing import List
from aws_cdk import core
from aws_cdk.aws_ec2 import (
    GatewayVpcEndpointAwsService, 
    GatewayVpcEndpointOptions, 
    ISubnet, 
    InterfaceVpcEndpointAwsService, 
    Port, 
    SecurityGroup, 
    SubnetConfiguration, 
    SubnetSelection, 
    SubnetType, 
    Vpc,)

import aws_cdk.aws_iam as iam
import aws_cdk.custom_resources as cr
import aws_cdk.aws_elasticsearch as es
from aws_cdk.aws_logs import LogGroup

PRIVATE_SUBNET_GROUP = 'Private'
PUBLIC_NAT_GWS_SUBNET_GROUP = 'NATGWsPublic'

class VPCConstruct(core.Construct):

    def __init__(self, scope: core.Construct, id_: str, num_of_azs: int) -> None:
        super().__init__(scope, id_)

        self.audit_vpc = Vpc(
            self,
            id_,
            max_azs=num_of_azs,
            subnet_configuration=[
                #Currently IOT, AppConfig & Cloudmap are not accessable via VPC endpoint, so we use NAT GW access them
                SubnetConfiguration(name=PRIVATE_SUBNET_GROUP, subnet_type=SubnetType.PRIVATE, cidr_mask=24),
                SubnetConfiguration(name=PUBLIC_NAT_GWS_SUBNET_GROUP, subnet_type=SubnetType.PUBLIC, cidr_mask=24)
            ],
            gateway_endpoints={
                'S3':
                    GatewayVpcEndpointOptions(service=GatewayVpcEndpointAwsService.S3,
                                              subnets=[SubnetSelection(subnet_group_name=PRIVATE_SUBNET_GROUP)]),
                'DynamoDb':
                    GatewayVpcEndpointOptions(service=GatewayVpcEndpointAwsService.DYNAMODB,
                                              subnets=[SubnetSelection(subnet_group_name=PRIVATE_SUBNET_GROUP)]),
            },
            enable_dns_support=True,  # For the ElasticSearch Public Domain
            enable_dns_hostnames=True)

        self.audit_vpc.add_interface_endpoint('SsmVpcEndpoint', service=InterfaceVpcEndpointAwsService.SSM,
                                              subnets=SubnetSelection(one_per_az=True))

        self.audit_vpc.add_interface_endpoint('SqsVpcEndpoint', service=InterfaceVpcEndpointAwsService.SQS,
                                              subnets=SubnetSelection(one_per_az=True))
        self.audit_vpc.add_interface_endpoint('Ec2VpcEndpoint', service=InterfaceVpcEndpointAwsService.EC2,
                                              subnets=SubnetSelection(one_per_az=True))

        self.audit_vpc.add_interface_endpoint('LambdaVpcEndpoint', service=InterfaceVpcEndpointAwsService.LAMBDA_,
                                              subnets=SubnetSelection(one_per_az=True))

        self.lambdas_sg = SecurityGroup(self, id='LambdaSg', vpc=self.audit_vpc, security_group_name='Audit-Lambda')

    def _get_subnets(self, subnet_group: str) -> List[ISubnet]:
        return self.audit_vpc.select_subnets(subnet_group_name=subnet_group).subnets

class CdkBugTestStack(core.Stack):

    def __init__(self, scope: core.Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        role = iam.Role(scope=self, id='AwsCustomResourceRole', assumed_by=iam.ServicePrincipal('lambda.amazonaws.com'));
        role.add_to_policy(iam.PolicyStatement(actions=['iam:PassRole' ], resources=['*']))

        my_custom_resource = cr.AwsCustomResource(
            scope=self, id='MyAwsCustomResource', 
            role=role,
            policy=cr.AwsCustomResourcePolicy.from_sdk_calls(resources=['*']),
            on_create=cr.AwsSdkCall(
                action='listBuckets',
                service='s3',
                physical_resource_id=cr.PhysicalResourceId.of('BucketsList'),)
        )

        vpc = VPCConstruct(self, id_='test-vpc', num_of_azs=2)
        security_group = SecurityGroup(self, id='test-security-group', vpc=vpc, security_group_name='test-security-group')
        security_group.add_ingress_rule(connection=Port.tcp(443), peer=vpc.lambdas_sg)

        domain = es.Domain(scope=self, id='Domain', 
                version=es.ElasticsearchVersion.V7_9, 
                domain_name="es-domain-name",
                enable_version_upgrade=False,
                enforce_https=True,
                fine_grained_access_control=None,
                node_to_node_encryption=True,
                tls_security_policy=es.TLSSecurityPolicy.TLS_1_0,
                logging=es.LoggingOptions(app_log_enabled=True, slow_index_log_enabled=True, slow_search_log_enabled=True,
                                          app_log_group=LogGroup(scope=self, id="app-log-group", 
                                                     log_group_name=f'/aws/aes/domains/esdomain/app-log-group',
                                                     removal_policy=core.RemovalPolicy.DESTROY),
                                          slow_index_log_group=LogGroup(scope=self, id="slow-index-log-group", 
                                                     log_group_name=f'/aws/aes/domains/esdomain/slow-index-log-group',
                                                     removal_policy=core.RemovalPolicy.DESTROY),
                                          slow_search_log_group=LogGroup(scope=self, id="slow-search-log-group", 
                                                     log_group_name=f'/aws/aes/domains/esdomain/slow-search-log-group',
                                                     removal_policy=core.RemovalPolicy.DESTROY)),
                 removal_policy=core.RemovalPolicy.DESTROY,
                 zone_awareness=es.ZoneAwarenessConfig(availability_zone_count=2, enabled=True),
                 vpc_options=es.VpcOptions(security_groups=[security_group],
                          subnets=vpc.audit_vpc.select_subnets(subnet_group_name=PRIVATE_SUBNET_GROUP).subnets)
                )
