"""Copyright 2021 Google LLC.

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

   https://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
"""

DEPENDENT_OPERATIONS = {
    'ListKeys': 'ListAliases',
    'DescribeInternetGateways': 'DescribeVpcs',
}

# Services to ignore
SERVICE_BLACKLIST = [
    'alexaforbusiness',
    'apigatewaymanagementapi',
    'cloudsearchdomain',
    'kinesis-video-archived-media',
    'kinesis-video-media',
    'managedblockchain',
    'mediastore-data',
    's3control',
    'accessanalyzer',
    'apigatewaymanagementapi',
    'appconfig',
    'clouddirectory',
    'cloudsearchdomain',
    'comprehendmedical',
    'connectparticipant',
    'dax',
    'dlm',
    'imagebuilder',
    'importexport',
    'iotsecuretunneling',
    'kinesisanalytics',
    'machinelearning',
    'mturk',
    'networkmanager',
    'opsworkscm',
    'pi',
    'pricing',
    'resourcegroupstaggingapi',
    'route53domains',
    'route53resolver',
    's3control',
    'workmailmessageflow',
]

PARAMETERS_REQUIRED = {
    'appstream': ['DescribeUserStackAssociations'],
    'batch': ['ListJobs'],
    'cloudformation': ['GetTemplateSummary', 'DescribeStackResources',
                       'DescribeStackEvents', 'GetTemplate'],
    'cloudhsm': ['DescribeHsm', 'DescribeLunaClient'],
    'cloudtrail': ['GetEventSelectors'],
    'codecommit': ['GetBranch'],
    'codedeploy': ['GetDeploymentTarget', 'ListDeploymentTargets'],
    'cognito-idp': ['GetUser'],
    'directconnect': ['DescribeDirectConnectGatewayAssociations',
                      'DescribeDirectConnectGatewayAttachments'],
    'ec2': ['DescribeSpotDatafeedSubscription',
            'DescribeLaunchTemplateVersions'],
    'ecs': ['ListContainerInstances', 'ListServices', 'ListTasks'],
    'efs': ['DescribeMountTargets'],
    'elasticache': ['ListAllowedNodeTypeModifications',
                    'DescribeCacheSecurityGroups'],
    'elasticbeanstalk': ['DescribeEnvironmentManagedActionHistory',
                         'DescribeEnvironmentResources',
                         'DescribeEnvironmentManagedActions',
                         'DescribeEnvironmentHealth',
                         'DescribeInstancesHealth',
                         'DescribeConfigurationOptions',
                         'DescribePlatformVersion'],
    'elbv2': ['DescribeRules', 'DescribeListeners'],
    'gamelift': ['DescribeGameSessionDetails', 'DescribeGameSessions',
                 'DescribePlayerSessions'],
    'globalaccelerator': ['DescribeAcceleratorAttributes'],
    'glue': ['GetDataflowGraph', 'GetResourcePolicy'],
    'health': ['DescribeEventTypes', 'DescribeEntityAggregates',
               'DescribeEvents', 'DescribeEventsForOrganization',
               'DescribeHealthServiceStatusForOrganization'],
    'iot': ['GetLoggingOptions', 'GetEffectivePolicies', 'ListAuditFindings'],
    'kinesis': ['DescribeStreamConsumer', 'ListShards'],
    'kinesisvideo': ['DescribeStream', 'ListTagsForStream'],
    'kinesis-video-archived-media': ['GetHLSStreamingSessionURL'],
    'mediastore': ['DescribeContainer'],
    'opsworks': ['DescribeAgentVersions', 'DescribeApps', 'DescribeCommands',
                 'DescribeDeployments', 'DescribeEcsClusters',
                 'DescribeElasticIps', 'DescribeElasticLoadBalancers',
                 'DescribeInstances', 'DescribeLayers',
                 'DescribePermissions', 'DescribeRaidArrays',
                 'DescribeVolumes'],
    'pricing': ['GetProducts'],
    'redshift': ['DescribeTableRestoreStatus',
                 'DescribeClusterSecurityGroups'],
    'route53domains': ['GetContactReachabilityStatus'],
    'schemas': ['GetResourcePolicy'],
    'secretsmanager': ['GetRandomPassword'],
    'servicecatalog': ['DescribeProduct', 'DescribeProductAsAdmin',
                       'DescribeProvisionedProduct',
                       'DescribeProvisioningArtifact',
                       'DescribeProvisioningParameters',],
    'shield': ['DescribeSubscription', 'DescribeProtection'],
    'sms': ['GetApp', 'GetAppLaunchConfiguration',
            'GetAppReplicationConfiguration'],
    'ssm': ['DescribeAssociation', 'DescribeMaintenanceWindowSchedule',
            'ListComplianceItems'],
    'waf': ['ListActivatedRulesInRuleGroup', 'ListLoggingConfigurations'],
    'waf-regional': ['ListActivatedRulesInRuleGroup'],
    'workdocs': ['DescribeActivities', 'GetResources'],
    'worklink': ['ListFleets'],
    'xray': ['GetGroup'],
}


# This lists API calls that do return a list of resource-like
# objects which cannot be influenced by the user
AWS_RESOURCE_QUERIES = {
    'apigateway': ['GetSdkTypes'],
    'autoscaling': [
        'DescribeAdjustmentTypes', 'DescribeTerminationPolicyTypes',
        'DescribeAutoScalingNotificationTypes',
        'DescribeScalingProcessTypes', 'DescribeMetricCollectionTypes',
        'DescribeLifecycleHookTypes'
    ],
    'backup': ['GetSupportedResourceTypes', 'ListBackupPlanTemplates'],
    'clouddirectory': ['ListManagedSchemaArns'],
    'cloudhsm': ['ListAvailableZones'],
    'cloudtrail': ['ListPublicKeys'],
    'codebuild': ['ListCuratedEnvironmentImages'],
    'codedeploy': ['ListDeploymentConfigs'],
    'codepipeline': ['ListActionTypes'],
    'codestar-notifications': ['ListEventTypes'],
    'devicefarm': ['ListDevices', 'ListOfferings', 'ListOfferingTransactions'],
    'directconnect': ['DescribeLocations'],
    'dynamodb': ['DescribeEndpoints'],
    'dms': ['DescribeEndpointTypes', 'DescribeOrderableReplicationInstances',
            'DescribeEventCategories'],
    'docdb': ['DescribeCertificates', 'DescribeDBEngineVersions',
              'DescribeEventCategories'],
    'ec2': ['DescribeAggregateIdFormat', 'DescribeCapacityProviders',
            'DescribeAvailabilityZones', 'DescribeHostReservationOfferings',
            'DescribeIdFormat', 'DescribeInstanceTypeOfferings',
            'DescribeInstanceTypes', 'DescribeManagedPrefixLists',
            'DescribePrefixLists', 'DescribeRegions',
            'DescribeReservedInstancesOfferings', 'DescribeSpotPriceHistory',
            'DescribeVpcClassicLinkDnsSupport', 'DescribeVpcEndpointServices'],
    'elasticache': ['DescribeCacheParameterGroups',
                    'DescribeCacheEngineVersions', 'DescribeServiceUpdates'],
    'elasticbeanstalk': ['ListAvailableSolutionStacks', 'ListPlatformBranches',
                         'PlatformSummaryList'],
    'elastictranscoder': ['ListPresets'],
    'elb': ['DescribeLoadBalancerPolicyTypes', 'DescribeLoadBalancerPolicies'],
    'elbv2': ['DescribeSSLPolicies'],
    'es': ['DescribeReservedElasticsearchInstanceOfferings',
           'GetCompatibleElasticsearchVersions'],
    'groundstation': ['ListGroundStations'],
    'inspector': ['ListRulesPackages'],
    'kafka': ['GetCompatibleKafkaVersions', 'ListKafkaVersions'],
    'lex-models': ['GetBuiltinIntents', 'GetBuiltinSlotTypes'],
    'lightsail': ['GetBlueprints', 'GetBundles', 'GetDistributionBundles',
                  'GetRegions', 'GetRelationalDatabaseBlueprints',
                  'GetRelationalDatabaseBundles'],
    'mediaconvert': ['DescribeEndpoints'],
    'medialive': ['ListOfferings'],
    'mobile': ['ListBundles'],
    'mq': ['DescribeBrokerInstanceOptions', 'DescribeBrokerEngineTypes'],
    'neptune': ['DescribeDBEngineVersions', 'DescribeEventCategories'],
    'personalize': ['ListRecipes'],
    'pricing': ['DescribeServices'],
    'polly': ['DescribeVoices'],
    'ram': ['ListPermissions', 'ListResourceTypes'],
    'rds': ['DescribeDBEngineVersions', 'DescribeSourceRegions',
            'DescribeCertificates', 'DescribeEventCategories'],
    'redshift': ['DescribeClusterVersions', 'DescribeReservedNodeOfferings',
                 'DescribeOrderableClusterOptions', 'DescribeEventCategories',
                 'DescribeClusterTracks'],
    'route53': ['GetCheckerIpRanges', 'ListGeoLocations'],
    'savingsplans': ['DescribeSavingsPlansOfferingRates',
                     'DescribeSavingsPlansOfferings'],
    'securityhub': ['DescribeStandards'],
    'service-quotas': ['ListServices'],
    'signer': ['ListSigningPlatforms'],
    'ssm': ['DescribeAvailablePatches', 'GetInventorySchema'],
    'synthetics': ['DescribeRuntimeVersions'],
    'transfer': ['ListSecurityPolicies'],
    'xray': ['GetSamplingRules'],
}

# This lists API calls that do not return resources or resource-like objects.
NOT_RESOURCE_DESCRIPTIONS = {
    'apigateway': ['GetAccount'],
    'autoscaling': ['DescribeAccountLimits'],
    'alexaforbusiness': ['GetInvitationConfiguration'],
    'athena': ['ListQueryExecutions'],
    'chime': ['GetGlobalSettings'],
    'cloudformation': ['DescribeAccountLimits'],
    'cloudwatch': ['DescribeAlarmHistory'],
    'codebuild': ['ListBuilds'],
    'config': ['GetComplianceSummaryByResourceType',
               'GetComplianceSummaryByConfigRule',
               'DescribeComplianceByConfigRule',
               'DescribeComplianceByResource',
               'DescribeConfigRuleEvaluationStatus',
               'GetDiscoveredResourceCounts'],
    'dax': ['DescribeDefaultParameters', 'DescribeParameterGroups'],
    'devicefarm': ['GetAccountSettings', 'GetOfferingStatus'],
    'discovery': ['GetDiscoverySummary'],
    'dms': ['DescribeAccountAttributes',
            'DescribeApplicableIndividualAssessments',
            'DescribeEventCategories'],
    'docdb': ['DescribeEvents'],
    'ds': ['GetDirectoryLimits'],
    'dynamodb': ['DescribeLimits'],
    'ec2': ['DescribeAccountAttributes', 'DescribeDhcpOptions',
            'DescribeVpcClassicLink', 'DescribeVpcClassicLinkDnsSupport',
            'DescribePrincipalIdFormat', 'GetEbsDefaultKmsKeyId',
            'GetEbsEncryptionByDefault'],
    'ecr': ['GetAuthorizationToken'],
    'ecs': ['DescribeClusters'],
    'elastic-inference': ['DescribeAcceleratorTypes'],
    'elasticache': ['DescribeReservedCacheNodesOfferings'],
    'elasticbeanstalk': ['DescribeAccountAttributes', 'DescribeEvents'],
    'elb': ['DescribeAccountLimits'],
    'elbv2': ['DescribeAccountLimits'],
    'es': ['ListElasticsearchVersions'],
    'events': ['DescribeEventBus'],
    'fms': ['GetAdminAccount', 'GetNotificationChannel'],
    'gamelift': ['DescribeEC2InstanceLimits',
                 'DescribeMatchmakingConfigurations',
                 'DescribeMatchmakingRuleSets'],
    'glue': ['GetCatalogImportStatus', 'GetDataCatalogEncryptionSettings'],
    'guardduty': ['GetInvitationsCount'],
    'iam': ['GetAccountPasswordPolicy', 'GetAccountSummary', 'GetUser',
            'GetAccountAuthorizationDetails'],
    'inspector': ['DescribeCrossAccountAccessRole'],
    'iot': ['DescribeAccountAuditConfiguration',
            'DescribeEndpoint',
            'DescribeEventConfigurations',
            'GetIndexingConfiguration',
            'GetRegistrationCode',
            'GetV2LoggingOptions',
            'ListV2LoggingLevels'],
    'iotevents': ['DescribeLoggingOptions'],
    'iotthingsgraph': ['DescribeNamespace', 'GetNamespaceDeletionStatus'],
    'kinesis': ['DescribeLimits'],
    'lambda': ['GetAccountSettings'],
    'neptune': ['DescribeEvents'],
    'opsworks': ['DescribeMyUserProfile', 'DescribeUserProfiles',
                 'DescribeOperatingSystems'],
    'opsworkscm': ['DescribeAccountAttributes'],
    'organizations': ['DescribeOrganization'],
    'pinpoint-email': ['GetAccount', 'GetDeliverabilityDashboardOptions'],
    'redshift': ['DescribeStorage', 'DescribeAccountAttributes'],
    'rds': ['DescribeAccountAttributes', 'DescribeDBEngineVersions',
            'DescribeReservedDBInstancesOfferings',
            'DescribeEvents'],
    'resourcegroupstaggingapi': ['GetResources', 'GetTagKeys',
                                 'DescribeReportCreation',
                                 'GetComplianceSummary'],
    'route53': ['GetTrafficPolicyInstanceCount', 'GetHostedZoneCount',
                'GetHealthCheckCount', 'GetGeoLocation'],
    'route53domains': ['ListOperations'],
    'sagemaker': ['ListTrainingJobs'],
    'securityhub': ['GetInvitationsCount'],
    'servicediscovery': ['ListOperations'],
    'ses': ['GetSendQuota', 'GetAccountSendingEnabled'],
    'sesv2': ['GetAccount', 'GetDeliverabilityDashboardOptions'],
    'shield': ['GetSubscriptionState'],
    'sms': ['GetServers'],
    'snowball': ['GetSnowballUsage'],
    'sns': ['GetSMSAttributes', 'ListPhoneNumbersOptedOut'],
    'ssm': ['GetDefaultPatchBaseline'],
    'sts': ['GetSessionToken', 'GetCallerIdentity'],
    'waf': ['GetChangeToken'],
    'waf-regional': ['GetChangeToken'],
    'xray': ['GetEncryptionConfig'],
    'workspaces': ['DescribeAccount', 'DescribeAccountModifications'],
}

DEPRECATED_OR_DISALLOWED = {
    'config': [
        'DescribeAggregationAuthorizations',
        'DescribeConfigurationAggregators',
        'DescribePendingAggregationRequests',
    ],
    'dms': [
        'DescribeReplicationTaskAssessmentResults'
    ],
    'emr': ['DescribeJobFlows'],
    'greengrass': ['GetServiceRoleForAccount'],
    'iam': ['GetCredentialReport'],
    'iot': ['DescribeDefaultAuthorizer'],
    'mediaconvert': ['ListJobTemplates', 'ListJobs', 'ListPresets',
                     'ListQueues'],
    'servicecatalog': ['ListTagOptions'],
    'workdocs': ['DescribeUsers'],
    'ec2': ['DescribeTags', 'GetVpnConnectionDeviceTypes',
            'DescribeFpgaImages', 'GetKeyPairs']
}

# List of requests with legitimate, persistent errors
# that indicate that no listable resources are present.
# If the request would never return listable resources,
# it should not be done and be listed in one of the lists
RESULT_IGNORE_ERRORS = {
    'apigateway': {
        'GetVpcLinks': 'vpc link not supported for region',
    },
    'autoscaling-plans': {
        'DescribeScalingPlans': 'AccessDeniedException',
    },
    'backup': {
        'GetSupportedResourceTypes': 'AccessDeniedException',
    },
    'cloud9': {
        'ListEnvironments': 'SSLError',
        'DescribeEnvironmentMemberships': 'SSLError',
    },
    'cloudhsm': {
        'ListHapgs': 'This service is unavailable.',
        'ListLunaClients': 'This service is unavailable.',
        'ListHsms': 'This service is unavailable.',
    },
    'config': {
        'DescribeConfigRules': 'AccessDeniedException',
    },
    'cur': {
        'DescribeReportDefinitions':
                'is not authorized to callDescribeReportDefinitions',
    },
    'directconnect': {
        'DescribeInterconnects': 'not an authorized Direct Connect partner.',
    },
    'dynamodb': {
        'ListBackups': 'UnknownOperationException',
        'ListGlobalTables': 'UnknownOperationException',
    },
    'ec2': {
        'DescribeFpgaImages':
            'not valid for this web service',
        'DescribeReservedInstancesListings':
            'not authorized to use the requested product. ' +
            'Please complete the seller registration',
        'DescribeClientVpnEndpoints':
            'InternalError',
    },
    'fms': {
        'ListMemberAccounts': 'not currently delegated by AWS FM',
        'ListPolicies': 'not currently delegated by AWS FM',
    },
    'iot': {
        'DescribeAccountAuditConfiguration': ['An error occurred',
                                              'No listing'],
        'ListActiveViolations': 'An error occurred',
        'ListIndices': 'An error occurred',
        'ListJobs': 'An error occurred',
        'ListOTAUpdates': 'An error occurred',
        'ListScheduledAudits': 'An error occurred',
        'ListSecurityProfiles': 'An error occurred',
        'ListStreams': 'An error occurred',
    },
    'iotanalytics': {
        'DescribeLoggingOptions': 'An error occurred',
    },
    'license-manager': {
        'GetServiceSettings': 'Service role not found',
        'ListLicenseConfigurations': 'Service role not found',
        'ListResourceInventory': 'Service role not found',
    },
    'lightsail': {
        'GetDomains': 'only available in the us-east-1',
    },
    'machinelearning': {
        'DescribeBatchPredictions':
                'AmazonML is no longer available to new customers.',
        'DescribeDataSources':
                'AmazonML is no longer available to new customers.',
        'DescribeEvaluations':
                'AmazonML is no longer available to new customers.',
        'DescribeMLModels':
                'AmazonML is no longer available to new customers.',
    },
    'macie': {
        'ListMemberAccounts': 'Macie is not enabled',
        'ListS3Resources': 'Macie is not enabled',
    },
    'mturk': {
        'GetAccountBalance':
            'Your AWS account must be linked to your ' +
            'Amazon Mechanical Turk Account',
        'ListBonusPayments':
            'Your AWS account must be linked to your ' +
            'Amazon Mechanical Turk Account',
        'ListHITs':
            'Your AWS account must be linked to your ' +
            'Amazon Mechanical Turk Account',
        'ListQualificationRequests':
            'Your AWS account must be linked to your ' +
            'Amazon Mechanical Turk Account',
        'ListReviewableHITs':
            'Your AWS account must be linked to your ' +
            'Amazon Mechanical Turk Account',
        'ListWorkerBlocks':
            'Your AWS account must be linked to your ' +
            'Amazon Mechanical Turk Account',
    },
    'organizations': {
        'DescribeOrganization': 'AccessDeniedException',
        'ListAWSServiceAccessForOrganization': 'AccessDeniedException',
        'ListAccounts': 'AccessDeniedException',
        'ListCreateAccountStatus': 'AccessDeniedException',
        'ListHandshakesForOrganization': 'AccessDeniedException',
        'ListRoots': 'AccessDeniedException',
    },
    'rds': {
        'DescribeGlobalClusters': 'Access Denied to API Version',
    },
    'rekognition': {
        'ListStreamProcessors': 'AccessDeniedException',
    },
    'robomaker': {
        'ListDeploymentJobs': 'ForbiddenException',
        'ListFleets': 'ForbiddenException',
        'ListRobotApplications': 'ForbiddenException',
        'ListRobots': 'ForbiddenException',
        'ListSimulationApplications': 'ForbiddenException',
        'ListSimulationJobs': 'ForbiddenException',
    },
    'service-quotas': {
        'GetAssociationForServiceQuotaTemplate':
                'TemplatesNotAvailableInRegionException',
        'ListServiceQuotaIncreaseRequestsInTemplate':
                'TemplatesNotAvailableInRegionException',
    },
    'servicecatalog': {
        'GetAWSOrganizationsAccessStatus': 'AccessDeniedException',
    },
    'ses': {
        'DescribeActiveReceiptRuleSet':
                'Service returned the HTTP status code: 404',
        'ListReceiptFilters':
                'Service returned the HTTP status code: 404',
        'ListReceiptRuleSets':
                'Service returned the HTTP status code: 404',
    },
    'shield': {
        'DescribeDRTAccess': 'An error occurred',
        'DescribeEmergencyContactSettings': 'An error occurred',
        'ListProtections': 'ResourceNotFoundException',
    },
    'snowball': {
        'ListCompatibleImages': 'An error occurred',
    },
    'storagegateway': {
        'DescribeTapeArchives': 'InvalidGatewayRequestException',
        'ListTapes': 'InvalidGatewayRequestException',
    },
}

# query.py
not_available_for_region_strings = [
    'is not supported in this region',
    'is not available in this region',
    'not supported in the called region.',
    'Operation not available in this region',
    'Credential should be scoped to a valid region,',
    'The security token included in the request is invalid.',
    'AWS was not able to validate the provided access credentials',
    'InvalidAction',
]

# query.py
not_available_for_account_strings = [
    'This request has been administratively disabled',
    'Your account isn\'t authorized to call this operation.',
    'AWS Premium Support Subscription is required',
    'not subscribed to AWS Security Hub',
    'is not authorized to use this service',
    'Account not whitelisted',
]

# listing.py
PARAMETERS = {
    'cloudfront': {
        'ListCachePolicies': {
            'Type': 'custom'
        },
    },
    'ec2': {
        'DescribeSnapshots': {
            'OwnerIds': ['self']
        },
        'DescribeImages': {
            'Owners': ['self']
        },
    },
    'ecs': {
        'ListTaskDefinitionFamilies': {
            'status': 'ACTIVE',
        }
    },
    'elasticbeanstalk': {
        'ListPlatformVersions': {
            'Filters': [{
                'Operator': '=',
                'Type': 'PlatformOwner',
                'Values': ['self']
            }]
        }
    },
    'emr': {
        'ListClusters': {
            'ClusterStates': ['STARTING', 'BOOTSTRAPPING',
                              'RUNNING', 'WAITING', 'TERMINATING'],
        }
    },
    'iam': {
        'ListPolicies': {
            'Scope': 'Local'
        },
    },
    'ssm': {
        'ListDocuments': {
            'DocumentFilterList': [{
                'key': 'Owner',
                'value': 'self'
            }]
        },
    },
    'waf-regional': {
        'ListLoggingConfigurations': {
            'Limit': 100,
        },
    },
}