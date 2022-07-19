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

import json


class ResourceFilter:
  """Resource filter class."""

  def execute(self, listing, response):
    pass


class CloudfrontFilter:
  """Cloudfront filter class."""

  def execute(self, listing, response):
    """Apply filter.

    Args:
      listing: data returned from aws api.
      response: relevant data returned to caller.
    """
    if listing.service == 'cloudfront':
      assert len(response.keys()) == 1, ('Unexpected ' +
                                    'cloudfront response: {}'.format(response))
      key = list(response.keys())[0][:-len('List')]
      response = list(response.values())[0]
      response[key] = response.get('Items', [])


class MedialiveFilter:
  """Medialive filter class."""

  def execute(self, listing, response):
    """Apply filter.

    Args:
      listing: data returned from aws api.
      response: relevant data returned to caller.
    """
    if listing.service == 'medialive':
      if listing.operation == 'ListChannels' and not response['Channels']:
        if 'Channels' in response:
          del response['Channels']
        if 'NextToken' in response:
          del response['NextToken']
        if listing.operation == 'ListInputs' and not response['Inputs']:
          if 'Inputs' in response:
            del response['Inputs']
          if 'NextToken' in response:
            del response['NextToken']


class SSMListCommandsFilter:
  """SSMListCommands filter class."""

  def execute(self, listing, response):
    """Apply filter.

    Args:
      listing: data returned from aws api.
      response: relevant data returned to caller.
    """
    if listing.service == 'ssm' and listing.operation == 'ListCommands':
      if 'NextToken' in response and not response['Commands']:
        del response['NextToken']


class SNSListSubscriptionsFilter:
  """SNSListSubscriptions filter class."""

  def execute(self, listing, response):
    """Apply filter.

    Args:
      listing: data returned from aws api.
      response: relevant data returned to caller.
    """
    if listing.service == 'sns' and listing.operation == 'ListSubscriptions':
      del response['NextToken']


class AthenaWorkGroupsFilter:
  """AthenaWorkGroups filter class."""

  def execute(self, listing, response):
    """Apply filter.

    Args:
      listing: data returned from aws api.
      response: relevant data returned to caller.
    """
    if listing.service == 'athena' and listing.operation == 'ListWorkGroups':
      response['WorkGroups'] = [wg for wg in response.get('WorkGroups', [])
                                if wg['Name'] != 'primary']


class ListEventBusesFilter:
  """ListEventBuses filter class."""

  def execute(self, listing, response):
    """Apply filter.

    Args:
      listing: data returned from aws api.
      response: relevant data returned to caller.
    """
    if listing.service == 'events' and listing.operation == 'ListEventBuses':
      response['EventBuses'] = [wg for wg in response.get('EventBuses', [])
                                if wg['Name'] != 'default']


class XRayGroupsFilter:
  """XRayGroups filter class."""

  def execute(self, listing, response):
    """Apply filter.

    Args:
      listing: data returned from aws api.
      response: relevant data returned to caller.
    """
    if listing.service == 'xray' and listing.operation == 'GetGroups':
      response['Groups'] = [wg for wg in response.get('Groups', [])
                            if wg['GroupName'] != 'Default']


class Route53ResolverFilter:
  """Route53Resolver filter class."""

  def execute(self, listing, response):
    """Apply filter.

    Args:
      listing: data returned from aws api.
      response: relevant data returned to caller.
    """
    if listing.service == 'route53resolver':
      if listing.operation == 'ListResolverRules':
        response['ResolverRules'] = [
            rule for rule in response.get('ResolverRules', [])
            if rule['Id'] != 'rslvr-autodefined-rr-internet-resolver'
        ]
      if listing.operation == 'ListResolverRuleAssociations':
        response['ResolverRuleAssociations'] = [
            rule for rule in response.get('ResolverRuleAssociations', [])
            if (rule['ResolverRuleId'] !=
                'rslvr-autodefined-rr-internet-resolver')
        ]


class KMSListAliasesFilter:
  """KMSListAliases filter class."""

  def execute(self, listing, response):
    """Apply filter.

    Args:
      listing: data returned from aws api.
      response: relevant data returned to caller.
    """
    if listing.service == 'kms' and listing.operation == 'ListAliases':
      response['Aliases'] = [
          alias for alias in response.get('Aliases', [])
          if not alias.get('AliasName').lower().startswith('alias/aws')
      ]


class KMSListKeysFilter:
  """KMSListKeys filter class."""

  def __init__(self, directory):
    self.directory = directory

  def execute(self, listing, response):
    """Apply filter.

    Args:
      listing: data returned from aws api.
      response: relevant data returned to caller.
    """
    if listing.service == 'kms' and listing.operation == 'ListKeys':
      aliases_file = '{}_{}_{}_{}.json'.format(listing.service, 'ListAliases',
                                               listing.region, listing.profile)
      aliases_file = self.directory + aliases_file
      aliases_listing = listing.from_json(json.load(open(aliases_file, 'rb')))
      list_aliases = aliases_listing.response
      service_key_ids = [
          k.get('TargetKeyId') for k in list_aliases.get('Aliases', [])
          if k.get('AliasName').lower().startswith('alias/aws')
      ]
      response['Keys'] = [k for k in response.get('Keys', [])
                          if k.get('KeyId') not in service_key_ids]


class AppstreamImagesFilter:
  """AppstreamImages filter class."""

  def execute(self, listing, response):
    """Apply filter.

    Args:
      listing: data returned from aws api.
      response: relevant data returned to caller.
    """
    if (listing.service == 'appstream'
        and listing.operation == 'DescribeImages'):
      response['Images'] = [
          image for image in response.get('Images', [])
          if image.get('Visibility', 'PRIVATE') != 'PUBLIC'
      ]


class CloudsearchFilter:
  """Cloudsearch filter class."""

  def execute(self, listing, response):
    # This API returns a dict instead of a list
    if (listing.service == 'cloudsearch'
        and listing.operation == 'ListDomainNames'):
      response['DomainNames'] = list(response['DomainNames'].items())


class CloudTrailFilter:
  """CloudTrail filter class."""

  def execute(self, listing, response):
    """Apply filter.

    Args:
      listing: data returned from aws api.
      response: relevant data returned to caller.
    """
    if (listing.service == 'cloudtrail'
        and listing.operation == 'DescribeTrails'):
      response['trailList'] = [
          trail for trail in response['trailList']
          if (trail.get('HomeRegion') == self.region
              or not trail.get('IsMultiRegionTrail'))
      ]


class CloudWatchFilter:
  """CloudWatch filter class."""

  def execute(self, listing, response):
    """Apply filter.

    Args:
      listing: data returned from aws api.
      response: relevant data returned to caller.
    """
    if listing.service == 'cloudwatch' and listing.operation == 'ListMetrics':
      response['Metrics'] = [
          metric for metric in response['Metrics']
          if not metric.get('Namespace').startswith('AWS/')
      ]


class IAMPoliciesFilter:
  """IAMPolicies filter class."""

  def execute(self, listing, response):
    """Apply filter.

    Args:
      listing: data returned from aws api.
      response: relevant data returned to caller.
    """
    if listing.service == 'iam' and listing.operation == 'ListPolicies':
      response['Policies'] = [
          policy for policy in response['Policies']
          if not policy['Arn'].startswith('arn:aws:iam::aws:')
      ]


class S3OwnerFilter:
  """S3Owner filter class."""

  def execute(self, listing, response):
    """Apply filter.

    Args:
      listing: data returned from aws api.
      response: relevant data returned to caller.
    """
    # Owner Info is not necessary
    if listing.service == 's3' and listing.operation == 'ListBuckets':
      del response['Owner']


class ECSClustersFailureFilter:
  """ECSClusters filter class."""

  def execute(self, listing, response):
    """Apply filter.

    Args:
      listing: data returned from aws api.
      response: relevant data returned to caller.
    """
    if listing.service == 'ecs' and listing.operation == 'DescribeClusters':
      if 'failures' in response:
        del response['failures']


class PinpointGetAppsFilter:
  """PinpointGetApps filter class."""

  def execute(self, listing, response):
    """Apply filter.

    Args:
      listing: data returned from aws api.
      response: relevant data returned to caller.
    """
    if listing.service == 'pinpoint' and listing.operation == 'GetApps':
      response['ApplicationsResponse'] = (
          response.get('ApplicationsResponse', {}).get('Items', []))


class SSMBaselinesFilter:
  """SSMBaselines filter class."""

  def execute(self, listing, response):
    """Apply filter.

    Args:
      listing: data returned from aws api.
      response: relevant data returned to caller.
    """
    if listing.service == 'ssm' and listing.operation == 'DescribePatchBaselines':
      response['BaselineIdentities'] = [
          line for line in response['BaselineIdentities']
          if not line['BaselineName'].startswith('AWS-')
      ]


class DBSecurityGroupsFilter:
  """DBSecurityGroups filter class."""

  def execute(self, listing, response):
    """Apply filter.

    Args:
      listing: data returned from aws api.
      response: relevant data returned to caller.
    """
    if listing.service in 'rds' and listing.operation == 'DescribeDBSecurityGroups':
      response['DBSecurityGroups'] = [
          group for group in response['DBSecurityGroups']
          if group['DBSecurityGroupName'] != 'default'
      ]


class DBParameterGroupsFilter:
  """DBParameterGroups filter class."""

  def execute(self, listing, response):
    """Apply filter.

    Args:
      listing: data returned from aws api.
      response: relevant data returned to caller.
    """
    if (listing.service in ('rds', 'neptune', 'docdb')
        and listing.operation in 'DescribeDBParameterGroups'):
      response['DBParameterGroups'] = [
          group for group in response['DBParameterGroups']
          if not group['DBParameterGroupName'].startswith('default.')
      ]


class DBClusterParameterGroupsFilter:
  """DBClusterParameterGroups filter class."""

  def execute(self, listing, response):
    """Apply filter.

    Args:
      listing: data returned from aws api.
      response: relevant data returned to caller.
    """
    if (listing.service in ('rds', 'neptune', 'docdb')
        and listing.operation in 'DescribeDBClusterParameterGroups'):
      response['DBClusterParameterGroups'] = [
          group for group in response['DBClusterParameterGroups']
          if not group['DBClusterParameterGroupName'].startswith('default.')
      ]


class DBOptionGroupsFilter:
  """DBOptionGroups filter class."""

  def execute(self, listing, response):
    """Apply filter.

    Args:
      listing: data returned from aws api.
      response: relevant data returned to caller.
    """
    if listing.service == 'rds' and listing.operation == 'DescribeOptionGroups':
      response['OptionGroupsList'] = [
          group for group in response['OptionGroupsList']
          if not group['OptionGroupName'].startswith('default:')
      ]


class EC2VPCFilter:
  """EC2VPC filter class."""

  def execute(self, listing, response):
    """Apply filter.

    Args:
      listing: data returned from aws api.
      response: relevant data returned to caller.
    """
    if listing.service == 'ec2' and listing.operation == 'DescribeVpcs':
      response['Vpcs'] = [vpc for vpc in response['Vpcs']
                          if not vpc['IsDefault']]


class EC2SubnetsFilter:
  """EC2Subnets filter class."""

  def execute(self, listing, response):
    """Apply filter.

    Args:
      listing: data returned from aws api.
      response: relevant data returned to caller.
    """
    if listing.service == 'ec2' and listing.operation == 'DescribeSubnets':
      response['Subnets'] = [net for net in response['Subnets']
                             if not net['DefaultForAz']]


class EC2SecurityGroupsFilter:
  """EC2SecurityGroups filter class."""

  def execute(self, listing, response):
    """Apply filter.

    Args:
      listing: data returned from aws api.
      response: relevant data returned to caller.
    """
    if listing.service == 'ec2' and listing.operation == 'DescribeSecurityGroups':
      response['SecurityGroups'] = [sg for sg in response['SecurityGroups']
                                    if sg['GroupName'] != 'default']


class EC2RouteTablesFilter:
  """EC2RouteTables filter class."""

  def execute(self, listing, response):
    """Apply filter.

    Args:
      listing: data returned from aws api.
      response: relevant data returned to caller.
    """
    if listing.service == 'ec2' and listing.operation == 'DescribeRouteTables':
      response['RouteTables'] = [
          rt for rt in response['RouteTables']
          if not any(x['Main'] for x in rt['Associations'])
      ]


class EC2NetworkAclsFilter:
  """EC2NetworkAcls filter class."""

  def execute(self, listing, response):
    """Apply filter.

    Args:
      listing: data returned from aws api.
      response: relevant data returned to caller.
    """
    if listing.service == 'ec2' and listing.operation == 'DescribeNetworkAcls':
      response['NetworkAcls'] = [nacl for nacl in response['NetworkAcls']
                                 if not nacl['IsDefault']]


class EC2InternetGatewaysFilter:
  """EC2InternetGateways filter class."""

  def __init__(self, directory):
    self.directory = directory

  def execute(self, listing, response):
    """Apply filter.

    Args:
      listing: data returned from aws api.
      response: relevant data returned to caller.
    """
    if listing.service == 'ec2' and listing.operation == 'DescribeInternetGateways':
      vpcs_file = '{}_{}_{}_{}.json'.format(listing.service, 'DescribeVpcs',
                                            listing.region, listing.profile)
      vpcs_file = self.directory + vpcs_file
      vpcs_listing = listing.from_json(json.load(open(vpcs_file, 'rb')))
      describe_vpcs = vpcs_listing.response
      vpcs = {v['VpcId']: v for v in describe_vpcs.get('Vpcs', [])}
      internet_gateways = []
      for ig in response['InternetGateways']:
        attachments = ig.get('Attachments', [])
        if len(attachments) != 1:
          continue
        vpc = attachments[0].get('VpcId')
        if not vpcs.get(vpc, {}).get('IsDefault', False):
          internet_gateways.append(ig)
      response['InternetGateways'] = internet_gateways


class EC2FpgaImagesFilter:
  """EC2FpgaImages filter class."""

  def execute(self, listing, response):
    """Apply filter.

    Args:
      listing: data returned from aws api.
      response: relevant data returned to caller.
    """
    if listing.service == 'ec2' and listing.operation == 'DescribeFpgaImages':
      response['FpgaImages'] = [
          image for image in response.get('FpgaImages', [])
          if not image.get('Public')]


class WorkmailDeletedOrganizationsFilter:
  """WorkmailDeletedOrganizations filter class."""

  def execute(self, listing, response):
    """Apply filter.

    Args:
      listing: data returned from aws api.
      response: relevant data returned to caller.
    """
    if listing.service == 'workmail' and listing.operation == 'ListOrganizations':
      response['OrganizationSummaries'] = [
          s for s in response.get('OrganizationSummaries', [])
          if s.get('State') != 'Deleted'
      ]


class ElasticacheSubnetGroupsFilter:
  """ElasticacheSubnetGroups filter class."""

  def execute(self, listing, response):
    """Apply filter.

    Args:
      listing: data returned from aws api.
      response: relevant data returned to caller.
    """
    if listing.service == 'elasticache' and listing.operation == 'DescribeCacheSubnetGroups':
      response['CacheSubnetGroups'] = [
          g for g in response.get('CacheSubnetGroups', [])
          if g.get('CacheSubnetGroupName') != 'default'
      ]


class CountFilter:
  """Count filter class."""

  def __init__(self, complete):
    self.complete = complete

  def execute(self, listing, response):
    """Apply filter.

    Args:
      listing: data returned from aws api.
      response: relevant data returned to caller.
    """
    if 'Count' in response:
      if 'MaxResults' in response:
        if response['MaxResults'] <= response['Count']:
          self.complete = False
        del response['MaxResults']
      del response['Count']


class QuantityFilter:
  """Quantity filter class."""

  def __init__(self, complete):
    self.complete = complete

  def execute(self, listing, response):
    """Apply filter.

    Args:
      listing: data returned from aws api.
      response: relevant data returned to caller.
    """
    if 'Quantity' in response:
      if 'MaxItems' in response:
        if response['MaxItems'] <= response['Quantity']:
          self.complete = False
        del response['MaxItems']
      del response['Quantity']


class NeutralThingFilter:
  """NeutralThing filter class."""

  def execute(self, listing, response):
    """Apply filter.

    Args:
      listing: data returned from aws api.
      response: relevant data returned to caller.
    """
    for neutral_thing in ('MaxItems', 'MaxResults', 'Quantity'):
      if neutral_thing in response:
        del response[neutral_thing]


class BadThingFilter:
  """Remove unwanted responses."""

  def __init__(self, complete):
    self.complete = complete

  def execute(self, listing, response):
    """Apply filter.

    Args:
      listing: data returned from aws api.
      response: relevant data returned to caller.
    """
    for bad_thing in (
        'hasMoreResults', 'IsTruncated', 'Truncated', 'HasMoreApplications',
        'HasMoreDeliveryStreams', 'HasMoreStreams', 'NextToken', 'NextMarker',
        'nextMarker', 'Marker'
    ):
      if bad_thing in response:
        if response[bad_thing]:
          self.complete = False
        del response[bad_thing]


class NextTokenFilter:

  def __init__(self, complete):
    self.complete = complete

  def execute(self, listing, response):
    """Apply filter.

    Args:
      listing: data returned from aws api.
      response: relevant data returned to caller.
    """
    if (listing.service, listing.operation) in (('inspector', 'ListFindings'),
                                                ('logs', 'DescribeLogGroups')):
      if response.get('nextToken'):
        self.complete = False
        del response['nextToken']


def apply_filters(listing, unfilter_list, response, complete):
  """Apply filters for operations to be handled in a special way.

  Args:
    listing:
    unfilter_list:
    response:
    complete:

  Returns:
    data set with filters applied
  """
  apply_complete = complete

  if 'cloudfront' not in unfilter_list:
    filter = CloudfrontFilter()
    filter.execute(listing, response)

  if 'medialive' not in unfilter_list:
    filter = MedialiveFilter()
    filter.execute(listing, response)

  if 'ssmListCommands' not in unfilter_list:
    filter = SSMListCommandsFilter()
    filter.execute(listing, response)

  if 'snsListSubscriptions' not in unfilter_list:
    filter = SNSListSubscriptionsFilter()
    filter.execute(listing, response)

  if 'athenaWorkGroups' not in unfilter_list:
    filter = AthenaWorkGroupsFilter()
    filter.execute(listing, response)

  if 'listEventBuses' not in unfilter_list:
    filter = ListEventBusesFilter()
    filter.execute(listing, response)

  if 'xRayGroups' not in unfilter_list:
    filter = XRayGroupsFilter()
    filter.execute(listing, response)

  if 'route53Resolver' not in unfilter_list:
    filter = Route53ResolverFilter()
    filter.execute(listing, response)

  filter = CountFilter(apply_complete)
  filter.execute(listing, response)
  apply_complete = filter.complete

  filter = QuantityFilter(apply_complete)
  filter.execute(listing, response)
  apply_complete = filter.complete

  filter = NeutralThingFilter()
  filter.execute(listing, response)

  filter = BadThingFilter(apply_complete)
  filter.execute(listing, response)
  apply_complete = filter.complete

  if 'kmsListAliases' not in unfilter_list:
    filter = KMSListAliasesFilter()
    filter.execute(listing, response)

  if 'appstreamImages' not in unfilter_list:
    filter = AppstreamImagesFilter()
    filter.execute(listing, response)

  if 'cloudsearch' not in unfilter_list:
    filter = CloudsearchFilter()
    filter.execute(listing, response)

  if 'cloudTrail' not in unfilter_list:
    filter = CloudTrailFilter()
    filter.execute(listing, response)

  if 'cloudWatch' not in unfilter_list:
    filter = CloudWatchFilter()
    filter.execute(listing, response)

  if 'iamPolicies' not in unfilter_list:
    filter = IAMPoliciesFilter()
    filter.execute(listing, response)

  if 's3Owner' not in unfilter_list:
    filter = S3OwnerFilter()
    filter.execute(listing, response)

  if 'ecsClustersFailure' not in unfilter_list:
    filter = ECSClustersFailureFilter()
    filter.execute(listing, response)

  if 'pinpointGetApps' not in unfilter_list:
    filter = PinpointGetAppsFilter()
    filter.execute(listing, response)

  if 'ssmBaselines' not in unfilter_list:
    filter = SSMBaselinesFilter()
    filter.execute(listing, response)

  if 'dbSecurityGroups' not in unfilter_list:
    filter = DBSecurityGroupsFilter()
    filter.execute(listing, response)

  if 'dbParameterGroups' not in unfilter_list:
    filter = DBParameterGroupsFilter()
    filter.execute(listing, response)

  if 'dbClusterParameterGroups' not in unfilter_list:
    filter = DBClusterParameterGroupsFilter()
    filter.execute(listing, response)

  if 'dbOptionGroups' not in unfilter_list:
    filter = DBOptionGroupsFilter()
    filter.execute(listing, response)

  if 'ec2VPC' not in unfilter_list:
    filter = EC2VPCFilter()
    filter.execute(listing, response)

  if 'ec2Subnets' not in unfilter_list:
    filter = EC2SubnetsFilter()
    filter.execute(listing, response)

  if 'ec2SecurityGroups' not in unfilter_list:
    filter = EC2SecurityGroupsFilter()
    filter.execute(listing, response)

  if 'ec2RouteTables' not in unfilter_list:
    filter = EC2RouteTablesFilter()
    filter.execute(listing, response)

  if 'ec2NetworkAcls' not in unfilter_list:
    filter = EC2NetworkAclsFilter()
    filter.execute(listing, response)

  if 'ec2FpgaImages' not in unfilter_list:
    filter = EC2FpgaImagesFilter()
    filter.execute(listing, response)

  if 'workmailDeletedOrganizations' not in unfilter_list:
    filter = WorkmailDeletedOrganizationsFilter()
    filter.execute(listing, response)

  if 'elasticacheSubnetGroups' not in unfilter_list:
    filter = ElasticacheSubnetGroupsFilter()
    filter.execute(listing, response)

  filter = NextTokenFilter(apply_complete)
  filter.execute(listing, response)
  apply_complete = filter.complete

  return apply_complete