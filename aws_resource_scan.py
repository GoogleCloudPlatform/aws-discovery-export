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

import collections
import contextlib
import functools
import json
from multiprocessing.pool import ThreadPool
import random
import sys
import time
import traceback

import boto3
import filter_aws
import reference_aws


class Resources:
  resource_array = []
  resource_count = 0

_clients = {}
_resource_list = []

verbs_listings = ['Describe', 'Get', 'List']

result_nothing = '---'
result_something = '+++'
result_error = '!!!'
result_no_access = '>:|'

# Resource object definition
resource_info = {
    'ResourceGroup': '',
    'Location': '',
    'ResourceType': '',
    'Tags': '',
    'Name': '',
    'Source': 'AWS'
}

# resource name mapping
object_name_map = {
    'ec2.Vpcs': 'vpcid',
    'ec2.InternetGateways': 'InternetGatewayId',
    'ec2.Subnets': 'SubnetId',
    'ec2.Instances': 'InstanceId',
    'ec2.KeyPairs': 'KeyName'
}


not_available_strings = (reference_aws.not_available_for_region_strings +
                         reference_aws.not_available_for_account_strings)


class RawListing(object):
  """Represents a listing operation on an AWS service and its result."""

  def __init__(self, service, region, operation, response, error=''):
    self.service = service
    self.region = region
    self.operation = operation
    self.response = response
    self.error = error

  def to_json(self):
    """Return data in json format.

    Returns:
      data in json format
    """
    return {
        'service': self.service,
        'region': self.region,
        'operation': self.operation,
        'response': self.response,
        'error': self.error,
    }

  def find_dict_extract(self, key, var):
    """Find a specified key in current AWS data.

    Args:
      key: key to search for.
      var: list or dictionary containing data.

    Returns:
      boolean indicating if key was found and value of the key.
    """
    if hasattr(var, 'items'):
      for k, v in var.items():
        if k == key:
          return True, v
        if isinstance(v, dict):
          is_found, return_val = self.find_dict_extract(key, v)
          if is_found:
            return True, return_val
        elif isinstance(v, list):
          for d in v:
            is_found, return_val = self.find_dict_extract(key, d)
            if is_found:
              return True, return_val
      return False, None
    else:
      return False, None

  def lookup_name_property(self, lookup_key):
    """Lookup property containing resource name in the map.

    Args:
      lookup_key: key name to search for

    Returns:
      if found it returns field name
    """

    if lookup_key in object_name_map:
      return object_name_map[lookup_key]
    else:
      return 'Name'

  def add_to_dictionary(self):
    """Add current resource to the list for future dump to json file."""
    try:
      if self.operation == 'DescribeLoadBalancers':
        container_name = 'LoadBalancerDescriptions'
      elif self.operation == 'ListAccessKeys':
        container_name = 'AccessKeyMetadata'
      else:
        container_name = self.operation.replace('Describe', '')
        container_name = container_name.replace('List', '')
        container_name = container_name.replace('Get', '')

      is_found, found_resource_data = self.find_dict_extract(container_name,
                                                             self.response)
      item_count = 0

      if is_found:
        for i in found_resource_data:
          found_resource = resource_info.copy()
          found_resource['Location'] = self.region
          found_resource['ResourceType'] = self.service + '/' + container_name
          lookup_name = self.service + '.' + container_name

          item_count = item_count + 1
          tags_found, find_tags = self.find_dict_extract('Tags', i)
          if tags_found:
            assigned_tags = {}
            for t in find_tags:
              assigned_tags[t['Key']] = t['Value']
              found_resource['Tags'] = assigned_tags

          name_found, find_name = self.find_dict_extract(
              self.lookup_name_property(lookup_name), i)
          if name_found:
            found_resource['Name'] = find_name
          else:
            found_resource['Name'] = lookup_name
          _resource_list.append(found_resource)

    except Exception as exc:
      print('Exception: ' + str(exc))

  @classmethod
  def from_json(cls, data):
    """Return data contained by json file.

    Args:
      data: data to be converted.

    Returns:
      data.
    """
    return cls(
        service=data.get('service'),
        region=data.get('region'),
        operation=data.get('operation'),
        response=data.get('response'),
        error=data.get('error')
    )

  def __str__(self):
    opdesc = '{} {} {}'.format(self.service, self.region, self.operation)
    if len(self.resource_types) == 0 or self.resource_total_count == 0:
      return '{} (no resources found)'.format(opdesc)
    return opdesc + ', '.join('#{}: {}'.format(key, len(listing)) for key,
                              listing in self.resources.items())

  @classmethod
  def acquire(cls, service, region, operation):
    """Acquire the given listing by making an AWS request.

    Args:
      service: aws service name.
      region: aws region name.
      operation: service operation

    Returns:
      list.
    """
    response = run_raw_listing_operation(service, region, operation)
    if response['ResponseMetadata']['HTTPStatusCode'] != 200:
      raise ValueError('Bad AWS HTTP Status Code', response)
    return cls(service, region, operation, response)

  @property
  def resources(self):
    """Transform the response data into a dict of resource names.

      Args:
        self: instance of the class

      Returns:
        response.
    """
    if not self.response:
      return self.response.copy()
    response = self.response.copy()
    complete = True

    del response['ResponseMetadata']

    for key, value in response.items():
      if not isinstance(value, list):
        raise ValueError('No listing: {} is no list:'.format(key), response)

    if not complete:
      response['truncated'] = [True]

    return response


class FilteredListing(object):
  """Filter objects."""

  def __init__(self, input, directory='./', unfilter=None):
    self.input = input
    self.directory = directory
    self.unfilter = [] if unfilter is None else unfilter

  @property
  def resource_types(self):
    """The list of resource types (Keys with list content) in the response.

      Args:
        self: instance of the class.

      Returns:
        list of keys.
    """
    return list(self.resources.keys())

  @property
  def resource_total_count(self):
    """The estimated total count of resources - can be incomplete.

      Args:
        self: instance of the class.

      Returns:
        resource count.
    """
    return sum(len(v) for v in self.resources.values())

  def __str__(self):
    opdesc = '{} {} {} '.format(self.input.service, self.input.region,
                                self.input.operation)
    if len(self.resource_types) == 0 or self.resource_total_count == 0:
      return '{} (no resources found)'.format(opdesc)
    return opdesc + ', '.join('#{}: {}'.format(key, len(listing)) for key,
                              listing in self.resources.items())

  @property
  def resources(self):
    """Transform the response into a dict of names to resource listings.

      Args:
        self: instance of the class.

      Returns:
        resource listing.
    """
    if not self.input.response:
      return self.input.response.copy()
    response = self.input.response.copy()
    complete = True
    del response['ResponseMetadata']

    complete = filter_aws.apply_filters(self.input, self.unfilter,
                                        response, complete)
    unfilter_list = self.unfilter

    # Special handling for service-level kms keys; derived from alias name.
    if ('kmsListKeys' not in unfilter_list and self.input.service == 'kms' and
        self.input.operation == 'ListKeys'):
      try:
        aliases_file = '{}_{}_{}.json'.format(self.input.service,
                                              'ListAliases', self.input.region)
        aliases_file = self.directory + '/' + aliases_file
        aliases_listing = RawListing.from_json(
            json.load(open(aliases_file, 'rb')))
        list_aliases = aliases_listing.response
        service_key_ids = [
            k.get('TargetKeyId') for k in list_aliases.get('Aliases', [])
            if k.get('AliasName').lower().startswith('alias/aws')
        ]
        response['Keys'] = [k for k in response.get('Keys', [])
                            if k.get('KeyId') not in service_key_ids]
      except Exception as exc:
        self.input.error = repr(exc)

    # Filter default Internet Gateways
    if ('ec2InternetGateways' not in unfilter_list and
        self.input.service == 'ec2' and
        self.input.operation == 'DescribeInternetGateways'):
      try:
        vpcs_file = '{}_{}_{}.json'.format(self.input.service,
                                           'DescribeVpcs', self.input.region)
        vpcs_file = self.directory + '/' + vpcs_file
        vpcs_listing = RawListing.from_json(json.load(open(vpcs_file, 'rb')))
        describe_vpcs = vpcs_listing.response
        vpcs = {v['VpcId']: v for v in describe_vpcs.get('Vpcs', [])}
        internet_gateways = []
        for ig in response['InternetGateways']:
          attachments = ig.get('Attachments', [])
          # more than one, it cannot be default.
          if len(attachments) != 1:
            continue
          vpc = attachments[0].get('VpcId')
          if not vpcs.get(vpc, {}).get('IsDefault', False):
            internet_gateways.append(ig)
        response['InternetGateways'] = internet_gateways
      except ValueError as exc:
        self.input.error = repr(exc)

    for key, value in response.items():
      if not isinstance(value, list):
        raise ValueError('No listing: {} is no list:'.format(key), response)

    if not complete:
      response['truncated'] = [True]

    return response


class ResultListing(object):
  """Listing result summary acquired from the function acquire_listing."""

  def __init__(self, input, result_type, details):
    self.input = input
    self.result_type = result_type
    self.details = details

  @property
  def to_tuple(self):
    """Return a tuple of strings describing the result of an executed query.

      Args:
        self: instance of the class.

      Returns:
        tuple.
    """
    return (self.result_type, self.input.service, self.input.region,
            self.input.operation, self.details)


def get_client(service, region=None):
  """Return (cached) boto3 clients for this service and this region.

  Args:
    service: aws service name.
    region: aws region name.
  Returns:
    list of current clients.
  """
  if (service, region) not in _clients:

    _clients[(service, region)] = (
        boto3.Session(region_name=region).client(service))
  return _clients[(service, region)]


def get_services():
  """Return a list of all service names.

  Returns:
    List of resources.
  """
  return [service for service in sorted(
      boto3.Session().get_available_services())
          if service not in reference_aws.SERVICE_BLACKLIST]


def get_regions_for_service(requested_service, requested_regions=()):
  """Get regions where service is available.

  Args:
    requested_service: aws service name.
    requested_regions: aws region name.

  Returns:
    List of regions.
  """
  if requested_service in ('iam', 'cloudfront', 's3', 'route53'):
    return [None]

  regions = requested_regions
  return list(regions)


def get_listing_operations(service, region=None, selected_operations=()):
  """Return a list of API calls.

  Return a list of API calls which (probably) list
  resources created by the user
  in the given service (in contrast to AWS-managed or default resources).

  Args:
    service: aws service name.
    region: aws region name.
    selected_operations: service operations.

  Returns:
    list of operations.
  """
  client = get_client(service, region)
  operations = []

  for operation in sorted(client.meta.service_model.operation_names):
    if not any(operation.startswith(prefix) for prefix in verbs_listings):
      continue
    op_model = client.meta.service_model.operation_model(operation)
    required_members = (op_model.input_shape.required_members
                        if op_model.input_shape else [])
    required_members = [m for m in required_members if m != 'MaxResults']
    if required_members:
      continue

    if operation in reference_aws.PARAMETERS_REQUIRED.get(service, []):
      continue
    if operation in reference_aws.AWS_RESOURCE_QUERIES.get(service, []):
      continue
    if operation in reference_aws.NOT_RESOURCE_DESCRIPTIONS.get(service, []):
      continue
    if operation in reference_aws.DEPRECATED_OR_DISALLOWED.get(service, []):
      continue

    if selected_operations and operation not in selected_operations:
      continue
    operations.append(operation)

  return operations


def run_raw_listing_operation(service, region, operation):
  """Execute a given operation and return its raw result.

  Args:
    service: aws service name.
    region: aws region name.
    operation: service operation.
  Returns:
    Data attributes.
  """
  client = get_client(service, region)
  api_to_method_mapping = dict((v, k) for k, v in
                               client.meta.method_to_api_mapping.items())
  parameters = reference_aws.PARAMETERS.get(service, {}).get(operation, {})
  op_model = client.meta.service_model.operation_model(operation)
  required_members = (op_model.input_shape.required_members
                      if op_model.input_shape else [])

  if 'MaxResults' in required_members:
    parameters['MaxResults'] = 10
  return getattr(client, api_to_method_mapping[operation])(**parameters)


def acquire_listing(verbose, what):
  """Acquire resource listing.

  Given a service, region and operation execute the operation,
  serialize and save the result and
  return a tuple of strings describing the result.

  Args:
    verbose: verbose mode flag.
    what: service, region, operation.
  Returns:
    result listing.
  """
  service, region, operation = what
  start_time = time.time()
  try:
    if verbose > 1:
      print(what, 'starting request...')
    listing = RawListing.acquire(service, region, operation)
    listing_file = FilteredListing(listing, './', None)
    duration = time.time() - start_time
    if verbose > 1:
      print(what, '...request successful')
      print('timing [success]:', duration, what)

    resource_count = listing_file.resource_total_count
    if listing_file.input.error == result_error:
      return ResultListing(listing, result_error,
                           'Error(Error during processing of resources)')
    if resource_count > 0:
      listing.add_to_dictionary()
      return ResultListing(listing, result_something,
                           ', '.join(listing_file.resource_types))
    else:
      return ResultListing(listing, result_nothing,
                           ', '.join(listing_file.resource_types))
  except Exception as exc:  # pylint:disable=broad-except
    duration = time.time() - start_time
    if verbose > 1:
      print(what, '...exception:', exc)
      print('timing [failure]:', duration, what)
    if verbose > 2:
      traceback.print_exc()
    result_type = (result_no_access if 'AccessDeniedException'
                   in str(exc) else result_error)
    if (service == 'ec2' and operation == 'DescribeInstances'):
      print(exc)

    ignored_err = reference_aws.RESULT_IGNORE_ERRORS.get(
        service, {}).get(operation)
    if ignored_err is not None:
      if not isinstance(ignored_err, list):
        ignored_err = list(ignored_err)
      for ignored_str_err in ignored_err:
        if ignored_str_err in str(exc):
          result_type = result_nothing

    for not_available_string in not_available_strings:
      if not_available_string in str(exc):
        result_type = result_nothing

    listing = RawListing(service, region, operation, {}, result_type)
    return ResultListing(listing, result_type, repr(exc))


def execute_query(to_run, verbose, parallel, results_by_type):
  """Execute created queries.

  Args:
    to_run: queries to execute.
    verbose: enable verbose mode.
    parallel: number of threads to start.
    results_by_type: query results.

  Returns:
    results by type
  """
  # the `with` block is a workaround for a bug:
  # https://bugs.python.org/issue35629
  with contextlib.closing(ThreadPool(parallel)) as pool:
    for result in pool.imap_unordered(functools.partial(acquire_listing,
                                                        verbose), to_run):
      results_by_type[result.result_type].append(result)

      if verbose > 1:
        print('ExecutedQueryResult: {}'.format(result.to_tuple))
      else:
        sys.stdout.flush()
  return results_by_type


def do_query(services, selected_regions=(), selected_operations=(), verbose=0,
             parallel=32):
  """For the given services, execute all selected operations.

  Args:
    services: specified services.
    selected_regions: specified regions.
    selected_operations: if limiting operations list here.
    verbose: enable verbose mode.
    parallel: number of threads to spin up. default=32.
  """
  to_run = []
  dependencies = {}

  for service in services:

    for region in get_regions_for_service(service, selected_regions):

      for operation in get_listing_operations(service,
                                              region, selected_operations):

        if operation in reference_aws.DEPENDENT_OPERATIONS:
          dependencies[reference_aws.DEPENDENT_OPERATIONS[operation],
                       region] = ([service, region,
                                reference_aws.DEPENDENT_OPERATIONS[operation]])
        if operation in reference_aws.DEPENDENT_OPERATIONS.values():
          dependencies[operation, region] = [service, region, operation]
          continue

        to_run.append([service, region, operation])

  random.shuffle(to_run)  # Distribute requests across endpoints
  results_by_type = collections.defaultdict(list)

  results_by_type = execute_query(dependencies.values(), verbose,
                                  parallel, results_by_type)
  results_by_type = execute_query(to_run, verbose, parallel, results_by_type)


def scan_aws(service_collection, region_list):
  """Start scan of all AWS regions looking for specified services.

  Args:
    service_collection: service collection type. Default is basic limiting.
        search to most common services, full would search for all services.
    region_list: list of regions to search.
  """
  Resources.resource_array = []
  Resources.resource_count = 0

  operation = []
  parallel = 40

  if service_collection == 'basic':
    services = ['ec2', 's3', 'route53', 'apigatewayv2', 'appconfig',
                'appstream', 'appconfigdata', 'application-autoscaling',
                'autoscaling', 'eks', 'efs', 'ebs', 'lambda', 'rds', 'sns',
                'cloudfront', 'elasticbeanstalk', 'iam', 'glacier', 'kinesis',
                'dynamodb', 'elasticache', 'redshift', 'sagemaker', 'sqs',
                'lightsail', 'cloudwatch', 'chime', 'clouddirectory']
  else:
    services = get_services()

  global _clients

  region_count = 0
  for region in region_list:
    region_count = region_count + 1

    regions = [region]
    do_query(
        services,
        regions,
        operation,
        verbose=0,
        parallel=parallel
    )
    _clients = {}

  with open('./output/resources.json', 'w+', encoding='utf-8') as f:
    json.dump(_resource_list, f, ensure_ascii=False, indent=4)

  return
