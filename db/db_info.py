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

version 1.5.1
"""

import boto3


class DBConnection:
  """Class to store database connection info."""

  def __init__(self):
    self.username = ''
    self.password = ''
    self.engine = ''
    self.host = ''
    self.port = -1,
    self.dbname = ''


class Query:
  """Class to store data collection query."""

  def __init__(self, query_type, query):
    self.query_type = query_type
    self.query = query


class DBInstanceHelper:
  """Class to get database image size details."""

  def get_image_size_details(self, rds_client, secret, region):
    """Get image size details.

    Args:
        rds_client: RDS boto3 client
        secret: secret value to RDS database
        region: resource region

    Returns:
        Dictionary object with instance details.
    """
    instance_type = rds_client.describe_db_instances(
        DBInstanceIdentifier=secret['dbInstanceIdentifier']
    )['DBInstances'][0]['DBInstanceClass']
    allocated_storage = rds_client.describe_db_instances(
        DBInstanceIdentifier=secret['dbInstanceIdentifier']
    )['DBInstances'][0]['AllocatedStorage']
    storage_type = rds_client.describe_db_instances(
        DBInstanceIdentifier=secret['dbInstanceIdentifier']
    )['DBInstances'][0]['StorageType']

    if instance_type.startswith('db.'):
      instance_type = instance_type[3:]

    client = boto3.client('ec2', region)
    instance_type_info = (
        client.describe_instance_types(InstanceTypes=[
            instance_type,
        ]).get('InstanceTypes'))

    return {
        'instanceType': instance_type,
        'allocatedStorage': allocated_storage,
        'storageType': storage_type,
        'memory': instance_type_info[0]['MemoryInfo']['SizeInMiB'] / 1024,
        'cpu': instance_type_info[0]['VCpuInfo']['DefaultVCpus']
    }
