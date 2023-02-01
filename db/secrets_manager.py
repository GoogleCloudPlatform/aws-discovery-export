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
from botocore.exceptions import ClientError


class SecretsManager:
  """Helper class to connect to Secrets Manager."""

  def __init__(self, region_name):
    session = boto3.session.Session()
    self.client = session.client(
        service_name='secretsmanager', region_name=region_name)

  def get_secret(self, secret_name):
    """Get secret value for the specified secret key.

    Args:
        secret_name: secret key name

    Returns:
        Value of the secret
    """
    if not secret_name:
      return

    try:

      get_secret_value_response = self.client.get_secret_value(
          SecretId=secret_name)

      return get_secret_value_response['SecretString']

    except ClientError as e:
      raise e
