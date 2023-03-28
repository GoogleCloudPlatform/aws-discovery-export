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

import hashlib
import json
import logging
import os
import boto3
from db.db_info import DBConnection
from db.db_info import DBInstanceHelper
from db.mysql_scanner import MysqlScanner
from db.postgresql_scanner import PostgreSQLScanner
from db.secrets_manager import SecretsManager
from db.sqlserver_scanner import SqlServerScanner


class RdsScanner:
  """Helper class to scan rds databases."""

  def scan(self, secret_name, secret_region):
    """Connects to RDS database and collects data.

    Args:
        secret_name: Name of the RDS database credential secret key
        secret_region: Name of the RDS database credential secret region

    Returns:
        True if collection is successful
        False otherwise
    """
    try:
      secrets_manager = SecretsManager(secret_region)
      secret = json.loads(secrets_manager.get_secret(secret_name))

      rds_info = DBConnection()
      rds_info.username = secret['username']
      rds_info.password = secret['password']
      rds_info.engine = secret['engine']
      rds_info.host = secret['host']
      rds_info.port = secret['port']
      rds_info.dbname = secret['dbname'] if secret['engine'] != 'sqlserver' else 'master'

      session = boto3.session.Session()
      client = session.client(service_name='rds', region_name=secret_region)

      db_instance_helper = DBInstanceHelper()
      instance_details = db_instance_helper.get_image_size_details(
          client, secret, secret_region)

      output = {
          'instanceDetails': instance_details,
          'hostName': rds_info.host,
          'databaseName': rds_info.dbname,
          'port': rds_info.port
      }

      if secret['engine'] == 'mysql':
        output['dbType'] = 4
        scanner = MysqlScanner(secret_region)
      elif secret['engine'] == 'postgres':
        output['dbType'] = 1
        scanner = PostgreSQLScanner(secret_region)
      elif secret['engine'] == 'sqlserver':
        output['dbType'] = 2
        scanner = SqlServerScanner(secret_region)

      if not scanner.scan(rds_info, output):
        return False

      json_object = json.dumps(output, default=str)

      file_hash = hashlib.md5((rds_info.host + str(rds_info.port) +
                               rds_info.dbname).encode('utf-8')).hexdigest()
      if not os.path.exists('./output/services/'):
        os.makedirs('./output/services/')
      with open('./output/services/db_' + file_hash + '.json', 'w+',
                encoding='utf-8') as outfile:
        outfile.write(json_object)
      return True

    except Exception as e:  # pylint: disable=broad-except
      logging.error('Received an unexpected error')
      logging.error(e)
      return False
