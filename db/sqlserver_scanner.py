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

import pyodbc 
import logging
from db.db_info import Query

class SqlServerScanner:
  """Helper class to scan SQL Server database."""

  def __init__(self, region):
    self.region = region

  def scan(self, rds_info, output):
    """Connects to MySQL database and collects data.

    Args:
      rds_info: Dictionary object with database connection information
      output: Dictionary object to store the collected data

    Returns:
      True if collection is successful
      False otherwise
    """
    queries = self.get_queries()
    collection = {}

    try:
      conn = pyodbc.connect(
        'Driver={SQL Server};' + 
        'SERVER=' + rds_info.host +
        ';DATABASE=master' +
        ';UID=' + rds_info.username +
        ';PWD=' + rds_info.password)
            
      for query in queries:
        try:
          cur = conn.cursor()
          cur.execute(query.query) 

          row_headers = [x[0] for x in cur.description]
          query_results = cur.fetchall()

          if query.query_type == "SQLServer_Version":
            version = query_results[0][0]

            collection["version"] = version
            output["version"] = version
          else:
            result_array = []
            for result in query_results:
              result_array.append(dict(zip(row_headers, result)))

            collection[query.query_type] = result_array

        except Exception as ex:  # pylint: disable=broad-except
          if query.query_type == "SQLServer_Version":
            raise ex
          logging.error("Failed to run %s", query.query_type)
          logging.error(ex)
      
      output["SQLServer"] = collection
      return True

    except Exception as e:   # pylint: disable=broad-except
      logging.error("Received an unexpected error")
      logging.error(e)
      return False

  def get_queries(self):
    """Gets a list of data collection queries.

    Returns:
        List of data collection queries
    """
    version_query = "select @@version as version"
    return [
      Query("SQLServer_Version", version_query),
      Query("SQLServer_DBs", "select name from sys.databases"),
      Query("SQLServer_SSISPackage", "select count(*) as ssisPackageCount from msdb.[dbo].[sysssispackages] where ownersid <>0x01"),
      Query("SQLServer_WindowsSQLLogin", "select count(*) as windowsSQLLoginCount from master..syslogins where isntname = 1 and hasaccess = 1 and loginname not like 'NT %'"),
      Query("SQLServer_StorageInGB", "select s.[name], sum (convert(Decimal(18,2), (size*8/1024)))/1024 as GB_Storage_Used from sys.master_files m join sys.databases s ON m.database_id = s.database_id group by m.database_id, s.[name]"),
      Query("SQLServer_AlwaysOn", "select CAST(coalesce(serverproperty('IsHadrEnabled') ,0) AS NVARCHAR(50)) IsHadrEnabled"),
      Query("SQLServer_FailoverCluster", "select CAST(serverproperty('IsClustered') AS NVARCHAR(50)) [IsClustered]"),
      Query("SQLServer_LogShipping", "exec master.sys.sp_help_log_shipping_monitor"),
      Query("SQLServer_MailInUse", "select CAST(value_in_use AS NVARCHAR(50)) DBMailEnabled from  sys.configurations where name = 'Database Mail XPs'"),
      Query("SQLServer_FileTable", "select count(*) FTDBs from sys.database_filestream_options where non_transacted_access_desc <> 'OFF'"),
      Query("SQLServer_MaintenancePlans", "select count(*) MaintPlans from msdb..sysmaintplan_plans"),
      Query("SQLServer_PolicyMgmtPolicies", "select count(*) PoliciesEnabled from msdb..syspolicy_policies where is_enabled =1"),
      Query("SQLServer_ExternalScripts", "select convert(int, value_in_use) as ExtScriptsEnabled from sys.configurations where (name collate Latin1_General_CI_AS) = 'external scripts enabled'"),
      Query("SQLServer_ComputeNodes", "select count(*) ComputeNodes from sys.dm_exec_compute_nodes"),
      Query("SQLServer_ResourceGovernorGroups", "select count(*) ResGovGroups from sys.resource_governor_workload_groups"),
      Query("SQLServer_Audits", "select count(*) ServerAudits from sys.server_audits"),
      Query("SQLServer_ServerLevelTriggers", "select count(*) ServTriggers from sys.server_triggers"),
      Query("SQLServer_ServiceBrokerTasks", "select count(*) ServBrokerTasks from sys.dm_broker_activated_tasks"),
      Query("SQLServer_Endpoints", "select count(*) Endpoints from sys.endpoints where state =0"),
      Query("SQLServer_CDCEnabled", "select count(*) DBsWithCdc from sys.databases where is_cdc_enabled=1"),
      Query("SQLServer_CLR", "Select count(*) UserCLRObjects from sysobjects where ObjectProperty(id, 'IsMSShipped') =0 and (xtype ='FS' or type ='FT' or type ='TA' or type ='PC')"),
      Query("SQLServer_LinkedServers", "select count(*) LinkedServiers from sys.servers where is_linked = 1"),
      Query("SQLServer_ExternalAccessAssemblies", "select count(*) ExtAccAsmblyEnabled from sys.server_permissions where permission_name = 'External access assembly' and state='G'"),
      Query("SQLServer_DQSRoles", "exec sp_msforeachdb \"select '?' as dbName,  count(name) as sqlServerDQSRoleCount from [?].sys.database_principals where name like 'dqs_%'\""),
      Query("SQLServer_FilestreamGroups", "exec sp_msforeachdb \"select '?' as dbName,  count(type) as sqlServerFileStreamGroupCount  from [?].sys.filegroups Where type = 'FD'\""),
      Query("SQLServer_DCUsers", "exec sp_msforeachdb \"select '?' as dbName,  count(name) as sqlServerDCUserCount from [?].sys.database_principals where name like 'dc_%'\""),
    ]
