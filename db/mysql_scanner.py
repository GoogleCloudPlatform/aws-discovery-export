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

import logging
from db.db_info import Query
import mysql.connector


class MysqlScanner:
  """Helper class to scan MySQL database."""

  def __init__(self, region):
    self.major_version = 0
    self.minor_version = 0
    self.region = region

  def set_version(self, version):
    version_parts = version.split(".")

    if len(version_parts) >= 2:
      self.major_version = int(version_parts[0])
      self.minor_version = int(version_parts[1])

  def cannot_process_query(self, query_type):
    """Checks whether the given query_type can be executed for the given version of MySQL.

    Args:
      query_type: query type enum value

    Returns:
      True if the query can be executed
      False otherwise
    """
    if (query_type == "MySQL_UsersWithEmptyPasswords5_6" and
        (self.major_version > 5 or
         (self.major_version == 5 and self.minor_version > 6))):
      return True

    if (query_type == "MySQL_UsersWithEmptyPasswords5_7" and
        (self.major_version < 5 or
         (self.major_version == 5 and self.minor_version < 7))):
      return True

    return False

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
      conn = mysql.connector.connect(
          host=rds_info.host,
          user=rds_info.username,
          passwd=rds_info.password,
          port=rds_info.port,
          database=rds_info.dbname)

      for query in queries:
        try:
          if self.cannot_process_query(query.query_type):
            continue

          cur = conn.cursor()
          cur.execute(query.query)
          row_headers = [x[0] for x in cur.description]
          query_results = cur.fetchall()

          if query.query_type == "MySQL_Version":
            version = query_results[0][0]
            self.set_version(version)

            collection["version()"] = version
            output["version"] = version
          else:
            result_array = []
            for result in query_results:
              result_array.append(dict(zip(row_headers, result)))

            collection[query.query_type] = result_array
        except Exception as ex:  # pylint: disable=broad-except
          if query.query_type == "MySQL_Version":
            raise ex
          logging.error("Failed to run %s", query.query_type)
          logging.error(ex)

      output["MySQL"] = collection
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
    version_query = "select version() as version"
    return [
        Query("MySQL_Version", version_query),
        Query("MySQL_VersionComment", """
select @@version_comment
"""),
        Query("MySQL_DataDir", """
select @@datadir
"""),
        Query("MySQL_Plugins", """
SHOW PLUGINS
"""),
        Query("MySQL_Engines", """
SHOW ENGINES
"""),
        Query(
            "MySQL_ConnectedApplications", """
select id, host, db, command, time, state FROM information_schema.processlist
"""),
        Query(
            "MySQL_DBSize", """
select /*+ MAX_EXECUTION_TIME(5000) */ COUNT(*) as 'TABLE_COUNT',
ROUND(sum(data_length) / ( 1024 * 1024 * 1024 ), 2) DATA,
ROUND(sum(index_length) / ( 1024 * 1024 * 1024 ), 2) INDEXES
FROM information_schema.tables
WHERE table_schema NOT IN ('mysql','performance_schema','information_schema','sys')
"""),
        Query(
            "MySQL_SizeByStorageEngine", """
select /*+ MAX_EXECUTION_TIME(5000) */ ENGINE AS Storage_Engine, COUNT(*) Tables_Count,
ROUND(SUM(data_length) / (1024*1024*1024),2) Data_Size,
ROUND(SUM(index_length)/ (1024*1024*1024),2) Index_Size
FROM information_schema.TABLES
WHERE ENGINE IS NOT NULL
AND table_schema NOT IN ('mysql', 'information_schema', 'performance_schema', 'sys')
GROUP BY ENGINE
"""),
        Query(
            "MySQL_SizeByDatabase", """
select /*+ MAX_EXECUTION_TIME(5000) */ table_schema,
ROUND(SUM(data_length)/1024/1024/1024,2) as Data_Size_GB,
ROUND(SUM(index_length)/1024/1024/1024,2) as Index_Size_GB
FROM information_schema.tables
WHERE table_schema NOT IN ('mysql', 'information_schema', 'performance_schema', 'sys')
AND TABLE_TYPE <> 'VIEW'
GROUP BY 1 ORDER BY 2 DESC
"""),
        Query(
            "MySQL_Top10LargestTables", """
select /*+ MAX_EXECUTION_TIME(5000) */ CONCAT(table_schema, '.', table_name) Schema_Table,
ROUND(table_rows / 1000000, 2) Rows_Count,
ROUND(data_length / ( 1024 * 1024 * 1024 ), 2) Data_Size,
ROUND(index_length / ( 1024 * 1024 * 1024 ), 2) Index_Size
FROM  information_schema.TABLES
WHERE table_schema NOT IN ('mysql', 'information_schema', 'performance_schema', 'sys') AND TABLE_TYPE <> 'VIEW'
ORDER BY data_length + index_length DESC LIMIT 10
"""),
        Query(
            "MySQL_TablesWithPartitions", """
select /*+ MAX_EXECUTION_TIME(5000) */ COUNT(*) AS PARTS_COUNT, TABLE_SCHEMA, TABLE_NAME, PARTITION_EXPRESSION
FROM information_schema.PARTITIONS
WHERE table_schema NOT IN ('mysql', 'information_schema', 'performance_schema', 'sys')
GROUP BY TABLE_SCHEMA, TABLE_NAME, PARTITION_EXPRESSION HAVING COUNT(*) > 1
"""),
        Query(
            "MySQL_FullTextIndexes", """
select /*+ MAX_EXECUTION_TIME(5000) */ S.table_schema, S.table_name, S.column_name, T.ENGINE AS storage_engine
FROM information_schema.STATISTICS S
JOIN information_schema.TABLES T ON S.TABLE_SCHEMA=T.TABLE_SCHEMA AND S.TABLE_NAME = T.TABLE_NAME
WHERE index_type = 'FULLTEXT'
AND S.table_schema NOT IN ('mysql', 'information_schema', 'performance_schema', 'sys')
"""),
        Query(
            "MySQL_CompressedTables", """
select /*+ MAX_EXECUTION_TIME(5000) */ CONCAT(table_schema, '.', table_name) Schema_Table,
ROUND(table_rows / 1000000, 2) Rows_Count,
ROUND(data_length / ( 1024 * 1024 * 1024 ), 2) Data_Size,
ROUND(index_length / ( 1024 * 1024 * 1024 ), 2) Index_Size
FROM  information_schema.TABLES
WHERE table_schema NOT IN ('mysql', 'information_schema', 'performance_schema', 'sys') AND ROW_FORMAT='COMPRESSED'
ORDER BY data_length + index_length DESC
"""),
        Query(
            "MySQL_TablesWithNoPK", """
select /*+ MAX_EXECUTION_TIME(5000) */ tables.table_schema, tables.table_name, tables.table_rows
FROM information_schema.tables
LEFT JOIN (
SELECT table_schema, table_name
FROM information_schema.statistics
GROUP BY table_schema, table_name, index_name
HAVING SUM(CASE WHEN non_unique = 0 AND nullable != 'YES' THEN 1 ELSE 0 END) = COUNT(*)
) puks ON tables.table_schema = puks.table_schema AND tables.table_name = puks.table_name
WHERE puks.table_name IS NULL
AND tables.table_schema NOT IN ('mysql', 'information_schema', 'performance_schema', 'sys')
AND tables.table_type = 'BASE TABLE'
"""),
        Query(
            "MySQL_UsersWithAdminAccess", """
select count(*) as userCount, host FROM mysql.user WHERE (Shutdown_Priv = 'Y' OR Super_Priv = 'Y' OR Reload_Priv = 'Y') group by host
"""),
        Query(
            "MySQL_UsersWithAccessFromAnyHost", """
select count(*) as userCount, host FROM mysql.user WHERE host = '%' OR host = '' group by host
"""),
        Query(
            "MySQL_UsersWithEmptyPasswords5_6", """
select count(*) as userCount, host FROM mysql.user WHERE  password = '' group by host
"""),
        Query(
            "MySQL_UsersWithEmptyPasswords5_7", """
select count(*) as userCount, host FROM mysql.user WHERE  authentication_string = '' group by host
"""),
        Query(
            "MySQL_ConnectionsByDatabase", """
select db, count(*) as 'count' from information_schema.processlist  group by db order by 2 desc
"""),
        Query(
            "MySQL_ConnectionsByUsers", """
select substring_index(host,':',1) as 'host',count(*) as 'count' from information_schema.processlist group by substring_index(host,':',1)
"""),
        Query(
            "MySQL_StoredProcs", """
select /*+ MAX_EXECUTION_TIME(5000) */ ROUTINE_SCHEMA, ROUTINE_NAME
FROM information_schema.ROUTINES
WHERE ROUTINE_TYPE = 'PROCEDURE' and routine_schema NOT IN ('mysql', 'information_schema', 'performance_schema', 'sys')
order by ROUTINE_SCHEMA
"""),
        Query(
            "MySQL_Functions", """
SELECT /*+ MAX_EXECUTION_TIME(5000) */ ROUTINE_SCHEMA, ROUTINE_NAME
FROM information_schema.ROUTINES
WHERE ROUTINE_TYPE = 'FUNCTION' and routine_schema NOT IN ('mysql', 'information_schema', 'performance_schema', 'sys')
order by ROUTINE_SCHEMA
"""),
        Query(
            "MySQL_Triggers", """
SELECT /*+ MAX_EXECUTION_TIME(5000) */ TRIGGER_SCHEMA,TRIGGER_NAME
FROM information_schema.TRIGGERS
WHERE trigger_schema NOT IN ('mysql', 'information_schema', 'performance_schema', 'sys')
ORDER BY TRIGGER_SCHEMA
"""),
        Query(
            "MySQL_Events", """
select /*+ MAX_EXECUTION_TIME(5000) */ event_schema,event_name
from information_schema.events
WHERE event_schema NOT IN ('mysql', 'information_schema', 'performance_schema', 'sys')
ORDER BY event_schema
"""),
        Query(
            "MySQL_DefinerClauses", """
SELECT /*+ MAX_EXECUTION_TIME(5000) */ DEFINER
FROM information_schema.views
WHERE TABLE_SCHEMA NOT IN ('mysql', 'information_schema', 'performance_schema', 'sys')
UNION
SELECT DEFINER
FROM information_schema.ROUTINES
WHERE ROUTINE_TYPE = 'PROCEDURE' and routine_schema NOT IN ('mysql', 'information_schema', 'performance_schema', 'sys')
UNION
SELECT DEFINER
FROM information_schema.ROUTINES
WHERE ROUTINE_TYPE = 'FUNCTION' and routine_schema NOT IN ('mysql', 'information_schema', 'performance_schema', 'sys')
UNION
SELECT DEFINER
FROM information_schema.TRIGGERS
WHERE trigger_schema NOT IN ('mysql', 'information_schema', 'performance_schema', 'sys')
UNION
SELECT DEFINER
FROM information_schema.events
WHERE event_schema NOT IN ('mysql', 'information_schema', 'performance_schema', 'sys')
"""),
        Query(
            "MySQL_ForeignKeys", """
SELECT /*+ MAX_EXECUTION_TIME(5000) */ CONSTRAINT_SCHEMA, CONSTRAINT_NAME, TABLE_SCHEMA, TABLE_NAME
FROM information_schema.TABLE_CONSTRAINTS
WHERE table_schema NOT IN ('mysql', 'information_schema', 'performance_schema', 'sys')
AND CONSTRAINT_TYPE= 'FOREIGN KEY'
"""),
        Query("MySQL_BinLog", """
select @@log_bin,@@log_slave_updates
"""),
        Query(
            "MySQL_GlobalVariables", """
SHOW GLOBAL STATUS WHERE VARIABLE_NAME IN ('THREADS_CONNECTED','THREADS_RUNNING', 'QUERIES')
"""),
    ]
