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

import json
import logging
from db.db_info import Query
import psycopg2


class PostgreSQLScanner:
  """Helper class to scan PostgreSql database."""

  def __init__(self, region):
    self.region = region

  def scan(self, rds_info, output):
    """Connects to PostgreSql database and collects data.

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
      conn = psycopg2.connect(
          host=rds_info.host,
          port=rds_info.port,
          database=rds_info.dbname,
          user=rds_info.username,
          password=rds_info.password)

      for query in queries:
        try:
          cur = conn.cursor()
          cur.execute(query.query)
          row_headers = [x[0] for x in cur.description]
          query_results = cur.fetchall()

          if query.query_type == "PostgreSQL_Version":
            version = query_results[0][0]
            collection["version"] = version
            output["version"] = version
          else:
            result_array = []
            for result in query_results:
              result_array.append(
                  dict(zip(row_headers, self.check_result(result))))

            collection[query.query_type] = result_array
        except Exception as ex:   # pylint: disable=broad-except
          if query.query_type == "PostgreSQL_Version":
            raise ex
          logging.error("Failed to run %s", query.query_type)
          logging.error(ex)

      output["PostgreSQL"] = collection
      return True

    except Exception as e:   # pylint: disable=broad-except
      logging.error("Received an unexpected error")
      logging.error(e)
      return False

  def check_result(self, result):
    """Converts any non-primitive types in the resultset to JSON strings.

    Args:
        result: Query result set

    Returns:
        Updated results set
    """
    res = []
    for i, item in enumerate(result):
      if isinstance(item, list):
        res.append(json.dumps(item))
      else:
        res.append(result[i])
    return res

  def get_queries(self):
    """Gets a list of data collection queries.

    Returns:
        List of data collection queries
    """
    return [
        Query("PostgreSQL_Version", """
            select version()
            """),
        Query("PostgreSQL_DBFlags", """
            select * from pg_settings
            """),
        Query("PostgreSQL_Extensions", """
            select * from pg_extension
            """),
        Query(
            "PostgreSQL_ConnectedApplications", """
            select application_name, count(*) from pg_stat_activity group by 1
            """),
        Query(
            "PostgreSQL_ForeignTables", """
            select n.nspname AS "Schema", /* for foreign tables */
            c.relname AS "Table",
            s.srvname AS "Server"
            FROM pg_catalog.pg_foreign_table ft
            INNER JOIN pg_catalog.pg_class c ON c.oid = ft.ftrelid
            INNER JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
            INNER JOIN pg_catalog.pg_foreign_server s ON s.oid = ft.ftserver
            WHERE pg_catalog.pg_table_is_visible(c.oid)
            ORDER BY 1, 2
            """),
        Query(
            "PostgreSQL_TablesNoPK", """
            select round(pg_relation_size(relid)/( 1024.0 * 1024 * 1024 ), 2) as size, relname from pg_stat_user_tables where relid not in (select indrelid from pg_index where indisprimary)
            """),
        Query(
            "PostgreSQL_DiskUsage", """
            select round(pg_database_size(datname)/( 1024.0 * 1024 * 1024 ), 2) as size, * from pg_stat_database;
            """),
        Query(
            "PostgreSQL_UserRoles", """
            select r.oid::text as roleName, r.rolsuper, r.rolinherit,
            r.rolcreaterole, r.rolcreatedb, r.rolcanlogin,
            r.rolconnlimit, r.rolvaliduntil,
            ARRAY(SELECT b.rolname
                    FROM pg_catalog.pg_auth_members m
                    JOIN pg_catalog.pg_roles b ON (m.roleid = b.oid)
                    WHERE m.member = r.oid)::varchar(5000) as memberof
            , pg_catalog.shobj_description(r.oid, 'pg_authid') AS description
            , r.rolreplication
            , r.rolbypassrls
            FROM pg_catalog.pg_roles r
            WHERE r.rolname !~ '^pg_'
            ORDER BY 1
            """),
        Query(
            "PostgreSQL_UserTableStats", """
            select pg_total_relation_size(relid) as total_size, pg_relation_size(relid) as size, * from pg_stat_user_tables
            """),
        Query(
            "PostgreSQL_UserTableIOStats", """
            select * FROM pg_statio_user_tables
            """),
        Query(
            "PostgreSQL_UserTableIndexStats", """
            select pg_relation_size(s.indexrelid) as index_size, s.*, i.indisunique, i.indisprimary from pg_stat_user_indexes as s join pg_index as i using(indexrelid)
            """),
        Query(
            "PostgreSQL_IndexIOStats", """
            select * FROM pg_statio_user_indexes
            """),
        Query(
            "PostgreSQL_ReplicationSlots", """
            select * FROM pg_replication_slots
            """),
        Query(
            "PostgreSQL_ReplicationStats", """
            select * FROM pg_stat_replication
            """),
        Query("PostgreSQL_BgWriterStats", """
            select * from pg_stat_bgwriter
            """),
        Query(
            "PostgreSQL_FunctionsDefined", """
            select proowner::varchar(255), l.lanname, count(*) from pg_proc pr join pg_language l on l.oid = pr.prolang group by 1,2
            """),
    ]
