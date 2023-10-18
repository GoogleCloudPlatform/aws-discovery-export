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
        Query("PostgreSQL_Extensions", """
            select * from pg_extension
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
            "PostgreSQL_UserTableStats", """
            select pg_total_relation_size(relid) as total_size, pg_relation_size(relid) as size, * from pg_stat_user_tables
            """),
        Query(
            "PostgreSQL_AWSExtensionSchemaCheck", """
            select
                exists (
                    select
                    FROM
                    information_schema.tables
                    WHERE
                    table_schema = 'aws_oracle_ext'
                    and table_name = 'versions'
                ) as SCTOracleExtensionExists
            """),
        Query(
            "PostgreSQL_AWSExtensionVersion", """
            SELECT componentversion as AWSExtensionVersion FROM aws_oracle_ext.versions as extVersion
            """),
        Query(
            "PostgreSQL_AWSExtensionUsageDetails", """
            (with alias1 as (
  select 
    alias1.proname, 
    ns.nspname, 
    case when relkind = 'r' then 'TABLE' END AS objType, 
    depend.relname, 
    pg_get_expr(
      pg_attrdef.adbin, pg_attrdef.adrelid
    ) as def 
  from 
    pg_depend 
    inner join (
      select 
        distinct pg_proc.oid as procoid, 
        nspname || '.' || proname as proname, 
        pg_namespace.oid 
      from 
        pg_namespace, 
        pg_proc 
      where 
        nspname = 'aws_oracle_ext' 
        and pg_proc.pronamespace = pg_namespace.oid
    ) alias1 on pg_depend.refobjid = alias1.procoid 
    inner join pg_attrdef on pg_attrdef.oid = pg_depend.objid 
    inner join pg_class depend on depend.oid = pg_attrdef.adrelid 
    inner join pg_namespace ns on ns.oid = depend.relnamespace
), 
alias2 as (
  select 
    alias1.nspname as schema, 
    alias1.relname as table_name, 
    alias2.* 
  from 
    alias1 cross 
    join lateral (
      select 
        i as funcname, 
        cntgroup as cnt 
      from 
        (
          select 
            (
              regexp_matches(
                alias1.def, 'aws_oracle_ext[.][a-z]*[_,a-z,$,""]*', 
                'ig'
              )
            ) [1] i, 
            count(1) cntgroup
          group by
            (
              regexp_matches(
                alias1.def, 'aws_oracle_ext[.][a-z]*[_,a-z,$,""]*',
                'ig'
              )
            )[1]
        ) t
    ) as alias2
  where
    def ~*'aws_oracle_ext.*'
) 
select
  alias2.schema as schemaName, 
  'N/A' as language,
  'TableDefaultConstraints' as type,
  alias2.table_name as typeName, 
  alias2.funcname as AWSExtensionDependency, 
  sum(cnt) as SCTFunctionReferenceCount
from
  alias2
group by
  alias2.schema, 
  alias2.table_name, 
  alias2.funcname
)
UNION
(with alias1 as (
  select
    pgc.conname as constraint_name,
    ccu.table_schema as table_schema,
    ccu.table_name,
    ccu.column_name,
    pg_get_constraintdef(pgc.oid) as def
  from
    pg_constraint pgc
    join pg_namespace nsp on nsp.oid = pgc.connamespace
    join pg_class cls on pgc.conrelid = cls.oid
    left
  join information_schema.constraint_column_usage ccu on pgc.conname = ccu.constraint_name

and nsp.nspname = ccu.constraint_schema
  where
    contype = 'c'
  order by
    pgc.conname
),
alias2 as (
  select
    alias1.table_schema,
    alias1.constraint_name,
    alias1.table_name,
    alias1.column_name,
    alias2.*
  from
    alias1
    cross join lateral (
      select
        i as funcname,
        cntgroup as cnt
      from
        (
          select
            (
              regexp_matches(
                alias1.def,
                'aws_oracle_ext[.][a-z]*[_,a-z,$,""]*',
                'ig'
              )
            )[1] i,
            count(1) cntgroup
          group by
            (
              regexp_matches(
                alias1.def,
                'aws_oracle_ext[.][a-z]*[_,a-z,$,""]*',
                'ig'
              )
            )[1]
        ) t
    ) as alias2
  where
    def ~*'aws_oracle_ext.*'
)
select
  alias2.table_schema as schemaName, 
  'N/A' as language,
  'TableCheckConstraints' as type,
  alias2.table_name as typeName, 
  alias2.funcname as AWSExtensionDependency, 
  sum(cnt) as SCTFunctionReferenceCount
from
  alias2
group by
  alias2.table_schema,
  alias2.table_name,
  alias2.funcname
)
UNION
(with alias1 as (
  select
    alias1.proname,
    nspname,
    case when relkind = 'i' then 'INDEX' END AS objType,
    depend.relname,
    pg_get_indexdef(depend.oid) def
  from
    pg_depend
    inner join (
      select
        distinct pg_proc.oid as procoid,
        nspname || '.' || proname as proname,
        pg_namespace.oid
      from
        pg_namespace,
        pg_proc
      where
        nspname = 'aws_oracle_ext'
        and pg_proc.pronamespace = pg_namespace.oid
    ) alias1 on pg_depend.refobjid = alias1.procoid
    inner join pg_class depend on depend.oid = pg_depend.objid
    inner join pg_namespace ns on ns.oid = depend.relnamespace
  where
    relkind = 'i'
),
alias2 as (
  select
    alias1.nspname as Schema,
    alias1.relname as IndexName,
    alias2.*
  from
    alias1
    cross join lateral (
      select
        i as funcname,
        cntgroup as cnt
      from
        (
          select
            (
              regexp_matches(
                alias1.def,
                'aws_oracle_ext[.][a-z]*[_,a-z,$,""]*',
                'ig'
              )
            )[1] i,
            count(1) cntgroup
          group by
            (
              regexp_matches(
                alias1.def,
                'aws_oracle_ext[.][a-z]*[_,a-z,$,""]*',
                'ig'
              )
            )[1]
        ) t
    ) as alias2
  where
    def ~*'aws_oracle_ext.*'
)
select
  alias2.Schema as schemaName, 
  'N/A' as language,
  'TableIndexesAsFunctions' as type,
  alias2.IndexName as typeName, 
  alias2.funcname as AWSExtensionDependency, 
  sum(cnt) as SCTFunctionReferenceCount
from
  alias2
group by
  alias2.Schema,
  alias2.IndexName,
  alias2.funcname
)
UNION
(with alias1 as (
  select
    alias1.proname,
    nspname,
    case when depend.relkind = 'v' then 'VIEW' END AS objType,
    depend.relname,
    pg_get_viewdef(depend.oid) def
  from
    pg_depend
    inner join (
      select
        distinct pg_proc.oid as procoid,
        nspname || '.' || proname as proname,
        pg_namespace.oid
      from
        pg_namespace,
        pg_proc
      where
        nspname = 'aws_oracle_ext'
        and pg_proc.pronamespace = pg_namespace.oid
    ) alias1 on pg_depend.refobjid = alias1.procoid
    inner join pg_rewrite on pg_rewrite.oid = pg_depend.objid
    inner join pg_class depend on depend.oid = pg_rewrite.ev_class
    inner join pg_namespace ns on ns.oid = depend.relnamespace
  where
    not exists(
      select
        1
      from
        pg_namespace
      where
        pg_namespace.oid = depend.relnamespace
        and nspname = 'aws_oracle_ext'
    )
),
alias2 as (
  select
    alias1.nspname as Schema,
    alias1.relname as ViewName,
    alias2.*
  from
    alias1
    cross join lateral (
      select
        i as funcname,
        cntgroup as cnt
      from
        (
          select
            (
              regexp_matches(
                alias1.def,
                'aws_oracle_ext[.][a-z]*[_,a-z,$,""]*',
                'ig'
              )
            )[1] i,
            count(1) cntgroup
          group by
            (
              regexp_matches(
                alias1.def,
                'aws_oracle_ext[.][a-z]*[_,a-z,$,""]*',
                'ig'
              )
            )[1]
        ) t
    ) as alias2
  where
    def ~*'aws_oracle_ext.*'
)
select
  alias2.Schema as schemaName, 
  'N/A' as language,
  'Views' as type,
  alias2.ViewName as typeName,
  alias2.funcname as AWSExtensionDependency, 
  sum(cnt) as SCTFunctionReferenceCount
from
  alias2
group by
  alias2.Schema,
  alias2.ViewName,
  alias2.funcname
)
UNION
(with alias1 as (
  select
    distinct n.nspname as function_schema,
    p.proname as function_name,
    l.lanname as function_language,
    (
      select
        'Y'
      from
        pg_trigger
      where
        tgfoid = (n.nspname || '.' || p.proname) :: regproc
    ) as Trigger_Func,
    lower(pg_get_functiondef(p.oid) :: text) as def
  from
    pg_proc p
    left
  join pg_namespace n on p.pronamespace = n.oid

left
  join pg_language l on p.prolang = l.oid

left
  join pg_type t on t.oid = p.prorettype
  where
    n.nspname not in (
      'pg_catalog',
      'information_schema',
      'aws_oracle_ext'
    )
    and p.prokind not in ('a', 'w')
    and l.lanname in ('sql', 'plpgsql')
  order by
    function_schema,
    function_name
),
alias2 as (
  select
    alias1.function_schema,
    alias1.function_name,
    alias1.function_language,
    alias1.Trigger_Func,
    alias2.*
  from
    alias1
    cross join lateral (
      select
        i as funcname,
        cntgroup as cnt
      from
        (
          select
            (
              regexp_matches(
                alias1.def,
                'aws_oracle_ext[.][a-z]*[_,a-z,$,""]*',
                'ig'
              )
            )[1] i,
            count(1) cntgroup
          group by
            (
              regexp_matches(
                alias1.def,
                'aws_oracle_ext[.][a-z]*[_,a-z,$,""]*',
                'ig'
              )
            )[1]
        ) t
    ) as alias2
  where
    def ~*'aws_oracle_ext.*'
    and Trigger_Func = 'Y'
)
select
  function_schema as schemaName,
  function_language as language,
  'Triggers' as type,
  function_name as typeName, 
  funcname as AWSExtensionDependency, 
  sum(cnt) as SCTFunctionReferenceCount
from
  alias2
where
  1 = 1
group by
  function_schema,
  function_language,
  function_name,
  funcname
order by
  3,
  4 desc
)
UNION
(with alias1 as (
  select
    distinct n.nspname as function_schema,
    p.proname as function_name,
    l.lanname as function_language,
    (
      select
        'Y'
      from
        pg_trigger
      where
        tgfoid = (n.nspname || '.' || p.proname) :: regproc
    ) as Trigger_Func,
    lower(pg_get_functiondef(p.oid) :: text) as def
  from
    pg_proc p
    left
  join pg_namespace n on p.pronamespace = n.oid

left
  join pg_language l on p.prolang = l.oid

left
  join pg_type t on t.oid = p.prorettype
  where
    n.nspname not in (
      'pg_catalog',
      'information_schema',
      'aws_oracle_ext'
    )
    and p.prokind not in ('a', 'w', 'p')
    and l.lanname in ('sql', 'plpgsql')
  order by
    function_schema,
    function_name
),
alias2 as (
  select
    alias1.function_schema,
    alias1.function_name,
    alias1.function_language,
    alias1.Trigger_Func,
    alias2.*
  from
    alias1
    cross join lateral (
      select
        i as funcname,
        cntgroup as cnt
      from
        (
          select
            (
              regexp_matches(
                alias1.def,
                'aws_oracle_ext[.][a-z]*[_,a-z,$,""]*',
                'ig'
              )
            )[1] i,
            count(1) cntgroup
          group by
            (
              regexp_matches(
                alias1.def,
                'aws_oracle_ext[.][a-z]*[_,a-z,$,""]*',
                'ig'
              )
            )[1]
        ) t
    ) as alias2
  where
    def ~*'aws_oracle_ext.*'
    and alias1.Trigger_Func is NULL
)
select
  function_schema as schemaName,
  function_language as language,
  'Functions' as type,
  function_name as typeName, 
  funcname as AWSExtensionDependency, 
  sum(cnt) as SCTFunctionReferenceCount
from
  alias2
where
  1 = 1
group by
  function_schema,
  function_language,
  function_name,
  funcname
order by
  3,
  4 desc
)

UNION

(with alias1 as (
  select
    distinct n.nspname as function_schema,
    p.proname as function_name,
    l.lanname as function_language,
    (
      select
        'Y'
      from
        pg_trigger
      where
        tgfoid = (n.nspname || '.' || p.proname) :: regproc
    ) as Trigger_Func,
    lower(pg_get_functiondef(p.oid) :: text) as def
  from
    pg_proc p
    left
  join pg_namespace n on p.pronamespace = n.oid

left
  join pg_language l on p.prolang = l.oid

left
  join pg_type t on t.oid = p.prorettype
  where
    n.nspname not in (
      'pg_catalog',
      'information_schema',
      'aws_oracle_ext'
    )
    and p.prokind not in ('a', 'w', 'f')
    and l.lanname in ('sql', 'plpgsql')
  order by
    function_schema,
    function_name
),
alias2 as (
  select
    alias1.function_schema,
    alias1.function_name,
    alias1.function_language,
    alias1.Trigger_Func,
    alias2.*
  from
    alias1
    cross join lateral (
      select
        i as funcname,
        cntgroup as cnt
      from
        (
          select
            (
              regexp_matches(
                alias1.def,
                'aws_oracle_ext[.][a-z]*[_,a-z,$,""]*',
                'ig'
              )
            )[1] i,
            count(1) cntgroup
          group by
            (
              regexp_matches(
                alias1.def,
                'aws_oracle_ext[.][a-z]*[_,a-z,$,""]*',
                'ig'
              )
            )[1]
        ) t
    ) as alias2
  where
    def ~*'aws_oracle_ext.*'
)
select
  function_schema as schemaName,
  function_language as language,
  'Procedures' as type,
  function_name as typeName, 
  funcname as AWSExtensionDependency, 
  sum(cnt) as SCTFunctionReferenceCount
from
  alias2
where
  1 = 1
group by
  function_schema,
  function_language,
  function_name,
  funcname
order by
  3,
  4 desc
)
            """),
    ]
