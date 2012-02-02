/*
 * dbmodule.cpp
 *
 *  Created on: Jan 20, 2012
 *      Author: root
 */

#include "dbmodule.h"
#include "basemodule.h"
#include "baseapp.h"

const char * CONST_db_name = "acedb";

//this class is internal for implementation only. invisible outside of dbmodule
class MyPGResultGuard
{
public:
  MyPGResultGuard(PGresult * res): m_result(res)
  {}
  ~MyPGResultGuard()
  {
    PQclear(m_result);
  }

private:
  MyPGResultGuard(const MyPGResultGuard &);
  MyPGResultGuard & operator = (const MyPGResultGuard &);

  PGresult * m_result;
};

//MyDB//

MyDB::MyDB()
{
  m_connection = NULL;
}

MyDB::~MyDB()
{
  disconnect();
}

bool MyDB::connect()
{
  ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, false);
  if (connected())
    return true;
  MyConfig * cfg = MyConfigX::instance();
  const char * connect_str_template = "hostaddr=%s port=%d user='%s' password='%s' dbname=acedb";
  const int STRING_LEN = 1024;
  char connect_str[STRING_LEN];
  ACE_OS::snprintf(connect_str, STRING_LEN - 1, connect_str_template,
      cfg->db_server_addr.c_str(), cfg->db_server_port, cfg->db_user_name.c_str(), cfg->db_password.c_str());
  m_connection = PQconnectdb(connect_str);
  MY_INFO("start connecting to database\n");
  bool result = (PQstatus(m_connection) == CONNECTION_OK);
  if (!result)
  {
    MY_ERROR("connect to database failed, msg = %s\n", PQerrorMessage(m_connection));
    PQfinish(m_connection);
    m_connection = NULL;
  }
  else
    MY_INFO("connect to database OK\n");
  return result;

}

void MyDB::disconnect()
{
  if (connected())
  {
    PQfinish(m_connection);
    m_connection = NULL;
  }
}

bool MyDB::connected() const
{
  return m_connection != NULL;
}

bool MyDB::begin_transaction()
{
  return exec_command("BEGIN");
}

bool MyDB::commit()
{
  return exec_command("COMMIT");
}

bool MyDB::rollback()
{
  return exec_command("ROLLBACK");
}

const char * MyDB::wrap_str(const char * s) const
{
  if (!s || !*s)
    return "null";
  else
    return s;
}

bool MyDB::exec_command(const char * sql_command)
{
  if (unlikely(!sql_command))
    return false;
  PGresult * pres = PQexec(m_connection, sql_command);
  MyPGResultGuard guard(pres);
  if (!pres || PQresultStatus(pres) != PGRES_COMMAND_OK)
  {
    MY_ERROR("MyDB::exec_command(%s) failed: %s\n", sql_command, PQerrorMessage(m_connection));
    return false;
  } else
    return true;
}

bool MyDB::get_client_ids(MyClientIDTable * id_table)
{
  if (unlikely(!id_table))
    return false;
  ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, false);

  const char * CONST_select_sql_template = "select client_id, auto_seq "
                                           "from tb_clients where auto_seq > %d order by auto_seq";
  char select_sql[1024];
  ACE_OS::snprintf(select_sql, 1024 - 1, CONST_select_sql_template, id_table->last_sequence());

  PGresult * pres = PQexec(m_connection, select_sql);
  MyPGResultGuard guard(pres);
  if (!pres || PQresultStatus(pres) != PGRES_TUPLES_OK)
  {
    MY_ERROR("MyDB::sql (%s) failed: %s\n", select_sql, PQerrorMessage(m_connection));
    return false;
  }
  int count = PQntuples(pres);
  if (count > 0)
  {
    id_table->prepare_space(count);
    for (int i = 0; i < count; ++i)
      id_table->add(PQgetvalue(pres, i, 0));
    int last_seq = atoi(PQgetvalue(pres, count - 1, 1));
    id_table->last_sequence(last_seq);
  }

  MY_INFO("MyDB::get %d client_IDs from database\n", count);
  return true;
}

bool MyDB::save_client_id(const char * s)
{
  MyClientID id = s;
  id.trim_tail_space();
  if (id.as_string()[0] == 0)
    return false;

  const char * insert_sql_template = "insert into tb_clients(client_id) values(%s)";
  char insert_sql[1024];
  ACE_OS::snprintf(insert_sql, 1024 - 1, insert_sql_template, id.as_string());

  ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, false);
  return exec_command(insert_sql);
}

bool MyDB::save_dist(MyHttpDistRequest & http_dist_request)
{
  const char * insert_sql_template = "insert into tb_dist_info("
               "dist_id, dist_type, dist_aindex, dist_findex, dist_fdir,"
               "dist_ftype, dist_adir, dist_password) values(%s, %s, %s, %s, %s, %s, %s. %s)";
  char insert_sql[4096];
  ACE_OS::snprintf(insert_sql, 4096 - 1, insert_sql_template,
      http_dist_request.ver, http_dist_request.type, wrap_str(http_dist_request.aindex),
      wrap_str(http_dist_request.findex),  wrap_str(http_dist_request.fdir),
      http_dist_request.ftype, wrap_str(http_dist_request.adir), http_dist_request.password);

  ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, false);
  return exec_command(insert_sql);
}

bool MyDB::save_dist_clients(char * idlist, const char * dist_id)
{
  const char * insert_sql_template = "insert into tb_dist_clients(dc_dist_id, dc_client_id) values(%s, %s)";
  char insert_sql[1024];

  char seperator[2] = {';', 0};
  char *str, *token, *saveptr;
  const int BATCH_COUNT = 20;
  int i = 0, total = 0, ok = 0;
  for (str = idlist; ; str = NULL)
  {
    token = strtok_r(str, seperator, &saveptr);
    if (!token)
      break;
    if (!*token)
      continue;
    total ++;
    if (i == 0)
    {
      if (!begin_transaction())
      {
        MY_ERROR("failed to begin transaction @MyDB::save_dist_clients\n");
        return false;
      }
    }
    ACE_OS::snprintf(insert_sql, 1024 - 1, insert_sql_template, dist_id, token);
    exec_command(insert_sql);
    ++i;
    if (i == BATCH_COUNT)
    {
      if (!commit())
      {
        MY_ERROR("failed to commit transaction @MyDB::save_dist_clients\n");
        rollback();
      } else
        ok += i;

      i = 0;
    }
  }

  if (i != 0)
  {
    if (!commit())
    {
      MY_ERROR("failed to commit transaction @MyDB::save_dist_clients\n");
      rollback();
    } else
      ok += i;
  }

  MY_INFO("MyDB::save_dist_clients success/total = %d/%d\n", ok, total);
  return true;
}
