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

time_t MyDB::get_time_from_string(const char * s)
{
  static time_t _current = time(NULL);
  const time_t const_longevity = const_one_year * 10;

  if (unlikely(!s || !*s))
    return 0;
  struct tm _tm;
  int ret = sscanf(s, "%04d-%02d-%02d %02d:%02d:%02d", &_tm.tm_year, &_tm.tm_mon, &_tm.tm_mday,
      &_tm.tm_hour, &_tm.tm_min, &_tm.tm_sec);
  _tm.tm_year -= 1900;
  _tm.tm_mon -= 1;
  _tm.tm_isdst = -1;
  if (ret != 6 || _tm.tm_year <= 0)
    return 0;

  time_t result = mktime(&_tm);
  if (result + const_longevity < _current || _current + const_longevity < result)
    return 0;

  return result;
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

bool MyDB::ping_db_server()
{
  ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, false);
  const char * select_sql = "select ('now'::text)::timestamp(0) without time zone";
  exec_command(select_sql);
  return check_db_connection();
}

bool MyDB::check_db_connection()
{
  if (unlikely(!connected()))
    return false;
  ConnStatusType cst = PQstatus(m_connection);
  if (cst == CONNECTION_BAD)
  {
    MY_ERROR("connection to db lost, trying to re-connect...\n");
    PQreset(m_connection);
    cst = PQstatus(m_connection);
    if (cst == CONNECTION_BAD)
    {
      MY_ERROR("reconnect to db failed: %s\n", PQerrorMessage(m_connection));
      return false;
    } else
      MY_INFO("reconnect to db OK!\n");
  }
  return true;
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

void MyDB::wrap_str(const char * s, MyPooledMemGuard & wrapped) const
{
  if (!s || !*s)
    wrapped.init_from_string("null");
  else
    wrapped.init_from_string("'", s, "'");
}

time_t MyDB::get_db_time_i()
{
  const char * CONST_select_sql = "select ('now'::text)::timestamp(0) without time zone";
  PGresult * pres = PQexec(m_connection, CONST_select_sql);
  MyPGResultGuard guard(pres);
  if (!pres || PQresultStatus(pres) != PGRES_TUPLES_OK)
  {
    MY_ERROR("MyDB::sql (%s) failed: %s\n", CONST_select_sql, PQerrorMessage(m_connection));
    return 0;
  }
  if (unlikely(PQntuples(pres) <= 0))
    return 0;
  return get_time_from_string(PQgetvalue(pres, 0, 0));
}

bool MyDB::exec_command(const char * sql_command, int * affected)
{
  if (unlikely(!sql_command || !*sql_command))
    return false;
  PGresult * pres = PQexec(m_connection, sql_command);
  MyPGResultGuard guard(pres);
  if (!pres || (PQresultStatus(pres) != PGRES_COMMAND_OK && PQresultStatus(pres) != PGRES_TUPLES_OK))
  {
    MY_ERROR("MyDB::exec_command(%s) failed: %s\n", sql_command, PQerrorMessage(m_connection));
    return false;
  } else
  {
    if (affected)
    {
      const char * s = PQcmdTuples(pres);
      if (!s || !*s)
        *affected = 0;
      else
        *affected = atoi(PQcmdTuples(pres));
    }
    return true;
  }
}

bool MyDB::get_client_ids(MyClientIDTable * id_table)
{
  MY_ASSERT_RETURN(id_table != NULL, "null id_table @MyDB::get_client_ids\n", false);

  const char * CONST_select_sql_template = "select client_id, client_password, client_expired, auto_seq "
                                           "from tb_clients where auto_seq > %d order by auto_seq";
  char select_sql[1024];
  ACE_OS::snprintf(select_sql, 1024 - 1, CONST_select_sql_template, id_table->last_sequence());

  ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, false);
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
    bool expired;
    const char * p;
    for (int i = 0; i < count; ++i)
    {
      p = PQgetvalue(pres, i, 2);
      expired = p && (*p == 't' || *p == 'T');
      id_table->add(PQgetvalue(pres, i, 0), PQgetvalue(pres, i, 1), expired);
    }
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

  const char * insert_sql_template = "insert into tb_clients(client_id) values('%s')";
  char insert_sql[1024];
  ACE_OS::snprintf(insert_sql, 1024, insert_sql_template, id.as_string());

  ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, false);
  return exec_command(insert_sql);
}

bool MyDB::save_dist(MyHttpDistRequest & http_dist_request, const char * md5, const char * mbz_md5)
{
  const char * insert_sql_template = "insert into tb_dist_info("
               "dist_id, dist_type, dist_aindex, dist_findex, dist_fdir,"
               "dist_ftype, dist_password, dist_md5, dist_mbz_md5) "
               "values('%s', '%s', %s, '%s', '%s', '%s', '%s', '%s', '%s')";
  const char * _md5 = md5 ? md5 : "";
  const char * _mbz_md5 = mbz_md5 ? mbz_md5 : "";
  int len = ACE_OS::strlen(insert_sql_template) + ACE_OS::strlen(_md5) + ACE_OS::strlen(_mbz_md5) + 2000;
  MyPooledMemGuard sql;
  MyMemPoolFactoryX::instance()->get_mem(len, &sql);
  MyPooledMemGuard aindex;
  wrap_str(http_dist_request.aindex, aindex);
  ACE_OS::snprintf(sql.data(), len - 1, insert_sql_template,
      http_dist_request.ver, http_dist_request.type, aindex.data(),
      http_dist_request.findex, http_dist_request.fdir,
      http_dist_request.ftype, http_dist_request.password, _md5, _mbz_md5);

  ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, false);
  return exec_command(sql.data());
}

bool MyDB::save_sr(char * dids, const char * cmd, char * idlist)
{
  const char * sql_tpl = "update tb_dist_clients set dc_status = %d where dc_dist_id = '%s' and dc_client_id = '%s'";
  int status = *cmd == '1'? 5: 7;

  char sql[1024];

  ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, false);

  char separator[2] = {';', 0};
  const int BATCH_COUNT = 20;
  int i = 0, total = 0, ok = 0;
  MyStringTokenizer client_ids(idlist, separator);
  MyStringTokenizer dist_ids(dids, separator);
  char * client_id, *dist_id;
  while ((client_id = client_ids.get_token()) != NULL)
  {
    dist_id = dist_ids.get_token();
    if (dist_id == NULL)
      break;
    total ++;
    if (i == 0)
    {
      if (!begin_transaction())
      {
        MY_ERROR("failed to begin transaction @MyDB::save_sr\n");
        return false;
      }
    }
    ACE_OS::snprintf(sql, 1024, sql_tpl, status, dist_id, client_id);
    exec_command(sql);
    ++i;
    if (i == BATCH_COUNT)
    {
      if (!commit())
      {
        MY_ERROR("failed to commit transaction @MyDB::save_sr\n");
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
      MY_ERROR("failed to commit transaction @MyDB::save_sr\n");
      rollback();
    } else
      ok += i;
  }

  MY_INFO("MyDB::save_sr success/total = %d/%d\n", ok, total);
  return true;
}

bool MyDB::save_prio(const char * prio)
{
  if (!prio || !*prio)
    return false;
  char sql[2048];
  const char * sql_template = "update tb_config set cfg_value = '%s' where cfg_id = 2";
  ACE_OS::snprintf(sql, 2048, sql_template, prio);
  ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, false);
  return exec_command(sql);
}

bool MyDB::save_dist_clients(char * idlist, char * adirlist, const char * dist_id)
{
  const char * insert_sql_template1 = "insert into tb_dist_clients(dc_dist_id, dc_client_id, dc_adir) values('%s', '%s', '%s')";
  const char * insert_sql_template2 = "insert into tb_dist_clients(dc_dist_id, dc_client_id) values('%s', '%s')";
  char insert_sql[2048];

  ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, false);

  char separator[2] = {';', 0};
  const int BATCH_COUNT = 20;
  int i = 0, total = 0, ok = 0;
  MyStringTokenizer client_ids(idlist, separator);
  MyStringTokenizer adirs(adirlist, separator);
  char * client_id, * adir;
  while ((client_id = client_ids.get_token()) != NULL)
  {
    adir = adirs.get_token();
    total ++;
    if (i == 0)
    {
      if (!begin_transaction())
      {
        MY_ERROR("failed to begin transaction @MyDB::save_dist_clients\n");
        return false;
      }
    }
    if (adir)
      ACE_OS::snprintf(insert_sql, 2048, insert_sql_template1, dist_id, client_id, adir);
    else
      ACE_OS::snprintf(insert_sql, 2048, insert_sql_template2, dist_id, client_id);
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

bool MyDB::save_dist_cmp_done(const char *dist_id)
{
  if (unlikely(!dist_id || !*dist_id))
    return false;

  const char * update_sql_template = "update tb_dist_info set dist_cmp_done = 1 where dist_id='%s'";
  char insert_sql[1024];
  ACE_OS::snprintf(insert_sql, 1024, update_sql_template, dist_id);

  ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, false);
  return exec_command(insert_sql);
}

int MyDB::load_dist_infos(MyHttpDistInfos & infos)
{
  const char * CONST_select_sql = "select dist_id, dist_type, dist_aindex, dist_findex, dist_fdir,"
                                  " dist_ftype, dist_time, dist_password, dist_mbz_md5, dist_md5"
                                   " from tb_dist_info order by dist_time";
//      "select *, ((('now'::text)::timestamp(0) without time zone - dist_cmp_time > interval '00:10:10') "
//      ") and dist_cmp_done = '0' as cmp_needed, "
//      "((('now'::text)::timestamp(0) without time zone - dist_md5_time > interval '00:10:10') "
//      ") and (dist_md5 is null) and (dist_type = '1') as md5_needed "
//      "from tb_dist_info order by dist_time";

  ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, false);

  PGresult * pres = PQexec(m_connection, CONST_select_sql);
  MyPGResultGuard guard(pres);
  if (!pres || PQresultStatus(pres) != PGRES_TUPLES_OK)
  {
    MY_ERROR("MyDB::sql (%s) failed: %s\n", CONST_select_sql, PQerrorMessage(m_connection));
    return -1;
  }

  int count = PQntuples(pres);
  int field_count = PQnfields(pres);
  if (unlikely(field_count != 10))
  {
    MY_ERROR("incorrect column count(%d) @MyDB::load_dist_infos\n", field_count);
    return -1;
  }

  infos.prepare_update(count);
  for (int i = 0; i < count; ++ i)
  {
    MyHttpDistInfo * info = infos.create_http_dist_info(PQgetvalue(pres, i, 0));

    for (int j = 0; j < field_count; ++j)
    {
      const char * fvalue = PQgetvalue(pres, i, j);
      if (!fvalue || !*fvalue)
        continue;

      if (j == 5)
        info->ftype[0] = *fvalue;
      else if (j == 4)
        info->fdir.init_from_string(fvalue);
      else if (j == 3)
      {
        info->findex.init_from_string(fvalue);
        info->findex_len = ACE_OS::strlen(fvalue);
      }
      else if (j == 9)
      {
        info->md5.init_from_string(fvalue);
        info->md5_len = ACE_OS::strlen(fvalue);
      }
      else if (j == 1)
        info->type[0] = *fvalue;
      else if (j == 7)
      {
        info->password.init_from_string(fvalue);
        info->password_len = ACE_OS::strlen(fvalue);
      }
      else if (j == 6)
      {
        info->dist_time.init_from_string(fvalue);
      }
      else if (j == 2)
      {
        info->aindex.init_from_string(fvalue);
        info->aindex_len = ACE_OS::strlen(fvalue);
      }
      else if (j == 8)
        info->mbz_md5.init_from_string(fvalue);
    }

    info->calc_md5_opt_len();
  }

  MY_INFO("MyDB::get %d dist infos from database\n", count);
  return count;
}

//bool MyDB::dist_take_cmp_ownership(MyHttpDistInfo * info)
//{
//  if (unlikely(!info))
//    return false;
//
//  char where[128];
//  ACE_OS::snprintf(where, 128, "where dist_id = '%s'", info->ver.data());
//  return take_owner_ship("tb_dist_info", "dist_cmp_time", info->cmp_time, where);
//}
//
//bool MyDB::dist_take_md5_ownership(MyHttpDistInfo * info)
//{
//  if (unlikely(!info))
//    return false;
//
//  char where[128];
//  ACE_OS::snprintf(where, 128, "where dist_id = '%s'", info->ver.data());
//  return take_owner_ship("tb_dist_info", "dist_md5_time", info->md5_time, where);
//}

bool MyDB::take_owner_ship(const char * table, const char * field, MyPooledMemGuard & old_time, const char * where_clause)
{
  const char * update_sql_template = "update %s set "
                                     "%s = ('now'::text)::timestamp(0) without time zone "
                                     "%s and %s %s %s";
  char sql[1024];
  if (old_time.data() && old_time.data()[0])
  {
    MyPooledMemGuard wrapped_time;
    wrap_str(old_time.data(), wrapped_time);
    ACE_OS::snprintf(sql, 1024, update_sql_template, table, field, where_clause, field, "=", wrapped_time.data());
  }
  else
    ACE_OS::snprintf(sql, 1024, update_sql_template, table, field, where_clause, field, "is", "null");

  ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, false);
  int m = 0;
  if (!exec_command(sql, &m))
    return false;

  bool result = (m == 1);

  const char * select_sql_template = "select %s from %s %s";
  ACE_OS::snprintf(sql, 1024, select_sql_template, field, table, where_clause);
  PGresult * pres = PQexec(m_connection, sql);
  MyPGResultGuard guard(pres);
  if (!pres || PQresultStatus(pres) != PGRES_TUPLES_OK)
  {
    MY_ERROR("MyDB::sql (%s) failed: %s\n", sql, PQerrorMessage(m_connection));
    return result;
  }
  int count = PQntuples(pres);
  if (count > 0)
    old_time.init_from_string(PQgetvalue(pres, 0, 0));
  return result;
}

bool MyDB::dist_mark_cmp_done(const char * dist_id)
{
  if (unlikely(!dist_id || !*dist_id))
    return false;

  const char * update_sql_template = "update tb_dist_info set dist_cmp_done = 1 "
                                     "where dist_id = '%s'";
  char sql[1024];
  ACE_OS::snprintf(sql, 1024, update_sql_template, dist_id);

  ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, false);
  return exec_command(sql);
}

bool MyDB::dist_mark_md5_done(const char * dist_id)
{
  if (unlikely(!dist_id || !*dist_id))
    return false;

  const char * update_sql_template = "update tb_dist_info set dist_md5_done = 1 "
                                     "where dist_id = '%s'";
  char sql[1024];
  ACE_OS::snprintf(sql, 1024, update_sql_template, dist_id);

  ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, false);
  return exec_command(sql);
}

bool MyDB::save_dist_md5(const char * dist_id, const char * md5, int md5_len)
{
  if (unlikely(!dist_id || !*dist_id || !md5))
    return false;

  const char * update_sql_template = "update tb_dist_info set dist_md5 = '%s' "
                                     "where dist_id = '%s'";
  int len = md5_len + ACE_OS::strlen(update_sql_template) + ACE_OS::strlen(dist_id) + 20;
  MyPooledMemGuard sql;
  MyMemPoolFactoryX::instance()->get_mem(len, &sql);
  ACE_OS::snprintf(sql.data(), len, update_sql_template, md5, dist_id);

  ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, false);
  return exec_command(sql.data());
}

bool MyDB::save_dist_ftp_md5(const char * dist_id, const char * md5)
{
  if (unlikely(!dist_id || !*dist_id || !md5 || !*md5))
    return false;

  const char * update_sql_template = "update tb_dist_info set dist_mbz_md5 = '%s' "
                                     "where dist_id = '%s'";
  char sql[1024];
  ACE_OS::snprintf(sql, 1024, update_sql_template, md5, dist_id);

  ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, false);
  return exec_command(sql);
}

bool MyDB::load_dist_clients(MyDistClients * dist_clients, MyDistClientOne * _dc_one)
{
  MY_ASSERT_RETURN(dist_clients != NULL, "null dist_clients @MyDB::load_dist_clients\n", false);

  const char * CONST_select_sql_1 = "select dc_dist_id, dc_client_id, dc_status, dc_adir, dc_last_update,"
      " dc_mbz_file, dc_mbz_md5, dc_md5"
      " from tb_dist_clients order by dc_client_id";
  const char * CONST_select_sql_2 = "select dc_dist_id, dc_client_id, dc_status, dc_adir, dc_last_update,"
      " dc_mbz_file, dc_mbz_md5, dc_md5"
      " from tb_dist_clients where dc_client_id = '%s'";
  const char * const_select_sql;

  char sql[512];
  if (!_dc_one)
    const_select_sql = CONST_select_sql_1;
  else
  {
    ACE_OS::snprintf(sql, 512, CONST_select_sql_2, _dc_one->client_id());
    const_select_sql = sql;
  }

  ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, false);

//  dist_clients->db_time = get_db_time_i();
//  if (unlikely(dist_clients->db_time == 0))
//  {
//    MY_ERROR("can not get db server time\n");
//    return false;
//  }

  PGresult * pres = PQexec(m_connection, const_select_sql);
  MyPGResultGuard guard(pres);
  if (!pres || PQresultStatus(pres) != PGRES_TUPLES_OK)
  {
    MY_ERROR("MyDB::sql (%s) failed: %s\n", const_select_sql, PQerrorMessage(m_connection));
    return -1;
  }
  int count = PQntuples(pres);
  int field_count = PQnfields(pres);
  int count_added = 0;
  MyDistClientOne * dc_one;

  if (count == 0)
    goto __exit__;
  if (unlikely(field_count != 8))
  {
    MY_ERROR("wrong column number(%d) @MyDB::load_dist_clients()\n", field_count);
    return false;
  }

  MyHttpDistInfo * info;
  if (!_dc_one)
    dc_one = dist_clients->create_client_one(PQgetvalue(pres, 0, 1));
  else
    dc_one = _dc_one;
  for (int i = 0; i < count; ++ i)
  {
    info = dist_clients->find_dist_info(PQgetvalue(pres, i, 0));
    if (unlikely(!info))
      continue;

    if (!_dc_one)
    {
      const char * client_id = PQgetvalue(pres, i, 1);
      if (unlikely(!dc_one->is_client_id(client_id)))
        dc_one = dist_clients->create_client_one(client_id);
    }

    MyDistClient * dc = dc_one->create_dist_client(info);

    const char * md5 = NULL;
    for (int j = 0; j < field_count; ++j)
    {
      const char * fvalue = PQgetvalue(pres, i, j);
      if (!fvalue || !*fvalue)
        continue;

      if (j == 2)
        dc->status = atoi(fvalue);
      else if (j == 3)
        dc->adir.init_from_string(fvalue);
      else if (j == 7)
        md5 = fvalue;
      else if (j == 5)
        dc->mbz_file.init_from_string(fvalue);
      else if (j == 4)
        dc->last_update = get_time_from_string(fvalue);
      else if (j == 6)
        dc->mbz_md5.init_from_string(fvalue);
    }

    if (dc->status < 3 && md5 != NULL)
      dc->md5.init_from_string(md5);

    ++ count_added;
  }

__exit__:
  if (!_dc_one)
    MY_INFO("MyDB::get %d/%d dist client infos from database\n", count_added, count);
  return count;
}

bool MyDB::set_dist_client_status(MyDistClient & dist_client, int new_status)
{
  return set_dist_client_status(dist_client.client_id(), dist_client.dist_info->ver.data(), new_status);
}

bool MyDB::set_dist_client_status(const char * client_id, const char * dist_id, int new_status)
{
  const char * update_sql_template = "update tb_dist_clients set dc_status = %d "
                                     "where dc_dist_id = '%s' and dc_client_id='%s' and dc_status < %d";
  char sql[1024];
  ACE_OS::snprintf(sql, 1024, update_sql_template, new_status, dist_id, client_id, new_status);

  ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, false);
  return exec_command(sql);
}

bool MyDB::set_dist_client_md5(const char * client_id, const char * dist_id, const char * md5, int new_status)
{
  const char * update_sql_template = "update tb_dist_clients set dc_status = %d, dc_md5 = '%s' "
                                     "where dc_dist_id = '%s' and dc_client_id='%s' and dc_status < %d";
  int len = ACE_OS::strlen(update_sql_template) + ACE_OS::strlen(md5) + ACE_OS::strlen(client_id)
    + ACE_OS::strlen(dist_id) + 40;
  MyPooledMemGuard sql;
  MyMemPoolFactoryX::instance()->get_mem(len, &sql);
  ACE_OS::snprintf(sql.data(), len, update_sql_template, new_status, md5, dist_id, client_id, new_status);

  ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, false);
  int num = 0;
  return exec_command(sql.data(), &num) && num == 1;
}

bool MyDB::set_dist_client_mbz(const char * client_id, const char * dist_id, const char * mbz, const char * mbz_md5)
{
  const char * update_sql_template = "update tb_dist_clients set dc_mbz_file = '%s', dc_mbz_md5 = '%s' "
                                     "where dc_dist_id = '%s' and dc_client_id='%s' and dc_status < 3";
  int len = ACE_OS::strlen(update_sql_template) + ACE_OS::strlen(mbz) + ACE_OS::strlen(client_id)
          + ACE_OS::strlen(dist_id) + 40 + ACE_OS::strlen(mbz_md5);
  MyPooledMemGuard sql;
  MyMemPoolFactoryX::instance()->get_mem(len, &sql);
  ACE_OS::snprintf(sql.data(), len, update_sql_template, mbz, mbz_md5, dist_id, client_id);

  ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, false);
  int num = 0;
  return exec_command(sql.data(), &num) && num == 1;
}

bool MyDB::delete_dist_client(const char * client_id, const char * dist_id)
{
  const char * delete_sql_template = "delete from tb_dist_clients where dc_dist_id = '%s' and dc_client_id='%s'";
  char sql[1024];
  ACE_OS::snprintf(sql, 1024, delete_sql_template, dist_id, client_id);

  ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, false);
  return exec_command(sql);
}

bool MyDB::dist_info_is_update(MyHttpDistInfos & infos)
{
  {
    ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, false);
    if (!check_db_connection())
      return true;
  }
  MyPooledMemGuard value;
  if (!load_cfg_value(1, value))
    return true;
  bool result = ACE_OS::strcmp(infos.last_load_time.data(), value.data()) == 0;
  if (!result)
    infos.last_load_time.init_from_string(value.data());
  return result;
}

bool MyDB::load_pl(MyPooledMemGuard & value)
{
  return load_cfg_value(2, value);
}

bool MyDB::dist_info_update_status()
{
  int now = (int)time(NULL);
  int x = random() % 0xFFFFFF;
  char buff[64];
  ACE_OS::snprintf(buff, 64, "%d-%d", now, x);
  return set_cfg_value(1, buff);
}

bool MyDB::remove_orphan_dist_info()
{
  const char * sql = "select post_process()";

  ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, false);
  return exec_command(sql);
}

bool MyDB::get_dist_ids(MyUnusedPathRemover & path_remover)
{
  const char * sql = "select dist_id from tb_dist_info";

  ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, false);
  PGresult * pres = PQexec(m_connection, sql);
  MyPGResultGuard guard(pres);
  if (!pres || PQresultStatus(pres) != PGRES_TUPLES_OK)
  {
    MY_ERROR("MyDB::sql (%s) failed: %s\n", sql, PQerrorMessage(m_connection));
    return false;
  }
  int count = PQntuples(pres);
  if (count > 0)
  {
    for (int i = 0; i < count; ++i)
      path_remover.add_dist_id(PQgetvalue(pres, i, 0));
  }
  return true;
}

bool MyDB::mark_client_valid(const char * client_id, bool valid)
{
  char sql[1024];
  if (!valid)
  {
    const char * sql_template = "delete from tb_clients where client_id = '%s'";
    ACE_OS::snprintf(sql, 1024, sql_template, client_id);
  } else
  {
    const char * sql_template = "insert into tb_clients(client_id, client_password) values('%s', '%s')";
    ACE_OS::snprintf(sql, 1024, sql_template, client_id, client_id);
  }

  ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, false);
  return exec_command(sql);
}

bool MyDB::set_cfg_value(const int id, const char * value)
{
  const char * sql_template = "update tb_config set cfg_value = '%s' where cfg_id = %d";
  char sql[1024];
  ACE_OS::snprintf(sql, 1024, sql_template, value, id);

  ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, false);
  return exec_command(sql);
}

bool MyDB::load_cfg_value(const int id, MyPooledMemGuard & value)
{
  ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, false);
  return load_cfg_value_i(id, value);
}

bool MyDB::load_cfg_value_i(const int id, MyPooledMemGuard & value)
{
  const char * CONST_select_sql_template = "select cfg_value from tb_config where cfg_id = %d";
  char select_sql[1024];
  ACE_OS::snprintf(select_sql, 1024, CONST_select_sql_template, id);

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
    value.init_from_string(PQgetvalue(pres, 0, 0));
    return true;
  } else
    return false;
}


bool MyDB::load_db_server_time_i(time_t &t)
{
  const char * select_sql = "select ('now'::text)::timestamp(0) without time zone";
  PGresult * pres = PQexec(m_connection, select_sql);
  MyPGResultGuard guard(pres);
  if (!pres || PQresultStatus(pres) != PGRES_TUPLES_OK)
  {
    MY_ERROR("MyDB::sql (%s) failed: %s\n", select_sql, PQerrorMessage(m_connection));
    return false;
  }
  if (PQntuples(pres) <= 0)
    return false;
  t = get_time_from_string(PQgetvalue(pres, 0, 0));
  return true;
}
