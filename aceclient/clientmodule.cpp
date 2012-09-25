/*
 * clientmodule.cpp
 *
 *  Created on: Jan 8, 2012
 *      Author: root
 */

#include <ace/FILE_Addr.h>
#include <ace/FILE_Connector.h>
#include <ace/FILE_IO.h>
#include <fstream>

#include "clientmodule.h"
#include "baseapp.h"
#include "client.h"


std::string current_ver()
{
  char buff[100];
  ACE_OS::snprintf(buff, 99, "%d.%d build 120717", const_client_version_major, const_client_version_minor);
  std::string result = buff;
  return result;
}

//MyPL//

MyPL::MyPL()
{
  for (int i = 0; i < 10; ++ i)
    m_value[i] = 0;
}

bool MyPL::load(const char * client_id)
{
  if (g_is_test)
    return true;
  CMemGuard data_path, fn;
  MyClientApp::data_path(data_path, client_id);
  fn.from_string(data_path.data(), "/plist");
  CUnixFileGuard fh;
  fh.error_report(false);
  if (!fh.open_read(fn.data()))
    return false;
  char buff[100];
  int m = ::read(fh.handle(), buff, 100);
  if (m <= 0)
    return false;
  buff[std::min(99, m)] = 0;
  return parse(buff);
}

bool MyPL::save(const char * client_id, const char * s)
{
  if (g_is_test)
    return true;
  if (!s)
    return false;
  CMemGuard data_path, fn;
  MyClientApp::data_path(data_path, client_id);
  fn.from_string(data_path.data(), "/plist");
  CUnixFileGuard fh;
  if (fh.open_write(fn.data(), true, true, false, true))
  {
    int m = strlen(s);
    return m == ::write(fh.handle(), s, m);
  }
  return false;
}

int MyPL::value(int i)
{
  if (i < 0 || i > 10)
    return 0;
  ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, 0);
  return m_value[i];
}

MyPL & MyPL::instance()
{
  static MyPL g_pl;
  return g_pl;
}

bool MyPL::parse(char * s)
{
  if (g_is_test)
    return true;
  if (!s || !*s)
  {
    C_INFO("empty plist\n");
    return false;
  }
  ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, false);
  C_INFO("plist = %s\n", s);
  const char separator[] = {';', 0};
  CStringTokenizer tknz(s, separator);
  char * token;
  int i = 0;
  while ((token = tknz.get()) != NULL)
  {
    m_value[i] = atoi(token);
    ++i;
    if (i >= 10)
      break;
  }
  return true;
}


//MyClickInfo//

MyClickInfo::MyClickInfo()
{
  len = 0;
}

MyClickInfo::MyClickInfo(const char * chn, const char * pcode, const char * count):
    channel(chn), point_code(pcode), click_count(count)
{
  len = channel.length() + point_code.length() + click_count.length() + 3;
}


//MyServerID//

u_int8_t MyServerID::load(const char * client_id)
{
  CMemGuard data_path, fn;
  MyClientApp::data_path(data_path, client_id);
  fn.from_string(data_path.data(), "/server.id");
  CUnixFileGuard fh;
  if (fh.open_read(fn.data()))
  {
    char buff[32];
    int m = ::read(fh.handle(), buff, 32);
    if (m > 0)
    {
      buff[std::min(31, m)] = 0;
      return (u_int8_t)atoi(buff);
    }
  }

  return 0;
}

void MyServerID::save(const char * client_id, int server_id)
{
  CMemGuard data_path, fn;
  MyClientApp::data_path(data_path, client_id);
  fn.from_string(data_path.data(), "/server.id");
  CUnixFileGuard fh;
  if (fh.open_write(fn.data(), true, true, false, true))
  {
    char buff[32];
    ACE_OS::snprintf(buff, 32, "%d", server_id);
    ::write(fh.handle(), buff, strlen(buff));
  }
}



//MyClientDB//

ACE_Thread_Mutex MyClientDB::m_mutex;

MyClientDB::MyClientDB()
{
  m_db = NULL;
}

MyClientDB::~MyClientDB()
{
  if (m_db)
    sqlite3_close(m_db);
}

bool MyClientDB::init_db()
{
  if (unlikely(!m_db))
    return false;

  const char * const_sql_tb_ftp_info =
      "create table if not exists tb_ftp_info(ftp_dist_id text PRIMARY KEY, ftp_str text, ftp_status integer, ftp_recv_time integer, "
                "md5_client text, md5_server text, ftp_adir text, ftp_aindex text, ftp_ftype num)";
  const char * const_sql_tb_click =
      "create table if not exists tb_click(channel_id text, point_code text, click_num, primary key(channel_id, point_code))";
  const char * const_sql_tb_adv =
      "create table if not exists tb_adv(filename text, last_access, primary key(filename))";
  const char * const_sql_fist_record_tpl =
      "insert into tb_adv(filename, last_access) values('_Xx001_', %d)";
  const char * const_sql_delete_adv_tpl = "delete from tb_adv";

  do_exec(const_sql_tb_ftp_info, false);
  do_exec(const_sql_tb_adv, false);
  bool result = do_exec(const_sql_tb_click, false);
  if (CCfgX::instance()->client_adv_expire_days > 0)
  {
    char sql[200];
    ACE_OS::snprintf(sql, 200, const_sql_fist_record_tpl, (int)time(NULL));
    do_exec(sql, false);
  } else
    do_exec(const_sql_delete_adv_tpl);
  return result;
}

bool MyClientDB::open_db(const char * client_id, bool do_init)
{
  if (m_db)
    return true;

  bool retried = false;
  CMemGuard db_path, db_name;
  MyClientAppX::instance()->data_path(db_path, client_id);
  db_name.from_string(db_path.data(), "/client.db");

  while(true)
  {
    if(sqlite3_open(db_name.data(), &m_db))
    {
      C_ERROR("failed to database %s, msg=%s\n", db_name.data(), sqlite3_errmsg(m_db));
      close_db();
      if (retried)
        return false;
      retried = true;
      CSysFS::remove(db_name.data());
    } else
      break;
  }

  if (do_init || retried)
    init_db();
  return true;
}

void MyClientDB::close_db()
{
  if (m_db)
  {
    sqlite3_close(m_db);
    m_db = NULL;
  }
}

bool MyClientDB::do_exec(const char *sql, bool show_error)
{
  char * zErrMsg = 0;
  if (sqlite3_exec(m_db, sql, NULL, 0, &zErrMsg) != SQLITE_OK)
  {
    if (show_error)
      C_ERROR("do_exec(sql=%s) failed, msg=%s\n", sql, zErrMsg);
    if (zErrMsg)
      sqlite3_free(zErrMsg);
    return false;
  }
  if (zErrMsg)
    sqlite3_free(zErrMsg);
  return true;
}

bool MyClientDB::ftp_command_existing(const char * dist_id)
{
  int count = 0;
  const char * const_sql_template = "select count(*) from tb_ftp_info where ftp_dist_id = '%s'";
  char sql[200];
  ACE_OS::snprintf(sql, 200, const_sql_template, dist_id);

  char *zErrMsg = 0;
  if (sqlite3_exec(m_db, sql, get_one_integer_value_callback, &count, &zErrMsg) != SQLITE_OK)
  {
    C_ERROR("do_exec(sql=%s) failed, msg=%s\n", sql, zErrMsg);
    if (zErrMsg)
      sqlite3_free(zErrMsg);
  }
  if (zErrMsg)
    sqlite3_free(zErrMsg);

  return count >= 1;
}

bool MyClientDB::save_ftp_command(const char * ftp_command, const MyDistInfoFtp & dist_ftp)
{
  if (unlikely(!ftp_command || !*ftp_command))
    return false;

  const char * const_sql_template1 = "insert into tb_ftp_info(ftp_dist_id, ftp_str, ftp_status, ftp_recv_time, ftp_adir, ftp_aindex, ftp_ftype) "
                                    "values('%s', '%s', 2, %d, '%s', '%s', '%c')";
  const char * const_sql_template2 = "update tb_ftp_info set ftp_str = '%s', ftp_status = 2, ftp_recv_time = %d, ftp_adir='%s', ftp_aindex='%s', ftp_ftype='%c' "
                                    "where ftp_dist_id = '%s'";
  bool bExist = ftp_command_existing(dist_ftp.dist_id.data());
  const char * sql_tpl = bExist? const_sql_template2 : const_sql_template1;

  int len = ACE_OS::strlen(dist_ftp.dist_id.data());
  const char * adir = dist_ftp.adir.data()? dist_ftp.adir.data(): "";
  const char * aindex = dist_ftp.index_file();
  int total_len = ACE_OS::strlen(sql_tpl) + len + ACE_OS::strlen(ftp_command) + 50 +
      ACE_OS::strlen(adir) + ACE_OS::strlen(aindex);
  CMemGuard sql;
  CMemPoolX::instance()->alloc_mem(total_len, &sql);

  if (!bExist)
  {
    ACE_OS::snprintf(sql.data(), total_len, sql_tpl,
        dist_ftp.dist_id.data(),
        ftp_command,
        dist_ftp.recv_time,
        adir,
        aindex,
        dist_ftp.ftype);

  } else
    ACE_OS::snprintf(sql.data(), total_len, sql_tpl, ftp_command, dist_ftp.recv_time, adir, aindex, dist_ftp.ftype, dist_ftp.dist_id.data());

  return do_exec(sql.data());
}

bool MyClientDB::save_md5_command(const char * dist_id, const char * md5_server, const char * md5_client)
{
  if (unlikely(!md5_server || !*md5_server || !dist_id || !*dist_id))
    return false;

  if (!ftp_command_existing(dist_id))
  {
    const char * const_sql_template = "insert into tb_ftp_info(ftp_dist_id, ftp_status, md5_server, md5_client) "
                                      "values('%s', 0, '%s', '%s')";
    int len = ACE_OS::strlen(dist_id);
    int total_len = ACE_OS::strlen(const_sql_template) + len + ACE_OS::strlen(md5_server) + ACE_OS::strlen(md5_client) + 20;
    CMemGuard sql;
    CMemPoolX::instance()->alloc_mem(total_len, &sql);
    ACE_OS::snprintf(sql.data(), total_len, const_sql_template, dist_id, md5_server, md5_client);
    return do_exec(sql.data());
  } else
  {
    const char * const_sql_template = "update tb_ftp_info set md5_server = '%s', md5_client = '%s' where ftp_dist_id = '%s'";
    int len = ACE_OS::strlen(dist_id);
    int total_len = ACE_OS::strlen(const_sql_template) + len + ACE_OS::strlen(md5_server) + ACE_OS::strlen(md5_client) + 20;
    CMemGuard sql;
    CMemPoolX::instance()->alloc_mem(total_len, &sql);
    ACE_OS::snprintf(sql.data(), total_len, const_sql_template, dist_id, md5_server, md5_client);
    return do_exec(sql.data());
  }
}

bool MyClientDB::load_ftp_md5_for_diff(MyDistInfoFtp & dist_info)
{
  const char * const_sql_template = "select md5_server, md5_client from tb_ftp_info where ftp_dist_id = '%s'";
  char sql[200];
  ACE_OS::snprintf(sql, 200, const_sql_template, dist_info.dist_id.data());
  char *zErrMsg = 0;
  if (sqlite3_exec(m_db, sql, get_ftp_md5_for_diff_callback, &dist_info, &zErrMsg) != SQLITE_OK)
  {
    C_ERROR("do_exec(sql=%s) failed, msg=%s\n", sql, zErrMsg);
    if (zErrMsg)
      sqlite3_free(zErrMsg);
    return false;
  }
  if (zErrMsg)
    sqlite3_free(zErrMsg);
  return true;
}

bool MyClientDB::set_ftp_command_status(const char * dist_id, int status)
{
  const char * const_sql_template = "update tb_ftp_info set ftp_status = %d where ftp_dist_id = '%s' "
                                    "and ftp_status < %d";
  char sql[200];
  ACE_OS::snprintf(sql, 200, const_sql_template, status, dist_id, status);
  return do_exec(sql);
}

bool MyClientDB::reset_ftp_command_status()
{
  const char * sql = "update tb_ftp_info set ftp_status = -2 where ftp_status = 2";
  return do_exec(sql);
}

bool MyClientDB::get_ftp_command_status(const char * dist_id, int & status)
{
  if (unlikely(!dist_id))
    return false;
  status = -10;
  const char * const_sql_template = "select ftp_status from tb_ftp_info where ftp_dist_id = '%s'";
  char sql[200];
  ACE_OS::snprintf(sql, 200, const_sql_template, dist_id);

  char *zErrMsg = 0;
  if (sqlite3_exec(m_db, sql, get_one_integer_value_callback, &status, &zErrMsg) != SQLITE_OK)
  {
    C_ERROR("do_exec(sql=%s) failed, msg=%s\n", sql, zErrMsg);
    if (zErrMsg)
      sqlite3_free(zErrMsg);
    return false;
  }
  if (zErrMsg)
    sqlite3_free(zErrMsg);
  return status != -10;
}

bool MyClientDB::save_click_info(const char * channel, const char * point_code)
{
  if (unlikely(!channel || !*channel || !point_code || !*point_code))
    return false;
  char sql[800];
  int num = 0;

  {
    const char * const_sql_template = "select click_num from tb_click where channel_id='%s' and point_code='%s'";
    ACE_OS::snprintf(sql, 800, const_sql_template, channel, point_code);

    char *zErrMsg = 0;
    if (sqlite3_exec(m_db, sql, get_one_integer_value_callback, &num, &zErrMsg) != SQLITE_OK)
    {
      C_ERROR("do_exec(sql=%s) failed, msg=%s\n", sql, zErrMsg);
      if (zErrMsg)
        sqlite3_free(zErrMsg);
      return false;
    }
    if (zErrMsg)
      sqlite3_free(zErrMsg);
  }

  if (num > 0)
  {
    const char * const_sql_template = "update tb_click set click_num = click_num + 1 where channel_id='%s' and point_code='%s'";
    ACE_OS::snprintf(sql, 800, const_sql_template, channel, point_code);
    return do_exec(sql);
  } else
  {
    const char * const_sql_template = "insert into tb_click(channel_id, point_code, click_num) values('%s', '%s', 1)";
    ACE_OS::snprintf(sql, 800, const_sql_template, channel, point_code);
    return do_exec(sql);
  }
}

bool MyClientDB::clear_click_infos()
{
  const char * sql = "delete from tb_click";
  return do_exec(sql);
}

bool MyClientDB::get_click_infos(MyClickInfos & infos)
{
//  const char * sql = "select channel_id, point_code, count(*) from tb_click group by channel_id, point_code";
  const char * sql = "select channel_id, point_code, click_num from tb_click";
  char *zErrMsg = 0;
  if (sqlite3_exec(m_db, sql, get_click_infos_callback, &infos, &zErrMsg) != SQLITE_OK)
  {
    C_ERROR("do_exec(sql=%s) failed, msg=%s\n", sql, zErrMsg);
    if (zErrMsg)
      sqlite3_free(zErrMsg);
    return false;
  }
  if (zErrMsg)
    sqlite3_free(zErrMsg);
  return true;
}

bool MyClientDB::update_adv_time(const char * filename, time_t t)
{
  if (unlikely(!filename || !*filename))
    return true;

  char sql[1024];
  int num = 0;

  {
    const char * const_sql_template = "select count(*) from tb_adv where filename='%s'";
    ACE_OS::snprintf(sql, 1024, const_sql_template, filename);

    char *zErrMsg = 0;
    if (sqlite3_exec(m_db, sql, get_one_integer_value_callback, &num, &zErrMsg) != SQLITE_OK)
    {
      C_ERROR("do_exec(sql=%s) failed, msg=%s\n", sql, zErrMsg);
      if (zErrMsg)
        sqlite3_free(zErrMsg);
      return false;
    }
    if (zErrMsg)
      sqlite3_free(zErrMsg);
  }

  if (num > 0)
  {
    const char * const_sql_template = "update tb_adv set last_access = '%d' where filename='%s'";
    ACE_OS::snprintf(sql, 800, const_sql_template, (int)t, filename);
    return do_exec(sql);
  } else
  {
    const char * const_sql_template = "insert into tb_adv(filename, last_access) values('%s', %d)";
    ACE_OS::snprintf(sql, 800, const_sql_template, filename, (int)t);
    return do_exec(sql);
  }
}

bool MyClientDB::delete_old_adv(time_t deadline)
{
  const char * const_sql_template = "delete from tb_adv where last_access < %d and filename <> '_Xx001_'";
  char sql[200];
  ACE_OS::snprintf(sql, 200, const_sql_template, (int)deadline);
  return do_exec(sql);
}

bool MyClientDB::adv_db_is_older(time_t deadline)
{
  char sql[200];
  int num = 0;

  {
    const char * const_sql_template = "select count(*) from tb_adv where filename = '_Xx001_' and last_access < %d";
    ACE_OS::snprintf(sql, 200, const_sql_template, (int)deadline);

    char *zErrMsg = 0;
    if (sqlite3_exec(m_db, sql, get_one_integer_value_callback, &num, &zErrMsg) != SQLITE_OK)
    {
      C_ERROR("do_exec(sql=%s) failed, msg=%s\n", sql, zErrMsg);
      if (zErrMsg)
        sqlite3_free(zErrMsg);
      return false;
    }
    if (zErrMsg)
      sqlite3_free(zErrMsg);
  }

  return num >= 1;
}

bool MyClientDB::adv_has_file(const char * filename)
{
  if (unlikely(!filename || !*filename))
    return false;

  char sql[800];
  int num = 0;

  {
    const char * const_sql_template = "select count(*) from tb_adv where filename='%s'";
    ACE_OS::snprintf(sql, 800, const_sql_template, filename);

    char *zErrMsg = 0;
    if (sqlite3_exec(m_db, sql, get_one_integer_value_callback, &num, &zErrMsg) != SQLITE_OK)
    {
      C_ERROR("do_exec(sql=%s) failed, msg=%s\n", sql, zErrMsg);
      if (zErrMsg)
        sqlite3_free(zErrMsg);
      return false;
    }
    if (zErrMsg)
      sqlite3_free(zErrMsg);
  }

  return num >= 1;
}

void MyClientDB::remove_outdated_ftp_command(time_t deadline)
{
  const char * const_sql_template = "delete from tb_ftp_info where ftp_recv_time <= %ld";
  char sql[200];
  ACE_OS::snprintf(sql, 200, const_sql_template, (long)deadline);
  do_exec(sql);
}

bool MyClientDB::ftp_obsoleted(MyDistInfoFtp & dist_ftp)
{
  const char * const_chn_tpl = "select count(*) from tb_ftp_info where ftp_ftype in ('1', '2', '4') and ftp_adir = '%s' and ftp_recv_time > %d";
  const char * const_frm_tpl = "select count(*) from tb_ftp_info where ftp_ftype = '0' and ftp_recv_time > %d";
  const char * const_other_tpl = "select count(*) from tb_ftp_info where ftp_ftype in (%s) and ftp_aindex = '%s' and ftp_recv_time > %d";
  const int BUFF_SIZE = 4096;
  char sql[BUFF_SIZE];
  if (ftype_is_chn(dist_ftp.ftype))
    ACE_OS::snprintf(sql, BUFF_SIZE, const_chn_tpl, dist_ftp.adir.data(), dist_ftp.recv_time);
  else if (ftype_is_frame(dist_ftp.ftype))
    ACE_OS::snprintf(sql, BUFF_SIZE, const_frm_tpl, dist_ftp.recv_time);
  else if (ftype_is_adv(dist_ftp.ftype))
    ACE_OS::snprintf(sql, BUFF_SIZE, const_other_tpl, "'3', '5', '6'", dist_ftp.index_file(), dist_ftp.recv_time);
  else if (ftype_is_led(dist_ftp.ftype))
    ACE_OS::snprintf(sql, BUFF_SIZE, const_other_tpl, "'7', '9'", dist_ftp.index_file(), dist_ftp.recv_time);
  else if (ftype_is_backgnd(dist_ftp.ftype))
    ACE_OS::snprintf(sql, BUFF_SIZE, const_other_tpl, "'8'", dist_ftp.index_file(), dist_ftp.recv_time);
  else
  {
    C_FATAL("unknown ftype (%c) of dist_ftp @MyClientDB::ftp_obsoleted\n", dist_ftp.ftype);
    return false;
  }


  int num = 0;
  {
    char *zErrMsg = 0;
    if (sqlite3_exec(m_db, sql, get_one_integer_value_callback, &num, &zErrMsg) != SQLITE_OK)
    {
      C_ERROR("do_exec(sql=%s) failed, msg=%s\n", sql, zErrMsg);
      if (zErrMsg)
        sqlite3_free(zErrMsg);
      return false;
    }
    if (zErrMsg)
      sqlite3_free(zErrMsg);
  }

  return num > 0;
}

bool MyClientDB::load_ftp_commands(MyDistInfoFtps * dist_ftps)
{
  if (unlikely(!dist_ftps))
    return false;
  const char * sql = "select ftp_dist_id, ftp_str, ftp_status, ftp_recv_time from tb_ftp_info "
                     "where ftp_status <= 3 and ftp_status >= 2 order by ftp_recv_time";
  char *zErrMsg = 0;
  if (sqlite3_exec(m_db, sql, load_ftp_commands_callback, dist_ftps, &zErrMsg) != SQLITE_OK)
  {
    C_ERROR("do_exec(sql=%s) failed, msg=%s\n", sql, zErrMsg);
    if (zErrMsg)
      sqlite3_free(zErrMsg);
    return false;
  }
  if (zErrMsg)
    sqlite3_free(zErrMsg);
  return true;
}

bool MyClientDB::load_ftp_command(MyDistInfoFtp & dist_ftp, const char * dist_id)
{
  if (unlikely(!dist_id || !*dist_id))
    return false;
  const char * sql_tpl = "select ftp_dist_id, ftp_str, ftp_status, ftp_recv_time from tb_ftp_info where ftp_dist_id = '%s'";
  char sql[200];
  ACE_OS::snprintf(sql, 200, sql_tpl, dist_id);
  char *zErrMsg = 0;
  if (sqlite3_exec(m_db, sql, load_ftp_command_callback, &dist_ftp, &zErrMsg) != SQLITE_OK)
  {
    C_ERROR("do_exec(sql=%s) failed, msg=%s\n", sql, zErrMsg);
    if (zErrMsg)
      sqlite3_free(zErrMsg);
    return false;
  }
  if (zErrMsg)
    sqlite3_free(zErrMsg);
  return true;
}

int MyClientDB::load_ftp_commands_callback(void * p, int argc, char **argv, char **azColName)
{
  ACE_UNUSED_ARG(azColName);

  MyDistInfoFtps * dist_ftps = (MyDistInfoFtps *)p;
  if (unlikely(!dist_ftps))
  {
    C_ERROR("NULL dist_ftps parameter @load_ftp_commands_callback\n");
    return -1;
  }
  if (unlikely(argc != 4))
  {
    C_ERROR("unexpected parameter number (=%d) @load_ftp_commands_callback\n", argc);
    return -1;
  }

  //ftp_dist_id, ftp_str, ftp_status, ftp_recv_time
  MyDistInfoFtp * dist_ftp = new MyDistInfoFtp();

  if (unlikely(!argv[2] || !*argv[2]))
  {
    delete dist_ftp;
    return 0;
  }
  dist_ftp->status = atoi(argv[2]);
//  if (dist_ftp->status == -2)
//    dist_ftp->status = 2;
  if (dist_ftp->status == 2)
    dist_ftp->inc_failed(3);

  if (unlikely(!dist_ftp->load_from_string(argv[1])))
  {
    delete dist_ftp;
    return 0;
  }

  if (unlikely(!argv[3] || !*argv[3]))
  {
    delete dist_ftp;
    return 0;
  }
  dist_ftp->recv_time = atoi(argv[3]);
  dist_ftp->last_update = 0;
  if (!g_is_test)
  {
    dist_ftp->client_id = MyClientAppX::instance()->client_id();
    dist_ftp->client_id_index = 0;
    dist_ftp->ftp_password.from_string(MyClientAppX::instance()->ftp_password());
  }
  dist_ftps->add(dist_ftp);
  return 0;
}

int MyClientDB::load_ftp_command_callback(void * p, int argc, char **argv, char **azColName)
{
  ACE_UNUSED_ARG(azColName);

  MyDistInfoFtp * dist_ftp = (MyDistInfoFtp *)p;
  if (unlikely(!dist_ftp))
  {
    C_ERROR("NULL dist_ftp parameter @load_ftp_command_callback\n");
    return -1;
  }
  dist_ftp->status = -1;
  if (unlikely(argc != 4))
  {
    C_ERROR("unexpected parameter number (=%d) @load_ftp_commands_callback\n", argc);
    return -1;
  }
  if (unlikely(!argv[2] || !*argv[2]))
    return 0;

  dist_ftp->status = atoi(argv[2]);

  //ftp_dist_id, ftp_str, ftp_status, ftp_recv_time
  if (unlikely(!dist_ftp->load_from_string(argv[1])))
    return 0;

  if (unlikely(!argv[3] || !*argv[3]))
    return 0;

  dist_ftp->recv_time = atoi(argv[3]);
  return 0;
}

int MyClientDB::get_click_infos_callback(void * p, int argc, char **argv, char **azColName)
{
  ACE_UNUSED_ARG(azColName);
  MyClickInfos * infos = (MyClickInfos *)p;
  if (unlikely(argc != 3 || !argv[0] || !argv[0][0] || !argv[1] || !argv[1][0] || !argv[2] || !argv[2][0]))
    return 0;

  infos->push_back(MyClickInfo(argv[0], argv[1], argv[2]));
  return 0;
}

int MyClientDB::get_one_integer_value_callback(void * p, int argc, char **argv, char **azColName)
{
  ACE_UNUSED_ARG(azColName);

  if (argc != 1 || !argv[0])
    return -1;
  *(int*)p = atoi(argv[0]);
  return 0;
}

int MyClientDB::get_ftp_md5_for_diff_callback(void * p, int argc, char **argv, char **azColName)
{
  ACE_UNUSED_ARG(azColName);

  if (argc != 2 || !argv[0])
    return -1;
  MyDistInfoFtp * dist_info = (MyDistInfoFtp *) p;
  dist_info->server_md5.from_string(argv[0]);
  dist_info->client_md5.from_string(argv[1]);
  return 0;
}

//MyConnectIni//

void MyConnectIni::update_connect_status(MyConnectIni::CONNECT_STATUS cs)
{
  CMemGuard path, fn;
  MyClientApp::calc_display_parent_path(path, NULL);
  fn.from_string(path.data(), "/connect.ini");
  std::ofstream ofs(fn.data());
  if (!ofs || ofs.bad())
  {
    C_ERROR("can not open file %s for writing: %s\n", fn.data(), (const char*)CErrno());
    return;
  }
  ofs << (int)cs;
}


//MyFTPClient//

MyFTPClient::MyFTPClient(const std::string &remote_ip, const u_short remote_port,
                     const std::string &user_name, const std::string &pass_word, MyDistInfoFtp * ftp_info)
{
  m_user_name = user_name;
  m_password = pass_word;
  m_remote_addr.set((u_short)remote_port, remote_ip.c_str());
  m_ftp_server_addr.from_string(remote_ip.c_str());
  m_ftp_info = ftp_info;
}

MyFTPClient::~MyFTPClient()
{
  m_peer.close_writer();
  m_peer.close_reader();
  m_peer.close();
}

bool MyFTPClient::download(MyDistInfoFtp * dist_info, const char * server_ip)
{
  const char * client_id = dist_info->client_id.as_string();
  const char * ftp_password = dist_info->ftp_password.data();
  if (!ftp_password || !*ftp_password)
  {
    dist_info->ftp_password.from_string(MyClientAppX::instance()->ftp_password());
    ftp_password = dist_info->ftp_password.data();
  }
  if (unlikely(!client_id || !*client_id || !ftp_password || !*ftp_password || !server_ip || ! *server_ip))
  {
    C_ERROR("bad parameter @MyFTPClient::download(%s, %s, %s)\n", server_ip, client_id, ftp_password);
    return false;
  }
  MyFTPClient ftp_client(server_ip, 21, client_id, ftp_password, dist_info);
  if (!ftp_client.login())
    return false;
  CMemGuard ftp_file_name;
  ftp_file_name.from_string(dist_info->dist_id.data(), "/", dist_info->file_name.data());
  if (!ftp_client.get_file(ftp_file_name.data(), dist_info->local_file_name.data()))
  {
    ftp_client.logout();
    return false;
  }
  ftp_client.logout();
  if (dist_info->ftp_md5.data() && *dist_info->ftp_md5.data())
  {
    CMemGuard md5_result;
    if (!c_util_calculate_file_md5(dist_info->local_file_name.data(), md5_result))
      return false;
    if (ACE_OS::strcmp(md5_result.data(), dist_info->ftp_md5.data()) != 0)
    {
      C_ERROR("bad ftp file (%s)'s md5 check sum, local(%s) remote(%s)\n", dist_info->dist_id.data(), md5_result.data(), dist_info->ftp_md5.data());
      return false;
    }
  }
  return true;
}

bool MyFTPClient::recv()
{
  const int BUFF_SIZE = 2048;
  char line[BUFF_SIZE];
  int i = 0;
  ACE_Time_Value tv(get_timeout_seconds());

  while (true)
  {
    char c;
    switch (m_peer.recv_n(&c, 1, &tv))
    {
    case   0:
    case  -1:
      line[i] = 0;
      m_response.from_string(line);
      return false;
    default:
      if (unlikely(i >= BUFF_SIZE - 2))
      {
        C_ERROR("ftp unexpected too long response line from server %s\n", m_ftp_server_addr.data());
        line[i] = 0;
        m_response.from_string(line);
        return false;
      }
      line[i++] = c;
      break;
    }

    if ('\n' == c)
    {
      line[i] = 0;
      m_response.from_string(line);
      if (i < 3)
        return false;
      break;
    }
  }

  if (unlikely(!MyClientAppX::instance()->running()))
    return false;

  return true;
}

bool MyFTPClient::is_response(const char * res_code)
{
  const char * res = m_response.data();
  return res && (ACE_OS::strlen(res) >= 3) && (ACE_OS::memcmp(res, res_code, 3) == 0);
}

int MyFTPClient::get_timeout_seconds() const
{
  return CCfgX::instance()->client_download_timeout;
}

bool MyFTPClient::send(const char * command)
{
  int cmd_len = ACE_OS::strlen(command);
  if (unlikely(cmd_len == 0))
    return true;
  if (unlikely(!MyClientAppX::instance()->running()))
    return false;

  ACE_Time_Value  tv(get_timeout_seconds());
  return (cmd_len == m_peer.send_n(command, cmd_len, &tv));
}

bool MyFTPClient::login()
{
  ACE_Time_Value  tv(get_timeout_seconds());
  const int CMD_BUFF_LEN = 2048;
  char command[CMD_BUFF_LEN];

//  C_INFO("ftp connecting to server %s\n", m_ftp_server_addr.data());

  if (this->m_connector.connect(m_peer, m_remote_addr, &tv) == -1)
  {
    C_ERROR("ftp connecting to server %s failed %s\n", m_ftp_server_addr.data(), (const char *)CErrno());
    return false;
  }

  if (!this->recv() || !is_response("220"))
  {
    C_ERROR("ftp no/bad response after connecting to server (%s): %s\n", m_ftp_server_addr.data(), m_response.data());
    return false;
  }

  ACE_OS::snprintf(command, CMD_BUFF_LEN, "USER %s\r\n", this->m_user_name.c_str());
  if (this->send(command))
  {
    if (!this->recv() || !is_response("331"))
    {
      C_ERROR("ftp no/bad response on USER command to server (%s), user=(%s): %s\n",
          m_ftp_server_addr.data(), this->m_user_name.c_str(), m_response.data());
      return false;
    }
  }

  ACE_OS::snprintf(command, CMD_BUFF_LEN, "PASS %s\r\n", this->m_password.c_str());
  if (this->send(command))
  {
    if (!this->recv() || !is_response("230"))
    {
      C_ERROR("ftp no/bad response on PASS command to server (%s), user=(%s): %s\n",
          m_ftp_server_addr.data(), this->m_user_name.c_str(), m_response.data());
      return false;
    }
  }

  C_INFO("ftp authentication  to server %s OK, user=%s\n", m_ftp_server_addr.data(), this->m_user_name.c_str());
  return true;
}

bool MyFTPClient::logout()
{
  if (this->send("QUIT \r\n"))
  {
    if (!this->recv() || !is_response("221"))
      return false;
  }

  return true;
}

bool MyFTPClient::change_remote_dir(const char *dirname)
{
  CMemGuard cwd;
  cwd.from_string("CWD ", dirname, "\r\n");
  if (this->send(cwd.data()))
  {
    if (!this->recv() || !is_response("250"))
    {
      C_ERROR("ftp no/bad response on CWD command to server %s\n", m_ftp_server_addr.data());
      return false;
    }
  } else
    return false;

  if (this->send("PWD \r\n"))
  {
    if (!this->recv() || !is_response("257"))
    {
      C_ERROR("ftp no/bad response on PWD command to server %s\n", m_ftp_server_addr.data());
      return false;
    }
  } else
    return false;

  return true;
}

bool MyFTPClient::get_file(const char *filename, const char * localfile)
{
  C_ASSERT_RETURN(filename && *filename && localfile && *localfile, "\n", false);

  ACE_Time_Value  tv(get_timeout_seconds());
  int d0, d1, d2, d3, p0, p1;
  char ip[32];
  ACE_INET_Addr ftp_data_addr;

  ACE_SOCK_Stream     stream;
  ACE_SOCK_Connector  connector;

  ACE_FILE_IO file_put;
  ACE_FILE_Connector file_con;
  char file_cache[MAX_BUFSIZE];
  int file_size, all_size, fs_server = 0, fs_client = 0;

  struct stat _stat;
  if (CSysFS::stat(localfile, &_stat))
    fs_client = (int)_stat.st_size;

  if (this->send("TYPE I\r\n"))
  {
    if (!this->recv() || !is_response("200"))
    {
      C_ERROR("ftp no/bad response on TYPE command to server (%s): %s\n", m_ftp_server_addr.data(), m_response.data());
      return false;
    }
  }

  if (fs_client > 0)
  {
    CMemGuard fs;
    fs.from_string("SIZE ", filename, "\r\n");
    if (!this->send(fs.data()))
      return false;
    if (!this->recv() || !is_response("213"))
    {
      C_ERROR("ftp no/bad response on SIZE command to server (%s): %s\n", m_ftp_server_addr.data(), m_response.data());
      return false;
    }
    const char * ptr = m_response.data() + 3;
    while (*ptr == ' ')
      ptr ++;
    fs_server = atoi(ptr);
    if (fs_server <= 0)
    {
      C_ERROR("bad fs_server value = %d\n", fs_server);
      return false;
    }
    C_INFO("ftp (%s) server reported size = %d, local size = %d\n", m_ftp_info->dist_id.data(), fs_server, fs_client);
    if (fs_client >= fs_server)
      fs_client = 0;
  }

  if (this->send("PASV\r\n"))
  {
    if (!this->recv() || !is_response("227"))
    {
      C_ERROR("ftp no/bad response on PASV command to server (%s): %s\n", m_ftp_server_addr.data(), m_response.data());
      return false;
    }
  }

  char * ptr1 = ACE_OS::strrchr(m_response.data(), '(');
  char * ptr2 = NULL;
  if (ptr1)
    ptr2 = ACE_OS::strrchr(ptr1, ')');
  if (unlikely(!ptr1 || !ptr2))
  {
    C_ERROR("ftp bad response data format on PASV command to server (%s): %s\n", m_ftp_server_addr.data(), m_response.data());
    return false;
  }
  *ptr1 ++ = 0;
  *ptr2 = 0;

  if (sscanf(ptr1, "%d,%d,%d,%d,%d,%d", &d0, &d1, &d2, &d3, &p0, &p1) == -1)
  {
    C_ERROR("ftp bad response address data format on PASV command to server %s\n", m_ftp_server_addr.data());
    return false;
  }
  snprintf(ip, 32, "%d.%d.%d.%d", d0, d1, d2, d3);
  ftp_data_addr.set((p0 << 8) + p1, ip);

  if (connector.connect(stream, ftp_data_addr, &tv) == -1)
  {
    C_ERROR("ftp failed to establish data connection to server %s\n", m_ftp_server_addr.data());
    return false;
  }
  CSStreamGuard gs(stream);
//  else
//    C_INFO("ftp establish data connection OK to server %s\n", m_ftp_server_addr.data());

  if (fs_client > 0)
  {
    char tmp[64];
    ACE_OS::snprintf(tmp, 64, "REST %d\r\n", fs_client);
    this->send(tmp);
    if (!this->recv() || !is_response("350"))
    {
      C_ERROR("ftp no/bad response on REST command to server (%s): %s\n", m_ftp_server_addr.data(), m_response.data());
      return false;
    }
    C_INFO("ftp (%s) continue @%d, ftype=%c, adir=%s\n", m_ftp_info->dist_id.data(), fs_client,
        m_ftp_info->ftype, m_ftp_info->adir.data() ? m_ftp_info->adir.data() : "");
  }

  CMemGuard retr;
  retr.from_string("RETR ", filename, "\r\n");
  if (this->send(retr.data()))
  {
    if (!this->recv() || !is_response("150"))
    {
      C_ERROR("ftp no/bad response on RETR (%s) command to server (%s): %s\n",
          filename, m_ftp_server_addr.data(), m_response.data());
//      if (is_response("550"))
//        m_ftp_info->inc_failed(MyDistInfoFtp::MAX_FAILED_COUNT);
      return false;
    }
  }

  int flag = O_RDWR | O_CREAT;
  if (fs_client <= 0)
    flag |= O_TRUNC;
  else
    flag |= O_APPEND;

  tv.sec(get_timeout_seconds());
  if (file_con.connect(file_put, ACE_FILE_Addr(localfile), &tv, ACE_Addr::sap_any, 0, flag, S_IRUSR | S_IWUSR) == -1)
  {
    C_ERROR("ftp failed to open local file %s to save download %s\n", localfile, (const char*)CErrno());
    return false;
  }
  CFIOGuard g(file_put);
  if (unlikely(!MyClientAppX::instance()->running()))
    return false;

  if (m_ftp_info->first_download && fs_client <= 0)
  {
    m_ftp_info->first_download = false;
    m_ftp_info->post_status_message(9);
  }

  all_size = 0;
  tv.sec(get_timeout_seconds() * 6);
  while ((file_size = stream.recv(file_cache, sizeof(file_cache), &tv)) > 0)
  {
    if (unlikely(!MyClientAppX::instance()->running()))
      return false;

    if (unlikely(file_put.send_n(file_cache, file_size) != file_size))
    {
      C_ERROR("ftp write to file %s failed %s\n", localfile, (const char*)CErrno());
      return false;
    }
    all_size += file_size;
    tv.sec(get_timeout_seconds() * 6);
    if (MyClientAppX::instance()->client_to_dist_module()->dist_info_ftps().prio() > m_ftp_info->prio())
    {
      C_INFO("ftp pause file %s as %s size = %d, ftype = %c, adir = %s prio = %d\n", filename, localfile, all_size,
          m_ftp_info->ftype, m_ftp_info->adir.data() ? m_ftp_info->adir.data() : "", m_ftp_info->prio());
      m_ftp_info->inc_failed(-1);
      return false;
    }
  }

  if (file_size < 0)
  {
    C_ERROR("ftp read data for file %s from server %s failed %s, completed = %d, ftype=%c, adir=%s\n",
        filename, m_ftp_server_addr.data(), (const char*)CErrno(), all_size,
        m_ftp_info->ftype, m_ftp_info->adir.data() ? m_ftp_info->adir.data() : "");
    return false;
  }

//  if (!this->recv() || !is_response("226"))
//  {
//    C_ERROR("ftp no/bad response after transfer of file completed from server %s\n", m_ftp_server_addr.data());
//    return false;
//  }

  C_INFO("ftp downloaded file %s as %s size = %d, ftype = %c, adir = %s\n", filename, localfile, all_size,
      m_ftp_info->ftype, m_ftp_info->adir.data() ? m_ftp_info->adir.data() : "");
  return true;
}



//MyDistInfoHeader//

MyDistInfoHeader::MyDistInfoHeader()
{
  ftype = 0;
  type = 0;
}


MyDistInfoHeader::~MyDistInfoHeader()
{

}

bool MyDistInfoHeader::validate()
{
  if (!ftype_is_valid(ftype))
  {
    C_ERROR("bad MyDistInfoHeader, ftype = %c\n", ftype);
    return false;
  }

  if (!type_is_valid(type))
  {
    C_ERROR("bad MyDistInfoHeader, type = %c\n", type);
    return false;
  }

  if (/*aindex.data() && aindex.data()[0] &&*/ !(findex.data() && findex.data()[0]))
  {
    C_ERROR("bad MyDistInfoHeader, findex is null\n");
    return false;
  }

  if (!(dist_id.data() && dist_id.data()[0]))
  {
    C_ERROR("bad MyDistInfoHeader, dist_id is null\n");
    return false;
  }

  if (!(adir.data() && adir.data()[0]))
  {
    if (ftype_is_chn(ftype))
    {
      C_ERROR("bad MyDistInfoHeader, dist_id=%s, ftype=%c, adir is null\n", dist_id.data(), ftype);
      return false;
    }
  }

  return true;
}

const char * MyDistInfoHeader::index_file() const
{
  if (aindex.data() && aindex.data()[0])
    return aindex.data();
  return findex.data();
}

bool MyDistInfoHeader::need_spl() const
{
  if (!aindex.data() || !aindex.data()[0])
    return false;
  return ACE_OS::strcmp(aindex.data(), findex.data()) != 0;
}

int MyDistInfoHeader::load_header_from_string(char * src)
{
  if (unlikely(!src))
    return -1;

  char * end = strchr(src, MyDataPacketHeader::FINISH_SEPARATOR);
  if (!end)
  {
    C_ERROR("bad packet data @MyDistInfoHeader::load_from_string, no FINISH_SEPARATOR found\n");
    return false;
  }
  *end = 0;

  const char separator[2] = { MyDataPacketHeader::ITEM_SEPARATOR, 0 };
  CStringTokenizer tk(src, separator);
  char * token = tk.get();
  if (unlikely(!token))
    return -1;
  else
    dist_id.from_string(token);

  token = tk.get();
  if (unlikely(!token))
    return -1;
  else
    findex.from_string(token);

  token = tk.get();
  if (unlikely(!token))
    return -1;
  else if (ACE_OS::strcmp(token, Null_Item) != 0)
    adir.from_string(token);

  token = tk.get();
  if (unlikely(!token))
    return -1;
  else if (ACE_OS::strcmp(token, Null_Item) != 0)
    aindex.from_string(token);

  token = tk.get();
  if (unlikely(!token))
    return -1;
  else if (ACE_OS::strcmp(token, Null_Item) != 0)
    ftype = *token;
  else
    return -1;

  token = tk.get();
  if (unlikely(!token))
    return -1;
  else if (ACE_OS::strcmp(token, Null_Item) != 0)
    type = *token;
  else
    return -1;

  return end - src + 1;
}

void MyDistInfoHeader::calc_target_parent_path(CMemGuard & target_parent_path, bool extract_only, bool bv)
{
  if (extract_only)
    MyClientApp::calc_dist_parent_path(target_parent_path, dist_id.data(), client_id.as_string());
  else if (bv)
    MyClientApp::data_path(target_parent_path, client_id.as_string());
  else
    MyClientApp::calc_display_parent_path(target_parent_path, client_id.as_string());
}

bool MyDistInfoHeader::calc_target_path(const char * target_parent_path, CMemGuard & target_path)
{
  C_ASSERT_RETURN(target_parent_path && *target_parent_path, "empty parameter target_parent_path\n", false);
  const char * sub_path;
  if (ftype_is_chn(ftype))
  {
    target_path.from_string(target_parent_path, "/index/", sub_path = adir.data());
    return true;
  }
  else if (ftype_is_adv(ftype))
    sub_path = "5";
  else if (ftype_is_led(ftype))
    sub_path = "led";
  else if (ftype_is_frame(ftype))
  {
    target_path.from_string(target_parent_path);
    return true;
  }
  else if (ftype_is_backgnd(ftype))
    sub_path = "8";
  else
  {
    C_ERROR("invalid dist ftype = %c\n", ftype);
    return false;
  }

  target_path.from_string(target_parent_path, "/", sub_path);
  return true;
}

bool MyDistInfoHeader::calc_update_ini_value(CMemGuard & value)
{
  if (ftype_is_chn(ftype))
    value.from_string(adir.data());
  else if (ftype_is_adv_list(ftype))
    value.from_string("p");
  else if (ftype_is_adv(ftype))
    value.from_string("g");
  else if (ftype_is_led(ftype))
    value.from_string("l");
  else if (ftype_is_frame(ftype))
    value.from_string("k");
  else if (ftype_is_backgnd(ftype))
    value.from_string("d");
  else
  {
    C_ERROR("invalid dist ftype = %c\n", ftype);
    return false;
  }

  return true;
}


//MyDistInfoFtp//

MyDistInfoFtp::MyDistInfoFtp()
{
  m_failed_count = 0;
  last_update = 0;
  first_download = true;
  recv_time = time(NULL);
  status = 2;
  m_prio = 0;
}

int MyDistInfoFtp::prio() const
{
  return m_prio;
}

bool MyDistInfoFtp::validate()
{
  if (!super::validate())
    return false;

  if (status < 2 || status > 6)
  {
    C_ERROR("bad MyDistInfoFtp status (%d)\n", status);
    return false;
  }

  time_t t = time(NULL);
  if (unlikely(!(recv_time < t + const_one_year && recv_time > t - const_one_year)))
  {
    C_WARNING("obsolete MyDistInfoFtp object, recv_time = %d\n", recv_time);
    return false;
  }

  return true;
}

bool MyDistInfoFtp::load_from_string(char * src)
{
  if (unlikely(!src || !*src))
    return false;

  int data_len = ACE_OS::strlen(src);
  int header_len = load_header_from_string(src);
  if (header_len <= 0)
  {
    C_ERROR("bad ftp file packet, no valid header info\n");
    return false;
  }

  if (unlikely(header_len >= data_len))
  {
    C_ERROR("bad ftp file packet, no valid file/password info\n");
    return false;
  }

  char * file_name = src + header_len;
  char * file_password = ACE_OS::strchr(file_name, MyDataPacketHeader::FINISH_SEPARATOR);
  if (unlikely(!file_password))
  {
    C_ERROR("No filename/password found at dist ftp packet\n");
    return false;
  }
  *file_password++ = 0;

  char * ftp_mbz_md5 = ACE_OS::strchr(file_name, MyDataPacketHeader::ITEM_SEPARATOR);
  if (unlikely(!ftp_mbz_md5))
  {
    C_ERROR("No ftp file md5 found at dist ftp packet\n");
    return false;
  }
  *ftp_mbz_md5++ = 0;
  if (ACE_OS::strcmp(ftp_mbz_md5, Null_Item) != 0)
    this->ftp_md5.from_string(ftp_mbz_md5);

  this->file_name.from_string(file_name);

  if (unlikely(!*file_password))
  {
    C_ERROR("No password found at dist ftp packet\n");
    return false;
  }
  this->file_password.from_string(file_password);
  bool ret = validate();
  if (ret)
    m_prio = MyPL::instance().value(ftype - '0');
  return ret;
};

time_t MyDistInfoFtp::get_delay_penalty() const
{
  //return (time_t)(std::min(m_failed_count + 1, (int)MAX_FAILED_COUNT) * 60 * FAILED_PENALTY);
  return (time_t)(60 * CCfgX::instance()->client_download_retry_interval);
}

bool MyDistInfoFtp::should_ftp(time_t now) const
{
  return status == 2 && last_update + get_delay_penalty() < now;
}

bool MyDistInfoFtp::should_extract() const
{
  return status == 3;
}

void MyDistInfoFtp::touch()
{
  last_update = time(NULL);
}

void MyDistInfoFtp::inc_failed(int steps)
{
  m_failed_count += steps;
  if (m_failed_count >= CCfgX::instance()->client_download_retry_count)
  {
    if (status <= 3)
    {
      status = 7;
      update_db_status();
      post_status_message();
    }
  }
}

int MyDistInfoFtp::failed_count() const
{
  return m_failed_count;
}

void MyDistInfoFtp::calc_local_file_name()
{
  if (unlikely(local_file_name.data() != NULL))
    return;
  CMemGuard download_path;
  MyClientApp::calc_download_parent_path(download_path, client_id.as_string());
  local_file_name.from_string(download_path.data(), "/", dist_id.data(), ".mbz");
}

ACE_Message_Block * MyDistInfoFtp::make_ftp_dist_message(const char * dist_id, int status, bool ok, char ftype)
{
  if (status == 6)
    status = 3;
  int dist_id_len = ACE_OS::strlen(dist_id);
  int total_len = dist_id_len + 1 + 2 + 2;
  ACE_Message_Block * mb = CMemPoolX::instance()->get_mb_cmd(total_len, MyDataPacketHeader::CMD_FTP_FILE, false);
  MyDataPacketExt * dpe = (MyDataPacketExt*) mb->base();
  ACE_OS::memcpy(dpe->data, dist_id, dist_id_len);
  dpe->data[dist_id_len] = MyDataPacketHeader::ITEM_SEPARATOR;
  dpe->data[dist_id_len + 1] = (ok ? '1':'0');
  dpe->data[dist_id_len + 2] = (char)(status + '0');
  dpe->data[dist_id_len + 3] = ftype;
  dpe->data[dist_id_len + 4] = 0;
  return mb;
}

void MyDistInfoFtp::post_status_message(int _status) const
{
  int m = _status < 0 ? status: _status;
  bool result_ok;
  if (m == 5 || m == 7 || m == 6)
    result_ok = false;
  else
    result_ok = true;
  ACE_Message_Block * mb = make_ftp_dist_message(dist_id.data(), m, result_ok, ftype);
  MyDataPacketExt * dpe = (MyDataPacketExt*) mb->base();
  if (g_is_test)
    dpe->magic = client_id_index;

//  MyClientAppX::instance()->client_to_dist_module()->dispatcher()->add_to_buffered_mbs(mb);
  MyClientAppX::instance()->send_mb_to_dist(mb);
}

bool MyDistInfoFtp::update_db_status() const
{
  MyClientDBGuard dbg;
  if (dbg.db().open_db(client_id.as_string()))
    return dbg.db().set_ftp_command_status(dist_id.data(), status);
  return false;
}

void MyDistInfoFtp::generate_url_ini()
{
  if (!ftype_is_chn(ftype))
    return;

  CMemGuard path, file, dest_parent_path, true_dest_p_path, t_file;
  MyClientApp::calc_backup_parent_path(dest_parent_path, client_id.as_string());
  MyClientApp::calc_display_parent_path(true_dest_p_path, client_id.as_string());
  path.from_string(dest_parent_path.data(), "/new");
  file.from_string(path.data(), "/index/", adir.data(), "/url.ini");
  t_file.from_string(true_dest_p_path.data(), "/index/", adir.data(), "/url.ini");
  {
    CUnixFileGuard h;
    if (unlikely(!h.open_write(file.data(), true, true, false, false)))
      return;

    const char * s = index_file();
    ::write(h.handle(), s, ACE_OS::strlen(s));
    fsync(h.handle());
  }
  CSysFS::copy_file(file.data(), t_file.data(), true, false);

  if (ftype == '2')
  {
    file.from_string(path.data(), "/index/", adir.data(), "/date.ini");
    t_file.from_string(true_dest_p_path.data(), "/index/", adir.data(), "/date.ini");
    {
      CUnixFileGuard h;
      if (unlikely(!h.open_write(file.data(), true, true, false, false)))
        return;

      char buff[50];
      c_util_generate_time_string(buff, 50, false);
      buff[8] = 0;
      ::write(h.handle(), buff, 8);
      fsync(h.handle());
    }
    CSysFS::copy_file(file.data(), t_file.data(), true, false);
  }
}

void MyDistInfoFtp::generate_update_ini()
{
  CMemGuard value;
  if (unlikely(!calc_update_ini_value(value)))
    return;

  CMemGuard path, file;
  calc_target_parent_path(path, false, false);
  file.from_string(path.data(), "/update.ini");
  CUnixFileGuard h;
  if (unlikely(!h.open_write(file.data(), true, true, false, false)))
    return;

  time_t now = time(NULL);
  struct tm _tm;
  localtime_r(&now, &_tm);
  char buff[100];
  ACE_OS::snprintf(buff, 100, "%02d:%02d;%s", _tm.tm_hour, _tm.tm_min, value.data());
  ::write(h.handle(), buff, ACE_OS::strlen(buff));
}

bool MyDistInfoFtp::operator < (const MyDistInfoFtp & rhs) const
{
  return recv_time < rhs.recv_time;
}

bool MyDistInfoFtp::generate_dist_id_txt(const CMemGuard & path)
{
  CMemGuard fn;
  fn.from_string(path.data(), "/dist_id.txt");
  char buff[32];
  char * ptr;
  if (!dist_id.data() || ACE_OS::strlen(dist_id.data()) < 32)
  {
    ptr = buff;
    ACE_OS::memset(buff, '1', 32);
  } else
    ptr = dist_id.data();

  CUnixFileGuard h;
  if (unlikely(!h.open_write(fn.data(), true, true, false, false)))
    return false;
  bool ret = ::write(h.handle(), ptr, 32) == 32;
  fsync(h.handle());
  return ret;
}


//MyDistInfoFtps//

MyDistInfoFtps::MyDistInfoFtps()
{

}

MyDistInfoFtps::~MyDistInfoFtps()
{
  std::for_each(m_dist_info_ftps.begin(), m_dist_info_ftps.end(), CObjDeletor());
}

int MyDistInfoFtps::prio()
{
  ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, -1);
  if (m_dist_info_ftps.empty())
    return -1;
  MyDistInfoFtpList::iterator it = m_dist_info_ftps.begin();
  return (*it)->prio();
}

void MyDistInfoFtps::add(MyDistInfoFtp * p)
{
  if (unlikely(!p))
    return;
  if (p->status >= 4 || p->status < 2)
  {
    delete p;
    return;
  }

  if (p->status == 3)
  {
    MyClientAppX::instance()->client_to_dist_module()->service()->add_extract_task(p);
    return;
  }

  ACE_MT(ACE_GUARD(ACE_Thread_Mutex, ace_mon, this->m_mutex));
  if (m_dist_info_ftps.empty())
    m_dist_info_ftps.push_back(p);
  else
  {
    MyDistInfoFtpList::iterator it;
    for (it = m_dist_info_ftps.begin(); it != m_dist_info_ftps.end(); ++ it)
    {
      if (p->prio() > (*it)->prio())
      {
        m_dist_info_ftps.insert(it, p);
        return;
      }
    }
    m_dist_info_ftps.push_back(p);
  }
}

int MyDistInfoFtps::status(const char * dist_id, const char * client_id)
{
  if (unlikely(!dist_id || !*dist_id || !client_id || !*client_id))
    return -10;
  int _status;
  MyClientDBGuard dbg;
  if (dbg.db().open_db(client_id))
  {
    if (dbg.db().get_ftp_command_status(dist_id, _status))
      return _status;
  }

  return -10;
}

MyDistInfoFtp * MyDistInfoFtps::get()
{
  ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, NULL);
  if (m_dist_info_ftps.empty())
    return NULL;
  MyDistInfoFtpList::iterator it = m_dist_info_ftps.begin();
  if ((*it)->should_ftp(time(NULL)))
  {
    MyDistInfoFtp * result = (*it);
    m_dist_info_ftps.erase(it);
    return result;
  }
  return NULL;
}


//MyDistFtpFileExtractor//

MyDistFtpFileExtractor::MyDistFtpFileExtractor()
{
  m_dist_info = NULL;
}

bool MyDistFtpFileExtractor::get_true_dest_path(MyDistInfoFtp * dist_info, CMemGuard & target_path)
{
  CMemGuard target_parent_path;
  dist_info->calc_target_parent_path(target_parent_path, false, ftype_is_vd(dist_info->ftype));
  return dist_info->calc_target_path(target_parent_path.data(), target_path);
}

bool MyDistFtpFileExtractor::extract(MyDistInfoFtp * dist_info)
{
  C_ASSERT_RETURN(dist_info, "parameter dist_info null pointer\n", false);

  CClientIDS & idtable = MyClientAppX::instance()->client_id_table();
  CClientInfo client_info;
  if (!idtable.value_all(dist_info->client_id_index, client_info))
  {
    C_ERROR("invalid client_id_index @MyDistFtpFileExtractor::extract()");
    CSysFS::remove(dist_info->local_file_name.data());
    return false;
  }

  if (client_info.expired)
  {
    C_INFO("skipping extract due to previous errors client_id(%s) dist_id(%s)\n", dist_info->client_id.as_string(), dist_info->dist_id.data());
    CSysFS::remove(dist_info->local_file_name.data());
    return false;
  }

  CMemGuard target_parent_path, pn, po, dest_parent_path;
  MyClientApp::calc_backup_parent_path(dest_parent_path, dist_info->client_id.as_string());
  pn.from_string(dest_parent_path.data(), "/new");
  po.from_string(dest_parent_path.data(), "/old");
  dist_info->calc_target_parent_path(target_parent_path, true, false);
  C_INFO("Updating dist(%s) client_id(%s)...\n", dist_info->dist_id.data(), dist_info->client_id.as_string());
  bool bn, bo, bv;
  bv = ftype_is_adv(dist_info->ftype);
  bn = has_id(pn);
  bo = has_id(po);

  if (!bo && !bn)
    C_WARNING("no id found\n");

  bool result = true;
  if (bn && !bo)
  {
    if (!bv)
    {
      if (!syn(dist_info))
        result = false;
    }
    if (result)
      result = do_extract(dist_info, target_parent_path);
  } else
  {
    result = do_extract(dist_info, target_parent_path);
    if (result)
    {
      if (!bv)
        syn(dist_info);
    }
  }

  if (!result)
  {
    C_ERROR("apply update failed for dist_id(%s) client_id(%s)\n", dist_info->dist_id.data(), dist_info->client_id.as_string());
//    idtable.expired(dist_info->client_id_index, true);
//todo: lock or unlock?
  }
  else
  {
    C_INFO("apply update OK for dist_id(%s) client_id(%s)\n", dist_info->dist_id.data(), dist_info->client_id.as_string());
//    if (!g_test_mode && ftype_is_adv_list(dist_info->ftype))
//    {
//      MyConfig * cfg = MyConfigX::instance();
//      if(cfg->adv_expire_days > 0)
//      {
//        MyPooledMemGuard mpath;
//        MyClientApp::calc_display_parent_path(mpath, MyClientAppX::instance()->client_id());
//        MyAdvCleaner cleaner;
//        cleaner.do_clean(mpath, MyClientAppX::instance()->client_id(), cfg->adv_expire_days);
//      }
//    }
  }
  CSysFS::remove_path(target_parent_path.data(), true);
  ACE_OS::sleep(30);
  CSysFS::remove(dist_info->local_file_name.data());
  return result;
}

bool MyDistFtpFileExtractor::do_extract(MyDistInfoFtp * dist_info, const CMemGuard & target_parent_path)
{
  dist_info->calc_local_file_name();
  bool bv = ftype_is_adv(dist_info->ftype);
  if (!CSysFS::make_path(target_parent_path.data(), true))
  {
    C_ERROR("can not mkdir(%s) %s\n", target_parent_path.data(), (const char *)CErrno());
    return false;
  }
  CMemGuard target_path;
  if (!dist_info->calc_target_path(target_parent_path.data(), target_path))
    return false;

  int prefix_len = ACE_OS::strlen(target_parent_path.data());
  if (!CSysFS::make_path_const(target_path.data(), prefix_len, false, true))
  {
    C_ERROR("can not mkdir(%s) %s\n", target_path.data(), (const char *)CErrno());
    return false;
  }

  CMemGuard true_dest_path;
  if (unlikely(!get_true_dest_path(dist_info,  true_dest_path)))
    return false;

  CMemGuard s_n, dest_parent_path, dest_path;
  if (!bv)
  {
    MyClientApp::calc_backup_parent_path(dest_parent_path, dist_info->client_id.as_string());
    s_n.from_string(dest_parent_path.data(), "/new");
    prefix_len = ACE_OS::strlen(dest_parent_path.data());
    if (!CSysFS::make_path_const(s_n.data(), prefix_len, false, true))
    {
      C_ERROR("can not mkdir(%s) %s\n", s_n.data(), (const char *)CErrno());
      return false;
    }
    dist_info->calc_target_path(s_n.data(), dest_path);
  } else
  {
    MyClientApp::data_path(dest_parent_path, dist_info->client_id.as_string());
    prefix_len = ACE_OS::strlen(dest_parent_path.data());
    dest_path.from_string(dest_parent_path.data(), "/5");
    if (!CSysFS::make_path_const(dest_path.data(), prefix_len, false, true))
    {
      C_ERROR("can not mkdir(%s) %s\n", dest_path.data(), (const char *)CErrno());
      return false;
    }
  }
/*
  if (type_is_multi(dist_info->type))
  {
    if (!mycomutil_string_end_with(dist_info->file_name.data(), "/all_in_one.mbz"))
    {
      if (ftype_is_frame(dist_info->ftype))
      {
        MyPooledMemGuard src, dest;
        src.from_string(true_dest_path.data(), "/index.html");
        dest.from_string(target_path.data(), "/index.html");
        struct stat buf;
        if (MyFilePaths::stat(src.data(), &buf) && S_ISREG(buf.st_mode))
        {
          if (!MyFilePaths::copy_file(src.data(), dest.data(), true))
          {
            C_ERROR("failed to copy file %s to %s, %s\n", src.data(), dest.data(), (const char*)MyErrno());
            return false;
          }
        }
        src.from_string(true_dest_path.data(), "/index");
        dest.from_string(target_path.data(), "/index");

        if (MyFilePaths::stat(src.data(), &buf) && S_ISDIR(buf.st_mode))
        {
          if (!MyFilePaths::copy_path(src.data(), dest.data(), true))
          {
            C_ERROR("copy path failed from %s to %s\n", src.data(), dest.data());
            return false;
          }
        }
      } else
      {
        struct stat buf;
        if (MyFilePaths::stat(true_dest_path.data(), &buf) && S_ISDIR(buf.st_mode))
        {
          if (!MyFilePaths::copy_path(true_dest_path.data(), target_path.data(), true))
          {
            C_ERROR("copy path failed from %s to %s\n", true_dest_path.data(), target_path.data());
            return false;
          }
        }
      }

      {
        MyClientDBGuard dbg;
        if (dbg.db().open_db(dist_info->client_id.as_string()))
          dbg.db().load_ftp_md5_for_diff(*dist_info);
      }

      if (unlikely(!dist_info->server_md5.data() || !dist_info->server_md5.data()[0]))
      {
        C_ERROR("no server md5 list for diff dist(%s) client(%s)\n", dist_info->dist_id.data(), dist_info->client_id.as_string());
        return false;
      }
#if 0
      MyMfileSplitter spl;
      spl.init(dist_info->aindex.data());
      MyFileMD5s server_md5s, client_md5s;
//    C_DEBUG("cmp md5 server: %s\n", dist_info->server_md5.data());
//    C_DEBUG("cmp md5 client: %s\n", dist_info->client_md5.data());
      if (!server_md5s.from_buffer(dist_info->server_md5.data(), &spl) ||
          !client_md5s.from_buffer(dist_info->client_md5.data()))
      {
        C_ERROR("bad server/client md5 list @MyDistFtpFileExtractor::do_extract\n");
        return false;
      }
      client_md5s.base_dir(target_path.data());
      server_md5s.minus(client_md5s, NULL, true);

      if (ftype_is_frame(dist_info->ftype))
      {
        MyPooledMemGuard index_path;
        index_path.from_string(target_path.data(), "/", dist_info->index_file());
        MyFilePaths::get_correlate_path(index_path, 0);
        MyFilePaths::zap_empty_paths(index_path);
      }
#else

      if (!MyFilePaths::make_path_const(target_path.data(), prefix_len, false, true))
      {
        C_ERROR("can not mkdir(%s) %s\n", target_path.data(), (const char *)MyErrno());
        return false;
      }
#endif
    }
  }
*/

  CDataComp c;

  bool result = c.decompress(dist_info->local_file_name.data(), target_path.data(), dist_info->file_password.data(), dist_info->aindex.data());
  if (result)
  {
/*
    if (ftype_is_frame(dist_info->ftype) && type_is_all(dist_info->type))
    {
      MyPooledMemGuard mfile;
      if (MyClientApp::get_mfile(true_dest_path, mfile))
      {
        MyPooledMemGuard mfilex;
        mfilex.from_string(true_dest_path.data(), "/", mfile.data());
        MyFilePaths::zap(mfilex.data(), true);
        MyFilePaths::get_correlate_path(mfilex, 0);
        MyFilePaths::zap(mfilex.data(), true);
      }
    }
*/
    if (!bv)
    {
      CMemGuard fn;
      fn.from_string(s_n.data(), "/dist_id.txt");
      if (!CSysFS::remove(fn.data(), false))
        return false;
    }
    if (type_is_valid(dist_info->type))
    {
      if (type_is_single(dist_info->type))
      {
        if (!CSysFS::copy_path(target_path.data(), dest_path.data(), true, true))
          result = false;
        if (!bv && !CSysFS::copy_path(target_path.data(), true_dest_path.data(), true, false))
          C_WARNING("failed to copy_path for true_dest_path\n");
      } else if (type_is_all(dist_info->type) || type_is_multi(dist_info->type))
      {
        if (ftype_is_frame(dist_info->ftype) || type_is_multi(dist_info->type))
        {
          if (!CSysFS::copy_path(target_path.data(), dest_path.data(), true, true))
            result = false;
          if (!ftype_is_adv(dist_info->ftype) && !CSysFS::copy_path(target_path.data(), true_dest_path.data(), true, false))
            C_WARNING("failed to copy_path for true_dest_path\n");
        }
        else
        {
          if (!CSysFS::copy_path_zap(target_path.data(), dest_path.data(), true, ftype_is_chn(dist_info->ftype), true))
            result = false;
          if (!CSysFS::copy_path_zap(target_path.data(), true_dest_path.data(), true, ftype_is_chn(dist_info->ftype), false))
            C_WARNING("failed to copy_path_zap for true_dest_path\n");
        }

/*      if (!result && !ftype_is_vd(dist_info->ftype))
      {
        C_WARNING("doing restore due to deployment error client_id(%s)\n", dist_info->client_id.as_string());
        if (!MyClientApp::full_restore(NULL, true, true, dist_info->client_id.as_string()))
        {
          C_FATAL("locking update on client_id(%s)\n", dist_info->client_id.as_string());
          MyClientAppX::instance()->client_id_table().expired(dist_info->client_id_index, true);
        }
      }
    }else
    {
      C_ERROR("unknown dist type(%d) for dist_id(%s)\n", dist_info->type, dist_info->dist_id.data());
      result = false;
    }
*/
      }
    }
  }

  if (result)
  {
    ACE_OS::sleep(10);
    dist_info->generate_update_ini();
    dist_info->generate_url_ini();
    if (!bv)
      dist_info->generate_dist_id_txt(s_n);
    ACE_OS::sleep(20);
  }
  return result;
}

bool MyDistFtpFileExtractor::has_id(const CMemGuard & target_parent_path)
{
  CMemGuard fn;
  fn.from_string(target_parent_path.data(), "/dist_id.txt");
  return CSysFS::filesize(fn.data()) >= 32;
}

bool MyDistFtpFileExtractor::syn(MyDistInfoFtp * dist_info)
{
  CMemGuard pn, po, dest_parent_path, dest_path;
  MyClientApp::calc_backup_parent_path(dest_parent_path, dist_info->client_id.as_string());
  pn.from_string(dest_parent_path.data(), "/new");
  po.from_string(dest_parent_path.data(), "/old");
  CSysFS::remove_path(po.data(), true);
  if (!CSysFS::make_path(po.data(), true))
  {
    C_ERROR("can not mkdir(%s) %s\n", po.data(), (const char *)CErrno());
    return false;
  }

  if (!MyClientApp::do_backup_restore(pn, po, true, false, true))
    return false;
  ACE_OS::sleep(10);
  bool result = dist_info->generate_dist_id_txt(po);
  ACE_OS::sleep(20);
  return result;
}


//MyDistInfoMD5//

MyDistInfoMD5::MyDistInfoMD5()
{
  m_compare_done = false;
}

bool MyDistInfoMD5::compare_done() const
{
  return m_compare_done;
}

void MyDistInfoMD5::compare_done(bool done)
{
  m_compare_done = done;
}

CFileMD5s & MyDistInfoMD5::md5list()
{
  return m_md5list;
}

void MyDistInfoMD5::post_md5_message()
{
  int dist_id_len = ACE_OS::strlen(dist_id.data());
  int md5_len = m_md5list.total_size(false);
  int total_len = dist_id_len + 1 + md5_len;
  ACE_Message_Block * mb = CMemPoolX::instance()->get_mb_cmd(total_len, MyDataPacketHeader::CMD_SERVER_FILE_MD5_LIST);
  MyDataPacketExt * dpe = (MyDataPacketExt*) mb->base();
  if (g_is_test)
    dpe->magic = client_id_index;
  ACE_OS::memcpy(dpe->data, dist_id.data(), dist_id_len);
  dpe->data[dist_id_len] = MyDataPacketHeader::ITEM_SEPARATOR;
  m_md5list.to_buffer(dpe->data + dist_id_len + 1, md5_len, false);
//  if (g_test_mode)
    C_INFO("posting md5 reply to dist server for dist_id (%s), md5 len = %d\n", dist_id.data(), md5_len - 1);
//  else
//    C_INFO("posting md5 reply to dist server for dist_id (%s), md5 len = %d, data= %s\n", dist_id.data(), md5_len - 1, dpe->data + dist_id_len + 1);
  MyClientAppX::instance()->send_mb_to_dist(mb);
}

const char * MyDistInfoMD5::md5_text() const
{
  return m_md5_text.data();
}

bool MyDistInfoMD5::load_from_string(char * src)
{
  if (unlikely(!src || !*src))
    return false;

  int data_len = ACE_OS::strlen(src);
  int header_len = load_header_from_string(src);
  if (header_len <= 0)
  {
    C_ERROR("bad md5 list packet, no valid dist info\n");
    return false;
  }

  if (unlikely(header_len >= data_len))
  {
    C_ERROR("bad md5 list packet, no valid md5 list info\n");
    return false;
  }

  char * _md5_list = src + header_len;
  m_md5_text.from_string(_md5_list);

  if (!m_md5list.from_buffer(_md5_list))
    return false;

  return validate();
}

bool MyDistInfoMD5::validate()
{
  if (!super::validate())
    return false;

  return (m_md5list.count() > 0);
}


//MyDistInfoMD5s//

MyDistInfoMD5s::~MyDistInfoMD5s()
{
  std::for_each(m_dist_info_md5s.begin(), m_dist_info_md5s.end(), CObjDeletor());
//  std::for_each(m_dist_info_md5s_finished.begin(), m_dist_info_md5s_finished.end(), MyObjectDeletor());
}

void MyDistInfoMD5s::add(MyDistInfoMD5 * p)
{
  if (unlikely(!p))
    return;

  ACE_MT(ACE_GUARD(ACE_Thread_Mutex, ace_mon, this->m_mutex));
  if (p->compare_done())
  {
    //m_dist_info_md5s_finished.push_back(p);
    CObjDeletor dlt;
    dlt(p);
  }
  else
    m_dist_info_md5s.push_back(p);
}

MyDistInfoMD5 * MyDistInfoMD5s::get()
{
  ACE_MT(ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, NULL));
  if (m_dist_info_md5s.empty())
    return NULL;
  MyDistInfoMD5 * result = *m_dist_info_md5s.begin();
  m_dist_info_md5s.pop_front();
  return result;
}

MyDistInfoMD5 * MyDistInfoMD5s::get_finished(const MyDistInfoMD5 & rhs)
{
  ACE_UNUSED_ARG(rhs);
//  ACE_MT(ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, NULL));
//  MyDistInfoMD5ListPtr it;
//  for (it = m_dist_info_md5s_finished.begin(); it != m_dist_info_md5s_finished.end(); ++it)
//  {
//    if (ACE_OS::strcmp((*it)->dist_id.data(), rhs.dist_id.data()) == 0 && (*it)->client_id_index == rhs.client_id_index)
//    {
//      MyDistInfoMD5 * result = *it;
//      m_dist_info_md5s_finished.erase(it);
//      return result;
//    }
//  }

  return NULL;
}


//MyDistInfoMD5Comparer//

bool MyDistInfoMD5Comparer::compute(MyDistInfoHeader * dist_info_header, CFileMD5s & md5list)
{
  if (unlikely(!dist_info_header))
    return false;

  CMemGuard target_parent_path;
  dist_info_header->calc_target_parent_path(target_parent_path, false, false);

  CMemGuard target_path;
  if (!dist_info_header->calc_target_path(target_parent_path.data(), target_path))
    return false;

  int prefix_len = ACE_OS::strlen(target_parent_path.data());
  if (!CSysFS::make_path_const(target_path.data(), prefix_len, false, true))
  {
    C_ERROR("can not mkdir(%s) %s\n", target_path.data(), (const char *)CErrno());
    return false;
  }

  //const char * aindex = ftype_is_chn(dist_info_header->ftype)? NULL: dist_info_header->aindex.data();
  return md5list.calculate(target_path.data(), /*aindex,*/ dist_info_header->aindex.data(),
         type_is_single(dist_info_header->type));
}

bool MyDistInfoMD5Comparer::compute(MyDistInfoMD5 * dist_md5)
{
  if (unlikely(!dist_md5))
    return false;

  CMemGuard target_parent_path, px;
  dist_md5->calc_target_parent_path(px, false, true);
  target_parent_path.from_string(px.data(), "/new");

  CMemGuard target_path;
  if (!dist_md5->calc_target_path(target_parent_path.data(), target_path))
    return false;

//  int prefix_len = ACE_OS::strlen(target_parent_path.data());
//  if (!MyFilePaths::make_path_const(target_path.data(), prefix_len, false, true))
//  {
//    C_ERROR("can not mkdir(%s) %s\n", target_path.data(), (const char *)MyErrno());
//    return false;
//  }

  //const char * aindex = ftype_is_chn(dist_info_header->ftype)? NULL: dist_info_header->aindex.data();
  if (dist_md5->need_spl())
  {
    CMfileSplit spl;
    spl.init(dist_md5->aindex.data());
    return dist_md5->md5list().calculate_diff(target_path.data(), &spl);
  } else
    return dist_md5->md5list().calculate_diff(target_path.data(), NULL);
}

void MyDistInfoMD5Comparer::compare(MyDistInfoHeader * dist_info_header, CFileMD5s & server_md5, CFileMD5s & client_md5)
{
  if (unlikely(!dist_info_header))
    return;
  if (dist_info_header->aindex.data() && *dist_info_header->aindex.data())
  {
    CMfileSplit spl;
    spl.init(dist_info_header->aindex.data());
    server_md5.minus(client_md5, &spl, false);
  } else
    server_md5.minus(client_md5, NULL, false);
}


//MyWatchDog//

MyWatchDog::MyWatchDog()
{
  m_running = false;
}

void MyWatchDog::touch()
{
  m_time = time(NULL);
}

bool MyWatchDog::expired()
{
  if (unlikely(!m_running))
    return false;
  return (time(NULL) >= m_time + WATCH_DOG_TIME_OUT_VALUE);
}

void MyWatchDog::start()
{
  m_running = true;
  m_time = time(NULL);
}


//MyIpVerReply//

MyIpVerReply::MyIpVerReply()
{
  const char * default_time = "09001730";
  m_heart_beat_interval = DEFAULT_HEART_BEAT_INTERVAL;
  m_tail = '0';
  if (!load_from_file())
  {
    init_time_str(m_pc, default_time, '0');
    init_time_str(m_pc_x, default_time, '0');
  }
}

void MyIpVerReply::init_time_str(CMemGuard & g, const char * s, const char c)
{
  char buff[2];
  buff[1] = 0;
  buff[0] = c;
  const char * ptr = (s && *s)? s: "09001730";
  g.from_string("*", ptr, buff);
}

void MyIpVerReply::init(char * data)
{
  time_t t = time(NULL);
  CMemGuard cp;
  cp.from_string(data);

  ACE_GUARD(ACE_Thread_Mutex, ace_mon, this->m_mutex);
  do_init(m_pc, data, t);
  do_init(m_pc_x, cp.data(), t + const_one_day);
  if (ACE_OS::strlen(m_pc.data()) >= 10 && ACE_OS::strlen(m_pc_x.data()) >= 10)
  {
    if (m_pc.data()[9] == '1')
      ACE_OS::memset(m_pc.data() + 5, '0', 4);
    ACE_OS::memcpy(m_pc_x.data() + 5, m_pc.data() + 5, 4);
    m_pc_x.data()[9] = m_pc.data()[9];
  }
}

void MyIpVerReply::do_init(CMemGuard & g, char * data, time_t t)
{
  c_util_generate_time_string(m_now, 24, false, t);
  m_now[8] = 0;

  if (unlikely(!data || !*data))
    return;

  char * def = data;
  char * ptr = ACE_OS::strchr(data, ':');
  if (unlikely(!ptr))
    return;
  *ptr ++ = 0;

  char * on_off = ptr;
  ptr = ACE_OS::strchr(ptr, ':');
  if (unlikely(!ptr))
    return;
  *ptr ++ = 0;

  char * weekend = ptr;
  ptr = ACE_OS::strchr(ptr, ':');
  if (unlikely(!ptr))
    return;
  *ptr ++ = 0;

  char * temp = ptr; //policy
  ptr = ACE_OS::strchr(ptr, ':');
  if (unlikely(!ptr))
    return;
  *ptr ++ = 0;

  char * off = ptr;
  ptr = ACE_OS::strchr(ptr, ':');
  if (unlikely(!ptr))
    return;
  *ptr ++ = 0;

  m_heart_beat_interval = atoi(ptr);
  if (unlikely(m_heart_beat_interval < 0 || m_heart_beat_interval > 100))
  {
    C_ERROR("invalid heart beat interval (%d) received \n", m_heart_beat_interval);
    m_heart_beat_interval = DEFAULT_HEART_BEAT_INTERVAL;
  }

  if (*def != 0)
    save_to_file(def);

  if (search(off) != NULL)
  {
    init_time_str(g, def, '1');
    return;
  }

  const char * p = search(temp);
  if (p != NULL)
  {
    init_time_str(g, p, m_tail);
    return;
  }

  struct tm _tm;
  localtime_r(&t, &_tm);
  if ((_tm.tm_wday == 0 || _tm.tm_wday == 6) && *on_off != 0)
  {
    if (*on_off == '1')
    {
      init_time_str(g, def, '1');
      return;
    }
    else if (*weekend != 0)
    {
      init_time_str(g, weekend, '0');
      return;
    }
  }

  init_time_str(g, def, m_tail);
}

void MyIpVerReply::get_filename(CMemGuard & fn)
{
  fn.from_string(CCfgX::instance()->app_data_path.c_str(), "/pc_time.dat");
}

void MyIpVerReply::save_to_file(const char * s)
{
  if (!s || ACE_OS::strlen(s) != 8)
    return;

  CUnixFileGuard f;
  CMemGuard file_name;
  get_filename(file_name);
  if (!f.open_write(file_name.data(), true, true, false, true))
    return;
  if (::write(f.handle(), s, 8) != 8)
    C_ERROR("write to file %s failed %s\n", file_name.data(), (const char*)CErrno());
}

bool MyIpVerReply::load_from_file()
{
  CUnixFileGuard f;
  CMemGuard file_name;
  get_filename(file_name);
  if (!f.open_read(file_name.data()))
    return false;
  char buff[9];
  if (::read(f.handle(), buff, 8) != 8)
  {
    C_ERROR("read from file %s failed %s\n", file_name.data(), (const char*)CErrno());
    return false;
  }
  buff[8] = 0;
  init_time_str(m_pc, buff, '0');
  init_time_str(m_pc_x, buff, '0');
  return true;
}

const char * MyIpVerReply::search(char * src)
{
  const char separators[2] = {'#', 0 };
  CStringTokenizer tkn(src, separators);
  char * token;
  while ((token = tkn.get()) != NULL)
  {
    if (ACE_OS::strlen(token) < 16)
      continue;
    if (ACE_OS::strncmp(m_now, token, 8) < 0)
      continue;
    if (ACE_OS::strncmp(m_now, token + 8, 8) > 0)
      continue;
    return token + 16;
  }
  return NULL;
}

const char * MyIpVerReply::pc()
{
  time_t t = time(NULL);
  struct tm _tm;
  localtime_r(&t, &_tm);

  ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, "");
  if (ACE_OS::strlen(m_pc.data()) <= 5)
    return m_pc.data();

  char hour[3], minx[3];
  ACE_OS::memcpy(hour, m_pc.data() + 1, 2);
  ACE_OS::memcpy(minx, m_pc.data() + 3, 2);
  hour[2] = 0;
  minx[2] = 0;
  if (_tm.tm_hour < atoi(hour))
    return m_pc.data();
  else if (_tm.tm_hour == atoi(hour) && _tm.tm_min <= atoi(minx))
    return m_pc.data();
  return m_pc_x.data();
}

int MyIpVerReply::heart_beat_interval()
{
  ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, 1);
  return m_heart_beat_interval;
}


//MyClientToDistProcessor//

MyClientToDistProcessor::MyClientToDistProcessor(CHandlerBase * handler): CClientProcBase(handler)
{
  m_version_check_reply_done = false;
  m_handler->msg_queue()->high_water_mark(MSG_QUEUE_MAX_SIZE);
}

const char * MyClientToDistProcessor::name() const
{
  return "MyClientToDistProcessor";
}

int MyClientToDistProcessor::on_open()
{
  if (super::on_open() < 0)
    return -1;

  if (g_is_test)
  {
    const char * myid = MyClientAppX::instance()->client_to_dist_module()->id_generator().get();
    if (!myid)
    {
      C_ERROR(ACE_TEXT("can not fetch a test client id @MyClientToDistHandler::open\n"));
      return -1;
    }
    client_id(myid);
    m_client_id_index = MyClientAppX::instance()->client_id_table().index_of(myid);
    if (m_client_id_index < 0)
    {
      C_ERROR("MyClientToDistProcessor::on_open() can not find client_id_index for id = %s\n", myid);
      return -1;
    }
    m_handler->connection_manager()->set_connection_client_id_index(m_handler, m_client_id_index, NULL);
  } else
  {
    client_id(MyClientAppX::instance()->client_id());
    m_client_id_index = 0;
  }
  if (!g_is_test || m_client_id_index == 0)
    C_INFO("sending handshake request to dist server...\n");
  return send_version_check_req();
}

CProcBase::EVENT_RESULT MyClientToDistProcessor::on_recv_header()
{
  if (!g_is_test)
    C_DEBUG("get dist packet header: command = %d, len = %d\n", m_packet_header.command, m_packet_header.length);

  CProcBase::EVENT_RESULT result = super::on_recv_header();
  if (result != ER_CONTINUE)
    return ER_ERROR;

  bool bVersionCheckReply = m_packet_header.command == MyDataPacketHeader::CMD_CLIENT_VERSION_CHECK_REPLY; //m_version_check_reply_done
  if (bVersionCheckReply == m_version_check_reply_done)
  {
    C_ERROR(ACE_TEXT("unexpected packet header from dist server, version_check_reply_done = %d, "
                      "packet is version_check_reply = %d.\n"), m_version_check_reply_done, bVersionCheckReply);
    return ER_ERROR;
  }

  if (bVersionCheckReply)
  {
    if (!my_dph_validate_client_version_check_reply(&m_packet_header))
    {
      C_ERROR("failed to validate header for version check\n");
      return ER_ERROR;
    }
    return ER_OK;
  }

  if (m_packet_header.command == MyDataPacketHeader::CMD_SERVER_FILE_MD5_LIST)
  {
    if (!my_dph_validate_file_md5_list(&m_packet_header))
    {
      C_ERROR("failed to validate header for server file md5 list\n");
      return ER_ERROR;
    }
    return ER_OK;
  }

  if (m_packet_header.command == MyDataPacketHeader::CMD_FTP_FILE)
  {
    if (!my_dph_validate_ftp_file(&m_packet_header))
    {
      C_ERROR("failed to validate header for server ftp file\n");
      return ER_ERROR;
    }
    return ER_OK;
  }

  if (m_packet_header.command == MyDataPacketHeader::CMD_IP_VER_REQ)
  {
    if (m_packet_header.length <= (int)sizeof(MyDataPacketHeader) || m_packet_header.length >= 512
        || m_packet_header.magic != MyDataPacketHeader::DATAPACKET_MAGIC)
    {
      C_ERROR("failed to validate header for ip ver reply\n");
      return ER_ERROR;
    }
    return ER_OK;
  }

  if (m_packet_header.command == MyDataPacketHeader::CMD_ACK)
  {
    if (!my_dph_validate_base(&m_packet_header))
    {
      C_ERROR("failed to validate header for server ack packet\n");
      return ER_ERROR;
    }
    if (g_is_test)
      return ER_OK_FINISHED;
    else
      return ER_OK;
  }

  if (m_packet_header.command == MyDataPacketHeader::CMD_TQ)
  {
    if (m_packet_header.length <= (int)sizeof(MyDataPacketHeader) || m_packet_header.length >= 512
        || m_packet_header.magic != MyDataPacketHeader::DATAPACKET_MAGIC)
    {
      C_ERROR("failed to validate header for plist\n");
      return ER_ERROR;
    }
    return ER_OK;
  }


  if (m_packet_header.command == MyDataPacketHeader::CMD_REMOTE_CMD)
  {
    if (m_packet_header.length != (int)sizeof(MyDataPacketHeader) + 1
        || m_packet_header.magic != MyDataPacketHeader::DATAPACKET_MAGIC)
    {
      C_ERROR("failed to validate header for remote cmd\n");
      return ER_ERROR;
    }
    return ER_OK;
  }

  if (m_packet_header.command == MyDataPacketHeader::CMD_TEST)
  {
    if (m_packet_header.length < (int)sizeof(MyDataPacketHeader)
        || m_packet_header.magic != MyDataPacketHeader::DATAPACKET_MAGIC)
    {
      C_ERROR("failed to validate header for test cmd\n");
      return ER_ERROR;
    }
    return ER_OK;
  }

  if (m_packet_header.command == MyDataPacketHeader::CMD_PSP)
  {
    if (m_packet_header.length < (int)sizeof(MyDataPacketHeader) + 2
        || m_packet_header.magic != MyDataPacketHeader::DATAPACKET_MAGIC)
    {
      C_ERROR("failed to validate header for psp cmd\n");
      return ER_ERROR;
    }
    return ER_OK;
  }

  C_ERROR("unexpected packet header from dist server, header.command = %d\n", m_packet_header.command);
  return ER_ERROR;
}

CProcBase::EVENT_RESULT MyClientToDistProcessor::on_recv_packet_i(ACE_Message_Block * mb)
{
  if (!g_is_test)
    C_DEBUG("get complete dist packet: command = %d, len = %d\n", m_packet_header.command, m_packet_header.length);

  CFormatProcBase::on_recv_packet_i(mb);
  MyDataPacketHeader * header = (MyDataPacketHeader *)mb->base();

  if (header->command == MyDataPacketHeader::CMD_CLIENT_VERSION_CHECK_REPLY)
  {
    CProcBase::EVENT_RESULT result = do_version_check_reply(mb);

    if (result == ER_OK)
    {
      client_verified(true);
      ((MyClientToDistHandler*)m_handler)->setup_timer();

      if (g_is_test && m_client_id_index != 0)
      {
        ((MyClientToDistHandler*)m_handler)->setup_heart_beat_timer(1);
      } else
      {
        MyClientToDistModule * mod = MyClientAppX::instance()->client_to_dist_module();
        if (!mod->click_sent())
        {
          if (!((MyClientToDistHandler *)m_handler)->setup_click_send_timer())
            C_ERROR("can not set adv click timer %s\n", (const char *)CErrno());
        }
      }

      if (!g_is_test)
        MyConnectIni::update_connect_status(MyConnectIni::CS_ONLINE);
    }

    return result;
  }

  if (header->command == MyDataPacketHeader::CMD_SERVER_FILE_MD5_LIST)
    return do_md5_list_request(mb);

  if (header->command == MyDataPacketHeader::CMD_FTP_FILE)
    return do_ftp_file_request(mb);

  if (header->command == MyDataPacketHeader::CMD_IP_VER_REQ)
    return do_ip_ver_reply(mb);

  if (header->command == MyDataPacketHeader::CMD_REMOTE_CMD)
    return do_remote_cmd(mb);

  if (header->command == MyDataPacketHeader::CMD_ACK)
    return do_ack(mb);

  if (header->command == MyDataPacketHeader::CMD_TEST)
    return do_test(mb);

  if (header->command == MyDataPacketHeader::CMD_PSP)
    return do_psp(mb);

  if (header->command == MyDataPacketHeader::CMD_TQ)
    return do_pl(mb);


  CMBGuard guard(mb);
  C_ERROR("unsupported command received @MyClientToDistProcessor::on_recv_packet_i(), command = %d\n",
      header->command);
  return ER_ERROR;
}

bool MyClientToDistProcessor::check_vlc_empty()
{
  static char o = 'x';
  MyVLCLauncher & vlc = MyClientAppX::instance()->vlc_launcher();
  char c = vlc.empty_advlist() ? '1':'0';
  if (c == o)
    return true;
  o = c;
  ACE_Message_Block * mb = CMemPoolX::instance()->get_mb_cmd(1, MyDataPacketHeader::CMD_VLC_EMPTY);
  MyDataPacketExt * dpe = (MyDataPacketExt *)mb->base();
  dpe->data[0] = c;
  return m_handler->send_data(mb) >= 0;
}

int MyClientToDistProcessor::send_heart_beat()
{
  if (!m_version_check_reply_done)
    return 0;
  ACE_Message_Block * mb = CMemPoolX::instance()->get_mb_cmd(0, MyDataPacketHeader::CMD_HEARTBEAT_PING);
  int ret = (m_handler->send_data(mb) < 0? -1: 0);
  check_vlc_empty();
//  C_DEBUG("send_heart_beat = %d\n", ret);
  return ret;
}

CProcBase::EVENT_RESULT MyClientToDistProcessor::do_md5_list_request(ACE_Message_Block * mb)
{
  CMBGuard guard(mb);
  MyDataPacketExt * packet = (MyDataPacketExt *) mb->base();
  if (!packet->guard())
  {
    C_ERROR("empty md5 list packet client_id(%s)\n", m_client_id.as_string());
    return ER_OK;
  }

  MyDistInfoMD5 * dist_md5 = new MyDistInfoMD5;
  dist_md5->client_id = m_client_id;
  dist_md5->client_id_index = m_client_id_index;
  if (dist_md5->load_from_string(packet->data))
  {
    C_INFO("received one md5 file list command for dist %s, client_id=%s, ftype = %c\n",
        dist_md5->dist_id.data(),
        m_client_id.as_string(),
        dist_md5->ftype);
//    MyDistInfoMD5 * existing = MyClientAppX::instance()->client_to_dist_module()->dist_info_md5s().get_finished(*dist_md5);
//    if (unlikely(existing != NULL))
//    {
//      existing->post_md5_message();
//      MyClientAppX::instance()->client_to_dist_module()->dist_info_md5s().add(existing);
//      delete dist_md5;
//      return ER_OK;
//    }

    if (!MyClientAppX::instance()->client_to_dist_module()->service()->add_md5_task(dist_md5))
      delete dist_md5;
  }
  else
  {
    C_ERROR("bad md5 file list command packet received\n");
    delete dist_md5;
  }

  return ER_OK;
}

CProcBase::EVENT_RESULT MyClientToDistProcessor::do_ftp_file_request(ACE_Message_Block * mb)
{
  CMBGuard guard(mb);
  MyDataPacketExt * packet = (MyDataPacketExt *) mb->base();
  if (!packet->guard())
  {
    C_ERROR("empty ftp file packet\n");
    return ER_OK;
  }

  char dist_id[128];
  {
    const char * ptr = ACE_OS::strchr(packet->data, MyDataPacketHeader::ITEM_SEPARATOR);
    int len = ptr - packet->data;
    if (unlikely(!ptr || len >= 100 || len == 0))
    {
      C_ERROR("can not find dist_id @MyClientToDistProcessor::do_ftp_file_request\n");
      return ER_ERROR;
    }
    ACE_OS::memcpy(dist_id, packet->data, len);
    dist_id[len] = 0;
  }

  CMemGuard str_data;
  str_data.from_string(packet->data);

  MyDistInfoFtp * dist_ftp = new MyDistInfoFtp();
  dist_ftp->status = 2;
  dist_ftp->client_id = m_client_id;
  dist_ftp->client_id_index = m_client_id_index;
  dist_ftp->ftp_password.from_string(m_ftp_password.data());

  if (dist_ftp->load_from_string(packet->data))
  {
    C_INFO("received one ftp command for dist(%s) client(%s): ftype=%c, adir=%s, password=%s, file name=%s\n",
            dist_ftp->dist_id.data(), m_client_id.as_string(), dist_ftp->ftype,
            dist_ftp->adir.data() ? dist_ftp->adir.data(): "",
            dist_ftp->file_password.data(), dist_ftp->file_name.data());
    {
      MyClientDBGuard dbg;
      if (dbg.db().open_db(m_client_id.as_string()))
      {
        int ftp_status;
        if (dbg.db().get_ftp_command_status(dist_id, ftp_status))
        {
          if (ftp_status >= 2)
          {
            ACE_Message_Block * reply_mb = MyDistInfoFtp::make_ftp_dist_message(dist_id, ftp_status);
            C_INFO("dist ftp command already received, dist_id(%s) client_id(%s)\n", dist_id, m_client_id.as_string());
            delete dist_ftp;
            return (m_handler->send_data(reply_mb) < 0 ? ER_ERROR : ER_OK);
          }
          dbg.db().save_ftp_command(str_data.data(), *dist_ftp);
        } else
          dbg.db().save_ftp_command(str_data.data(), *dist_ftp);
      }
    }
    dist_ftp->status = 2;
    dist_ftp->post_status_message();
    MyClientAppX::instance()->client_to_dist_module()->dist_info_ftps().add(dist_ftp);
  }
  else
  {
    C_ERROR("bad ftp command packet received\n");
    delete dist_ftp;
  }

  return ER_OK;
}

void MyClientToDistProcessor::check_offline_report()
{
  time_t t = ((MyClientToDistConnector *)m_handler->connector())->reset_last_connect_time();
  time_t now = time(NULL);
  C_INFO("offline report now = %d, old = %d\n", (int)now, (int)t);
  if (now <= t + OFFLINE_THREASH_HOLD)
    return;

  char buff[64], buff2[64];
  if (unlikely(!c_util_generate_time_string(buff2, 32, false, now) || ! c_util_generate_time_string(buff, 32, false, t)))
  {
    C_ERROR("mycomutil_generate_time_string failed @MyClientToDistProcessor::check_offline_report()\n");
    return;
  }
  ACE_OS::strncat(buff, "-", 64 - 1);
  ACE_OS::strncat(buff, buff2 + 9, 64 -1);
  int len = ACE_OS::strlen(buff);
  ACE_Message_Block * mb = CMemPoolX::instance()->get_mb_cmd(len + 1 + 1,
      MyDataPacketHeader::CMD_PC_ON_OFF);
  MyDataPacketExt * dpe = (MyDataPacketExt *)mb->base();
  dpe->data[0] = '3';
  ACE_OS::memcpy(dpe->data + 1, buff, len + 1);
  m_handler->send_data(mb);
//  mycomutil_mb_putq(MyClientAppX::instance()->client_to_dist_module()->dispatcher(), mb, "client off-line report to dist queue");
}

CProcBase::EVENT_RESULT MyClientToDistProcessor::do_ip_ver_reply(ACE_Message_Block * mb)
{
  CMBGuard guard(mb);
  if (g_is_test && m_client_id_index != 0)
    return ER_OK;

  MyClientToDistModule * mod = MyClientAppX::instance()->client_to_dist_module();
  MyDataPacketExt * dpe = (MyDataPacketExt *) mb->base();
  mod->ip_ver_reply().init(dpe->data);
  return ((MyClientToDistHandler*)m_handler)->setup_heart_beat_timer(mod->ip_ver_reply().heart_beat_interval()) ?
          ER_OK: ER_ERROR;
}

CProcBase::EVENT_RESULT MyClientToDistProcessor::do_ack(ACE_Message_Block * mb)
{
  CMBGuard guard(mb);
  if (unlikely(g_is_test))
  {
    C_ERROR("unexpected ack packet on test mode\n");
    return ER_ERROR;
  }

  MyDataPacketHeader * dph = (MyDataPacketHeader *) mb->base();
  MyClientAppX::instance()->client_to_dist_module()->dispatcher()->on_ack(dph->uuid);
  return ER_OK;
}

CProcBase::EVENT_RESULT MyClientToDistProcessor::do_psp(ACE_Message_Block * mb)
{
  MyDataPacketExt * dpe = (MyDataPacketExt *)mb->base();
  if (!dpe->guard())
  {
    C_ERROR("bad psp packet\n");
    mb->release();
    return ER_OK;
  }

  C_INFO("get psp command (%c) for %s\n", dpe->data[0], dpe->data + 1);
  {
    MyClientDBGuard dbg;
    if (dbg.db().open_db(MyClientAppX::instance()->client_id()))
      dbg.db().set_ftp_command_status(dpe->data + 1, 6);
  }
/*
  if (dpe->data[0] != '0')
  {
    char * p = new char[strlen(dpe->data + 1) + 2];
    strcpy(p, dpe->data + 1);
    MyClientAppX::instance()->client_to_dist_module()->service()->add_rev_task(p);
  }
*/
  dpe->magic = MyDataPacketHeader::DATAPACKET_MAGIC;
  if (m_handler->send_data(mb) < 0)
    return ER_ERROR;
  return ER_OK;
}

CProcBase::EVENT_RESULT MyClientToDistProcessor::do_pl(ACE_Message_Block * mb)
{
  CMBGuard guard(mb);
  MyDataPacketExt * packet = (MyDataPacketExt *) mb->base();
  if (!packet->guard())
  {
    C_ERROR("bad pl packet client_id(%s)\n", m_client_id.as_string());
    return ER_OK;
  }

  MyPL::instance().save(m_client_id.as_string(), packet->data);
  MyPL::instance().parse(packet->data);
  return ER_OK;
}

CProcBase::EVENT_RESULT MyClientToDistProcessor::do_test(ACE_Message_Block * mb)
{
  CMBGuard guard(mb);
  C_DEBUG("received test packet of size %d\n", mb->capacity());
  return ER_OK;
}

CProcBase::EVENT_RESULT MyClientToDistProcessor::do_remote_cmd(ACE_Message_Block * mb)
{
  CMBGuard guard(mb);
  return ER_OK;
}

CProcBase::EVENT_RESULT MyClientToDistProcessor::do_version_check_reply(ACE_Message_Block * mb)
{
  CMBGuard guard(mb);
  m_version_check_reply_done = true;
//  if (!g_test_mode)
//    C_DEBUG("on ver reply: handler = %X, socket = %d\n", (int)(long)m_handler, m_handler->get_handle());

  MyClientVersionCheckReply * vcr;
  vcr = (MyClientVersionCheckReply *)mb->base();
  switch (vcr->reply_code)
  {
  case MyClientVersionCheckReply::VER_OK:
    if (!g_is_test || m_client_id_index == 0)
      C_INFO("handshake response from dist server: OK\n");
    client_verified(true);
    if (vcr->length > (int)sizeof(MyClientVersionCheckReply) + 1)
    {
      MyServerID::save(m_client_id.as_string(), (int)(u_int8_t)vcr->data[0]);
      m_ftp_password.from_string(vcr->data + 1);
      MyClientAppX::instance()->ftp_password(m_ftp_password.data());
    }
    m_handler->connector()->reset_retry_count();
    if (!g_is_test)
      check_offline_report();
    return CProcBase::ER_OK;

  case MyClientVersionCheckReply::VER_OK_CAN_UPGRADE:
    client_verified(true);
    if (vcr->length > (int)sizeof(MyClientVersionCheckReply) + 1)
    {
      MyServerID::save(m_client_id.as_string(), (int)(u_int8_t)vcr->data[0]);
      m_ftp_password.from_string(vcr->data + 1);
      MyClientAppX::instance()->ftp_password(m_ftp_password.data());
    }
    m_handler->connector()->reset_retry_count();
    if (!g_is_test || m_client_id_index == 0)
      C_INFO("handshake response from dist server: OK Can Upgrade\n");
    if (!g_is_test)
      check_offline_report();
    //todo: notify app to upgrade
    return CProcBase::ER_OK;

  case MyClientVersionCheckReply::VER_MISMATCH:
    if (vcr->length > (int)sizeof(MyClientVersionCheckReply) + 1)
      m_ftp_password.from_string(vcr->data);
    m_handler->connector()->reset_retry_count();
    if (!g_is_test || m_client_id_index == 0)
      C_ERROR("handshake response from dist server: Version Mismatch\n");
    //todo: notify app to upgrade
    return CProcBase::ER_ERROR;

  case MyClientVersionCheckReply::VER_ACCESS_DENIED:
    m_handler->connector()->reset_retry_count();
    if (!g_is_test || m_client_id_index == 0)
      C_ERROR("handshake response from dist server: Access Denied\n");
    return CProcBase::ER_ERROR;

  case MyClientVersionCheckReply::VER_SERVER_BUSY:
    if (!g_is_test || m_client_id_index == 0)
      C_INFO("handshake response from dist server: Server Busy\n");

    return CProcBase::ER_ERROR;

  default: //server_list
    if (!g_is_test || m_client_id_index == 0)
      C_INFO("handshake response from dist server: unknown code = %d\n", vcr->reply_code);
    return CProcBase::ER_ERROR;
  }
}

int MyClientToDistProcessor::send_version_check_req()
{
  ACE_INET_Addr addr;
  char my_addr[PEER_ADDR_LEN];
  ACE_OS::memset(my_addr, 0, PEER_ADDR_LEN);
  if (m_handler->peer().get_local_addr(addr) == 0)
    addr.get_host_addr((char*)my_addr, PEER_ADDR_LEN);
  const char * hw_ver = MyClientAppX::instance()->client_to_dist_module()->hw_ver();
  int len = ACE_OS::strlen(hw_ver) + 1;
  ACE_Message_Block * mb = make_version_check_request_mb(len);
  MyClientVersionCheckRequest * proc = (MyClientVersionCheckRequest *)mb->base();
  if (my_addr[0] != 0)
    ACE_OS::memcpy(proc->uuid, my_addr, PEER_ADDR_LEN);
  proc->client_version_major = const_client_version_major;
  proc->client_version_minor = const_client_version_minor;
  proc->client_id = m_client_id;
  proc->server_id = (u_int8_t) MyServerID::load(m_client_id.as_string());
  ACE_OS::memcpy(proc->hw_ver, hw_ver, len);
  return (m_handler->send_data(mb) < 0? -1: 0);
}

int MyClientToDistProcessor::send_ip_ver_req()
{
  ACE_Message_Block * mb = CMemPoolX::instance()->get_mb_cmd_direct(sizeof(MyIpVerRequest), MyDataPacketHeader::CMD_IP_VER_REQ);
  MyIpVerRequest * ivr = (MyIpVerRequest *) mb->base();
  ivr->client_version_major = const_client_version_major;
  ivr->client_version_minor = const_client_version_minor;
  if (!g_is_test || m_client_id_index == 0)
    C_INFO("sending ip ver to dist server...\n");
  return (m_handler->send_data(mb) < 0? -1: 0);
}


//MyDistServerAddrList//

MyDistServerAddrList::MyDistServerAddrList()
{
  m_index = -1;
  m_ftp_index = -1;
  m_addr_list_len = 0;
}

void MyDistServerAddrList::addr_list(char *list)
{
  ACE_MT(ACE_GUARD(ACE_Thread_Mutex, ace_mon, this->m_mutex));
  m_index = -1;
  m_ftp_index = -1;
  m_server_addrs.clear();
  m_ftp_addrs.clear();
  m_addr_list_len = 0;
  m_addr_list.free();

  if (!list || !*list)
    return;

  m_addr_list_len = ACE_OS::strlen(list) + 1;
  m_addr_list.from_string(list);
  char * ftp_list = strchr(list, MyDataPacketHeader::FINISH_SEPARATOR);
  if (ftp_list)
    *ftp_list++ = 0;

  char seperator[2] = {MyDataPacketHeader::ITEM_SEPARATOR, 0};
  char *str, *token, *saveptr;

  for (str = list; ;str = NULL)
  {
    token = strtok_r(str, seperator, &saveptr);
    if (token == NULL)
      break;
    if (!*token)
      continue;
    if (!valid_addr(token))
      C_WARNING("skipping invalid dist server addr: %s\n", token);
    else
    {
      C_INFO("adding dist server addr: %s\n", token);
      m_server_addrs.push_back(token);
    }
  }

  if (!ftp_list || !*ftp_list)
  {
    C_ERROR("not ftp server addr list found\n");
    return;
  }

  for (str = ftp_list; ;str = NULL)
  {
    token = strtok_r(str, seperator, &saveptr);
    if (token == NULL)
      break;
    if (!*token)
      continue;
    if (!valid_addr(token))
      C_WARNING("skipping invalid ftp server addr: %s\n", token);
    else
    {
      C_INFO("adding ftp server addr: %s\n", token);
      m_ftp_addrs.push_back(token);
    }
  }
}

const char * MyDistServerAddrList::begin()
{
  m_index = 0;
  if (m_server_addrs.empty())
    return NULL;
  return m_server_addrs[0].c_str();
}

const char * MyDistServerAddrList::next()
{
  if (m_index <= int(m_server_addrs.size() + 1) && m_index >= 0)
    ++m_index;
  if (m_index >= int(m_server_addrs.size()) || m_index < 0)
    return NULL;
  return m_server_addrs[m_index].c_str();
}

bool MyDistServerAddrList::empty() const
{
  return m_server_addrs.empty();
}

const char * MyDistServerAddrList::rnd()
{
  ACE_MT(ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, NULL));
  int m = m_ftp_addrs.size();
  if (m <= 0)
    return NULL;
  if (m == 1)
  {
    m_ftp_index = 0;
    return m_ftp_addrs[0].c_str();
  }
  int i = random() % m;
  if (i < 0)
    i = i * -1;
  if (i < 0 || i > m)
    i = 0;
  m_ftp_index = i;
  return m_ftp_addrs[m_ftp_index].c_str();
}

const char * MyDistServerAddrList::begin_ftp()
{
  ACE_MT(ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, NULL));
  m_ftp_index = 0;
  if (m_ftp_addrs.empty())
    return NULL;
  return m_ftp_addrs[0].c_str();
}

const char * MyDistServerAddrList::next_ftp()
{
  ACE_MT(ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, NULL));
  if (m_ftp_index <= int(m_ftp_addrs.size() + 1) && m_ftp_index >= 0)
    ++m_ftp_index;
  if (m_ftp_index >= int(m_ftp_addrs.size()) || m_ftp_index < 0)
    return NULL;
  return m_ftp_addrs[m_ftp_index].c_str();
}

bool MyDistServerAddrList::empty_ftp()
{
  ACE_MT(ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, true));
  return m_ftp_addrs.empty();
}

void MyDistServerAddrList::save()
{
  if (m_addr_list_len <= 5)
    return;
  CUnixFileGuard f;
  CMemGuard file_name;
  get_file_name(file_name);
  if (!f.open_write(file_name.data(), true, true, false, true))
    return;
  if (::write(f.handle(), m_addr_list.data(), m_addr_list_len) != m_addr_list_len)
    C_ERROR("write to file %s failed %s\n", file_name.data(), (const char*)CErrno());
}

void MyDistServerAddrList::load()
{
  CUnixFileGuard f;
  CMemGuard file_name;
  get_file_name(file_name);
  if (!f.open_read(file_name.data()))
    return;
  const int BUFF_SIZE = 2048;
  char buff[BUFF_SIZE];
  int n = ::read(f.handle(), buff, BUFF_SIZE);
  if (n <= 0)
    return;
  buff[n - 1] = 0;
  addr_list(buff);
}

void MyDistServerAddrList::get_file_name(CMemGuard & file_name)
{
  const char * const_file_name = "/config/servers.lst";
  file_name.from_string(CCfgX::instance()->app_path.c_str(), const_file_name);
}

bool MyDistServerAddrList::valid_addr(const char * addr) const
{
  struct in_addr ia;
  return (::inet_pton(AF_INET, addr, &ia) == 1);
}

bool MyDistServerAddrList::has_cache()
{
  CMemGuard file_name;
  get_file_name(file_name);
  struct stat st;
  if (!CSysFS::stat(file_name.data(), &st))
    return false;
  return st.st_size >= 7;
}


//MyVlcItem//

MyVlcItem::MyVlcItem()
{
  duration = 0;
}

int MyVlcItem::length() const
{
  return filename.length() + 10;
}


//MyVlcItems//

MyVlcItem * MyVlcItems::find(const char * fn)
{
  MyVlcItemList::iterator it = m_vlcs.begin();
  for (; it != m_vlcs.end(); ++it)
    if (strcmp(fn, it->filename.c_str()) == 0)
      return &(*it);

  return NULL;
}

void MyVlcItems::add(const char * , int )
{
}

int MyVlcItems::total_len()
{
  int result = 0;
  MyVlcItemList::iterator it = m_vlcs.begin();
  for (; it != m_vlcs.end(); ++it)
    result += it->length();
  return result;
}

bool MyVlcItems::empty() const
{
  return m_vlcs.empty();
}

ACE_Message_Block * MyVlcItems::make_mb()
{
  return NULL;
}


//MyVlcHistory//

void MyVlcHistory::items(MyVlcItems * _items)
{
  m_items = _items;
}

void MyVlcHistory::process()
{
  std::string vlc2 = CCfgX::instance()->app_data_path + "/vlc-history2.txt";
  std::string vlc1 = CCfgX::instance()->app_data_path + "/vlc-history.txt";
  CSysFS::remove(vlc1.c_str(), true);
  CSysFS::remove(vlc2.c_str(), true);
  return;
/*
  if (!MyFilePaths::exist(vlc1.c_str()))
    return;
  if (!MyFilePaths::rename(vlc1.c_str(), vlc2.c_str(), false))
    return;
  std::ifstream ifs(vlc2.c_str());
  if (!ifs || ifs.bad())
  {
    C_WARNING("failed to open %s: %s\n", vlc2.c_str(), (const char*)MyErrno());
    return;
  }

//  const char * leading = "/tmp/daily/5/";
//  int leading_len = ACE_OS::strlen(leading);
  int m, p = 0;
  const int BLOCK_SIZE = 1024;
  char line[BLOCK_SIZE];
  char pline[BLOCK_SIZE];
  pline[0] = 0;
  while (!ifs.eof())
  {
    ifs.getline(line, BLOCK_SIZE - 1);
    line[BLOCK_SIZE - 1] = 0;
    int len = ACE_OS::strlen(line);
    if (len <= 12 || line[10] != ',')
      continue;
    line[10] = 0;
    m = atoi(line);
    if (m < 10000)
      continue;
    int d = m - p;
    p = m;
    if (d <= 3 * 60 * 60 && pline[0] != 0 && d > 0)
      m_items->add(pline, d);
    if (ACE_OS::strcmp(line + 11, "Media Library") == 0 || ACE_OS::strcmp(line + 11, "gasket.avi") == 0)
      pline[0] = 0;
    else
      ACE_OS::strcpy(pline, line + 11);
  }
*/
}


//MyClientToDistHandler//

MyClientToDistHandler::MyClientToDistHandler(CConnectionManagerBase * xptr): CHandlerBase(xptr)
{
  m_processor = new MyClientToDistProcessor(this);
  m_heart_beat_timer = -1;
  m_heart_beat_tmp_timer = -1;
}

bool MyClientToDistHandler::setup_timer()
{
  ACE_Time_Value interval(IP_VER_INTERVAL * 60);
  if (reactor()->schedule_timer(this, (void*)IP_VER_TIMER, interval, interval) < 0)
  {
    C_ERROR(ACE_TEXT("MyClientToDistHandler setup ip ver timer failed, %s"), (const char*)CErrno());
    return false;
  }

  if (!g_is_test)
    C_INFO("MyClientToDistHandler setup ip ver timer: OK\n");

  ACE_Time_Value interval2(HEART_BEAT_PING_TMP_INTERVAL * 60);
  m_heart_beat_tmp_timer = reactor()->schedule_timer(this, (void*)HEART_BEAT_PING_TMP_TIMER, interval2, interval2);
  if (m_heart_beat_tmp_timer < 0)
    C_ERROR(ACE_TEXT("MyClientToDistHandler setup tmp heart beat timer failed, %s"), (const char*)CErrno());

  return true;
}

bool MyClientToDistHandler::setup_heart_beat_timer(int heart_beat_interval)
{
  if (m_heart_beat_timer >= 0)
    return true;

  if (unlikely(heart_beat_interval <= 0))
  {
    C_ERROR("received bad heart_beat_interval (%d), using default value (3) instead\n", heart_beat_interval);
    heart_beat_interval = 3;
  }

  if (!g_is_test || m_processor->client_id_index() == 0)
    C_INFO("setup heart beat timer (per %d minute(s))\n", heart_beat_interval);
  ACE_Time_Value interval(heart_beat_interval * 60);
  m_heart_beat_timer = reactor()->schedule_timer(this, (void*)HEART_BEAT_PING_TIMER, interval, interval);
  if (m_heart_beat_timer < 0)
  {
    C_ERROR(ACE_TEXT("MyClientToDistHandler setup heart beat timer failed, %s"), (const char*)CErrno());
    return false;
  } else
  {
    if (m_heart_beat_tmp_timer >= 0)
    {
      reactor()->cancel_timer(m_heart_beat_tmp_timer);
      m_heart_beat_tmp_timer = -1;
    }
    return true;
  }
}

bool MyClientToDistHandler::setup_click_send_timer()
{
  const int const_delay_max = 15 * 60;
  int delay = (int)(random() % const_delay_max);
  ACE_Time_Value interval(delay);
  if (reactor()->schedule_timer(this, (void*)CLICK_SEND_TIMER, interval) < 0)
  {
    C_ERROR(ACE_TEXT("MyClientToDistHandler setup click send timer failed, %s"), (const char*)CErrno());
    return false;
  }

  return true;
}

MyClientToDistModule * MyClientToDistHandler::module_x() const
{
  return (MyClientToDistModule *)connector()->module_x();
}

int MyClientToDistHandler::on_open()
{
  return 0;
}

int MyClientToDistHandler::handle_timeout(const ACE_Time_Value &current_time, const void *act)
{
  ACE_UNUSED_ARG(current_time);
//  C_DEBUG("MyClientToDistHandler::handle_timeout()\n");
  if (long(act) == HEART_BEAT_PING_TIMER)
  {
    if (m_processor->client_id_index() == 0)
      C_DEBUG("ping dist server now...\n");
#if 0
    const int extra_size = 1024 * 1024 * 1;
    ACE_Message_Block * mb = CMemPoolX::instance()->get_mb_cmd(extra_size, MyDataPacketHeader::CMD_TEST);
    MyDataPacketExt * dpe = (MyDataPacketExt *)mb->base();
    ACE_OS::memset(dpe->data, 0, extra_size);
    int ret = send_data(mb);
    if (ret == 0)
      ret = ((MyClientToDistProcessor*)m_processor)->send_heart_beat();
    return ret;
#else
    return ((MyClientToDistProcessor*)m_processor)->send_heart_beat();
#endif
  }
  else if (long(act) == HEART_BEAT_PING_TMP_TIMER)
  {
    if (m_processor->client_id_index() == 0)
      C_DEBUG("ping (tmp) dist server now...\n");
    return ((MyClientToDistProcessor*)m_processor)->send_heart_beat();
  }
  else if (long(act) == IP_VER_TIMER)
    return ((MyClientToDistProcessor*)m_processor)->send_ip_ver_req();
  else if (long(act) == CLICK_SEND_TIMER)
  {
    MyClientToDistModule * mod = MyClientAppX::instance()->client_to_dist_module();
    if (mod->click_sent())
      return 0;
    ACE_Message_Block * mb = mod->get_click_infos(m_processor->client_id().as_string());
    mod->click_sent_done(m_processor->client_id().as_string());
    C_INFO("adv click info, mb %s NULL\n", mb? "not": "is");
    if (mb != NULL)
    {
      MyClientAppX::instance()->client_to_dist_module()->dispatcher()->add_to_buffered_mbs(mb);
      if (send_data(mb) < 0)
        return -1;
    }

    mb = mod->get_vlc_infos(m_processor->client_id().as_string());
    /*C_INFO("vlc play info, mb %s NULL\n", mb? "not": "is");
    if (mb != NULL)
    {
      if (send_data(mb) < 0)
        return -1;
    }*/
    return 0;
  }
  else if (long(act) == 0)
    return -1;
  else
  {
    C_ERROR("unexpected timer call @MyClientToDistHandler::handle_timeout, timer id = %d\n", long(act));
    return 0;
  }
}

void MyClientToDistHandler::on_close()
{
  reactor()->cancel_timer(this);

  if (g_is_test)
  {
    if (m_connection_manager->locked())
      return;
    MyClientAppX::instance()->client_to_dist_module()->id_generator().put
        (
          ((MyClientToDistProcessor*)m_processor)->client_id().as_string()
        );
  }
}

PREPARE_MEMORY_POOL(MyClientToDistHandler);


//MyClientToDistService//

MyClientToDistService::MyClientToDistService(CMod * module, int numThreads):
    CTaskBase(module, numThreads)
{
  msg_queue()->high_water_mark(MSG_QUEUE_MAX_SIZE);
}

int MyClientToDistService::svc()
{
  C_INFO(ACE_TEXT ("running %s::svc()\n"), name());

  for (ACE_Message_Block *mb; getq(mb) != -1;)
  {
    int task_type;
    void * p;
    {
      CMBGuard guard(mb);
      p = get_task(mb, task_type);
    }

    if (unlikely(!p))
    {
      C_ERROR("null pointer get @%s::get_task(mb)\n", name());
      continue;
    }

    if (task_type == TASK_MD5)
      do_md5_task((MyDistInfoMD5 *)p);
    else if (task_type == TASK_EXTRACT)
      do_extract_task((MyDistInfoFtp *)p);
    else if (task_type == TASK_REV)
      do_rev_task((const char *)p);
    else
      C_ERROR("unknown task type = %d @%s::svc()\n", task_type, name());
  }

  C_INFO(ACE_TEXT ("exiting %s::svc()\n"), name());
  return 0;
}

const char * MyClientToDistService::name() const
{
  return "MyClientToDistService";
}

bool MyClientToDistService::add_md5_task(MyDistInfoMD5 * p)
{
  if (unlikely(!p->validate()))
  {
    C_ERROR("invalid md5 task @ %s::add_md5_task", name());
    delete p;
    return true;
  }
  return do_add_task(p, TASK_MD5);
}

bool MyClientToDistService::add_extract_task(MyDistInfoFtp * p)
{
  if (unlikely(!p->validate()))
  {
    C_ERROR("invalid extract task @ %s::add_extract_task", name());
    delete p;
    return true;
  }
  return do_add_task(p, TASK_EXTRACT);
}

bool MyClientToDistService::add_rev_task(const char * p)
{
  if (!p)
    return true;
  if (!*p)
  {
    delete []p;
    return true;
  }
  return do_add_task((void*)p, TASK_REV);
}

void MyClientToDistService::return_back(MyDistInfoFtp * dist_info)
{
  if (unlikely(!dist_info))
    return;
  ((MyClientToDistModule*)module_x())->dist_info_ftps().add(dist_info);
}

void MyClientToDistService::return_back_md5(MyDistInfoMD5 * p)
{
  if (unlikely(!p))
      return;
  ((MyClientToDistModule*)module_x())->dist_info_md5s().add(p);
}


void MyClientToDistService::do_md5_task(MyDistInfoMD5 * p)
{
  if (unlikely(!p || p->compare_done()))
  {
    return_back_md5(p);
    return;
  }

#if 1
  if (!MyDistInfoMD5Comparer::compute(p))
    C_ERROR("md5 file list generation error\n");

  bool b_saved = false;
  {
    MyClientDBGuard dbg;
    if (dbg.db().open_db(p->client_id.as_string()))
      b_saved = dbg.db().save_md5_command(p->dist_id.data(), p->md5_text(), "");
  }

  C_INFO("client side md5 for dist_id(%s) save: %s\n", p->dist_id.data(), b_saved? "OK":"failed");
#else
  CFileMD5s client_md5s;
  if (!MyDistInfoMD5Comparer::compute(p, client_md5s))
    C_ERROR("md5 file list generation error\n");

  bool b_saved = false;
  {
    CMemGuard md5_client;
    client_md5s.sort();
    int len = client_md5s.total_size(true);
    CMemPoolX::instance()->alloc_mem(len, &md5_client);
    client_md5s.to_buffer(md5_client.data(), len, true);

    MyClientDBGuard dbg;
    if (dbg.db().open_db(p->client_id.as_string()))
      b_saved = dbg.db().save_md5_command(p->dist_id.data(), p->md5_text(), md5_client.data());
  }

  C_INFO("client side md5 for dist_id(%s) save: %s\n", p->dist_id.data(), b_saved? "OK":"failed");

  MyDistInfoMD5Comparer::compare(p, p->md5list(), client_md5s);
#endif
  p->compare_done(true);
  p->post_md5_message();
  return_back_md5(p);
}

void MyClientToDistService::do_rev_task(const char * p)
{
  delete []p;
}

void MyClientToDistService::do_extract_task(MyDistInfoFtp * dist_info)
{
  if (likely(dist_info->status == 3))
  {
    MyDistFtpFileExtractor extractor;
    dist_info->status = extractor.extract(dist_info) ? 4:5;
    dist_info->update_db_status();
    dist_info->post_status_message();
    C_INFO("update done for dist_id(%s) client_id(%s)\n", dist_info->dist_id.data(), dist_info->client_id.as_string());
    if (!g_is_test && dist_info->status == 4)
    {
      if (ftype_is_adv_list(dist_info->ftype))
        MyClientAppX::instance()->vlc_monitor().relaunch();
      else if (ftype_is_frame(dist_info->ftype))
      {
        MyOperaLauncher & ol = MyClientAppX::instance()->opera_launcher();
        {
          ol.kill_instance();
          MyClientAppX::instance()->client_to_dist_module()->dispatcher()->start_watch_dog();
        }
      }
    }
  }
  return_back(dist_info);
}


//MyClientFtpService//

MyClientFtpService::MyClientFtpService(CMod * module, int numThreads):
    CTaskBase(module, numThreads)
{

}

int MyClientFtpService::svc()
{
  static bool bprinted = false;
  if (!bprinted)
  {
    C_INFO(ACE_TEXT ("running %s::svc()\n"), name());
    bprinted = true;
  }
  std::string server_addr = ((MyClientToDistModule*)module_x())->server_addr_list().rnd();
  int failed_count = 0;

  while (MyClientAppX::instance()->running())
  {
    if (!g_is_test)
    {
      const char * s = MyClientAppX::instance()->ftp_password();
      if (!s || !*s)
        ACE_OS::sleep(3);
    }

    MyDistInfoFtp * p = ((MyClientToDistModule*)module_x())->dist_info_ftps().get();
    if (!p)
      ACE_OS::sleep(3);
    else
      do_ftp_task((MyDistInfoFtp *)p, server_addr, failed_count);
  }

  if (bprinted)
  {
    C_INFO(ACE_TEXT ("exiting %s::svc()\n"), name());
    bprinted = false;
  }
  return 0;
}

void MyClientFtpService::do_ftp_task(MyDistInfoFtp * dist_info, std::string & server_addr, int & failed_count)
{
  if (dist_info->status == 2)
  {
    if (unlikely(server_addr.empty()))
    {
      dist_info->touch();
      return_back(dist_info);
      return;
    }

    if (!do_ftp_download(dist_info, server_addr.c_str()))
    {
      return_back(dist_info);
      if (++ failed_count > 3)
      {
        failed_count = 0;
        const char * p = ((MyClientToDistModule*)module_x())->server_addr_list().next_ftp();
        if (p)
          server_addr = p;
        else
          server_addr = ((MyClientToDistModule*)module_x())->server_addr_list().begin_ftp();
      }
      return;
    } else
      failed_count = 0;
  } //status == 0

  return_back(dist_info);
}

const char * MyClientFtpService::name() const
{
  return "MyClientFtpService";
}

bool MyClientFtpService::add_ftp_task(MyDistInfoFtp * p)
{
  return do_add_task(p, TASK_FTP);
}


bool MyClientFtpService::do_ftp_download(MyDistInfoFtp * dist_info, const char * server_ip)
{
  if (unlikely(dist_info->status >=  3))
    return true;

  C_INFO("processing ftp download for dist_id=%s, filename=%s, ftype=%c, adir=%s, password=%s, retry_count=%d\n",
      dist_info->dist_id.data(),
      dist_info->file_name.data(),
      dist_info->ftype,
      dist_info->adir.data() ? dist_info->adir.data():"",
      dist_info->file_password.data(),
      dist_info->failed_count());

  if (!g_is_test)
  {
    MyClientDBGuard dbg;
    if (dbg.db().open_db(MyClientAppX::instance()->client_id()))
    {
      if (dbg.db().ftp_obsoleted(*dist_info))
      {
        C_INFO("ftp dist_id (%s) is obsoleted, canceling...\n", dist_info->dist_id.data());
        dist_info->status = 6;
        dbg.db().set_ftp_command_status(dist_info->dist_id.data(), 6);
        return false;
      }

      int t = -1000;
      dbg.db().get_ftp_command_status(dist_info->dist_id.data(), t);
      if (t >= 6)
      {
        C_INFO("ftp dist_id (%s) not needed, canceling...\n", dist_info->dist_id.data());
        dist_info->status = t;
        return false;
      }
    }
  }

  dist_info->calc_local_file_name();
  bool result = MyFTPClient::download(dist_info, server_ip);
  dist_info->touch();
  if (result)
  {
    if (!g_is_test)
    {
      MyClientDBGuard dbg;
      if (dbg.db().open_db(MyClientAppX::instance()->client_id()))
      {
        int t = -1000;
        dbg.db().get_ftp_command_status(dist_info->dist_id.data(), t);
        if (t >= 6)
        {
          C_INFO("ftp dist_id (%s) not needed, canceling...\n", dist_info->dist_id.data());
          dist_info->status = t;
          return false;
        }
      }
    }

    dist_info->status = 3;
    dist_info->update_db_status();
    dist_info->post_status_message();
  }
  else
    dist_info->inc_failed();
  return result;
}

void MyClientFtpService::return_back(MyDistInfoFtp * dist_info)
{
  if (unlikely(!dist_info))
    return;
  ((MyClientToDistModule*)module_x())->dist_info_ftps().add(dist_info);
}

MyDistInfoFtp * MyClientFtpService::get_dist_info_ftp(ACE_Message_Block * mb) const
{
  if (unlikely(mb->capacity() != sizeof(void *) + sizeof(int)))
    return NULL;
  return *((MyDistInfoFtp **)mb->base());
}


//MyClientToDistConnector//

MyClientToDistConnector::MyClientToDistConnector(CDispatchBase * _dispatcher, CConnectionManagerBase * _manager):
    CConnectorBase(_dispatcher, _manager)
{
  m_tcp_port = CCfgX::instance()->ping_port;
  m_reconnect_interval = RECONNECT_INTERVAL;
  if (g_is_test)
    m_num_connection = MyClientAppX::instance()->client_id_table().count();
  m_last_connect_time = 0;
}

const char * MyClientToDistConnector::name() const
{
  return "MyClientToDistConnector";
}

void MyClientToDistConnector::dist_server_addr(const char * addr)
{
  if (likely(addr != NULL))
    m_tcp_addr = addr;
}

time_t MyClientToDistConnector::reset_last_connect_time()
{
  time_t result = m_last_connect_time;
  m_last_connect_time = time(NULL);
  return result;
}

int MyClientToDistConnector::make_svc_handler(CHandlerBase *& sh)
{
  sh = new MyClientToDistHandler(m_connection_manager);
  if (!sh)
  {
    C_ERROR("can not alloc MyClientToDistHandler from %s\n", name());
    return -1;
  }
//  C_DEBUG("MyClientToDistConnector::make_svc_handler(%X)...\n", long(sh));
  sh->parent((void*)this);
  sh->reactor(reactor());
  return 0;
}

bool MyClientToDistConnector::before_reconnect()
{
  if (m_last_connect_time == 0)
    m_last_connect_time = time(NULL);
  if (m_reconnect_retry_count <= 5)
    return true;

  MyDistServerAddrList & addr_list = ((MyClientToDistModule*)(m_module))->server_addr_list();
  const char * new_addr = addr_list.next();
  if (!new_addr || !*new_addr)
    new_addr = addr_list.begin();
  if (new_addr && *new_addr)
  {
    if (ACE_OS::strcmp("127.0.0.1", new_addr) == 0)
      new_addr = CCfgX::instance()->middle_addr.c_str();
    C_INFO("maximum connect to %s:%d retry count reached , now trying next addr %s:%d...\n",
        m_tcp_addr.c_str(), m_tcp_port, new_addr, m_tcp_port);
    m_tcp_addr = new_addr;
    m_reconnect_retry_count = 1;
  }
  return true;
}


//MyBufferedMB//

MyBufferedMB::MyBufferedMB(ACE_Message_Block * mb)
{
  m_mb = mb->duplicate();
  m_last = time(NULL);
}

MyBufferedMB::~MyBufferedMB()
{
  if (m_mb)
    m_mb->release();
}

ACE_Message_Block * MyBufferedMB::mb()
{
  return m_mb;
}

bool MyBufferedMB::timeout(time_t t) const
{
  return m_last + TIME_OUT_VALUE < t;
}

void MyBufferedMB::touch(time_t t)
{
  m_last = t;
}

bool MyBufferedMB::match(uuid_t uuid)
{
  MyDataPacketHeader * dph = (MyDataPacketHeader*)m_mb->base();
  return uuid_compare(dph->uuid, uuid) == 0;
}


//MyBufferedMBs//

MyBufferedMBs::MyBufferedMBs()
{
  m_con_manager = NULL;
}

MyBufferedMBs::~MyBufferedMBs()
{
  std::for_each(m_mblist.begin(), m_mblist.end(), CObjDeletor());
}

void MyBufferedMBs::connection_manager(CConnectionManagerBase * p)
{
  m_con_manager = p;
}

void MyBufferedMBs::add(ACE_Message_Block * mb)
{
  if (!mb || mb->capacity() < (size_t)sizeof(MyDataPacketHeader))
    return;
  MyBufferedMB * obj = new MyBufferedMB(mb);
  m_mblist.push_back(obj);
}

void MyBufferedMBs::check_timeout()
{
  if (!m_con_manager)
    return;
  MyBufferedMBList::iterator it;
  MyBufferedMB * p;
  time_t t = time(NULL);
  for (it = m_mblist.begin(); it != m_mblist.end(); ++it)
  {
    p = *it;
    if (p->timeout(t))
    {
      m_con_manager->send_single(p->mb()->duplicate());
      p->touch(t);
    }
  }
}

void MyBufferedMBs::on_reply(uuid_t uuid)
{
  MyBufferedMBList::iterator it;
  MyBufferedMB * p;
  for (it = m_mblist.begin(); it != m_mblist.end(); ++it)
  {
    p = *it;
    if (p->match(uuid))
    {
      delete p;
      m_mblist.erase(it);
      break;
    }
  }
}


//MyClientToDistDispatcher//

MyClientToDistDispatcher::MyClientToDistDispatcher(CMod * pModule, int numThreads):
    CDispatchBase(pModule, numThreads)
{
  m_connector = NULL;
  m_middle_connector = NULL;
  m_http1991_acceptor = NULL;
  m_clock_interval = FTP_CHECK_INTERVAL * 60;
  msg_queue()->high_water_mark(MSG_QUEUE_MAX_SIZE);
}

MyClientToDistDispatcher::~MyClientToDistDispatcher()
{

}

bool MyClientToDistDispatcher::on_start()
{
  m_middle_connector = new MyClientToMiddleConnector(this, new CConnectionManagerBase());
  add_connector(m_middle_connector);
  if (!g_is_test)
  {
    m_http1991_acceptor = new MyHttp1991Acceptor(this, new CConnectionManagerBase());
    add_acceptor(m_http1991_acceptor);

    ACE_Time_Value interval(WATCH_DOG_INTERVAL * 60);
    if (reactor()->schedule_timer(this, (const void*)TIMER_ID_WATCH_DOG, interval, interval) < 0)
      C_ERROR("setup watch dog timer failed %s %s\n", name(), (const char*)CErrno());

    if (MyClientAppX::instance()->opera_launcher().running())
      start_watch_dog();
  }
  return true;
}

const char * MyClientToDistDispatcher::name() const
{
  return "MyClientToDistDispatcher";
}


int MyClientToDistDispatcher::handle_timeout(const ACE_Time_Value &, const void * act)
{
  if ((long)act == (long)TIMER_ID_BASE)
  {
    ((MyClientToDistModule*)module_x())->check_ftp_timed_task();
    if (!g_is_test)
    {
      if (m_connector == NULL || m_connector->connection_manager()->active_count() == 0)
        MyConnectIni::update_connect_status(MyConnectIni::CS_DISCONNECTED);
      else
        m_buffered_mbs.check_timeout();
    }
  }
  else if ((long)act == (long)TIMER_ID_WATCH_DOG)
    check_watch_dog();
  else
    C_ERROR("unknown timer id (%d) @%s::handle_timeout()\n", (int)(long)act);
  return 0;
}

void MyClientToDistDispatcher::ask_for_server_addr_list_done(bool success)
{
  m_middle_connector->finish();
  MyDistServerAddrList & addr_list = ((MyClientToDistModule*)m_mod)->server_addr_list();
  if (!success)
  {
    C_INFO("failed to get any dist server addr from middle server, trying local cache...\n");
    addr_list.load();
  }

  if (addr_list.empty())
  {
    C_ERROR("no dist server addresses exist @%s\n", name());
    return;
  }

  C_INFO("starting connection to dist server from addr list...\n");
  if (!m_connector)
    m_connector = new MyClientToDistConnector(this, new CConnectionManagerBase());
  add_connector(m_connector);
  m_buffered_mbs.connection_manager(m_connector->connection_manager());

  const char * addr = addr_list.begin();
  if (ACE_OS::strcmp("127.0.0.1", addr) == 0)
    addr = CCfgX::instance()->middle_addr.c_str();
  m_connector->dist_server_addr(addr);
  m_connector->start();
}

void MyClientToDistDispatcher::start_watch_dog()
{
  ((MyClientToDistModule*)module_x())->watch_dog().start();
}

void MyClientToDistDispatcher::on_ack(uuid_t uuid)
{
  m_buffered_mbs.on_reply(uuid);
}

void MyClientToDistDispatcher::add_to_buffered_mbs(ACE_Message_Block * mb)
{
  m_buffered_mbs.add(mb);
}

void MyClientToDistDispatcher::on_stop()
{
  m_connector = NULL;
  m_middle_connector = NULL;
  m_http1991_acceptor = NULL;
}

void MyClientToDistDispatcher::check_watch_dog()
{
  if (((MyClientToDistModule*)module_x())->watch_dog().expired())
    MyClientAppX::instance()->opera_launcher().relaunch();
}

bool MyClientToDistDispatcher::on_event_loop()
{
  ACE_Message_Block * mb;
  const int const_batch_count = 30;
  for (int i = 0; i < const_batch_count; ++ i)
  {
    ACE_Time_Value tv(ACE_Time_Value::zero);
    if (this->getq(mb, &tv) != -1)
    {
      if (!g_is_test)
        C_DEBUG("packet to dist: length = %d\n", mb->length());
      if (g_is_test)
      {
        int index = ((MyDataPacketHeader*)mb->base())->magic;
        CHandlerBase * handler = m_connector->connection_manager()->find_handler_by_index(index);
        if (!handler)
        {
          C_WARNING("can not send data to client since connection is lost @ %s::on_event_loop\n", name());
          mb->release();
          continue;
        }

        ((MyDataPacketHeader*)mb->base())->magic = MyDataPacketHeader::DATAPACKET_MAGIC;
        if (handler->send_data(mb) < 0)
          handler->handle_close();
      } else
      {
        if (likely(mb->capacity() >= (int)sizeof(MyDataPacketHeader)))
        {
          MyDataPacketHeader * dph = (MyDataPacketHeader*)mb->base();
          if (dph->command == MyDataPacketHeader::CMD_FTP_FILE)
          {
            uuid_t uuid;
            uuid_clear(uuid);
            if (uuid_compare(dph->uuid, uuid) != 0)
              add_to_buffered_mbs(mb);
          }
        }
        if (m_connector && m_connector->connection_manager())
          m_connector->connection_manager()->send_single(mb);
        else
          mb->release();
      }
    } else
      break;
  }
  return true;
}


//MyHwAlarm//

MyHwAlarm::MyHwAlarm()
{
  m_x = 0;
  m_y = 0;
}

void MyHwAlarm::x(char _x)
{
  m_x = _x;
}

void MyHwAlarm::y(char _y)
{
  bool changed = (m_y != _y);
  m_y = _y;
  if (unlikely(changed))
  {
    ACE_Message_Block * mb = make_hardware_alarm_mb();
    if (likely(mb != NULL))
      c_util_mb_putq(MyClientAppX::instance()->client_to_dist_module()->dispatcher(), mb, "hw alarm to dist queue");
  }
}

ACE_Message_Block * MyHwAlarm::make_hardware_alarm_mb()
{
  ACE_Message_Block * mb = CMemPoolX::instance()->get_mb_cmd_direct(sizeof(MyPLCAlarm),
      MyDataPacketHeader::CMD_HARDWARE_ALARM);
  if (g_is_test)
    ((MyDataPacketHeader *)mb->base())->magic = 0;
  MyPLCAlarm * dpe = (MyPLCAlarm *)mb->base();
  dpe->x = m_x;
  dpe->y = m_y;
  return mb;
}


//MyClientToDistModule//

MyClientToDistModule::MyClientToDistModule(CApp * app): CMod(app)
{
  if (g_is_test)
  {
    CClientIDS & client_id_table = MyClientAppX::instance()->client_id_table();
    int count = client_id_table.count();
    MyClientID client_id;
    for (int i = 0; i < count; ++ i)
    {
      if (client_id_table.value(i, &client_id))
        m_id_generator.put(client_id.as_string());
    }
  }
  m_service = NULL;
  m_dispatcher = NULL;
  m_client_ftp_service = NULL;
  m_click_sent = false;
  lcd_alarm.x('6');
  led_alarm.x('5');
  temperature_alarm.x('1');
  door_alarm.x('2');
}

MyClientToDistModule::~MyClientToDistModule()
{

}

bool MyClientToDistModule::click_sent() const
{
  return m_click_sent;
}

void MyClientToDistModule::click_sent_done(const char * client_id)
{
  m_click_sent = true;
  MyClientDBGuard dbg;
  if (!dbg.db().open_db(client_id))
    return;
  dbg.db().clear_click_infos();
}

MyWatchDog & MyClientToDistModule::watch_dog()
{
  return m_watch_dog;
}

MyIpVerReply & MyClientToDistModule::ip_ver_reply()
{
  return m_ip_ver_reply;
}

const char * MyClientToDistModule::hw_ver()
{
//  if (unlikely(g_test_mode))
  {
    m_hw_ver = "1.0";
    return m_hw_ver.c_str();
  }
/*
  if (m_hw_ver.length() > 0)
    return m_hw_ver.c_str();
  const char * fn = "/tmp/daily/driver.ini";
  std::ifstream ifs(fn);
  if (!ifs || ifs.bad())
  {
    m_hw_ver = "NULL";
    C_WARNING("can not open file (%s) for read %s\n", fn, (const char*)MyErrno());
    return m_hw_ver.c_str();
  }
  char line[30];
  ifs.getline(line, 30);
  line[29] = 0;
  if (line[0] == 0)
  {
    m_hw_ver = "NULL";
    C_WARNING("file %s does not have led/lcd driver version\n", fn);
    return m_hw_ver.c_str();
  }
  m_hw_ver = line;
  C_INFO("get led/lcd driver version: %s\n", m_hw_ver.c_str());
  return m_hw_ver.c_str();
*/
}

const char * MyClientToDistModule::name() const
{
  return "MyClientToDistModule";
}

MyClientFtpService * MyClientToDistModule::client_ftp_service() const
{
  return m_client_ftp_service;
}

void MyClientToDistModule::ask_for_server_addr_list_done(bool success)
{
  m_dispatcher->ask_for_server_addr_list_done(success);
  if (unlikely(m_server_addr_list.empty_ftp()))
    return;
  if (m_client_ftp_service)
    return;
  if (g_is_test)
    add_task(m_client_ftp_service = new MyClientFtpService(this, CCfgX::instance()->test_client_download_thread_count));
  else
    add_task(m_client_ftp_service = new MyClientFtpService(this, 1));
  m_client_ftp_service->start();
  if (!g_is_test)
  {
    MyClientAppX::instance()->check_prev_extract_task(MyClientAppX::instance()->client_id());
    check_prev_download_task();
  }
}

MyDistInfoFtps & MyClientToDistModule::dist_info_ftps()
{
  return m_dist_info_ftps;
}

MyDistInfoMD5s & MyClientToDistModule::dist_info_md5s()
{
  return m_dist_info_md5s;
}

void MyClientToDistModule::check_ftp_timed_task()
{
  if (unlikely(!m_client_ftp_service))
    return;
}

ACE_Message_Block * MyClientToDistModule::get_click_infos(const char * client_id) const
{
  MyClickInfos click_infos;

  MyClickInfos::iterator it;
  int len = 0;

  {
    MyClientDBGuard dbg;
    if (!dbg.db().open_db(client_id))
      return NULL;

    dbg.db().get_click_infos(click_infos);

    for (it = click_infos.begin(); it != click_infos.end(); ++it)
      len += it->len;
    if (len == 0)
      return NULL;
  }

  ++len;
  ACE_Message_Block * mb = CMemPoolX::instance()->get_mb_cmd(len, MyDataPacketHeader::CMD_UI_CLICK, false);
  MyDataPacketExt * dpe = (MyDataPacketExt *)mb->base();
  char * ptr = dpe->data;
  for (it = click_infos.begin(); it != click_infos.end(); ++it)
  {
    ACE_OS::sprintf(ptr, "%s%c%s%c%s%c",
        it->channel.c_str(),
        MyDataPacketHeader::ITEM_SEPARATOR,
        it->point_code.c_str(),
        MyDataPacketHeader::ITEM_SEPARATOR,
        it->click_count.c_str(),
        MyDataPacketHeader::FINISH_SEPARATOR);
    ptr += it->len;
  }
  return mb;
}

ACE_Message_Block * MyClientToDistModule::get_vlc_infos(const char *) const
{
  MyVlcItems items;
  MyVlcHistory h;
  h.items(&items);
  h.process();
  if (items.empty())
    return NULL;
  return items.make_mb();
}

bool MyClientToDistModule::on_start()
{
  add_task(m_service = new MyClientToDistService(this, 1));
  add_dispatch(m_dispatcher = new MyClientToDistDispatcher(this));
  return true;
}

void MyClientToDistModule::on_stop()
{
  m_service = NULL;
  m_dispatcher = NULL;
  m_client_ftp_service = NULL;
}


MyDistServerAddrList & MyClientToDistModule::server_addr_list()
{
  return m_server_addr_list;
}

void MyClientToDistModule::check_prev_download_task()
{
  if (!g_is_test)
  {
    MyClientDBGuard dbg;
    if (dbg.db().open_db(MyClientAppX::instance()->client_id()))
      dbg.db().load_ftp_commands(&m_dist_info_ftps);
  }
}


/////////////////////////////////////
//client to middle
/////////////////////////////////////

//MyClientToMiddleProcessor//

MyClientToMiddleProcessor::MyClientToMiddleProcessor(CHandlerBase * handler): CClientProcBase(handler)
{

}

const char * MyClientToMiddleProcessor::name() const
{
  return "MyClientToMiddleProcessor";
}

int MyClientToMiddleProcessor::on_open()
{
  if (super::on_open() < 0)
    return -1;

  if (g_is_test)
  {
    MyTestClientIDGenerator & id_generator = MyClientAppX::instance()->client_to_dist_module()->id_generator();
    const char * myid = id_generator.get();
    if (!myid)
    {
      C_ERROR(ACE_TEXT("can not fetch a test client id @MyClientToDistHandler::open\n"));
      return -1;
    }
    client_id(myid);
    m_client_id_index = MyClientAppX::instance()->client_id_table().index_of(myid);
    if (m_client_id_index < 0)
    {
      C_ERROR("MyClientToDistProcessor::on_open() can not find client_id_index for id = %s\n", myid);
      return -1;
    }
    m_handler->connection_manager()->set_connection_client_id_index(m_handler, m_client_id_index, NULL);
    id_generator.put(myid);
  } else
  {
    client_id(MyClientAppX::instance()->client_id());
    m_client_id_index = 0;
  }

  return send_version_check_req();
}

CProcBase::EVENT_RESULT MyClientToMiddleProcessor::on_recv_header()
{
  CProcBase::EVENT_RESULT result = super::on_recv_header();
  if (result != ER_CONTINUE)
    return ER_ERROR;

  bool bVersionCheckReply = m_packet_header.command == MyDataPacketHeader::CMD_CLIENT_VERSION_CHECK_REPLY;

  if (bVersionCheckReply)
  {
    if (!my_dph_validate_client_version_check_reply(&m_packet_header))
    {
      C_ERROR("failed to validate header for version check reply\n");
      return ER_ERROR;
    }
    return ER_OK;
  }

  C_ERROR("unexpected packet header from dist server, header.command = %d\n", m_packet_header.command);
  return ER_ERROR;
}

CProcBase::EVENT_RESULT MyClientToMiddleProcessor::on_recv_packet_i(ACE_Message_Block * mb)
{
  CFormatProcBase::on_recv_packet_i(mb);
  m_wait_for_close = true;
  CMBGuard guard(mb);

  MyDataPacketHeader * header = (MyDataPacketHeader *)mb->base();
  if (header->command == MyDataPacketHeader::CMD_CLIENT_VERSION_CHECK_REPLY)
    do_version_check_reply(mb);
  else
    C_ERROR("unsupported command received @MyClientToDistProcessor::on_recv_packet_i(), command = %d\n",
        header->command);
  return ER_ERROR;
}

void MyClientToMiddleProcessor::do_version_check_reply(ACE_Message_Block * mb)
{
  const char * prefix_msg = "middle server version check reply:";
  MyClientVersionCheckReply * vcr = (MyClientVersionCheckReply *) mb->base();
  switch (vcr->reply_code)
  {
  case MyClientVersionCheckReply::VER_MISMATCH:
    C_ERROR("%s get version mismatch response\n", prefix_msg);
    return;

  case MyClientVersionCheckReply::VER_ACCESS_DENIED:
    C_ERROR("%s get access denied response\n", prefix_msg);
    return;

  case MyClientVersionCheckReply::VER_SERVER_BUSY:
    C_ERROR("%s get server busy response\n", prefix_msg);
    return;

  case MyClientVersionCheckReply::VER_SERVER_LIST:
    do_handle_server_list(mb);
    return;

  default:
    C_ERROR("%s get unexpected reply code = %d\n", prefix_msg, vcr->reply_code);
    return;
  }
}

void MyClientToMiddleProcessor::do_handle_server_list(ACE_Message_Block * mb)
{
  MyClientVersionCheckReply * vcr = (MyClientVersionCheckReply *)mb->base();
  MyClientToDistModule * module = MyClientAppX::instance()->client_to_dist_module();
  int len = vcr->length;
  if (len == (int)sizeof(MyClientVersionCheckReply))
  {
    C_WARNING("middle server returns empty dist server addr list\n");
    module->ask_for_server_addr_list_done(false);
    return;
  }
  ((char*)vcr)[len - 1] = 0;
  C_INFO("middle server returns dist server addr list as: %s\n", vcr->data);
  module->server_addr_list().addr_list(vcr->data);
  module->server_addr_list().save();
  module->ask_for_server_addr_list_done(true);
}

int MyClientToMiddleProcessor::send_version_check_req()
{
  ACE_Message_Block * mb = make_version_check_request_mb();
  MyClientVersionCheckRequest * proc = (MyClientVersionCheckRequest *)mb->base();
  proc->client_version_major = const_client_version_major;
  proc->client_version_minor = const_client_version_minor;
  proc->client_id = m_client_id;
  proc->server_id = 0;
  C_INFO("sending handshake request to middle server...\n");
  return (m_handler->send_data(mb) < 0? -1: 0);
}


//MyClientToMiddleHandler//

MyClientToMiddleHandler::MyClientToMiddleHandler(CConnectionManagerBase * xptr): CHandlerBase(xptr)
{
  m_processor = new MyClientToMiddleProcessor(this);
  m_timer_out_timer_id = -1;
}

void MyClientToMiddleHandler::setup_timer()
{
  ACE_Time_Value interval(TIME_OUT_INTERVAL * 60);
  m_timer_out_timer_id = reactor()->schedule_timer(this, (void*)TIMER_OUT_TIMER, interval);
  if (m_timer_out_timer_id < 0)
    C_ERROR(ACE_TEXT("MyClientToMiddleHandler setup time out timer failed, %s"), (const char*)CErrno());
}

MyClientToDistModule * MyClientToMiddleHandler::module_x() const
{
  return (MyClientToDistModule *)connector()->module_x();
}

int MyClientToMiddleHandler::on_open()
{
  return 0;
}

int MyClientToMiddleHandler::handle_timeout(const ACE_Time_Value &current_time, const void *act)
{
  ACE_UNUSED_ARG(current_time);
  ACE_UNUSED_ARG(act);
  return -1;
}

void MyClientToMiddleHandler::on_close()
{

}

PREPARE_MEMORY_POOL(MyClientToMiddleHandler);


//MyClientToMiddleConnector//

MyClientToMiddleConnector::MyClientToMiddleConnector(CDispatchBase * _dispatcher, CConnectionManagerBase * _manager):
    CConnectorBase(_dispatcher, _manager)
{
  m_tcp_port = CCfgX::instance()->middle_server_client_port;
  m_tcp_addr = CCfgX::instance()->middle_addr;
  m_reconnect_interval = RECONNECT_INTERVAL;
  m_retried_count = 0;
}

const char * MyClientToMiddleConnector::name() const
{
  return "MyClientToMiddleConnector";
}

void MyClientToMiddleConnector::finish()
{
  m_reconnect_interval = 0;
  m_idle_time_as_dead = 0;
  if (m_reconnect_timer_id >= 0)
  {
    reactor()->cancel_timer(m_reconnect_timer_id);
    m_reconnect_timer_id = -1;
  }
  if (m_idle_connection_timer_id >= 0)
  {
    reactor()->cancel_timer(m_idle_connection_timer_id);
    m_idle_connection_timer_id = -1;
  }
}

int MyClientToMiddleConnector::make_svc_handler(CHandlerBase *& sh)
{
  sh = new MyClientToMiddleHandler(m_connection_manager);
  if (!sh)
  {
    C_ERROR("can not alloc MyClientToMiddleHandler from %s\n", name());
    return -1;
  }
  sh->parent((void*)this);
  sh->reactor(reactor());
  return 0;
}

bool MyClientToMiddleConnector::before_reconnect()
{
  ++m_retried_count;
  if (m_retried_count <= MAX_CONNECT_RETRY_COUNT)
    return true;
  if (!MyDistServerAddrList::has_cache())
    return true;

  finish();
  MyClientAppX::instance()->client_to_dist_module()->ask_for_server_addr_list_done(false);
  return false;
}


/////////////////////////////////////
//http 1991
/////////////////////////////////////


//MyHttp1991Processor//

MyHttp1991Processor::MyHttp1991Processor(CHandlerBase * handler) : super(handler)
{
  m_mb = NULL;
  if (g_is_test)
    MyClientAppX::instance()->client_id_table().value(0, &m_client_id);
  else
    m_client_id = MyClientAppX::instance()->client_id();
}

MyHttp1991Processor::~MyHttp1991Processor()
{
  if (m_mb)
    m_mb->release();
}

int MyHttp1991Processor::handle_input()
{
  if (m_mb == NULL)
    m_mb = CMemPoolX::instance()->get_mb(MAX_COMMAND_LINE_LENGTH);
  if (c_util_recv_message_block(m_handler, m_mb) < 0)
    return -1;
  int len = m_mb->length();
  if (len >= MAX_COMMAND_LINE_LENGTH)
  {
    C_ERROR("invalid request @MyHttp1991Processor, request length = %d\n", len);
    return -1;
  }

  char * ptr = m_mb->base();
  if (!strstr(ptr, "\r\n\r\n"))
    return 0;

  ptr[len - 1] = 0;

  if (strstr(m_mb->base(), ":1991") == NULL)
  {
    C_ERROR("bad http request: %s\n", m_mb->base());
    return -1;
  }
  const char const_click_str[] = "/list?pg=";
  const int const_click_str_len = sizeof(const_click_str) / sizeof(char) - 1;
  const char const_plc_str[] = "/ctrl?type=";
  const int const_plc_str_len = sizeof(const_plc_str) / sizeof(char) - 1;

  char * value;
  if (ACE_OS::strstr(ptr, "/op") != NULL)
    do_command_watch_dog();
  else if ((value = ACE_OS::strstr(ptr, const_click_str)) != NULL)
    do_command_adv_click(value + const_click_str_len);
  else if ((value = ACE_OS::strstr(ptr, const_plc_str)) != NULL)
    do_command_plc(value + const_plc_str_len);

  return -1;
}

void MyHttp1991Processor::do_command_watch_dog()
{
//  C_DEBUG("watch dog updated!\n");
  MyClientAppX::instance()->client_to_dist_module()->watch_dog().touch();
  send_string("*1");
}

void MyHttp1991Processor::do_command_adv_click(char * parameter)
{
  char * pcode = ACE_OS::strstr(parameter, "&no=");
  if (unlikely(!pcode || pcode == parameter))
  {
    C_ERROR("invalid adv click (%s)\n", parameter);
    return;
  }

  *pcode = 0;
  pcode += ACE_OS::strlen("&no=");
  if (unlikely(*pcode == 0))
  {
    C_ERROR("invalid adv click: no point code\n");
    return;
  }

  char * ptr = ACE_OS::strchr(pcode, '\n');
  if (ptr)
    *ptr = 0;
  ptr = ACE_OS::strchr(pcode, '\r');
  if (ptr)
    *ptr = 0;
  ptr = ACE_OS::strstr(pcode, " HTTP/");
  if (ptr)
    *ptr = 0;

  MyClientDBGuard dbg;
  if (dbg.db().open_db(m_client_id.as_string()))
    dbg.db().save_click_info(parameter, pcode);
  send_string("*1");
}

void MyHttp1991Processor::do_command_plc(char * parameter)
{
  char * ptr = ACE_OS::strchr(parameter, '\n');
  if (ptr)
    ptr = 0;
  ptr = ACE_OS::strchr(parameter, '\r');
  if (ptr)
    ptr = 0;

  char * y = ACE_OS::strstr(parameter, "&value=");
  if (unlikely(y == parameter))
  {
    C_ERROR("invalid plc command (%s)\n", parameter);
    return;
  }

  if (y != NULL)
  {
    *y = 0;
    y += ACE_OS::strlen("&value=");
    if (*y == 0)
      y = NULL;
  }

  int x = atoi(parameter);
  MyClientToDistModule * mod = MyClientAppX::instance()->client_to_dist_module();

  if (x == 5) //led
  {
    send_string("*1");

    if (!y || (*y != '0' && *y != '1'))
    {
      C_ERROR("bad led alarm packet @MyHttp1991Processor::do_command_plc, y = %s\n", !y? "NULL": y);
      return;
    }
    mod->led_alarm.y(*y);
//    C_INFO("led alarm: x = %d, y = %c\n", x, *y);

  }
  else if (x == 6) //lcd
  {
    send_string("*1");
    if (!y || ACE_OS::strlen(y) < 2 || (*y != '0' && *y != '1') || (*(y + 1) != '0' && *(y + 1) != '1'))
    {
      C_ERROR("bad lcd alarm packet @MyHttp1991Processor::do_command_plc, y = %s\n", !y? "NULL": y);
      return;
    }
//    C_INFO("lcd alarm: x = %d, y = %s\n", x, y);
    char p = 0;
    if (ACE_OS::memcmp(y, "00", 2) == 0)
      p = '0';
    else if (ACE_OS::memcmp(y, "01", 2) == 0)
      p = '1';
    else if (ACE_OS::memcmp(y, "10", 2) == 0)
      p = '2';
    else if (ACE_OS::memcmp(y, "11", 2) == 0)
      p = '3';
    mod->lcd_alarm.y(p);
  }
  else if (x == 7) //pc
    send_string(mod->ip_ver_reply().pc());
  else if (x == 1 || x == 2)
  {
    send_string("*1");
    if (!y || (*y != '0' && *y != '1'))
    {
      C_ERROR("bad hardware alarm packet @MyHttp1991Processor::do_command_plc, y = %s\n", !y? "NULL": y);
      return;
    }

    //C_INFO("hardware alarm: x = %d, y = %c\n", x, *y);
    if (x == 1)
      mod->temperature_alarm.y(*y);
    else
      mod->door_alarm.y(*y);
  }
  else if (x == 11 || x == 12)
  {
    send_string("*1");
    if (!y || ACE_OS::strlen(y) < 15)
    {
      C_ERROR("invalid plc y(%s) for x(%d)\n", x, y);
      return;
    }
    *(y + 15) = 0;
    *(y + 8) = ' ';
    ACE_Message_Block * mb = make_pc_on_off_mb(x == 11, y);
    c_util_mb_putq(MyClientAppX::instance()->client_to_dist_module()->dispatcher(), mb, "pc on/off to dist queue");
  }
  else
  {
    C_ERROR("unknown command(%d) @MyHttp1991Processor::do_command_plc()\n", x);
    send_string("error: unknown command received.");
  }
}

ACE_Message_Block * MyHttp1991Processor::make_pc_on_off_mb(bool on, const char * sdata)
{
  int len = ACE_OS::strlen(sdata);
  ACE_Message_Block * mb = CMemPoolX::instance()->get_mb_cmd(len + 1 + 1,
      MyDataPacketHeader::CMD_PC_ON_OFF);
  if (g_is_test)
    ((MyDataPacketHeader *)mb->base())->magic = 0;
  MyDataPacketExt * dpe = (MyDataPacketExt *)mb->base();
  dpe->data[0] = on ? '1' : '2';
  ACE_OS::memcpy(dpe->data + 1, sdata, len + 1);
  return mb;
}

void MyHttp1991Processor::send_string(const char * s)
{
  const char * const_complete = "HTTP/1.1 200 OK\r\n"
                                "Content-Type: text/html\r\n"
                                "Content-Length: %d\r\n\r\n";

  const char * const_html_tpl = "<html><head></head><body>%s</body></html>\r\n";
  int html_len = ACE_OS::strlen(s) + ACE_OS::strlen(const_html_tpl) + 2;
  int len = html_len + ACE_OS::strlen(const_complete) + 20;
  ACE_Message_Block * mb = CMemPoolX::instance()->get_mb(len);
  CMemGuard guard;
  CMemPoolX::instance()->alloc_mem(html_len, &guard);
  ACE_OS::sprintf(guard.data(), const_html_tpl, s);
  html_len = ACE_OS::strlen(guard.data());
  ACE_OS::sprintf(mb->base(), const_complete, html_len);
  ACE_OS::strcat(mb->base(), guard.data());
  len = ACE_OS::strlen(mb->base());
  mb->wr_ptr(len);
  m_handler->send_data(mb);
}


//MyHttp1991Handler//

MyHttp1991Handler::MyHttp1991Handler(CConnectionManagerBase * xptr)
  : CHandlerBase(xptr)
{
  m_processor = new MyHttp1991Processor(this);
}


//MyHttp1991Acceptor//

MyHttp1991Acceptor::MyHttp1991Acceptor(CDispatchBase * _dispatcher, CConnectionManagerBase * _manager):
    CAcceptorBase(_dispatcher, _manager)
{
  m_tcp_port = 1991;
  m_idle_time_as_dead = IDLE_TIME_AS_DEAD;
}

int MyHttp1991Acceptor::make_svc_handler(CHandlerBase *& sh)
{
  sh = new MyHttp1991Handler(m_connection_manager);
  if (!sh)
  {
    C_ERROR("can not alloc MyHttp1991Handler from %s\n", name());
    return -1;
  }
  sh->parent((void*)this);
  sh->reactor(reactor());
  return 0;
}

const char * MyHttp1991Acceptor::name() const
{
  return "MyHttp1991Acceptor";
}
