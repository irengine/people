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
  CMemProt data_path, fn;
  MyClientApp::data_path(data_path, client_id);
  fn.init(data_path.get_ptr(), "/plist");
  CFileProt fh;
  fh.set_print_failure(false);
  if (!fh.open_nowrite(fn.get_ptr()))
    return false;
  char buff[100];
  int m = ::read(fh.get_fd(), buff, 100);
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
  CMemProt data_path, fn;
  MyClientApp::data_path(data_path, client_id);
  fn.init(data_path.get_ptr(), "/plist");
  CFileProt fh;
  if (fh.open_write(fn.get_ptr(), true, true, false, true))
  {
    int m = strlen(s);
    return m == ::write(fh.get_fd(), s, m);
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
  CTextDelimiter tknz(s, separator);
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
  CMemProt data_path, fn;
  MyClientApp::data_path(data_path, client_id);
  fn.init(data_path.get_ptr(), "/server.id");
  CFileProt fh;
  if (fh.open_nowrite(fn.get_ptr()))
  {
    char buff[32];
    int m = ::read(fh.get_fd(), buff, 32);
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
  CMemProt data_path, fn;
  MyClientApp::data_path(data_path, client_id);
  fn.init(data_path.get_ptr(), "/server.id");
  CFileProt fh;
  if (fh.open_write(fn.get_ptr(), true, true, false, true))
  {
    char buff[32];
    ACE_OS::snprintf(buff, 32, "%d", server_id);
    ::write(fh.get_fd(), buff, strlen(buff));
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
  if (CCfgX::instance()->adv_keep_days > 0)
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
  CMemProt db_path, db_name;
  MyClientAppX::instance()->data_path(db_path, client_id);
  db_name.init(db_path.get_ptr(), "/client.db");

  while(true)
  {
    if(sqlite3_open(db_name.get_ptr(), &m_db))
    {
      C_ERROR("failed to database %s, msg=%s\n", db_name.get_ptr(), sqlite3_errmsg(m_db));
      close_db();
      if (retried)
        return false;
      retried = true;
      CSysFS::remove(db_name.get_ptr());
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
  bool bExist = ftp_command_existing(dist_ftp.dist_id.get_ptr());
  const char * sql_tpl = bExist? const_sql_template2 : const_sql_template1;

  int len = ACE_OS::strlen(dist_ftp.dist_id.get_ptr());
  const char * adir = dist_ftp.adir.get_ptr()? dist_ftp.adir.get_ptr(): "";
  const char * aindex = dist_ftp.index_file();
  int total_len = ACE_OS::strlen(sql_tpl) + len + ACE_OS::strlen(ftp_command) + 50 +
      ACE_OS::strlen(adir) + ACE_OS::strlen(aindex);
  CMemProt sql;
  CCacheX::instance()->get(total_len, &sql);

  if (!bExist)
  {
    ACE_OS::snprintf(sql.get_ptr(), total_len, sql_tpl,
        dist_ftp.dist_id.get_ptr(),
        ftp_command,
        dist_ftp.recv_time,
        adir,
        aindex,
        dist_ftp.ftype);

  } else
    ACE_OS::snprintf(sql.get_ptr(), total_len, sql_tpl, ftp_command, dist_ftp.recv_time, adir, aindex, dist_ftp.ftype, dist_ftp.dist_id.get_ptr());

  return do_exec(sql.get_ptr());
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
    CMemProt sql;
    CCacheX::instance()->get(total_len, &sql);
    ACE_OS::snprintf(sql.get_ptr(), total_len, const_sql_template, dist_id, md5_server, md5_client);
    return do_exec(sql.get_ptr());
  } else
  {
    const char * const_sql_template = "update tb_ftp_info set md5_server = '%s', md5_client = '%s' where ftp_dist_id = '%s'";
    int len = ACE_OS::strlen(dist_id);
    int total_len = ACE_OS::strlen(const_sql_template) + len + ACE_OS::strlen(md5_server) + ACE_OS::strlen(md5_client) + 20;
    CMemProt sql;
    CCacheX::instance()->get(total_len, &sql);
    ACE_OS::snprintf(sql.get_ptr(), total_len, const_sql_template, dist_id, md5_server, md5_client);
    return do_exec(sql.get_ptr());
  }
}

bool MyClientDB::load_ftp_md5_for_diff(MyDistInfoFtp & dist_info)
{
  const char * const_sql_template = "select md5_server, md5_client from tb_ftp_info where ftp_dist_id = '%s'";
  char sql[200];
  ACE_OS::snprintf(sql, 200, const_sql_template, dist_info.dist_id.get_ptr());
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
  if (c_tell_ftype_chn(dist_ftp.ftype))
    ACE_OS::snprintf(sql, BUFF_SIZE, const_chn_tpl, dist_ftp.adir.get_ptr(), dist_ftp.recv_time);
  else if (c_tell_ftype_frame(dist_ftp.ftype))
    ACE_OS::snprintf(sql, BUFF_SIZE, const_frm_tpl, dist_ftp.recv_time);
  else if (c_tell_ftype_adv(dist_ftp.ftype))
    ACE_OS::snprintf(sql, BUFF_SIZE, const_other_tpl, "'3', '5', '6'", dist_ftp.index_file(), dist_ftp.recv_time);
  else if (c_tell_ftype_led(dist_ftp.ftype))
    ACE_OS::snprintf(sql, BUFF_SIZE, const_other_tpl, "'7', '9'", dist_ftp.index_file(), dist_ftp.recv_time);
  else if (c_tell_ftype_backgnd(dist_ftp.ftype))
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

  if (unlikely(!dist_ftp->load_init(argv[1])))
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
    dist_ftp->ftp_password.init(MyClientAppX::instance()->ftp_password());
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
  if (unlikely(!dist_ftp->load_init(argv[1])))
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
  dist_info->server_md5.init(argv[0]);
  dist_info->client_md5.init(argv[1]);
  return 0;
}

//MyConnectIni//

void MyConnectIni::update_connect_status(MyConnectIni::CONNECT_STATUS cs)
{
  CMemProt path, fn;
  MyClientApp::calc_display_parent_path(path, NULL);
  fn.init(path.get_ptr(), "/connect.ini");
  std::ofstream ofs(fn.get_ptr());
  if (!ofs || ofs.bad())
  {
    C_ERROR("can not open file %s for writing: %s\n", fn.get_ptr(), (const char*)CSysError());
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
  m_ftp_server_addr.init(remote_ip.c_str());
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
  const char * client_id = dist_info->client_id.to_str();
  const char * ftp_password = dist_info->ftp_password.get_ptr();
  if (!ftp_password || !*ftp_password)
  {
    dist_info->ftp_password.init(MyClientAppX::instance()->ftp_password());
    ftp_password = dist_info->ftp_password.get_ptr();
  }
  if (unlikely(!client_id || !*client_id || !ftp_password || !*ftp_password || !server_ip || ! *server_ip))
  {
    C_ERROR("bad parameter @MyFTPClient::download(%s, %s, %s)\n", server_ip, client_id, ftp_password);
    return false;
  }
  MyFTPClient ftp_client(server_ip, 21, client_id, ftp_password, dist_info);
  if (!ftp_client.login())
    return false;
  CMemProt ftp_file_name;
  ftp_file_name.init(dist_info->dist_id.get_ptr(), "/", dist_info->file_name.get_ptr());
  if (!ftp_client.get_file(ftp_file_name.get_ptr(), dist_info->local_file_name.get_ptr()))
  {
    ftp_client.logout();
    return false;
  }
  ftp_client.logout();
  if (dist_info->ftp_md5.get_ptr() && *dist_info->ftp_md5.get_ptr())
  {
    CMemProt md5_result;
    if (!c_tools_tally_md5(dist_info->local_file_name.get_ptr(), md5_result))
      return false;
    if (ACE_OS::strcmp(md5_result.get_ptr(), dist_info->ftp_md5.get_ptr()) != 0)
    {
      C_ERROR("bad ftp file (%s)'s md5 check sum, local(%s) remote(%s)\n", dist_info->dist_id.get_ptr(), md5_result.get_ptr(), dist_info->ftp_md5.get_ptr());
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
      m_response.init(line);
      return false;
    default:
      if (unlikely(i >= BUFF_SIZE - 2))
      {
        C_ERROR("ftp unexpected too long response line from server %s\n", m_ftp_server_addr.get_ptr());
        line[i] = 0;
        m_response.init(line);
        return false;
      }
      line[i++] = c;
      break;
    }

    if ('\n' == c)
    {
      line[i] = 0;
      m_response.init(line);
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
  const char * res = m_response.get_ptr();
  return res && (ACE_OS::strlen(res) >= 3) && (ACE_OS::memcmp(res, res_code, 3) == 0);
}

int MyFTPClient::get_timeout_seconds() const
{
  return CCfgX::instance()->download_timeout;
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
    C_ERROR("ftp connecting to server %s failed %s\n", m_ftp_server_addr.get_ptr(), (const char *)CSysError());
    return false;
  }

  if (!this->recv() || !is_response("220"))
  {
    C_ERROR("ftp no/bad response after connecting to server (%s): %s\n", m_ftp_server_addr.get_ptr(), m_response.get_ptr());
    return false;
  }

  ACE_OS::snprintf(command, CMD_BUFF_LEN, "USER %s\r\n", this->m_user_name.c_str());
  if (this->send(command))
  {
    if (!this->recv() || !is_response("331"))
    {
      C_ERROR("ftp no/bad response on USER command to server (%s), user=(%s): %s\n",
          m_ftp_server_addr.get_ptr(), this->m_user_name.c_str(), m_response.get_ptr());
      return false;
    }
  }

  ACE_OS::snprintf(command, CMD_BUFF_LEN, "PASS %s\r\n", this->m_password.c_str());
  if (this->send(command))
  {
    if (!this->recv() || !is_response("230"))
    {
      C_ERROR("ftp no/bad response on PASS command to server (%s), user=(%s): %s\n",
          m_ftp_server_addr.get_ptr(), this->m_user_name.c_str(), m_response.get_ptr());
      return false;
    }
  }

  C_INFO("ftp authentication  to server %s OK, user=%s\n", m_ftp_server_addr.get_ptr(), this->m_user_name.c_str());
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
  CMemProt cwd;
  cwd.init("CWD ", dirname, "\r\n");
  if (this->send(cwd.get_ptr()))
  {
    if (!this->recv() || !is_response("250"))
    {
      C_ERROR("ftp no/bad response on CWD command to server %s\n", m_ftp_server_addr.get_ptr());
      return false;
    }
  } else
    return false;

  if (this->send("PWD \r\n"))
  {
    if (!this->recv() || !is_response("257"))
    {
      C_ERROR("ftp no/bad response on PWD command to server %s\n", m_ftp_server_addr.get_ptr());
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
      C_ERROR("ftp no/bad response on TYPE command to server (%s): %s\n", m_ftp_server_addr.get_ptr(), m_response.get_ptr());
      return false;
    }
  }

  if (fs_client > 0)
  {
    CMemProt fs;
    fs.init("SIZE ", filename, "\r\n");
    if (!this->send(fs.get_ptr()))
      return false;
    if (!this->recv() || !is_response("213"))
    {
      C_ERROR("ftp no/bad response on SIZE command to server (%s): %s\n", m_ftp_server_addr.get_ptr(), m_response.get_ptr());
      return false;
    }
    const char * ptr = m_response.get_ptr() + 3;
    while (*ptr == ' ')
      ptr ++;
    fs_server = atoi(ptr);
    if (fs_server <= 0)
    {
      C_ERROR("bad fs_server value = %d\n", fs_server);
      return false;
    }
    C_INFO("ftp (%s) server reported size = %d, local size = %d\n", m_ftp_info->dist_id.get_ptr(), fs_server, fs_client);
    if (fs_client >= fs_server)
      fs_client = 0;
  }

  if (this->send("PASV\r\n"))
  {
    if (!this->recv() || !is_response("227"))
    {
      C_ERROR("ftp no/bad response on PASV command to server (%s): %s\n", m_ftp_server_addr.get_ptr(), m_response.get_ptr());
      return false;
    }
  }

  char * ptr1 = ACE_OS::strrchr(m_response.get_ptr(), '(');
  char * ptr2 = NULL;
  if (ptr1)
    ptr2 = ACE_OS::strrchr(ptr1, ')');
  if (unlikely(!ptr1 || !ptr2))
  {
    C_ERROR("ftp bad response data format on PASV command to server (%s): %s\n", m_ftp_server_addr.get_ptr(), m_response.get_ptr());
    return false;
  }
  *ptr1 ++ = 0;
  *ptr2 = 0;

  if (sscanf(ptr1, "%d,%d,%d,%d,%d,%d", &d0, &d1, &d2, &d3, &p0, &p1) == -1)
  {
    C_ERROR("ftp bad response address data format on PASV command to server %s\n", m_ftp_server_addr.get_ptr());
    return false;
  }
  snprintf(ip, 32, "%d.%d.%d.%d", d0, d1, d2, d3);
  ftp_data_addr.set((p0 << 8) + p1, ip);

  if (connector.connect(stream, ftp_data_addr, &tv) == -1)
  {
    C_ERROR("ftp failed to establish data connection to server %s\n", m_ftp_server_addr.get_ptr());
    return false;
  }
  CSStreamProt gs(stream);
//  else
//    C_INFO("ftp establish data connection OK to server %s\n", m_ftp_server_addr.data());

  if (fs_client > 0)
  {
    char tmp[64];
    ACE_OS::snprintf(tmp, 64, "REST %d\r\n", fs_client);
    this->send(tmp);
    if (!this->recv() || !is_response("350"))
    {
      C_ERROR("ftp no/bad response on REST command to server (%s): %s\n", m_ftp_server_addr.get_ptr(), m_response.get_ptr());
      return false;
    }
    C_INFO("ftp (%s) continue @%d, ftype=%c, adir=%s\n", m_ftp_info->dist_id.get_ptr(), fs_client,
        m_ftp_info->ftype, m_ftp_info->adir.get_ptr() ? m_ftp_info->adir.get_ptr() : "");
  }

  CMemProt retr;
  retr.init("RETR ", filename, "\r\n");
  if (this->send(retr.get_ptr()))
  {
    if (!this->recv() || !is_response("150"))
    {
      C_ERROR("ftp no/bad response on RETR (%s) command to server (%s): %s\n",
          filename, m_ftp_server_addr.get_ptr(), m_response.get_ptr());
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
    C_ERROR("ftp failed to open local file %s to save download %s\n", localfile, (const char*)CSysError());
    return false;
  }
  CFIOProt g(file_put);
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
      C_ERROR("ftp write to file %s failed %s\n", localfile, (const char*)CSysError());
      return false;
    }
    all_size += file_size;
    tv.sec(get_timeout_seconds() * 6);
    if (MyClientAppX::instance()->client_to_dist_module()->dist_info_ftps().prio() > m_ftp_info->prio())
    {
      C_INFO("ftp pause file %s as %s size = %d, ftype = %c, adir = %s prio = %d\n", filename, localfile, all_size,
          m_ftp_info->ftype, m_ftp_info->adir.get_ptr() ? m_ftp_info->adir.get_ptr() : "", m_ftp_info->prio());
      m_ftp_info->inc_failed(-1);
      return false;
    }
  }

  if (file_size < 0)
  {
    C_ERROR("ftp read data for file %s from server %s failed %s, completed = %d, ftype=%c, adir=%s\n",
        filename, m_ftp_server_addr.get_ptr(), (const char*)CSysError(), all_size,
        m_ftp_info->ftype, m_ftp_info->adir.get_ptr() ? m_ftp_info->adir.get_ptr() : "");
    return false;
  }

//  if (!this->recv() || !is_response("226"))
//  {
//    C_ERROR("ftp no/bad response after transfer of file completed from server %s\n", m_ftp_server_addr.data());
//    return false;
//  }

  C_INFO("ftp downloaded file %s as %s size = %d, ftype = %c, adir = %s\n", filename, localfile, all_size,
      m_ftp_info->ftype, m_ftp_info->adir.get_ptr() ? m_ftp_info->adir.get_ptr() : "");
  return true;
}



//MyDistInfoHeader//

MyDistInfoHeader::MyDistInfoHeader()
{
  client_id_index = -1;
  ftype = 0;
  type = 0;
}


MyDistInfoHeader::~MyDistInfoHeader()
{

}

bool MyDistInfoHeader::validate()
{
  if (!c_tell_ftype_valid(ftype))
  {
    C_ERROR("bad MyDistInfoHeader, ftype = %c\n", ftype);
    return false;
  }

  if (!c_tell_type_valid(type))
  {
    C_ERROR("bad MyDistInfoHeader, type = %c\n", type);
    return false;
  }

  if (/*aindex.data() && aindex.data()[0] &&*/ !(findex.get_ptr() && findex.get_ptr()[0]))
  {
    C_ERROR("bad MyDistInfoHeader, findex is null\n");
    return false;
  }

  if (!(dist_id.get_ptr() && dist_id.get_ptr()[0]))
  {
    C_ERROR("bad MyDistInfoHeader, dist_id is null\n");
    return false;
  }

  if (!(adir.get_ptr() && adir.get_ptr()[0]))
  {
    if (c_tell_ftype_chn(ftype))
    {
      C_ERROR("bad MyDistInfoHeader, dist_id=%s, ftype=%c, adir is null\n", dist_id.get_ptr(), ftype);
      return false;
    }
  }

  return true;
}

const char * MyDistInfoHeader::index_file() const
{
  if (aindex.get_ptr() && aindex.get_ptr()[0])
    return aindex.get_ptr();
  return findex.get_ptr();
}

bool MyDistInfoHeader::need_spl() const
{
  if (!aindex.get_ptr() || !aindex.get_ptr()[0])
    return false;
  return ACE_OS::strcmp(aindex.get_ptr(), findex.get_ptr()) != 0;
}

int MyDistInfoHeader::load_header_init(char * src)
{
  if (unlikely(!src))
    return -1;

  char * end = strchr(src, CCmdHeader::FINISH_SEPARATOR);
  if (!end)
  {
    C_ERROR("bad packet data @MyDistInfoHeader::load_init, no FINISH_SEPARATOR found\n");
    return false;
  }
  *end = 0;

  const char separator[2] = { CCmdHeader::ITEM_SEPARATOR, 0 };
  CTextDelimiter tk(src, separator);
  char * token = tk.get();
  if (unlikely(!token))
    return -1;
  else
    dist_id.init(token);

  token = tk.get();
  if (unlikely(!token))
    return -1;
  else
    findex.init(token);

  token = tk.get();
  if (unlikely(!token))
    return -1;
  else if (ACE_OS::strcmp(token, Item_NULL) != 0)
    adir.init(token);

  token = tk.get();
  if (unlikely(!token))
    return -1;
  else if (ACE_OS::strcmp(token, Item_NULL) != 0)
    aindex.init(token);

  token = tk.get();
  if (unlikely(!token))
    return -1;
  else if (ACE_OS::strcmp(token, Item_NULL) != 0)
    ftype = *token;
  else
    return -1;

  token = tk.get();
  if (unlikely(!token))
    return -1;
  else if (ACE_OS::strcmp(token, Item_NULL) != 0)
    type = *token;
  else
    return -1;

  return end - src + 1;
}

void MyDistInfoHeader::calc_target_parent_path(CMemProt & target_parent_path, bool extract_only, bool bv)
{
  if (extract_only)
    MyClientApp::calc_dist_parent_path(target_parent_path, dist_id.get_ptr(), client_id.to_str());
  else if (bv)
    MyClientApp::data_path(target_parent_path, client_id.to_str());
  else
    MyClientApp::calc_display_parent_path(target_parent_path, client_id.to_str());
}

bool MyDistInfoHeader::calc_target_path(const char * target_parent_path, CMemProt & target_path)
{
  C_ASSERT_RETURN(target_parent_path && *target_parent_path, "empty parameter target_parent_path\n", false);
  const char * sub_path;
  if (c_tell_ftype_chn(ftype))
  {
    target_path.init(target_parent_path, "/index/", sub_path = adir.get_ptr());
    return true;
  }
  else if (c_tell_ftype_adv(ftype))
    sub_path = "5";
  else if (c_tell_ftype_led(ftype))
    sub_path = "led";
  else if (c_tell_ftype_frame(ftype))
  {
    target_path.init(target_parent_path);
    return true;
  }
  else if (c_tell_ftype_backgnd(ftype))
    sub_path = "8";
  else
  {
    C_ERROR("invalid dist ftype = %c\n", ftype);
    return false;
  }

  target_path.init(target_parent_path, "/", sub_path);
  return true;
}

bool MyDistInfoHeader::calc_update_ini_value(CMemProt & value)
{
  if (c_tell_ftype_chn(ftype))
    value.init(adir.get_ptr());
  else if (c_tell_ftype_adv_list(ftype))
    value.init("p");
  else if (c_tell_ftype_adv(ftype))
    value.init("g");
  else if (c_tell_ftype_led(ftype))
    value.init("l");
  else if (c_tell_ftype_frame(ftype))
    value.init("k");
  else if (c_tell_ftype_backgnd(ftype))
    value.init("d");
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
  if (unlikely(!(recv_time < t + CONST_one_year && recv_time > t - CONST_one_year)))
  {
    C_WARNING("obsolete MyDistInfoFtp object, recv_time = %d\n", recv_time);
    return false;
  }

  return true;
}

bool MyDistInfoFtp::load_init(char * src)
{
  if (unlikely(!src || !*src))
    return false;

  int data_len = ACE_OS::strlen(src);
  int header_len = load_header_init(src);
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
  char * file_password = ACE_OS::strchr(file_name, CCmdHeader::FINISH_SEPARATOR);
  if (unlikely(!file_password))
  {
    C_ERROR("No filename/password found at dist ftp packet\n");
    return false;
  }
  *file_password++ = 0;

  char * ftp_mbz_md5 = ACE_OS::strchr(file_name, CCmdHeader::ITEM_SEPARATOR);
  if (unlikely(!ftp_mbz_md5))
  {
    C_ERROR("No ftp file md5 found at dist ftp packet\n");
    return false;
  }
  *ftp_mbz_md5++ = 0;
  if (ACE_OS::strcmp(ftp_mbz_md5, Item_NULL) != 0)
    this->ftp_md5.init(ftp_mbz_md5);

  this->file_name.init(file_name);

  if (unlikely(!*file_password))
  {
    C_ERROR("No password found at dist ftp packet\n");
    return false;
  }
  this->file_password.init(file_password);
  bool ret = validate();
  if (ret)
    m_prio = MyPL::instance().value(ftype - '0');
  return ret;
};

time_t MyDistInfoFtp::get_delay_penalty() const
{
  //return (time_t)(std::min(m_failed_count + 1, (int)MAX_FAILED_COUNT) * 60 * FAILED_PENALTY);
  return (time_t)(60 * CCfgX::instance()->download_retry_delay);
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
  if (m_failed_count >= CCfgX::instance()->download_retry_count)
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
  if (unlikely(local_file_name.get_ptr() != NULL))
    return;
  CMemProt download_path;
  MyClientApp::calc_download_parent_path(download_path, client_id.to_str());
  local_file_name.init(download_path.get_ptr(), "/", dist_id.get_ptr(), ".mbz");
}

ACE_Message_Block * MyDistInfoFtp::make_ftp_dist_message(const char * dist_id, int status, bool ok, char ftype)
{
  if (status == 6)
    status = 3;
  int dist_id_len = ACE_OS::strlen(dist_id);
  int total_len = dist_id_len + 1 + 2 + 2;
  ACE_Message_Block * mb = CCacheX::instance()->get_mb_cmd(total_len, CCmdHeader::PT_FTP_FILE, false);
  CCmdExt * dpe = (CCmdExt*) mb->base();
  ACE_OS::memcpy(dpe->data, dist_id, dist_id_len);
  dpe->data[dist_id_len] = CCmdHeader::ITEM_SEPARATOR;
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
  ACE_Message_Block * mb = make_ftp_dist_message(dist_id.get_ptr(), m, result_ok, ftype);
  CCmdExt * dpe = (CCmdExt*) mb->base();
  if (g_is_test)
    dpe->signature = client_id_index;

//  MyClientAppX::instance()->client_to_dist_module()->dispatcher()->add_to_buffered_mbs(mb);
  MyClientAppX::instance()->send_mb_to_dist(mb);
}

bool MyDistInfoFtp::update_db_status() const
{
  MyClientDBProt dbg;
  if (dbg.db().open_db(client_id.to_str()))
    return dbg.db().set_ftp_command_status(dist_id.get_ptr(), status);
  return false;
}

void MyDistInfoFtp::generate_url_ini()
{
  if (!c_tell_ftype_chn(ftype))
    return;

  CMemProt path, file, dest_parent_path, true_dest_p_path, t_file;
  MyClientApp::calc_backup_parent_path(dest_parent_path, client_id.to_str());
  MyClientApp::calc_display_parent_path(true_dest_p_path, client_id.to_str());
  path.init(dest_parent_path.get_ptr(), "/new");
  file.init(path.get_ptr(), "/index/", adir.get_ptr(), "/url.ini");
  t_file.init(true_dest_p_path.get_ptr(), "/index/", adir.get_ptr(), "/url.ini");
  {
    CFileProt h;
    if (unlikely(!h.open_write(file.get_ptr(), true, true, false, false)))
      return;

    const char * s = index_file();
    ::write(h.get_fd(), s, ACE_OS::strlen(s));
    fsync(h.get_fd());
  }
  CSysFS::copy_file(file.get_ptr(), t_file.get_ptr(), true, false);

  if (ftype == '2')
  {
    file.init(path.get_ptr(), "/index/", adir.get_ptr(), "/date.ini");
    t_file.init(true_dest_p_path.get_ptr(), "/index/", adir.get_ptr(), "/date.ini");
    {
      CFileProt h;
      if (unlikely(!h.open_write(file.get_ptr(), true, true, false, false)))
        return;

      char buff[50];
      c_tools_convert_time_to_text(buff, 50, false);
      buff[8] = 0;
      ::write(h.get_fd(), buff, 8);
      fsync(h.get_fd());
    }
    CSysFS::copy_file(file.get_ptr(), t_file.get_ptr(), true, false);
  }
}

void MyDistInfoFtp::generate_update_ini()
{
  CMemProt value;
  if (unlikely(!calc_update_ini_value(value)))
    return;

  CMemProt path, file;
  calc_target_parent_path(path, false, false);
  file.init(path.get_ptr(), "/update.ini");
  CFileProt h;
  if (unlikely(!h.open_write(file.get_ptr(), true, true, false, false)))
    return;

  time_t now = time(NULL);
  struct tm _tm;
  localtime_r(&now, &_tm);
  char buff[100];
  ACE_OS::snprintf(buff, 100, "%02d:%02d;%s", _tm.tm_hour, _tm.tm_min, value.get_ptr());
  ::write(h.get_fd(), buff, ACE_OS::strlen(buff));
}

bool MyDistInfoFtp::operator < (const MyDistInfoFtp & rhs) const
{
  return recv_time < rhs.recv_time;
}

bool MyDistInfoFtp::generate_dist_id_txt(const CMemProt & path)
{
  CMemProt fn;
  fn.init(path.get_ptr(), "/dist_id.txt");
  char buff[32];
  char * ptr;
  if (!dist_id.get_ptr() || ACE_OS::strlen(dist_id.get_ptr()) < 32)
  {
    ptr = buff;
    ACE_OS::memset(buff, '1', 32);
  } else
    ptr = dist_id.get_ptr();

  CFileProt h;
  if (unlikely(!h.open_write(fn.get_ptr(), true, true, false, false)))
    return false;
  bool ret = ::write(h.get_fd(), ptr, 32) == 32;
  fsync(h.get_fd());
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
  MyClientDBProt dbg;
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

bool MyDistFtpFileExtractor::get_true_dest_path(MyDistInfoFtp * dist_info, CMemProt & target_path)
{
  CMemProt target_parent_path;
  dist_info->calc_target_parent_path(target_parent_path, false, c_tell_ftype_vd(dist_info->ftype));
  return dist_info->calc_target_path(target_parent_path.get_ptr(), target_path);
}

bool MyDistFtpFileExtractor::extract(MyDistInfoFtp * dist_info)
{
  C_ASSERT_RETURN(dist_info, "parameter dist_info null pointer\n", false);

  CTermSNs & idtable = MyClientAppX::instance()->term_SNs();
  CTermData client_info;
  if (!idtable.get_termData(dist_info->client_id_index, client_info))
  {
    C_ERROR("invalid client_id_index @MyDistFtpFileExtractor::extract()");
    CSysFS::remove(dist_info->local_file_name.get_ptr());
    return false;
  }

  if (client_info.invalid)
  {
    C_INFO("skipping extract due to previous errors client_id(%s) dist_id(%s)\n", dist_info->client_id.to_str(), dist_info->dist_id.get_ptr());
    CSysFS::remove(dist_info->local_file_name.get_ptr());
    return false;
  }

  CMemProt target_parent_path, pn, po, dest_parent_path;
  MyClientApp::calc_backup_parent_path(dest_parent_path, dist_info->client_id.to_str());
  pn.init(dest_parent_path.get_ptr(), "/new");
  po.init(dest_parent_path.get_ptr(), "/old");
  dist_info->calc_target_parent_path(target_parent_path, true, false);
  C_INFO("Updating dist(%s) client_id(%s)...\n", dist_info->dist_id.get_ptr(), dist_info->client_id.to_str());
  bool bn, bo, bv;
  bv = c_tell_ftype_adv(dist_info->ftype);
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
    C_ERROR("apply update failed for dist_id(%s) client_id(%s)\n", dist_info->dist_id.get_ptr(), dist_info->client_id.to_str());
//    idtable.expired(dist_info->client_id_index, true);
//todo: lock or unlock?
  }
  else
  {
    C_INFO("apply update OK for dist_id(%s) client_id(%s)\n", dist_info->dist_id.get_ptr(), dist_info->client_id.to_str());
//    if (!g_test_mode && c_tell_ftype_adv_list(dist_info->ftype))
//    {
//      MyConfig * cfg = MyConfigX::instance();
//      if(cfg->adv_expire_days > 0)
//      {
//        MyPooledMemProt mpath;
//        MyClientApp::calc_display_parent_path(mpath, MyClientAppX::instance()->client_id());
//        MyAdvCleaner cleaner;
//        cleaner.do_clean(mpath, MyClientAppX::instance()->client_id(), cfg->adv_expire_days);
//      }
//    }
  }
  CSysFS::delete_dir(target_parent_path.get_ptr(), true);
  ACE_OS::sleep(30);
  CSysFS::remove(dist_info->local_file_name.get_ptr());
  return result;
}

bool MyDistFtpFileExtractor::do_extract(MyDistInfoFtp * dist_info, const CMemProt & target_parent_path)
{
  dist_info->calc_local_file_name();
  bool bv = c_tell_ftype_adv(dist_info->ftype);
  if (!CSysFS::create_dir(target_parent_path.get_ptr(), true))
  {
    C_ERROR("can not mkdir(%s) %s\n", target_parent_path.get_ptr(), (const char *)CSysError());
    return false;
  }
  CMemProt target_path;
  if (!dist_info->calc_target_path(target_parent_path.get_ptr(), target_path))
    return false;

  int prefix_len = ACE_OS::strlen(target_parent_path.get_ptr());
  if (!CSysFS::create_dir_const(target_path.get_ptr(), prefix_len, false, true))
  {
    C_ERROR("can not mkdir(%s) %s\n", target_path.get_ptr(), (const char *)CSysError());
    return false;
  }

  CMemProt true_dest_path;
  if (unlikely(!get_true_dest_path(dist_info,  true_dest_path)))
    return false;

  CMemProt s_n, dest_parent_path, dest_path;
  if (!bv)
  {
    MyClientApp::calc_backup_parent_path(dest_parent_path, dist_info->client_id.to_str());
    s_n.init(dest_parent_path.get_ptr(), "/new");
    prefix_len = ACE_OS::strlen(dest_parent_path.get_ptr());
    if (!CSysFS::create_dir_const(s_n.get_ptr(), prefix_len, false, true))
    {
      C_ERROR("can not mkdir(%s) %s\n", s_n.get_ptr(), (const char *)CSysError());
      return false;
    }
    dist_info->calc_target_path(s_n.get_ptr(), dest_path);
  } else
  {
    MyClientApp::data_path(dest_parent_path, dist_info->client_id.to_str());
    prefix_len = ACE_OS::strlen(dest_parent_path.get_ptr());
    dest_path.init(dest_parent_path.get_ptr(), "/5");
    if (!CSysFS::create_dir_const(dest_path.get_ptr(), prefix_len, false, true))
    {
      C_ERROR("can not mkdir(%s) %s\n", dest_path.get_ptr(), (const char *)CSysError());
      return false;
    }
  }
/*
  if (c_tell_type_multi(dist_info->type))
  {
    if (!mycomutil_string_end_with(dist_info->file_name.data(), "/all_in_one.mbz"))
    {
      if (c_tell_ftype_frame(dist_info->ftype))
      {
        MyPooledMemProt src, dest;
        src.init(true_dest_path.data(), "/index.html");
        dest.init(target_path.data(), "/index.html");
        struct stat buf;
        if (MyFilePaths::stat(src.data(), &buf) && S_ISREG(buf.st_mode))
        {
          if (!MyFilePaths::copy_file(src.data(), dest.data(), true))
          {
            C_ERROR("failed to copy file %s to %s, %s\n", src.data(), dest.data(), (const char*)MyErrno());
            return false;
          }
        }
        src.init(true_dest_path.data(), "/index");
        dest.init(target_path.data(), "/index");

        if (MyFilePaths::stat(src.data(), &buf) && S_ISDIR(buf.st_mode))
        {
          if (!MyFilePaths::copy_dir(src.data(), dest.data(), true))
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
          if (!MyFilePaths::copy_dir(true_dest_path.data(), target_path.data(), true))
          {
            C_ERROR("copy path failed from %s to %s\n", true_dest_path.data(), target_path.data());
            return false;
          }
        }
      }

      {
        MyClientDBProt dbg;
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

      if (c_tell_ftype_frame(dist_info->ftype))
      {
        MyPooledMemProt index_path;
        index_path.init(target_path.data(), "/", dist_info->index_file());
        MyFilePaths::get_correlate_path(index_path, 0);
        MyFilePaths::zap_empty_paths(index_path);
      }
#else

      if (!MyFilePaths::create_dir_const(target_path.data(), prefix_len, false, true))
      {
        C_ERROR("can not mkdir(%s) %s\n", target_path.data(), (const char *)MyErrno());
        return false;
      }
#endif
    }
  }
*/

  CDataComp c;

  bool result = c.bloat(dist_info->local_file_name.get_ptr(), target_path.get_ptr(), dist_info->file_password.get_ptr(), dist_info->aindex.get_ptr());
  if (result)
  {
/*
    if (c_tell_ftype_frame(dist_info->ftype) && c_tell_type_all(dist_info->type))
    {
      MyPooledMemProt mfile;
      if (MyClientApp::get_mfile(true_dest_path, mfile))
      {
        MyPooledMemProt mfilex;
        mfilex.init(true_dest_path.data(), "/", mfile.data());
        MyFilePaths::zap(mfilex.data(), true);
        MyFilePaths::get_correlate_path(mfilex, 0);
        MyFilePaths::zap(mfilex.data(), true);
      }
    }
*/
    if (!bv)
    {
      CMemProt fn;
      fn.init(s_n.get_ptr(), "/dist_id.txt");
      if (!CSysFS::remove(fn.get_ptr(), false))
        return false;
    }
    if (c_tell_type_valid(dist_info->type))
    {
      if (c_tell_type_single(dist_info->type))
      {
        if (!CSysFS::copy_dir(target_path.get_ptr(), dest_path.get_ptr(), true, true))
          result = false;
        if (!bv && !CSysFS::copy_dir(target_path.get_ptr(), true_dest_path.get_ptr(), true, false))
          C_WARNING("failed to copy_dir for true_dest_path\n");
      } else if (c_tell_type_all(dist_info->type) || c_tell_type_multi(dist_info->type))
      {
        if (c_tell_ftype_frame(dist_info->ftype) || c_tell_type_multi(dist_info->type))
        {
          if (!CSysFS::copy_dir(target_path.get_ptr(), dest_path.get_ptr(), true, true))
            result = false;
          if (!c_tell_ftype_adv(dist_info->ftype) && !CSysFS::copy_dir(target_path.get_ptr(), true_dest_path.get_ptr(), true, false))
            C_WARNING("failed to copy_dir for true_dest_path\n");
        }
        else
        {
          if (!CSysFS::copy_dir_clear(target_path.get_ptr(), dest_path.get_ptr(), true, c_tell_ftype_chn(dist_info->ftype), true))
            result = false;
          if (!CSysFS::copy_dir_clear(target_path.get_ptr(), true_dest_path.get_ptr(), true, c_tell_ftype_chn(dist_info->ftype), false))
            C_WARNING("failed to copy_dir_zap for true_dest_path\n");
        }

/*      if (!result && !c_tell_ftype_vd(dist_info->ftype))
      {
        C_WARNING("doing restore due to deployment error client_id(%s)\n", dist_info->client_id.as_string());
        if (!MyClientApp::full_restore(NULL, true, true, dist_info->client_id.as_string()))
        {
          C_FATAL("locking update on client_id(%s)\n", dist_info->client_id.as_string());
          MyClientAppX::instance()->term_SNs().expired(dist_info->client_id_index, true);
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

bool MyDistFtpFileExtractor::has_id(const CMemProt & target_parent_path)
{
  CMemProt fn;
  fn.init(target_parent_path.get_ptr(), "/dist_id.txt");
  return CSysFS::get_fsize(fn.get_ptr()) >= 32;
}

bool MyDistFtpFileExtractor::syn(MyDistInfoFtp * dist_info)
{
  CMemProt pn, po, dest_parent_path, dest_path;
  MyClientApp::calc_backup_parent_path(dest_parent_path, dist_info->client_id.to_str());
  pn.init(dest_parent_path.get_ptr(), "/new");
  po.init(dest_parent_path.get_ptr(), "/old");
  CSysFS::delete_dir(po.get_ptr(), true);
  if (!CSysFS::create_dir(po.get_ptr(), true))
  {
    C_ERROR("can not mkdir(%s) %s\n", po.get_ptr(), (const char *)CSysError());
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

CCheckSums & MyDistInfoMD5::md5list()
{
  return m_md5list;
}

void MyDistInfoMD5::post_md5_message()
{
  int dist_id_len = ACE_OS::strlen(dist_id.get_ptr());
  int md5_len = m_md5list.text_len(false);
  int total_len = dist_id_len + 1 + md5_len;
  ACE_Message_Block * mb = CCacheX::instance()->get_mb_cmd(total_len, CCmdHeader::PT_FILE_MD5_LIST);
  CCmdExt * dpe = (CCmdExt*) mb->base();
  if (g_is_test)
    dpe->signature = client_id_index;
  ACE_OS::memcpy(dpe->data, dist_id.get_ptr(), dist_id_len);
  dpe->data[dist_id_len] = CCmdHeader::ITEM_SEPARATOR;
  m_md5list.save_text(dpe->data + dist_id_len + 1, md5_len, false);
//  if (g_test_mode)
    C_INFO("posting md5 reply to dist server for dist_id (%s), md5 len = %d\n", dist_id.get_ptr(), md5_len - 1);
//  else
//    C_INFO("posting md5 reply to dist server for dist_id (%s), md5 len = %d, data= %s\n", dist_id.data(), md5_len - 1, dpe->data + dist_id_len + 1);
  MyClientAppX::instance()->send_mb_to_dist(mb);
}

const char * MyDistInfoMD5::md5_text() const
{
  return m_md5_text.get_ptr();
}

bool MyDistInfoMD5::load_init(char * src)
{
  if (unlikely(!src || !*src))
    return false;

  int data_len = ACE_OS::strlen(src);
  int header_len = load_header_init(src);
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
  m_md5_text.init(_md5_list);

  if (!m_md5list.load_text(_md5_list))
    return false;

  return validate();
}

bool MyDistInfoMD5::validate()
{
  if (!super::validate())
    return false;

  return (m_md5list.number() > 0);
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

bool MyDistInfoMD5Comparer::compute(MyDistInfoHeader * dist_info_header, CCheckSums & md5list)
{
  if (unlikely(!dist_info_header))
    return false;

  CMemProt target_parent_path;
  dist_info_header->calc_target_parent_path(target_parent_path, false, false);

  CMemProt target_path;
  if (!dist_info_header->calc_target_path(target_parent_path.get_ptr(), target_path))
    return false;

  int prefix_len = ACE_OS::strlen(target_parent_path.get_ptr());
  if (!CSysFS::create_dir_const(target_path.get_ptr(), prefix_len, false, true))
  {
    C_ERROR("can not mkdir(%s) %s\n", target_path.get_ptr(), (const char *)CSysError());
    return false;
  }

  //const char * aindex = c_tell_ftype_chn(dist_info_header->ftype)? NULL: dist_info_header->aindex.data();
  return md5list.compute(target_path.get_ptr(), /*aindex,*/ dist_info_header->aindex.get_ptr(),
         c_tell_type_single(dist_info_header->type));
}

bool MyDistInfoMD5Comparer::compute(MyDistInfoMD5 * dist_md5)
{
  if (unlikely(!dist_md5))
    return false;

  CMemProt target_parent_path, px;
  dist_md5->calc_target_parent_path(px, false, true);
  target_parent_path.init(px.get_ptr(), "/new");

  CMemProt target_path;
  if (!dist_md5->calc_target_path(target_parent_path.get_ptr(), target_path))
    return false;

//  int prefix_len = ACE_OS::strlen(target_parent_path.data());
//  if (!MyFilePaths::create_dir_const(target_path.data(), prefix_len, false, true))
//  {
//    C_ERROR("can not mkdir(%s) %s\n", target_path.data(), (const char *)MyErrno());
//    return false;
//  }

  //const char * aindex = c_tell_ftype_chn(dist_info_header->ftype)? NULL: dist_info_header->aindex.data();
  if (dist_md5->need_spl())
  {
    CDirConverter spl;
    spl.prepare(dist_md5->aindex.get_ptr());
    return dist_md5->md5list().compute_diverse(target_path.get_ptr(), &spl);
  } else
    return dist_md5->md5list().compute_diverse(target_path.get_ptr(), NULL);
}

void MyDistInfoMD5Comparer::compare(MyDistInfoHeader * dist_info_header, CCheckSums & server_md5, CCheckSums & client_md5)
{
  if (unlikely(!dist_info_header))
    return;
  if (dist_info_header->aindex.get_ptr() && *dist_info_header->aindex.get_ptr())
  {
    CDirConverter spl;
    spl.prepare(dist_info_header->aindex.get_ptr());
    server_md5.substract(client_md5, &spl, false);
  } else
    server_md5.substract(client_md5, NULL, false);
}


//MyWatchDog//

MyWatchDog::MyWatchDog()
{
  m_running = false;
  m_time = 0;
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

void MyIpVerReply::init_time_str(CMemProt & g, const char * s, const char c)
{
  char buff[2];
  buff[1] = 0;
  buff[0] = c;
  const char * ptr = (s && *s)? s: "09001730";
  g.init("*", ptr, buff);
}

void MyIpVerReply::init(char * data)
{
  time_t t = time(NULL);
  CMemProt cp;
  cp.init(data);

  ACE_GUARD(ACE_Thread_Mutex, ace_mon, this->m_mutex);
  do_init(m_pc, data, t);
  do_init(m_pc_x, cp.get_ptr(), t + CONST_one_day);
  if (ACE_OS::strlen(m_pc.get_ptr()) >= 10 && ACE_OS::strlen(m_pc_x.get_ptr()) >= 10)
  {
    if (m_pc.get_ptr()[9] == '1')
      ACE_OS::memset(m_pc.get_ptr() + 5, '0', 4);
    ACE_OS::memcpy(m_pc_x.get_ptr() + 5, m_pc.get_ptr() + 5, 4);
    m_pc_x.get_ptr()[9] = m_pc.get_ptr()[9];
  }
}

void MyIpVerReply::do_init(CMemProt & g, char * data, time_t t)
{
  c_tools_convert_time_to_text(m_now, 24, false, t);
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

void MyIpVerReply::get_filename(CMemProt & fn)
{
  fn.init(CCfgX::instance()->data_path.c_str(), "/pc_time.dat");
}

void MyIpVerReply::save_to_file(const char * s)
{
  if (!s || ACE_OS::strlen(s) != 8)
    return;

  CFileProt f;
  CMemProt file_name;
  get_filename(file_name);
  if (!f.open_write(file_name.get_ptr(), true, true, false, true))
    return;
  if (::write(f.get_fd(), s, 8) != 8)
    C_ERROR("write to file %s failed %s\n", file_name.get_ptr(), (const char*)CSysError());
}

bool MyIpVerReply::load_from_file()
{
  CFileProt f;
  CMemProt file_name;
  get_filename(file_name);
  if (!f.open_nowrite(file_name.get_ptr()))
    return false;
  char buff[9];
  if (::read(f.get_fd(), buff, 8) != 8)
  {
    C_ERROR("read from file %s failed %s\n", file_name.get_ptr(), (const char*)CSysError());
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
  CTextDelimiter tkn(src, separators);
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
  if (ACE_OS::strlen(m_pc.get_ptr()) <= 5)
    return m_pc.get_ptr();

  char hour[3], minx[3];
  ACE_OS::memcpy(hour, m_pc.get_ptr() + 1, 2);
  ACE_OS::memcpy(minx, m_pc.get_ptr() + 3, 2);
  hour[2] = 0;
  minx[2] = 0;
  if (_tm.tm_hour < atoi(hour))
    return m_pc.get_ptr();
  else if (_tm.tm_hour == atoi(hour) && _tm.tm_min <= atoi(minx))
    return m_pc.get_ptr();
  return m_pc_x.get_ptr();
}

int MyIpVerReply::heart_beat_interval()
{
  ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, 1);
  return m_heart_beat_interval;
}


//MyClientToDistProcessor//

MyClientToDistProcessor::MyClientToDistProcessor(CParentHandler * handler): CParentClientProc(handler)
{
  m_version_check_reply_done = false;
  m_handler->msg_queue()->high_water_mark(MSG_QUEUE_MAX_SIZE);
}

const char * MyClientToDistProcessor::name() const
{
  return "MyClientToDistProcessor";
}

int MyClientToDistProcessor::at_start()
{
  if (super::at_start() < 0)
    return -1;

  if (g_is_test)
  {
    const char * myid = MyClientAppX::instance()->client_to_dist_module()->id_generator().get();
    if (!myid)
    {
      C_ERROR(ACE_TEXT("can not fetch a test client id @MyClientToDistHandler::open\n"));
      return -1;
    }
    set_term_sn(myid);
    m_term_loc = MyClientAppX::instance()->term_SNs().find_location(myid);
    if (m_term_loc < 0)
    {
      C_ERROR("MyClientToDistProcessor::at_start() can not find client_id_index for id = %s\n", myid);
      return -1;
    }
    m_handler->handler_director()->sn_at_location(m_handler, m_term_loc, NULL);
  } else
  {
    set_term_sn(MyClientAppX::instance()->client_id());
    m_term_loc = 0;
  }
  if (!g_is_test || m_term_loc == 0)
    C_INFO("sending handshake request to dist server...\n");
  return send_version_check_req();
}

CProc::OUTPUT MyClientToDistProcessor::at_head_arrival()
{
  if (!g_is_test)
    C_DEBUG("get dist packet header: command = %d, len = %d\n", m_data_head.cmd, m_data_head.size);

  CProc::OUTPUT result = super::at_head_arrival();
  if (result != OP_GO_ON)
    return OP_FAIL;

  bool bVersionCheckReply = m_data_head.cmd == CCmdHeader::PT_VER_REPLY; //m_version_check_reply_done
  if (bVersionCheckReply == m_version_check_reply_done)
  {
    C_ERROR(ACE_TEXT("unexpected packet header from dist server, version_check_reply_done = %d, "
                      "packet is version_check_reply = %d.\n"), m_version_check_reply_done, bVersionCheckReply);
    return OP_FAIL;
  }

  if (bVersionCheckReply)
  {
    if (!c_packet_check_term_ver_reply(&m_data_head))
    {
      C_ERROR("failed to validate header for version check\n");
      return OP_FAIL;
    }
    return OP_OK;
  }

  if (m_data_head.cmd == CCmdHeader::PT_FILE_MD5_LIST)
  {
    if (!c_packet_check_file_md5_list(&m_data_head))
    {
      C_ERROR("failed to validate header for server file md5 list\n");
      return OP_FAIL;
    }
    return OP_OK;
  }

  if (m_data_head.cmd == CCmdHeader::PT_FTP_FILE)
  {
    if (!c_packet_check_ftp_file(&m_data_head))
    {
      C_ERROR("failed to validate header for server ftp file\n");
      return OP_FAIL;
    }
    return OP_OK;
  }

  if (m_data_head.cmd == CCmdHeader::PT_IP_VER_REQ)
  {
    if (m_data_head.size <= (int)sizeof(CCmdHeader) || m_data_head.size >= 512
        || m_data_head.signature != CCmdHeader::SIGNATURE)
    {
      C_ERROR("failed to validate header for ip ver reply\n");
      return OP_FAIL;
    }
    return OP_OK;
  }

  if (m_data_head.cmd == CCmdHeader::PT_ACK)
  {
    if (!c_packet_check_base(&m_data_head))
    {
      C_ERROR("failed to validate header for server ack packet\n");
      return OP_FAIL;
    }
    if (g_is_test)
      return OP_DONE;
    else
      return OP_OK;
  }

  if (m_data_head.cmd == CCmdHeader::PT_TQ)
  {
    if (m_data_head.size <= (int)sizeof(CCmdHeader) || m_data_head.size >= 512
        || m_data_head.signature != CCmdHeader::SIGNATURE)
    {
      C_ERROR("failed to validate header for plist\n");
      return OP_FAIL;
    }
    return OP_OK;
  }


  if (m_data_head.cmd == CCmdHeader::PT_REMOTE_CMD)
  {
    if (m_data_head.size != (int)sizeof(CCmdHeader) + 1
        || m_data_head.signature != CCmdHeader::SIGNATURE)
    {
      C_ERROR("failed to validate header for remote cmd\n");
      return OP_FAIL;
    }
    return OP_OK;
  }

  if (m_data_head.cmd == CCmdHeader::PT_TEST)
  {
    if (m_data_head.size < (int)sizeof(CCmdHeader)
        || m_data_head.signature != CCmdHeader::SIGNATURE)
    {
      C_ERROR("failed to validate header for test cmd\n");
      return OP_FAIL;
    }
    return OP_OK;
  }

  if (m_data_head.cmd == CCmdHeader::PT_PSP)
  {
    if (m_data_head.size < (int)sizeof(CCmdHeader) + 2
        || m_data_head.signature != CCmdHeader::SIGNATURE)
    {
      C_ERROR("failed to validate header for psp cmd\n");
      return OP_FAIL;
    }
    return OP_OK;
  }

  C_ERROR("unexpected packet header from dist server, header.command = %d\n", m_data_head.cmd);
  return OP_FAIL;
}

CProc::OUTPUT MyClientToDistProcessor::do_read_data(ACE_Message_Block * mb)
{
  if (!g_is_test)
    C_DEBUG("get complete dist packet: command = %d, len = %d\n", m_data_head.cmd, m_data_head.size);

  CFormatProcBase::do_read_data(mb);
  CCmdHeader * header = (CCmdHeader *)mb->base();

  if (header->cmd == CCmdHeader::PT_VER_REPLY)
  {
    CProc::OUTPUT result = do_version_check_reply(mb);

    if (result == OP_OK)
    {
      sn_check_ok(true);
      ((MyClientToDistHandler*)m_handler)->setup_timer();

      if (g_is_test && m_term_loc != 0)
      {
        ((MyClientToDistHandler*)m_handler)->setup_heart_beat_timer(1);
      } else
      {
        MyClientToDistModule * mod = MyClientAppX::instance()->client_to_dist_module();
        if (!mod->click_sent())
        {
          if (!((MyClientToDistHandler *)m_handler)->setup_click_send_timer())
            C_ERROR("can not set adv click timer %s\n", (const char *)CSysError());
        }
      }

      if (!g_is_test)
        MyConnectIni::update_connect_status(MyConnectIni::CS_ONLINE);
    }

    return result;
  }

  if (header->cmd == CCmdHeader::PT_FILE_MD5_LIST)
    return do_md5_list_request(mb);

  if (header->cmd == CCmdHeader::PT_FTP_FILE)
    return do_ftp_file_request(mb);

  if (header->cmd == CCmdHeader::PT_IP_VER_REQ)
    return do_ip_ver_reply(mb);

  if (header->cmd == CCmdHeader::PT_REMOTE_CMD)
    return do_remote_cmd(mb);

  if (header->cmd == CCmdHeader::PT_ACK)
    return do_ack(mb);

  if (header->cmd == CCmdHeader::PT_TEST)
    return do_test(mb);

  if (header->cmd == CCmdHeader::PT_PSP)
    return do_psp(mb);

  if (header->cmd == CCmdHeader::PT_TQ)
    return do_pl(mb);


  CMBProt guard(mb);
  C_ERROR("unsupported command received @MyClientToDistProcessor::do_read_data(), command = %d\n",
      header->cmd);
  return OP_FAIL;
}

bool MyClientToDistProcessor::check_vlc_empty()
{
  static char o = 'x';
  MyVLCLauncher & vlc = MyClientAppX::instance()->vlc_launcher();
  char c = vlc.empty_advlist() ? '1':'0';
  if (c == o)
    return true;
  o = c;
  ACE_Message_Block * mb = CCacheX::instance()->get_mb_cmd(1, CCmdHeader::PT_VLC_EMPTY);
  CCmdExt * dpe = (CCmdExt *)mb->base();
  dpe->data[0] = c;
  return m_handler->post_packet(mb) >= 0;
}

int MyClientToDistProcessor::send_heart_beat()
{
  if (!m_version_check_reply_done)
    return 0;
  ACE_Message_Block * mb = CCacheX::instance()->get_mb_cmd(0, CCmdHeader::PT_PING);
  int ret = (m_handler->post_packet(mb) < 0? -1: 0);
  check_vlc_empty();
//  C_DEBUG("send_heart_beat = %d\n", ret);
  return ret;
}

CProc::OUTPUT MyClientToDistProcessor::do_md5_list_request(ACE_Message_Block * mb)
{
  CMBProt guard(mb);
  CCmdExt * packet = (CCmdExt *) mb->base();
  if (!packet->validate())
  {
    C_ERROR("empty md5 list packet client_id(%s)\n", m_term_sn.to_str());
    return OP_OK;
  }

  MyDistInfoMD5 * dist_md5 = new MyDistInfoMD5;
  dist_md5->client_id = m_term_sn;
  dist_md5->client_id_index = m_term_loc;
  if (dist_md5->load_init(packet->data))
  {
    C_INFO("received one md5 file list command for dist %s, client_id=%s, ftype = %c\n",
        dist_md5->dist_id.get_ptr(),
        m_term_sn.to_str(),
        dist_md5->ftype);
//    MyDistInfoMD5 * existing = MyClientAppX::instance()->client_to_dist_module()->dist_info_md5s().get_finished(*dist_md5);
//    if (unlikely(existing != NULL))
//    {
//      existing->post_md5_message();
//      MyClientAppX::instance()->client_to_dist_module()->dist_info_md5s().add(existing);
//      delete dist_md5;
//      return OP_OK;
//    }

    if (!MyClientAppX::instance()->client_to_dist_module()->service()->add_md5_task(dist_md5))
      delete dist_md5;
  }
  else
  {
    C_ERROR("bad md5 file list command packet received\n");
    delete dist_md5;
  }

  return OP_OK;
}

CProc::OUTPUT MyClientToDistProcessor::do_ftp_file_request(ACE_Message_Block * mb)
{
  CMBProt guard(mb);
  CCmdExt * packet = (CCmdExt *) mb->base();
  if (!packet->validate())
  {
    C_ERROR("empty ftp file packet\n");
    return OP_OK;
  }

  char dist_id[128];
  {
    const char * ptr = ACE_OS::strchr(packet->data, CCmdHeader::ITEM_SEPARATOR);
    int len = ptr - packet->data;
    if (unlikely(!ptr || len >= 100 || len == 0))
    {
      C_ERROR("can not find dist_id @MyClientToDistProcessor::do_ftp_file_request\n");
      return OP_FAIL;
    }
    ACE_OS::memcpy(dist_id, packet->data, len);
    dist_id[len] = 0;
  }

  CMemProt str_data;
  str_data.init(packet->data);

  MyDistInfoFtp * dist_ftp = new MyDistInfoFtp();
  dist_ftp->status = 2;
  dist_ftp->client_id = m_term_sn;
  dist_ftp->client_id_index = m_term_loc;
  dist_ftp->ftp_password.init(m_ftp_password.get_ptr());

  if (dist_ftp->load_init(packet->data))
  {
    C_INFO("received one ftp command for dist(%s) client(%s): ftype=%c, adir=%s, password=%s, file name=%s\n",
            dist_ftp->dist_id.get_ptr(), m_term_sn.to_str(), dist_ftp->ftype,
            dist_ftp->adir.get_ptr() ? dist_ftp->adir.get_ptr(): "",
            dist_ftp->file_password.get_ptr(), dist_ftp->file_name.get_ptr());
    {
      MyClientDBProt dbg;
      if (dbg.db().open_db(m_term_sn.to_str()))
      {
        int ftp_status;
        if (dbg.db().get_ftp_command_status(dist_id, ftp_status))
        {
          if (ftp_status >= 2)
          {
            ACE_Message_Block * reply_mb = MyDistInfoFtp::make_ftp_dist_message(dist_id, ftp_status);
            C_INFO("dist ftp command already received, dist_id(%s) client_id(%s)\n", dist_id, m_term_sn.to_str());
            delete dist_ftp;
            return (m_handler->post_packet(reply_mb) < 0 ? OP_FAIL : OP_OK);
          }
          dbg.db().save_ftp_command(str_data.get_ptr(), *dist_ftp);
        } else
          dbg.db().save_ftp_command(str_data.get_ptr(), *dist_ftp);
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

  return OP_OK;
}

void MyClientToDistProcessor::check_offline_report()
{
  time_t t = ((MyClientToDistConnector *)m_handler->connector())->reset_last_connect_time();
  time_t now = time(NULL);
  C_INFO("offline report now = %d, old = %d\n", (int)now, (int)t);
  if (now <= t + OFFLINE_THREASH_HOLD)
    return;

  char buff[64], buff2[64];
  if (unlikely(!c_tools_convert_time_to_text(buff2, 32, false, now) || ! c_tools_convert_time_to_text(buff, 32, false, t)))
  {
    C_ERROR("mycomutil_generate_time_string failed @MyClientToDistProcessor::check_offline_report()\n");
    return;
  }
  ACE_OS::strncat(buff, "-", 64 - 1);
  ACE_OS::strncat(buff, buff2 + 9, 64 -1);
  int len = ACE_OS::strlen(buff);
  ACE_Message_Block * mb = CCacheX::instance()->get_mb_cmd(len + 1 + 1,
      CCmdHeader::PT_PC_ON_OFF);
  CCmdExt * dpe = (CCmdExt *)mb->base();
  dpe->data[0] = '3';
  ACE_OS::memcpy(dpe->data + 1, buff, len + 1);
  m_handler->post_packet(mb);
//  mycomutil_mb_putq(MyClientAppX::instance()->client_to_dist_module()->dispatcher(), mb, "client off-line report to dist queue");
}

CProc::OUTPUT MyClientToDistProcessor::do_ip_ver_reply(ACE_Message_Block * mb)
{
  CMBProt guard(mb);
  if (g_is_test && m_term_loc != 0)
    return OP_OK;

  MyClientToDistModule * mod = MyClientAppX::instance()->client_to_dist_module();
  CCmdExt * dpe = (CCmdExt *) mb->base();
  mod->ip_ver_reply().init(dpe->data);
  return ((MyClientToDistHandler*)m_handler)->setup_heart_beat_timer(mod->ip_ver_reply().heart_beat_interval()) ?
          OP_OK: OP_FAIL;
}

CProc::OUTPUT MyClientToDistProcessor::do_ack(ACE_Message_Block * mb)
{
  CMBProt guard(mb);
  if (unlikely(g_is_test))
  {
    C_ERROR("unexpected ack packet on test mode\n");
    return OP_FAIL;
  }

  CCmdHeader * dph = (CCmdHeader *) mb->base();
  MyClientAppX::instance()->client_to_dist_module()->dispatcher()->on_ack(dph->uuid);
  return OP_OK;
}

CProc::OUTPUT MyClientToDistProcessor::do_psp(ACE_Message_Block * mb)
{
  CCmdExt * dpe = (CCmdExt *)mb->base();
  if (!dpe->validate())
  {
    C_ERROR("bad psp packet\n");
    mb->release();
    return OP_OK;
  }

  C_INFO("get psp command (%c) for %s\n", dpe->data[0], dpe->data + 1);
  {
    MyClientDBProt dbg;
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
  dpe->signature = CCmdHeader::SIGNATURE;
  if (m_handler->post_packet(mb) < 0)
    return OP_FAIL;
  return OP_OK;
}

CProc::OUTPUT MyClientToDistProcessor::do_pl(ACE_Message_Block * mb)
{
  CMBProt guard(mb);
  CCmdExt * packet = (CCmdExt *) mb->base();
  if (!packet->validate())
  {
    C_ERROR("bad pl packet client_id(%s)\n", m_term_sn.to_str());
    return OP_OK;
  }

  MyPL::instance().save(m_term_sn.to_str(), packet->data);
  MyPL::instance().parse(packet->data);
  return OP_OK;
}

CProc::OUTPUT MyClientToDistProcessor::do_test(ACE_Message_Block * mb)
{
  CMBProt guard(mb);
  C_DEBUG("received test packet of size %d\n", mb->capacity());
  return OP_OK;
}

CProc::OUTPUT MyClientToDistProcessor::do_remote_cmd(ACE_Message_Block * mb)
{
  CMBProt guard(mb);
  return OP_OK;
}

CProc::OUTPUT MyClientToDistProcessor::do_version_check_reply(ACE_Message_Block * mb)
{
  CMBProt guard(mb);
  m_version_check_reply_done = true;
//  if (!g_test_mode)
//    C_DEBUG("on ver reply: handler = %X, socket = %d\n", (int)(long)m_handler, m_handler->get_handle());

  CTermVerReply * vcr;
  vcr = (CTermVerReply *)mb->base();
  switch (vcr->ret_subcmd)
  {
  case CTermVerReply::SC_OK:
    if (!g_is_test || m_term_loc == 0)
      C_INFO("handshake response from dist server: OK\n");
    sn_check_ok(true);
    if (vcr->size > (int)sizeof(CTermVerReply) + 1)
    {
      MyServerID::save(m_term_sn.to_str(), (int)(u_int8_t)vcr->data[0]);
      m_ftp_password.init(vcr->data + 1);
      MyClientAppX::instance()->ftp_password(m_ftp_password.get_ptr());
    }
    m_handler->connector()->reset_retry_count();
    if (!g_is_test)
      check_offline_report();
    return CProc::OP_OK;

  case CTermVerReply::SC_OK_UP:
    sn_check_ok(true);
    if (vcr->size > (int)sizeof(CTermVerReply) + 1)
    {
      MyServerID::save(m_term_sn.to_str(), (int)(u_int8_t)vcr->data[0]);
      m_ftp_password.init(vcr->data + 1);
      MyClientAppX::instance()->ftp_password(m_ftp_password.get_ptr());
    }
    m_handler->connector()->reset_retry_count();
    if (!g_is_test || m_term_loc == 0)
      C_INFO("handshake response from dist server: OK Can Upgrade\n");
    if (!g_is_test)
      check_offline_report();
    //todo: notify app to upgrade
    return CProc::OP_OK;

  case CTermVerReply::SC_NOT_MATCH:
    if (vcr->size > (int)sizeof(CTermVerReply) + 1)
      m_ftp_password.init(vcr->data);
    m_handler->connector()->reset_retry_count();
    if (!g_is_test || m_term_loc == 0)
      C_ERROR("handshake response from dist server: Version Mismatch\n");
    return CProc::OP_FAIL;

  case CTermVerReply::SC_ACCESS_DENIED:
    m_handler->connector()->reset_retry_count();
    if (!g_is_test || m_term_loc == 0)
      C_ERROR("handshake response from dist server: Access Denied\n");
    return CProc::OP_FAIL;

  case CTermVerReply::SC_SERVER_BUSY:
    if (!g_is_test || m_term_loc == 0)
      C_INFO("handshake response from dist server: Server Busy\n");

    return CProc::OP_FAIL;

  default: //server_list
    if (!g_is_test || m_term_loc == 0)
      C_INFO("handshake response from dist server: unknown code = %d\n", vcr->ret_subcmd);
    return CProc::OP_FAIL;
  }
}

int MyClientToDistProcessor::send_version_check_req()
{
  ACE_INET_Addr addr;
  char my_addr[IP_LEN];
  ACE_OS::memset(my_addr, 0, IP_LEN);
  if (m_handler->peer().get_local_addr(addr) == 0)
    addr.get_host_addr((char*)my_addr, IP_LEN);
  const char * hw_ver = MyClientAppX::instance()->client_to_dist_module()->hw_ver();
  int len = ACE_OS::strlen(hw_ver) + 1;
  ACE_Message_Block * mb = create_login_mb(len);
  CTerminalVerReq * proc = (CTerminalVerReq *)mb->base();
  if (my_addr[0] != 0)
    ACE_OS::memcpy(proc->uuid, my_addr, IP_LEN);
  proc->term_ver_major = const_client_version_major;
  proc->term_ver_minor = const_client_version_minor;
  proc->term_sn = m_term_sn;
  proc->server_id = (u_int8_t) MyServerID::load(m_term_sn.to_str());
  ACE_OS::memcpy(proc->hw_ver, hw_ver, len);
  return (m_handler->post_packet(mb) < 0? -1: 0);
}

int MyClientToDistProcessor::send_ip_ver_req()
{
  ACE_Message_Block * mb = CCacheX::instance()->get_mb_cmd_direct(sizeof(CIpVerReq), CCmdHeader::PT_IP_VER_REQ);
  CIpVerReq * ivr = (CIpVerReq *) mb->base();
  ivr->term_ver_major = const_client_version_major;
  ivr->term_ver_minor = const_client_version_minor;
  if (!g_is_test || m_term_loc == 0)
    C_INFO("sending ip ver to dist server...\n");
  return (m_handler->post_packet(mb) < 0? -1: 0);
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
  m_addr_list.init(list);
  char * ftp_list = strchr(list, CCmdHeader::FINISH_SEPARATOR);
  if (ftp_list)
    *ftp_list++ = 0;

  char seperator[2] = {CCmdHeader::ITEM_SEPARATOR, 0};
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
  CFileProt f;
  CMemProt file_name;
  get_file_name(file_name);
  if (!f.open_write(file_name.get_ptr(), true, true, false, true))
    return;
  if (::write(f.get_fd(), m_addr_list.get_ptr(), m_addr_list_len) != m_addr_list_len)
    C_ERROR("write to file %s failed %s\n", file_name.get_ptr(), (const char*)CSysError());
}

void MyDistServerAddrList::load()
{
  CFileProt f;
  CMemProt file_name;
  get_file_name(file_name);
  if (!f.open_nowrite(file_name.get_ptr()))
    return;
  const int BUFF_SIZE = 2048;
  char buff[BUFF_SIZE];
  int n = ::read(f.get_fd(), buff, BUFF_SIZE);
  if (n <= 0)
    return;
  buff[n - 1] = 0;
  addr_list(buff);
}

void MyDistServerAddrList::get_file_name(CMemProt & file_name)
{
  const char * const_file_name = "/config/servers.lst";
  file_name.init(CCfgX::instance()->app_path.c_str(), const_file_name);
}

bool MyDistServerAddrList::valid_addr(const char * addr) const
{
  struct in_addr ia;
  return (::inet_pton(AF_INET, addr, &ia) == 1);
}

bool MyDistServerAddrList::has_cache()
{
  CMemProt file_name;
  get_file_name(file_name);
  struct stat st;
  if (!CSysFS::stat(file_name.get_ptr(), &st))
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
  std::string vlc2 = CCfgX::instance()->data_path + "/vlc-history2.txt";
  std::string vlc1 = CCfgX::instance()->data_path + "/vlc-history.txt";
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

MyClientToDistHandler::MyClientToDistHandler(CHandlerDirector * xptr): CParentHandler(xptr)
{
  m_proc = new MyClientToDistProcessor(this);
  m_heart_beat_timer = -1;
  m_heart_beat_tmp_timer = -1;
}

bool MyClientToDistHandler::setup_timer()
{
  ACE_Time_Value interval(IP_VER_INTERVAL * 60);
  if (reactor()->schedule_timer(this, (void*)IP_VER_TIMER, interval, interval) < 0)
  {
    C_ERROR(ACE_TEXT("MyClientToDistHandler setup ip ver timer failed, %s"), (const char*)CSysError());
    return false;
  }

  if (!g_is_test)
    C_INFO("MyClientToDistHandler setup ip ver timer: OK\n");

  ACE_Time_Value interval2(HEART_BEAT_PING_TMP_INTERVAL * 60);
  m_heart_beat_tmp_timer = reactor()->schedule_timer(this, (void*)HEART_BEAT_PING_TMP_TIMER, interval2, interval2);
  if (m_heart_beat_tmp_timer < 0)
    C_ERROR(ACE_TEXT("MyClientToDistHandler setup tmp heart beat timer failed, %s"), (const char*)CSysError());

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

  if (!g_is_test || m_proc->term_sn_loc() == 0)
    C_INFO("setup heart beat timer (per %d minute(s))\n", heart_beat_interval);
  ACE_Time_Value interval(heart_beat_interval * 60);
  m_heart_beat_timer = reactor()->schedule_timer(this, (void*)HEART_BEAT_PING_TIMER, interval, interval);
  if (m_heart_beat_timer < 0)
  {
    C_ERROR(ACE_TEXT("MyClientToDistHandler setup heart beat timer failed, %s"), (const char*)CSysError());
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
    C_ERROR(ACE_TEXT("MyClientToDistHandler setup click send timer failed, %s"), (const char*)CSysError());
    return false;
  }

  return true;
}

MyClientToDistModule * MyClientToDistHandler::module_x() const
{
  return (MyClientToDistModule *)connector()->container();
}

int MyClientToDistHandler::at_start()
{
  return 0;
}

int MyClientToDistHandler::handle_timeout(const ACE_Time_Value &current_time, const void *act)
{
  ACE_UNUSED_ARG(current_time);
//  C_DEBUG("MyClientToDistHandler::handle_timeout()\n");
  if (long(act) == HEART_BEAT_PING_TIMER)
  {
    if (m_proc->term_sn_loc() == 0)
      C_DEBUG("ping dist server now...\n");
#if 0
    const int extra_size = 1024 * 1024 * 1;
    ACE_Message_Block * mb = CCacheX::instance()->get_mb_cmd(extra_size, CCmdHeader::PT_TEST);
    CCmdExt * dpe = (CCmdExt *)mb->base();
    ACE_OS::memset(dpe->get_ptr, 0, extra_size);
    int ret = post_packet(mb);
    if (ret == 0)
      ret = ((MyClientToDistProcessor*)m_proc)->send_heart_beat();
    return ret;
#else
    return ((MyClientToDistProcessor*)m_proc)->send_heart_beat();
#endif
  }
  else if (long(act) == HEART_BEAT_PING_TMP_TIMER)
  {
    if (m_proc->term_sn_loc() == 0)
      C_DEBUG("ping (tmp) dist server now...\n");
    return ((MyClientToDistProcessor*)m_proc)->send_heart_beat();
  }
  else if (long(act) == IP_VER_TIMER)
    return ((MyClientToDistProcessor*)m_proc)->send_ip_ver_req();
  else if (long(act) == CLICK_SEND_TIMER)
  {
    MyClientToDistModule * mod = MyClientAppX::instance()->client_to_dist_module();
    if (mod->click_sent())
      return 0;
    ACE_Message_Block * mb = mod->get_click_infos(m_proc->term_sn().to_str());
    mod->click_sent_done(m_proc->term_sn().to_str());
    C_INFO("adv click info, mb %s NULL\n", mb? "not": "is");
    if (mb != NULL)
    {
      MyClientAppX::instance()->client_to_dist_module()->dispatcher()->add_to_buffered_mbs(mb);
      if (post_packet(mb) < 0)
        return -1;
    }

    mb = mod->get_vlc_infos(m_proc->term_sn().to_str());
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

void MyClientToDistHandler::at_finish()
{
  reactor()->cancel_timer(this);

  if (g_is_test)
  {
    if (m_handler_director->is_down())
      return;
    MyClientAppX::instance()->client_to_dist_module()->id_generator().put
        (
          ((MyClientToDistProcessor*)m_proc)->term_sn().to_str()
        );
  }
}

PREPARE_MEMORY_POOL(MyClientToDistHandler);


//MyClientToDistService//

MyClientToDistService::MyClientToDistService(CContainer * module, int numThreads):
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
      CMBProt guard(mb);
      p = task_convert(mb, task_type);
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
  return add_new(p, TASK_MD5);
}

bool MyClientToDistService::add_extract_task(MyDistInfoFtp * p)
{
  if (unlikely(!p->validate()))
  {
    C_ERROR("invalid extract task @ %s::add_extract_task", name());
    delete p;
    return true;
  }
  return add_new(p, TASK_EXTRACT);
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
  return add_new((void*)p, TASK_REV);
}

void MyClientToDistService::return_back(MyDistInfoFtp * dist_info)
{
  if (unlikely(!dist_info))
    return;
  ((MyClientToDistModule*)container())->dist_info_ftps().add(dist_info);
}

void MyClientToDistService::return_back_md5(MyDistInfoMD5 * p)
{
  if (unlikely(!p))
      return;
  ((MyClientToDistModule*)container())->dist_info_md5s().add(p);
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
    MyClientDBProt dbg;
    if (dbg.db().open_db(p->client_id.to_str()))
      b_saved = dbg.db().save_md5_command(p->dist_id.get_ptr(), p->md5_text(), "");
  }

  C_INFO("client side md5 for dist_id(%s) save: %s\n", p->dist_id.get_ptr(), b_saved? "OK":"failed");
#else
  CCheckSums client_md5s;
  if (!MyDistInfoMD5Comparer::compute(p, client_md5s))
    C_ERROR("md5 file list generation error\n");

  bool b_saved = false;
  {
    CMemProt md5_client;
    client_md5s.sort();
    int len = client_md5s.text_len(true);
    CCacheX::instance()->get(len, &md5_client);
    client_md5s.save_text(md5_client.get_ptr(), len, true);

    MyClientDBProt dbg;
    if (dbg.db().open_db(p->term_sn.to_str()))
      b_saved = dbg.db().save_md5_command(p->dist_id.get_ptr(), p->md5_text(), md5_client.get_ptr());
  }

  C_INFO("client side md5 for dist_id(%s) save: %s\n", p->dist_id.get_ptr(), b_saved? "OK":"failed");

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
    C_INFO("update done for dist_id(%s) client_id(%s)\n", dist_info->dist_id.get_ptr(), dist_info->client_id.to_str());
    if (!g_is_test && dist_info->status == 4)
    {
      if (c_tell_ftype_adv_list(dist_info->ftype))
        MyClientAppX::instance()->vlc_monitor().relaunch();
      else if (c_tell_ftype_frame(dist_info->ftype))
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

MyClientFtpService::MyClientFtpService(CContainer * module, int numThreads):
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
  std::string server_addr = ((MyClientToDistModule*)container())->server_addr_list().rnd();
  int failed_count = 0;

  while (MyClientAppX::instance()->running())
  {
    if (!g_is_test)
    {
      const char * s = MyClientAppX::instance()->ftp_password();
      if (!s || !*s)
        ACE_OS::sleep(3);
    }

    MyDistInfoFtp * p = ((MyClientToDistModule*)container())->dist_info_ftps().get();
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
        const char * p = ((MyClientToDistModule*)container())->server_addr_list().next_ftp();
        if (p)
          server_addr = p;
        else
          server_addr = ((MyClientToDistModule*)container())->server_addr_list().begin_ftp();
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
  return add_new(p, TASK_FTP);
}


bool MyClientFtpService::do_ftp_download(MyDistInfoFtp * dist_info, const char * server_ip)
{
  if (unlikely(dist_info->status >=  3))
    return true;

  C_INFO("processing ftp download for dist_id=%s, filename=%s, ftype=%c, adir=%s, password=%s, retry_count=%d\n",
      dist_info->dist_id.get_ptr(),
      dist_info->file_name.get_ptr(),
      dist_info->ftype,
      dist_info->adir.get_ptr() ? dist_info->adir.get_ptr():"",
      dist_info->file_password.get_ptr(),
      dist_info->failed_count());

  if (!g_is_test)
  {
    MyClientDBProt dbg;
    if (dbg.db().open_db(MyClientAppX::instance()->client_id()))
    {
      if (dbg.db().ftp_obsoleted(*dist_info))
      {
        C_INFO("ftp dist_id (%s) is obsoleted, canceling...\n", dist_info->dist_id.get_ptr());
        dist_info->status = 6;
        dbg.db().set_ftp_command_status(dist_info->dist_id.get_ptr(), 6);
        return false;
      }

      int t = -1000;
      dbg.db().get_ftp_command_status(dist_info->dist_id.get_ptr(), t);
      if (t >= 6)
      {
        C_INFO("ftp dist_id (%s) not needed, canceling...\n", dist_info->dist_id.get_ptr());
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
      MyClientDBProt dbg;
      if (dbg.db().open_db(MyClientAppX::instance()->client_id()))
      {
        int t = -1000;
        dbg.db().get_ftp_command_status(dist_info->dist_id.get_ptr(), t);
        if (t >= 6)
        {
          C_INFO("ftp dist_id (%s) not needed, canceling...\n", dist_info->dist_id.get_ptr());
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
  ((MyClientToDistModule*)container())->dist_info_ftps().add(dist_info);
}

MyDistInfoFtp * MyClientFtpService::get_dist_info_ftp(ACE_Message_Block * mb) const
{
  if (unlikely(mb->capacity() != sizeof(void *) + sizeof(int)))
    return NULL;
  return *((MyDistInfoFtp **)mb->base());
}


//MyClientToDistConnector//

MyClientToDistConnector::MyClientToDistConnector(CParentScheduler * _dispatcher, CHandlerDirector * _manager):
    CParentConn(_dispatcher, _manager)
{
  m_port_of_ip = CCfgX::instance()->ping_port;
  m_retry_delay = RECONNECT_INTERVAL;
  if (g_is_test)
    m_conn_count = MyClientAppX::instance()->term_SNs().number();
  m_last_connect_time = 0;
}

const char * MyClientToDistConnector::name() const
{
  return "MyClientToDistConnector";
}

void MyClientToDistConnector::dist_server_addr(const char * addr)
{
  if (likely(addr != NULL))
    m_remote_ip = addr;
}

time_t MyClientToDistConnector::reset_last_connect_time()
{
  time_t result = m_last_connect_time;
  m_last_connect_time = time(NULL);
  return result;
}

int MyClientToDistConnector::make_svc_handler(CParentHandler *& sh)
{
  sh = new MyClientToDistHandler(m_director);
  if (!sh)
  {
    C_ERROR("can not alloc MyClientToDistHandler from %s\n", name());
    return -1;
  }
//  C_DEBUG("MyClientToDistConnector::make_svc_handler(%X)...\n", long(sh));
  sh->container((void*)this);
  sh->reactor(reactor());
  return 0;
}

bool MyClientToDistConnector::before_reconnect()
{
  if (m_last_connect_time == 0)
    m_last_connect_time = time(NULL);
  if (m_retry_num <= 5)
    return true;

  MyDistServerAddrList & addr_list = ((MyClientToDistModule*)(m_container))->server_addr_list();
  const char * new_addr = addr_list.next();
  if (!new_addr || !*new_addr)
    new_addr = addr_list.begin();
  if (new_addr && *new_addr)
  {
    if (ACE_OS::strcmp("127.0.0.1", new_addr) == 0)
      new_addr = CCfgX::instance()->middle_addr.c_str();
    C_INFO("maximum connect to %s:%d retry count reached , now trying next addr %s:%d...\n",
        m_remote_ip.c_str(), m_port_of_ip, new_addr, m_port_of_ip);
    m_remote_ip = new_addr;
    m_retry_num = 1;
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
  CCmdHeader * dph = (CCmdHeader*)m_mb->base();
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

void MyBufferedMBs::connection_manager(CHandlerDirector * p)
{
  m_con_manager = p;
}

void MyBufferedMBs::add(ACE_Message_Block * mb)
{
  if (!mb || mb->capacity() < (size_t)sizeof(CCmdHeader))
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
      m_con_manager->post_one(p->mb()->duplicate());
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

MyClientToDistDispatcher::MyClientToDistDispatcher(CContainer * pModule, int numThreads):
    CParentScheduler(pModule, numThreads)
{
  m_connector = NULL;
  m_middle_connector = NULL;
  m_http1991_acceptor = NULL;
  m_delay_clock = FTP_CHECK_INTERVAL * 60;
  msg_queue()->high_water_mark(MSG_QUEUE_MAX_SIZE);
}

MyClientToDistDispatcher::~MyClientToDistDispatcher()
{

}

bool MyClientToDistDispatcher::before_begin()
{
  m_middle_connector = new MyClientToMiddleConnector(this, new CHandlerDirector());
  conn_add(m_middle_connector);
  if (!g_is_test)
  {
    m_http1991_acceptor = new MyHttp1991Acceptor(this, new CHandlerDirector());
    acc_add(m_http1991_acceptor);

    ACE_Time_Value interval(WATCH_DOG_INTERVAL * 60);
    if (reactor()->schedule_timer(this, (const void*)TIMER_ID_WATCH_DOG, interval, interval) < 0)
      C_ERROR("setup watch dog timer failed %s %s\n", name(), (const char*)CSysError());

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
    ((MyClientToDistModule*)container())->check_ftp_timed_task();
    if (!g_is_test)
    {
      if (m_connector == NULL || m_connector->director()->active_count() == 0)
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
  MyDistServerAddrList & addr_list = ((MyClientToDistModule*)m_container)->server_addr_list();
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
    m_connector = new MyClientToDistConnector(this, new CHandlerDirector());
  conn_add(m_connector);
  m_buffered_mbs.connection_manager(m_connector->director());

  const char * addr = addr_list.begin();
  if (ACE_OS::strcmp("127.0.0.1", addr) == 0)
    addr = CCfgX::instance()->middle_addr.c_str();
  m_connector->dist_server_addr(addr);
  m_connector->begin();
}

void MyClientToDistDispatcher::start_watch_dog()
{
  ((MyClientToDistModule*)container())->watch_dog().start();
}

void MyClientToDistDispatcher::on_ack(uuid_t uuid)
{
  m_buffered_mbs.on_reply(uuid);
}

void MyClientToDistDispatcher::add_to_buffered_mbs(ACE_Message_Block * mb)
{
  m_buffered_mbs.add(mb);
}

void MyClientToDistDispatcher::before_finish()
{
  m_connector = NULL;
  m_middle_connector = NULL;
  m_http1991_acceptor = NULL;
}

void MyClientToDistDispatcher::check_watch_dog()
{
  if (((MyClientToDistModule*)container())->watch_dog().expired())
    MyClientAppX::instance()->opera_launcher().relaunch();
}

bool MyClientToDistDispatcher::do_schedule_work()
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
        int index = ((CCmdHeader*)mb->base())->signature;
        CParentHandler * handler = m_connector->director()->locate(index);
        if (!handler)
        {
          C_WARNING("can not send data to client since connection is lost @ %s::do_schedule_work\n", name());
          mb->release();
          continue;
        }

        ((CCmdHeader*)mb->base())->signature = CCmdHeader::SIGNATURE;
        if (handler->post_packet(mb) < 0)
          handler->handle_close();
      } else
      {
        if (likely(mb->capacity() >= (int)sizeof(CCmdHeader)))
        {
          CCmdHeader * dph = (CCmdHeader*)mb->base();
          if (dph->cmd == CCmdHeader::PT_FTP_FILE)
          {
            uuid_t uuid;
            uuid_clear(uuid);
            if (uuid_compare(dph->uuid, uuid) != 0)
              add_to_buffered_mbs(mb);
          }
        }
        if (m_connector && m_connector->director())
          m_connector->director()->post_one(mb);
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
      c_tools_mb_putq(MyClientAppX::instance()->client_to_dist_module()->dispatcher(), mb, "hw alarm to dist queue");
  }
}

ACE_Message_Block * MyHwAlarm::make_hardware_alarm_mb()
{
  ACE_Message_Block * mb = CCacheX::instance()->get_mb_cmd_direct(sizeof(CPLCWarning),
      CCmdHeader::PT_HARDWARE_ALARM);
  if (g_is_test)
    ((CCmdHeader *)mb->base())->signature = 0;
  CPLCWarning * dpe = (CPLCWarning *)mb->base();
  dpe->x = m_x;
  dpe->y = m_y;
  return mb;
}


//MyClientToDistModule//

MyClientToDistModule::MyClientToDistModule(CApp * app): CContainer(app)
{
  if (g_is_test)
  {
    CTermSNs & term_SNs = MyClientAppX::instance()->term_SNs();
    int count = term_SNs.number();
    CNumber client_id;
    for (int i = 0; i < count; ++ i)
    {
      if (term_SNs.get_sn(i, &client_id))
        m_id_generator.put(client_id.to_str());
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
  MyClientDBProt dbg;
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
    add_task(m_client_ftp_service = new MyClientFtpService(this, CCfgX::instance()->download_threads));
  else
    add_task(m_client_ftp_service = new MyClientFtpService(this, 1));
  m_client_ftp_service->begin();
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
    MyClientDBProt dbg;
    if (!dbg.db().open_db(client_id))
      return NULL;

    dbg.db().get_click_infos(click_infos);

    for (it = click_infos.begin(); it != click_infos.end(); ++it)
      len += it->len;
    if (len == 0)
      return NULL;
  }

  ++len;
  ACE_Message_Block * mb = CCacheX::instance()->get_mb_cmd(len, CCmdHeader::PT_ADV_CLICK, false);
  CCmdExt * dpe = (CCmdExt *)mb->base();
  char * ptr = dpe->data;
  for (it = click_infos.begin(); it != click_infos.end(); ++it)
  {
    ACE_OS::sprintf(ptr, "%s%c%s%c%s%c",
        it->channel.c_str(),
        CCmdHeader::ITEM_SEPARATOR,
        it->point_code.c_str(),
        CCmdHeader::ITEM_SEPARATOR,
        it->click_count.c_str(),
        CCmdHeader::FINISH_SEPARATOR);
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

bool MyClientToDistModule::before_begin()
{
  add_task(m_service = new MyClientToDistService(this, 1));
  add_scheduler(m_dispatcher = new MyClientToDistDispatcher(this));
  return true;
}

void MyClientToDistModule::before_finish()
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
    MyClientDBProt dbg;
    if (dbg.db().open_db(MyClientAppX::instance()->client_id()))
      dbg.db().load_ftp_commands(&m_dist_info_ftps);
  }
}


/////////////////////////////////////
//client to middle
/////////////////////////////////////

//MyClientToMiddleProcessor//

MyClientToMiddleProcessor::MyClientToMiddleProcessor(CParentHandler * handler): CParentClientProc(handler)
{

}

const char * MyClientToMiddleProcessor::name() const
{
  return "MyClientToMiddleProcessor";
}

int MyClientToMiddleProcessor::at_start()
{
  if (super::at_start() < 0)
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
    set_term_sn(myid);
    m_term_loc = MyClientAppX::instance()->term_SNs().find_location(myid);
    if (m_term_loc < 0)
    {
      C_ERROR("MyClientToDistProcessor::at_start() can not find client_id_index for id = %s\n", myid);
      return -1;
    }
    m_handler->handler_director()->sn_at_location(m_handler, m_term_loc, NULL);
    id_generator.put(myid);
  } else
  {
    set_term_sn(MyClientAppX::instance()->client_id());
    m_term_loc = 0;
  }

  return send_version_check_req();
}

CProc::OUTPUT MyClientToMiddleProcessor::at_head_arrival()
{
  CProc::OUTPUT result = super::at_head_arrival();
  if (result != OP_GO_ON)
    return OP_FAIL;

  bool bVersionCheckReply = m_data_head.cmd == CCmdHeader::PT_VER_REPLY;

  if (bVersionCheckReply)
  {
    if (!c_packet_check_term_ver_reply(&m_data_head))
    {
      C_ERROR("failed to validate header for version check reply\n");
      return OP_FAIL;
    }
    return OP_OK;
  }

  C_ERROR("unexpected packet header from dist server, header.command = %d\n", m_data_head.cmd);
  return OP_FAIL;
}

CProc::OUTPUT MyClientToMiddleProcessor::do_read_data(ACE_Message_Block * mb)
{
  CFormatProcBase::do_read_data(mb);
  m_mark_down = true;
  CMBProt guard(mb);

  CCmdHeader * header = (CCmdHeader *)mb->base();
  if (header->cmd == CCmdHeader::PT_VER_REPLY)
    do_version_check_reply(mb);
  else
    C_ERROR("unsupported command received @MyClientToDistProcessor::do_read_data(), command = %d\n",
        header->cmd);
  return OP_FAIL;
}

void MyClientToMiddleProcessor::do_version_check_reply(ACE_Message_Block * mb)
{
  const char * prefix_msg = "middle server version check reply:";
  CTermVerReply * vcr = (CTermVerReply *) mb->base();
  switch (vcr->ret_subcmd)
  {
  case CTermVerReply::SC_NOT_MATCH:
    C_ERROR("%s get version mismatch response\n", prefix_msg);
    return;

  case CTermVerReply::SC_ACCESS_DENIED:
    C_ERROR("%s get access denied response\n", prefix_msg);
    return;

  case CTermVerReply::SC_SERVER_BUSY:
    C_ERROR("%s get server busy response\n", prefix_msg);
    return;

  case CTermVerReply::SC_SERVER_LIST:
    do_handle_server_list(mb);
    return;

  default:
    C_ERROR("%s get unexpected reply code = %d\n", prefix_msg, vcr->ret_subcmd);
    return;
  }
}

void MyClientToMiddleProcessor::do_handle_server_list(ACE_Message_Block * mb)
{
  CTermVerReply * vcr = (CTermVerReply *)mb->base();
  MyClientToDistModule * module = MyClientAppX::instance()->client_to_dist_module();
  int len = vcr->size;
  if (len == (int)sizeof(CTermVerReply))
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
  ACE_Message_Block * mb = create_login_mb();
  CTerminalVerReq * proc = (CTerminalVerReq *)mb->base();
  proc->term_ver_major = const_client_version_major;
  proc->term_ver_minor = const_client_version_minor;
  proc->term_sn = m_term_sn;
  proc->server_id = 0;
  C_INFO("sending handshake request to middle server...\n");
  return (m_handler->post_packet(mb) < 0? -1: 0);
}


//MyClientToMiddleHandler//

MyClientToMiddleHandler::MyClientToMiddleHandler(CHandlerDirector * xptr): CParentHandler(xptr)
{
  m_proc = new MyClientToMiddleProcessor(this);
  m_timer_out_timer_id = -1;
}

void MyClientToMiddleHandler::setup_timer()
{
  ACE_Time_Value interval(TIME_OUT_INTERVAL * 60);
  m_timer_out_timer_id = reactor()->schedule_timer(this, (void*)TIMER_OUT_TIMER, interval);
  if (m_timer_out_timer_id < 0)
    C_ERROR(ACE_TEXT("MyClientToMiddleHandler setup time out timer failed, %s"), (const char*)CSysError());
}

MyClientToDistModule * MyClientToMiddleHandler::module_x() const
{
  return (MyClientToDistModule *)connector()->container();
}

int MyClientToMiddleHandler::at_start()
{
  return 0;
}

int MyClientToMiddleHandler::handle_timeout(const ACE_Time_Value &current_time, const void *act)
{
  ACE_UNUSED_ARG(current_time);
  ACE_UNUSED_ARG(act);
  return -1;
}

void MyClientToMiddleHandler::at_finish()
{

}

PREPARE_MEMORY_POOL(MyClientToMiddleHandler);


//MyClientToMiddleConnector//

MyClientToMiddleConnector::MyClientToMiddleConnector(CParentScheduler * _dispatcher, CHandlerDirector * _manager):
    CParentConn(_dispatcher, _manager)
{
  m_port_of_ip = CCfgX::instance()->pre_client_port;
  m_remote_ip = CCfgX::instance()->middle_addr;
  m_retry_delay = RECONNECT_INTERVAL;
  m_retried_count = 0;
}

const char * MyClientToMiddleConnector::name() const
{
  return "MyClientToMiddleConnector";
}

void MyClientToMiddleConnector::finish()
{
  m_retry_delay = 0;
  m_no_activity_delay = 0;
  if (m_retry_tid >= 0)
  {
    reactor()->cancel_timer(m_retry_tid);
    m_retry_tid = -1;
  }
  if (m_no_activity_tid >= 0)
  {
    reactor()->cancel_timer(m_no_activity_tid);
    m_no_activity_tid = -1;
  }
}

int MyClientToMiddleConnector::make_svc_handler(CParentHandler *& sh)
{
  sh = new MyClientToMiddleHandler(m_director);
  if (!sh)
  {
    C_ERROR("can not alloc MyClientToMiddleHandler from %s\n", name());
    return -1;
  }
  sh->container((void*)this);
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

MyHttp1991Processor::MyHttp1991Processor(CParentHandler * handler) : super(handler)
{
  m_mb = NULL;
  if (g_is_test)
    MyClientAppX::instance()->term_SNs().get_sn(0, &m_term_sn);
  else
    m_term_sn = MyClientAppX::instance()->client_id();
}

MyHttp1991Processor::~MyHttp1991Processor()
{
  if (m_mb)
    m_mb->release();
}

int MyHttp1991Processor::handle_input()
{
  if (m_mb == NULL)
    m_mb = CCacheX::instance()->get_mb(MAX_COMMAND_LINE_LENGTH);
  if (c_tools_read_mb(m_handler, m_mb) < 0)
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

  MyClientDBProt dbg;
  if (dbg.db().open_db(m_term_sn.to_str()))
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
    c_tools_mb_putq(MyClientAppX::instance()->client_to_dist_module()->dispatcher(), mb, "pc on/off to dist queue");
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
  ACE_Message_Block * mb = CCacheX::instance()->get_mb_cmd(len + 1 + 1,
      CCmdHeader::PT_PC_ON_OFF);
  if (g_is_test)
    ((CCmdHeader *)mb->base())->signature = 0;
  CCmdExt * dpe = (CCmdExt *)mb->base();
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
  ACE_Message_Block * mb = CCacheX::instance()->get_mb(len);
  CMemProt guard;
  CCacheX::instance()->get(html_len, &guard);
  ACE_OS::sprintf(guard.get_ptr(), const_html_tpl, s);
  html_len = ACE_OS::strlen(guard.get_ptr());
  ACE_OS::sprintf(mb->base(), const_complete, html_len);
  ACE_OS::strcat(mb->base(), guard.get_ptr());
  len = ACE_OS::strlen(mb->base());
  mb->wr_ptr(len);
  m_handler->post_packet(mb);
}


//MyHttp1991Handler//

MyHttp1991Handler::MyHttp1991Handler(CHandlerDirector * xptr)
  : CParentHandler(xptr)
{
  m_proc = new MyHttp1991Processor(this);
}


//MyHttp1991Acceptor//

MyHttp1991Acceptor::MyHttp1991Acceptor(CParentScheduler * _dispatcher, CHandlerDirector * _manager):
    CParentAcc(_dispatcher, _manager)
{
  m_tcp_port = 1991;
  m_reap_interval = IDLE_TIME_AS_DEAD;
}

int MyHttp1991Acceptor::make_svc_handler(CParentHandler *& sh)
{
  sh = new MyHttp1991Handler(m_director);
  if (!sh)
  {
    C_ERROR("can not alloc MyHttp1991Handler from %s\n", name());
    return -1;
  }
  sh->container((void*)this);
  sh->reactor(reactor());
  return 0;
}

const char * MyHttp1991Acceptor::name() const
{
  return "MyHttp1991Acceptor";
}
