/*
 * clientmodule.cpp
 *
 *  Created on: Jan 8, 2012
 *      Author: root
 */

#include <ace/FILE_Addr.h>
#include <ace/FILE_Connector.h>
#include <ace/FILE_IO.h>

#include "clientmodule.h"
#include "baseapp.h"
#include "client.h"

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
      "create table tb_ftp_info(ftp_dist_id text PRIMARY KEY, ftp_str text, ftp_status integer, ftp_recv_time integer)";

  return do_exec(const_sql_tb_ftp_info, false);
}

bool MyClientDB::open_db(const char * client_id)
{
  if (m_db)
    return true;

  bool retried = false;
  MyPooledMemGuard db_path, db_name;
  MyClientAppX::instance()->data_path(db_path, client_id);
  db_name.init_from_string(db_path.data(), "/client.db");

  while(true)
  {
    if(sqlite3_open(db_name.data(), &m_db))
    {
      MY_ERROR("failed to database %s, msg=%s\n", db_name.data(), sqlite3_errmsg(m_db));
      close_db();
      if (retried)
        return false;
      retried = true;
      MyFilePaths::remove(db_name.data());
    } else
      break;
  }

  init_db(); //no harm
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
      MY_ERROR("do_exec(sql=%s) failed, msg=%s\n", sql, zErrMsg);
    if (zErrMsg)
      sqlite3_free(zErrMsg);
    return false;
  }
  if (zErrMsg)
    sqlite3_free(zErrMsg);
  return true;
}

bool MyClientDB::save_ftp_command(const char * ftp_command)
{
  if (unlikely(!ftp_command || !*ftp_command))
    return false;

  const char * ptr = ACE_OS::strchr(ftp_command, MyDataPacketHeader::ITEM_SEPARATOR);
  int len = ptr - ftp_command;
  if (!ptr || len >= 100)
    return false;
  char dist_id[128];
  ACE_OS::memcpy(dist_id, ftp_command, len);
  dist_id[len] = 0;

  const char * const_sql_template = "insert into tb_ftp_info(ftp_dist_id, ftp_str, ftp_status, ftp_recv_time) "
                                    "values('%s', '%s', %d, %d)";
  int total_len = ACE_OS::strlen(const_sql_template) + len + ACE_OS::strlen(ftp_command) + 20;
  MyPooledMemGuard sql;
  MyMemPoolFactoryX::instance()->get_mem(total_len, &sql);
  ACE_OS::snprintf(sql.data(), total_len, const_sql_template, dist_id, ftp_command, 0, (long)time(NULL));
  return do_exec(sql.data());
}

bool MyClientDB::set_ftp_command_status(const char * dist_id, int status)
{
  const char * const_sql_template = "update tb_ftp_info set ftp_status = %d where ftp_dist_id = '%s'";
  char sql[200];
  ACE_OS::snprintf(sql, 200, const_sql_template, status, dist_id);
  return do_exec(sql);
}

void MyClientDB::remove_outdated_ftp_command(time_t deadline)
{
  const char * const_sql_template = "delete from tb_ftp_info where ftp_recv_time <= %ld";
  char sql[200];
  ACE_OS::snprintf(sql, 200, const_sql_template, (long)deadline);
  do_exec(sql);
}

bool MyClientDB::load_ftp_commands(MyDistInfoFtps * dist_ftps)
{
  if (unlikely(!dist_ftps))
    return false;
  const char * sql = "select ftp_dist_id, ftp_str, ftp_status, ftp_recv_time from tb_ftp_info";
  char *zErrMsg = 0;
  if (sqlite3_exec(m_db, sql, load_ftp_commands_callback, dist_ftps, &zErrMsg) != SQLITE_OK)
  {
    MY_ERROR("do_exec(sql=%s) failed, msg=%s\n", sql, zErrMsg);
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
    MY_ERROR("NULL dist_ftps parameter @load_ftp_commands_callback\n");
    return -1;
  }
  if (unlikely(argc != 4))
  {
    MY_ERROR("unexpected parameter number (=%d) @load_ftp_commands_callback\n", argc);
    return -1;
  }

  //ftp_dist_id, ftp_str, ftp_status, ftp_recv_time
  MyDistInfoFtp * dist_ftp = new MyDistInfoFtp();
  if (unlikely(!dist_ftp->load_from_string(argv[1])))
  {
    delete dist_ftp;
    return 0;
  }

  if (unlikely(!argv[2] || !*argv[2]))
  {
    delete dist_ftp;
    return 0;
  }
  dist_ftp->status = atoi(argv[2]);

  if (unlikely(!argv[3] || !*argv[3]))
  {
    delete dist_ftp;
    return 0;
  }
  dist_ftp->recv_time = atoi(argv[2]);

  if (unlikely(!dist_ftp->validate()))
  {
    delete dist_ftp;
    return 0;
  }

  dist_ftps->add(dist_ftp);
  return 0;
}



//MyFTPClient//

MyFTPClient::MyFTPClient(const std::string &remote_ip, const u_short remote_port,
                     const std::string &user_name, const std::string &pass_word)
{
  m_user_name = user_name;
  m_password = pass_word;
  m_remote_addr.set((u_short)remote_port, remote_ip.c_str());
  m_ftp_server_addr.init_from_string(remote_ip.c_str());
}

MyFTPClient::~MyFTPClient()
{
  m_peer.close_writer();
  m_peer.close_reader();
  m_peer.close();
}

bool MyFTPClient::download(const char * client_id, const char *remote_ip, const char *filename, const char * localfile)
{
  MyFTPClient ftp_client(remote_ip, 21, "root", "111111");
  if (!ftp_client.login())
    return false;
  MyPooledMemGuard ftp_file_name;
  ftp_file_name.init_from_string("compress_store/", client_id, "/", filename);
  if (!ftp_client.get_file(ftp_file_name.data(), localfile))
    return false;
  ftp_client.logout();
  return true;
}

bool MyFTPClient::recv()
{
  const int BUFF_SIZE = 2048;
  char line[BUFF_SIZE];
  int i = 0;
  ACE_Time_Value  tv(TIME_OUT_SECONDS);

  while (true)
  {
    char c;
    switch (m_peer.recv_n(&c, 1, &tv))
    {
    case   0:
    case  -1:
      return false;
    default:
      if (unlikely(i >= BUFF_SIZE - 2))
      {
        MY_ERROR("ftp unexpected too long response line from server %s\n", m_ftp_server_addr.data());
        return false;
      }
      line[i++] = c;
      break;
    }

    if ('\n' == c)
    {
      if (i < 3)
        return false;
      line[i] = 0;
      m_response.init_from_string(line);
      break;
    }
  }

  if (unlikely(!MyClientAppX::instance()->running()))
    return false;

  return true;
}

bool MyFTPClient::is_response(const char * res_code)
{
  return m_response.data() && (ACE_OS::memcmp(m_response.data(), res_code, 3) == 0);
}

bool MyFTPClient::send(const char * command)
{
  int cmd_len = ACE_OS::strlen(command);
  if (unlikely(cmd_len == 0))
    return true;
  if (unlikely(!MyClientAppX::instance()->running()))
    return false;

  ACE_Time_Value  tv(TIME_OUT_SECONDS);
  return (cmd_len == m_peer.send_n(command, cmd_len, &tv));
}

bool MyFTPClient::login()
{
  ACE_Time_Value  tv(TIME_OUT_SECONDS);
  const int CMD_BUFF_LEN = 2048;
  char command[CMD_BUFF_LEN];

  MY_INFO("ftp connecting to server %s\n", m_ftp_server_addr.data());

  if (this->m_connector.connect(m_peer, m_remote_addr, &tv) == -1)
  {
    MY_ERROR("ftp connecting to server %s failed %s\n", m_ftp_server_addr.data(), (const char *)MyErrno());
    return false;
  }

  if (!this->recv() || !is_response("220"))
  {
    MY_ERROR("ftp no/bad response after connecting to server %s\n", m_ftp_server_addr.data());
    return false;
  }

  ACE_OS::snprintf(command, CMD_BUFF_LEN, "USER %s\r\n", this->m_user_name.c_str());
  if (this->send(command))
  {
    if (!this->recv() || !is_response("331"))
    {
      MY_ERROR("ftp no/bad response on USER command to server %s\n", m_ftp_server_addr.data());
      return false;
    }
  }

  ACE_OS::snprintf(command, CMD_BUFF_LEN, "PASS %s\r\n", this->m_password.c_str());
  if (this->send(command))
  {
    if (!this->recv() || !is_response("230"))
    {
      MY_ERROR("ftp no/bad response on PASS command to server %s\n", m_ftp_server_addr.data());
      return false;
    }
  }

  MY_INFO("ftp authentication to server %s OK\n", m_ftp_server_addr.data());
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
  MyPooledMemGuard cwd;
  cwd.init_from_string("CWD ", dirname, "\r\n");
  if (this->send(cwd.data()))
  {
    if (!this->recv() || !is_response("250"))
    {
      MY_ERROR("ftp no/bad response on CWD command to server %s\n", m_ftp_server_addr.data());
      return false;
    }
  } else
    return false;

  if (this->send("PWD \r\n"))
  {
    if (!this->recv() || !is_response("257"))
    {
      MY_ERROR("ftp no/bad response on PWD command to server %s\n", m_ftp_server_addr.data());
      return false;
    }
  } else
    return false;

  return true;
}

bool MyFTPClient::get_file(const char *filename, const char * localfile)
{
  MY_ASSERT_RETURN(filename && *filename && localfile && *localfile, "", false);

  ACE_Time_Value  tv(TIME_OUT_SECONDS);
  int d0, d1, d2, d3, p0, p1;
  char ip[32];
  ACE_INET_Addr ftp_data_addr;

  ACE_SOCK_Stream     stream;
  ACE_SOCK_Connector  connector;

  ACE_FILE_IO file_put;
  ACE_FILE_Connector file_con;
  char file_cache[MAX_BUFSIZE];
  int file_size, all_size;

  if (this->send("PASV\r\n"))
  {
    if (!this->recv() || !is_response("227"))
    {
      MY_ERROR("ftp no/bad response on PASV command to server %s\n", m_ftp_server_addr.data());
      return false;
    }
  }

  char * ptr1 = ACE_OS::strrchr(m_response.data(), '(');
  char * ptr2 = NULL;
  if (ptr1)
    ptr2 = ACE_OS::strrchr(ptr1, ')');
  if (unlikely(!ptr1 || !ptr2))
  {
    MY_ERROR("ftp bad response data format on PASV command to server %s\n", m_ftp_server_addr.data());
    return false;
  }
  *ptr1 ++ = 0;
  *ptr2 = 0;

  if (sscanf(ptr1, "%d,%d,%d,%d,%d,%d", &d0, &d1, &d2, &d3, &p0, &p1) == -1)
  {
    MY_ERROR("ftp bad response address data format on PASV command to server %s\n", m_ftp_server_addr.data());
    return false;
  }
  snprintf(ip, 32, "%d.%d.%d.%d", d0, d1, d2, d3);
  ftp_data_addr.set((p0 << 8) + p1, ip);

  if (connector.connect(stream, ftp_data_addr, &tv) == -1)
  {
    MY_ERROR("ftp failed to establish data connection to server %s\n", m_ftp_server_addr.data());
    return false;
  }
  else
    MY_INFO("ftp establish data connection OK to server %s\n", m_ftp_server_addr.data());

  MyPooledMemGuard retr;
  retr.init_from_string("RETR ", filename, "\r\n");
  if (this->send(retr.data()))
  {
    if (!this->recv() || !is_response("150"))
    {
      MY_ERROR("ftp no/bad response on RETR command to server %s\n", m_ftp_server_addr.data());
      return false;
    }
  }

  tv.sec(TIME_OUT_SECONDS);
  if (file_con.connect(file_put, ACE_FILE_Addr(localfile), &tv, ACE_Addr::sap_any, 0, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR) == -1)
  {
    MY_ERROR("ftp failed to open local file %s to save download %s\n", localfile, (const char*)MyErrno());
    return false;
  }
  if (unlikely(!MyClientAppX::instance()->running()))
    return false;

  all_size = 0;
  tv.sec(TIME_OUT_SECONDS);
  while ((file_size = stream.recv(file_cache, sizeof(file_cache), &tv)) > 0)
  {
    if (unlikely(!MyClientAppX::instance()->running()))
      return false;

    if (unlikely(file_put.send_n(file_cache, file_size) != file_size))
    {
      MY_ERROR("ftp write to file %s failed %s\n", localfile, (const char*)MyErrno());
      return false;
    }
    all_size += file_size;
    tv.sec(TIME_OUT_SECONDS);
  }

  if (file_size < 0)
  {
    MY_ERROR("ftp read data for file %s from server %s failed %s\n", filename, m_ftp_server_addr.data(), (const char*)MyErrno());
    return false;
  }

//  if (!this->recv() || !is_response("226"))
//  {
//    MY_ERROR("ftp no/bad response after transfer of file completed from server %s\n", m_ftp_server_addr.data());
//    return false;
//  }

  MY_INFO("ftp downloaded file %s as %s size = %d\n", filename, localfile, all_size);
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
    return false;

  if (!type_is_valid(type))
    return false;

  if (aindex.data() && aindex.data()[0] && !(findex.data() && findex.data()[0]))
    return false;

  return (dist_id.data() && dist_id.data()[0]);
}

int MyDistInfoHeader::load_header_from_string(char * src)
{
  if (unlikely(!src))
    return -1;

  char * end = strchr(src, MyDataPacketHeader::FINISH_SEPARATOR);
  if (!end)
  {
    MY_ERROR("bad packet data @MyDistInfoHeader::load_from_string, no FINISH_SEPARATOR found\n");
    return false;
  }
  *end = 0;

  const char separator[2] = { MyDataPacketHeader::ITEM_SEPARATOR, 0 };
  MyStringTokenizer tk(src, separator);
  char * token = tk.get_token();
  if (unlikely(!token))
    return -1;
  else
    dist_id.init_from_string(token);

  token = tk.get_token();
  if (unlikely(!token))
    return -1;
  else
    findex.init_from_string(token);

  token = tk.get_token();
  if (unlikely(!token))
    return -1;
  else if (ACE_OS::strcmp(token, Null_Item) != 0)
    adir.init_from_string(token);

  token = tk.get_token();
  if (unlikely(!token))
    return -1;
  else if (ACE_OS::strcmp(token, Null_Item) != 0)
    aindex.init_from_string(token);

  token = tk.get_token();
  if (unlikely(!token))
    return -1;
  else if (ACE_OS::strcmp(token, Null_Item) != 0)
    ftype = *token;
  else
    return -1;

  token = tk.get_token();
  if (unlikely(!token))
    return -1;
  else if (ACE_OS::strcmp(token, Null_Item) != 0)
    type = *token;
  else
    return -1;

  return end - src + 1;
}

void MyDistInfoHeader::calc_target_parent_path(MyPooledMemGuard & target_parent_path, bool extract_only)
{
  ACE_UNUSED_ARG(extract_only); //todo: act according to extract_only

#ifdef MY_client_test
  MyClientApp::data_path(target_parent_path, client_id.as_string());
#else
  MyClientApp::data_path(target_parent_path);
#endif
}

bool MyDistInfoHeader::calc_target_path(const char * target_parent_path, MyPooledMemGuard & target_path)
{
  MY_ASSERT_RETURN(target_parent_path && *target_parent_path, "empty parameter target_parent_path\n", false);
  const char * sub_path;
  if (ftype_is_chn(ftype))
  {
    target_path.init_from_string(target_parent_path, "/index/", sub_path = adir.data());
    return true;
  }
  else if (ftype_is_adv(ftype))
    sub_path = "5";
  else if (ftype_is_led(ftype))
    sub_path = "7";
  else if (ftype_is_frame(ftype))
  {
    target_path.init_from_string(target_parent_path);
    return true;
  }
  else if (ftype_is_backgnd(ftype))
    sub_path = "8";
  else
  {
    MY_ERROR("invalid dist ftype = %c\n", ftype);
    return false;
  }

  target_path.init_from_string(target_parent_path, "/", sub_path);
  return true;
}



//MyDistInfoFtp//

MyDistInfoFtp::MyDistInfoFtp()
{
  failed_count = 0;
  last_update = time(NULL);
}

bool MyDistInfoFtp::validate()
{
  if (!super::validate())
    return false;

  if (status < 0 || status > 3)
    return false;
  const time_t long_time = 60 * 60 * 24 * 12 * 365; //one year
  time_t t = time(NULL);

  return recv_time < t + long_time && recv_time > t - long_time;
}

bool MyDistInfoFtp::load_from_string(char * src)
{
  if (unlikely(!src || !*src))
    return false;

  int data_len = ACE_OS::strlen(src);
  int header_len = load_header_from_string(src);
  if (header_len <= 0)
  {
    MY_ERROR("bad ftp file packet, no valid dist info\n");
    return false;
  }

  if (unlikely(header_len >= data_len))
  {
    MY_ERROR("bad ftp file packet, no valid file/password info\n");
    return false;
  }

  char * file_name = src + header_len;
  char * file_password = ACE_OS::strchr(file_name, MyDataPacketHeader::FINISH_SEPARATOR);
  if (unlikely(!file_password))
  {
    MY_ERROR("No filename/password found at dist ftp packet\n");
    return false;
  }
  *file_password++ = 0;
  this->file_name.init_from_string(file_name);

  if (unlikely(!*file_password))
  {
    MY_ERROR("No password found at dist ftp packet\n");
    return false;
  }
  this->file_password.init_from_string(file_password);
  return true;
};

time_t MyDistInfoFtp::get_delay_penalty() const
{
  return (time_t)(std::min(failed_count, (int)MAX_FAILED_COUNT) * 60 * FAILED_PENALTY);
}

bool MyDistInfoFtp::should_ftp(time_t now) const
{
  return status == 0 && last_update + get_delay_penalty() < now;
}

void MyDistInfoFtp::touch()
{
  last_update = time(NULL);
}

void MyDistInfoFtp::inc_failed()
{
  ++ failed_count;
}

void MyDistInfoFtp::calc_local_file_name()
{
  if (unlikely(local_file_name.data() != NULL))
    return;
  MyPooledMemGuard app_data_path;
#ifdef MY_client_test
  MyClientApp::data_path(app_data_path, client_id.as_string());
#else
  MyClientApp::data_path(app_data_path);
#endif
  local_file_name.init_from_string(app_data_path.data(), "/", dist_id.data(), ".mbz");
}


//MyDistInfoFtps//

MyDistInfoFtps::~MyDistInfoFtps()
{
  std::for_each(m_dist_info_ftps.begin(), m_dist_info_ftps.end(), MyObjectDeletor());
}

void MyDistInfoFtps::begin()
{
  m_current_ptr = m_dist_info_ftps.begin();
}

void MyDistInfoFtps::add(MyDistInfoFtp * p)
{
  if (unlikely(!p))
    return;
  ACE_MT(ACE_GUARD(ACE_Thread_Mutex, ace_mon, this->m_mutex));
  if (p->status > 1)
  {
    add_finished(p->dist_id.data());
    delete p;
    return;
  }
  m_dist_info_ftps.push_back(p);
}

void MyDistInfoFtps::add_finished(const char * dist_id)
{
  if (unlikely(!dist_id || !*dist_id))
    return;
  ACE_MT(ACE_GUARD(ACE_Thread_Mutex, ace_mon, this->m_mutex));
  m_finished_ftps.push_back(std::string(dist_id));
}

bool MyDistInfoFtps::finished(const char * dist_id)
{
  if (unlikely(!dist_id || !*dist_id))
    return true;
  ACE_MT(ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, false));
  MyDistInfoFtpFinishedListPtr ptr;
  for (ptr = m_finished_ftps.begin(); ptr != m_finished_ftps.end(); ++ptr)
    if (ptr->compare(dist_id) == 0)
      return true;
  return false;
}

MyDistInfoFtp * MyDistInfoFtps::get(time_t now)
{
  MyDistInfoFtp * result = NULL;
  for (; m_current_ptr != m_dist_info_ftps.end(); )
  {
    result = *m_current_ptr;
    if (result->should_ftp(now))
    {
      m_current_ptr = m_dist_info_ftps.erase(m_current_ptr);
      return result;
    } else
      ++m_current_ptr;
  }

  return NULL;
}


//MyDistFtpFileExtractor//

MyDistFtpFileExtractor::MyDistFtpFileExtractor()
{
  m_dist_info = NULL;
}

bool MyDistFtpFileExtractor::extract(MyDistInfoFtp * dist_info)
{
  MY_ASSERT_RETURN(dist_info, "parameter dist_info null pointer\n", false);
  dist_info->calc_local_file_name();

  MyPooledMemGuard target_parent_path;
  dist_info->calc_target_parent_path(target_parent_path, true);

  MyPooledMemGuard target_path;
  if (!dist_info->calc_target_path(target_parent_path.data(), target_path))
    return false;

  int prefix_len = ACE_OS::strlen(target_parent_path.data());
  if (!MyFilePaths::make_path_const(target_path.data(), prefix_len, false))
  {
    MY_ERROR("can not mkdir(%s) %s\n", target_path.data(), (const char *)MyErrno());
    return false;
  }

  MyBZCompressor c;
  bool result = c.decompress(dist_info->local_file_name.data(), target_path.data(), dist_info->file_password.data(), dist_info->aindex.data());
  if (result)
    MY_INFO("extract mbz ok: %s to %s\n", dist_info->local_file_name.data(), target_path.data());
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

MyFileMD5s & MyDistInfoMD5::md5list()
{
  return m_md5list;
}

bool MyDistInfoMD5::load_from_string(char * src)
{
  if (unlikely(!src || !*src))
    return false;

  int data_len = ACE_OS::strlen(src);
  int header_len = load_header_from_string(src);
  if (header_len <= 0)
  {
    MY_ERROR("bad md5 list packet, no valid dist info\n");
    return false;
  }

  if (unlikely(header_len >= data_len))
  {
    MY_ERROR("bad md5 list packet, no valid md5 list info\n");
    return false;
  }

  char * _md5_list = src + header_len;

  if (!m_md5list.from_buffer(_md5_list))
    return false;

  return m_md5list.count() > 0;
}

bool MyDistInfoMD5::validate()
{
  if (!super::validate())
    return false;

  return (m_md5list.count() > 0);
}


//MyDistInfoMD5s//

void MyDistInfoMD5s::add(MyDistInfoMD5 * p)
{
  if (unlikely(!p))
    return;

  ACE_MT(ACE_GUARD(ACE_Thread_Mutex, ace_mon, this->m_mutex));
  if (p->compare_done())
    m_dist_info_md5s_finished.push_back(p);
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



//MyDistInfoMD5Comparer//

bool MyDistInfoMD5Comparer::compute(MyDistInfoHeader * dist_info_header, MyFileMD5s & md5list)
{
  if (unlikely(!dist_info_header))
    return false;

  MyPooledMemGuard target_parent_path;
  dist_info_header->calc_target_parent_path(target_parent_path, false);

  MyPooledMemGuard target_path;
  if (!dist_info_header->calc_target_path(target_parent_path.data(), target_path))
    return false;

  int prefix_len = ACE_OS::strlen(target_parent_path.data());
  if (!MyFilePaths::make_path_const(target_path.data(), prefix_len, false))
  {
    MY_ERROR("can not mkdir(%s) %s\n", target_path.data(), (const char *)MyErrno());
    return false;
  }

  return md5list.calculate(target_path.data(), dist_info_header->aindex.data(),
         type_is_single(dist_info_header->type));
}

void MyDistInfoMD5Comparer::compare(MyDistInfoHeader * dist_info_header, MyFileMD5s & server_md5, MyFileMD5s & client_md5)
{
  if (unlikely(!dist_info_header))
    return;
  if (dist_info_header->aindex.data() && *dist_info_header->aindex.data())
  {
    MyMfileSplitter spl;
    spl.init(dist_info_header->aindex.data());
    server_md5.minus(client_md5, &spl, false);
  } else
    server_md5.minus(client_md5, NULL, false);
}



//MyClientToDistProcessor//

MyClientToDistProcessor::MyClientToDistProcessor(MyBaseHandler * handler): MyBaseClientProcessor(handler)
{
  m_version_check_reply_done = false;
}

int MyClientToDistProcessor::on_open()
{
  if (super::on_open() < 0)
    return -1;

#ifdef MY_client_test
  const char * myid = MyClientAppX::instance()->client_to_dist_module()->id_generator().get();
  if (!myid)
  {
    MY_ERROR(ACE_TEXT("can not fetch a test client id @MyClientToDistHandler::open\n"));
    return -1;
  }
  client_id(myid);
  m_client_id_index = MyClientAppX::instance()->client_id_table().index_of(myid);
  if (m_client_id_index < 0)
  {
    MY_ERROR("MyClientToDistProcessor::on_open() can not find client_id_index for id = %s\n", myid);
    return -1;
  }
  m_handler->connection_manager()->set_connection_client_id_index(m_handler, m_client_id_index, NULL);
#endif

  return send_version_check_req();
}

MyBaseProcessor::EVENT_RESULT MyClientToDistProcessor::on_recv_header()
{
  MyBaseProcessor::EVENT_RESULT result = super::on_recv_header();
  if (result != ER_CONTINUE)
    return ER_ERROR;

  bool bVersionCheckReply = m_packet_header.command == MyDataPacketHeader::CMD_CLIENT_VERSION_CHECK_REPLY; //m_version_check_reply_done
  if (bVersionCheckReply == m_version_check_reply_done)
  {
    MY_ERROR(ACE_TEXT("unexpected packet header from dist server, version_check_reply_done = %d, "
                      "packet is version_check_reply = %d.\n"), m_version_check_reply_done, bVersionCheckReply);
    return ER_ERROR;
  }

  if (bVersionCheckReply)
  {
    MyClientVersionCheckReplyProc proc;
    proc.attach((const char*)&m_packet_header);
    if (!proc.validate_header())
    {
      MY_ERROR("failed to validate header for version check\n");
      return ER_ERROR;
    }
    return ER_OK;
  }

  if (m_packet_header.command == MyDataPacketHeader::CMD_SERVER_FILE_MD5_LIST)
  {
    MyServerFileMD5ListProc proc;
    proc.attach((const char*)&m_packet_header);
    if (!proc.validate_header())
    {
      MY_ERROR("failed to validate header for server file md5 list\n");
      return ER_ERROR;
    }
    return ER_OK;
  }

  if (m_packet_header.command == MyDataPacketHeader::CMD_FTP_FILE)
  {
    MyFtpFileProc proc;
    proc.attach((const char*)&m_packet_header);
    if (!proc.validate_header())
    {
      MY_ERROR("failed to validate header for server ftp file\n");
      return ER_ERROR;
    }
    return ER_OK;
  }


  MY_ERROR("unexpected packet header from dist server, header.command = %d\n", m_packet_header.command);
  return ER_ERROR;
}

MyBaseProcessor::EVENT_RESULT MyClientToDistProcessor::on_recv_packet_i(ACE_Message_Block * mb)
{
  MyBasePacketProcessor::on_recv_packet_i(mb);
  MyDataPacketHeader * header = (MyDataPacketHeader *)mb->base();

  if (header->command == MyDataPacketHeader::CMD_CLIENT_VERSION_CHECK_REPLY)
  {
    MyBaseProcessor::EVENT_RESULT result = do_version_check_reply(mb);
    if (result == ER_OK)
    {
      ((MyClientToDistHandler*)m_handler)->setup_timer();
      client_id_verified(true);
    }
    return result;
  }

  if (header->command == MyDataPacketHeader::CMD_SERVER_FILE_MD5_LIST)
    return do_md5_list_request(mb);

  if (header->command == MyDataPacketHeader::CMD_FTP_FILE)
    return do_ftp_file_request(mb);

  MyMessageBlockGuard guard(mb);
  MY_ERROR("unsupported command received @MyClientToDistProcessor::on_recv_packet_i(), command = %d\n",
      header->command);
  return ER_ERROR;
}

int MyClientToDistProcessor::send_heart_beat()
{
  if (!m_version_check_reply_done)
    return 0;
  ACE_Message_Block * mb = MyMemPoolFactoryX::instance()->get_message_block(sizeof(MyDataPacketHeader), MyDataPacketHeader::CMD_HEARTBEAT_PING);
  int ret = (m_handler->send_data(mb) < 0? -1: 0);
//  MY_DEBUG("send_heart_beat = %d\n", ret);
  return ret;
}

MyBaseProcessor::EVENT_RESULT MyClientToDistProcessor::do_md5_list_request(ACE_Message_Block * mb)
{
  MyMessageBlockGuard guard(mb);
  MyDataPacketExt * packet = (MyDataPacketExt *) mb->base();
  if (!packet->guard())
  {
    MY_ERROR("empty md5 list packet %s\n");
    return ER_OK;
  }

  MyDistInfoMD5 * dist_md5 = new MyDistInfoMD5;
#ifdef MY_client_test
  dist_md5->client_id = m_client_id;
  dist_md5->client_id_index = m_client_id_index;
#endif
  if (dist_md5->load_from_string(packet->data))
  {
#ifdef MY_client_test
    MY_INFO("received one md5 file list command for dist %s, client_id=%s\n", dist_md5->dist_id.data(), m_client_id.as_string());
#endif
    bool added = false;
    if (MyClientAppX::instance()->client_to_dist_module()->service())
      added = MyClientAppX::instance()->client_to_dist_module()->service()->add_md5_task(dist_md5);
    if (!added)
      MyClientAppX::instance()->client_to_dist_module()->dist_info_md5s().add(dist_md5);
  }
  else
  {
    MY_ERROR("bad md5 file list command packet received\n");
    delete dist_md5;
  }

  return ER_OK;
}

MyBaseProcessor::EVENT_RESULT MyClientToDistProcessor::do_ftp_file_request(ACE_Message_Block * mb)
{
  MyMessageBlockGuard guard(mb);
  MyDataPacketExt * packet = (MyDataPacketExt *) mb->base();
  if (!packet->guard())
  {
    MY_ERROR("empty md5 list packet %s\n");
    return ER_OK;
  }

  {
    MyClientDBGuard dbg;
    if (dbg.db().open_db(m_client_id.as_string()))
      dbg.db().save_ftp_command(packet->data);
  }

  MyDistInfoFtp * dist_ftp = new MyDistInfoFtp();
  dist_ftp->status = 0;
#ifdef MY_client_test
  dist_ftp->client_id = m_client_id;
  dist_ftp->client_id_index = m_client_id_index;
#endif
  if (dist_ftp->load_from_string(packet->data))
  {
    MY_INFO("received one ftp command for dist %s: password = %s, file name = %s\n",
            dist_ftp->dist_id.data(), dist_ftp->file_password.data(), dist_ftp->file_name.data());
    bool added = false;
    if (MyClientAppX::instance()->client_to_dist_module()->client_ftp_service())
      added = MyClientAppX::instance()->client_to_dist_module()->client_ftp_service()->add_ftp_task(dist_ftp);
    if (!added)
      MyClientAppX::instance()->client_to_dist_module()->dist_info_ftps().add(dist_ftp);
  }
  else
  {
    MY_ERROR("bad ftp command packet received\n");
    delete dist_ftp;
  }

  return ER_OK;
}

MyBaseProcessor::EVENT_RESULT MyClientToDistProcessor::do_version_check_reply(ACE_Message_Block * mb)
{
  MyMessageBlockGuard guard(mb);
  m_version_check_reply_done = true;

  const char * prefix_msg = "dist server version check reply:";
  MyClientVersionCheckReplyProc vcr;
  vcr.attach(mb->base());
  switch (vcr.data()->reply_code)
  {
  case MyClientVersionCheckReply::VER_OK:
 //   MY_INFO("%s OK\n", prefix_msg);
    return MyBaseProcessor::ER_OK;

  case MyClientVersionCheckReply::VER_OK_CAN_UPGRADE:
    MY_INFO("%s get version can upgrade response\n", prefix_msg);
    //todo: notify app to upgrade
    return MyBaseProcessor::ER_OK;

  case MyClientVersionCheckReply::VER_MISMATCH:
    MY_ERROR("%s get version mismatch response\n", prefix_msg);
    //todo: notify app to upgrade
    return MyBaseProcessor::ER_ERROR;

  case MyClientVersionCheckReply::VER_ACCESS_DENIED:
    MY_ERROR("%s get access denied response\n", prefix_msg);
    return MyBaseProcessor::ER_ERROR;

  case MyClientVersionCheckReply::VER_SERVER_BUSY:
    MY_ERROR("%s get server busy response\n", prefix_msg);
    return MyBaseProcessor::ER_ERROR;

  default: //server_list
    MY_ERROR("%s get unknown reply code = %d\n", prefix_msg, vcr.data()->reply_code);
    return MyBaseProcessor::ER_ERROR;
  }

}

int MyClientToDistProcessor::send_version_check_req()
{
  ACE_Message_Block * mb = make_version_check_request_mb();
  MyClientVersionCheckRequestProc proc;
  proc.attach(mb->base());
  proc.data()->client_version = const_client_version;
  proc.data()->client_id = m_client_id;
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
  m_addr_list.init_from_string(list);
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
      MY_WARNING("skipping invalid dist server addr: %s\n", token);
    else
    {
      MY_INFO("adding dist server addr: %s\n", token);
      m_server_addrs.push_back(token);
    }
  }

  if (!ftp_list || !*ftp_list)
  {
    MY_ERROR("not ftp server addr list found\n");
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
      MY_WARNING("skipping invalid ftp server addr: %s\n", token);
    else
    {
      MY_INFO("adding ftp server addr: %s\n", token);
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
  MyUnixHandleGuard f;
  MyPooledMemGuard file_name;
  get_file_name(file_name);
  if (!f.open_write(file_name.data(), true, true, false))
    return;
  if (::write(f.handle(), m_addr_list.data(), m_addr_list_len) != m_addr_list_len)
    MY_ERROR("write to file %s failed %s\n", file_name.data(), (const char*)MyErrno());
}

void MyDistServerAddrList::load()
{
  MyUnixHandleGuard f;
  MyPooledMemGuard file_name;
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

void MyDistServerAddrList::get_file_name(MyPooledMemGuard & file_name)
{
  const char * const_file_name = "/config/servers.lst";
  file_name.init_from_string(MyConfigX::instance()->app_path.c_str(), const_file_name);
}

bool MyDistServerAddrList::valid_addr(const char * addr) const
{
  struct in_addr ia;
  return (::inet_pton(AF_INET, addr, &ia) == 1);
}


//MyClientToDistHandler//

MyClientToDistHandler::MyClientToDistHandler(MyBaseConnectionManager * xptr): MyBaseHandler(xptr)
{
  m_processor = new MyClientToDistProcessor(this);
  m_heat_beat_ping_timer_id = -1;
}

void MyClientToDistHandler::setup_timer()
{
//  MY_DEBUG("MyClientToDistHandler scheduling timer...\n");
  ACE_Time_Value interval (MyConfigX::instance()->client_heart_beat_interval);
  m_heat_beat_ping_timer_id = reactor()->schedule_timer(this, (void*)HEART_BEAT_PING_TIMER, interval, interval);
  if (m_heat_beat_ping_timer_id < 0)
    MY_ERROR(ACE_TEXT("MyClientToDistHandler setup heart beat timer failed, %s"), (const char*)MyErrno());
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
//  MY_DEBUG("MyClientToDistHandler::handle_timeout()\n");
  if (long(act) == HEART_BEAT_PING_TIMER)
    return ((MyClientToDistProcessor*)m_processor)->send_heart_beat();
  else
  {
    MY_ERROR("unexpected timer call @MyClientToDistHandler::handle_timeout, timer id = %d\n", long(act));
    return 0;
  }
}

void MyClientToDistHandler::on_close()
{
  if (m_heat_beat_ping_timer_id >= 0)
    reactor()->cancel_timer(m_heat_beat_ping_timer_id);

#ifdef MY_client_test
  if (m_connection_manager->locked())
    return;
  MyClientAppX::instance()->client_to_dist_module()->id_generator().put
      (
        ((MyClientToDistProcessor*)m_processor)->client_id().as_string()
      );
#endif
}

PREPARE_MEMORY_POOL(MyClientToDistHandler);


//MyClientToDistService//

MyClientToDistService::MyClientToDistService(MyBaseModule * module, int numThreads):
    MyBaseService(module, numThreads)
{
  msg_queue()->high_water_mark(MSG_QUEUE_MAX_SIZE);
}

int MyClientToDistService::svc()
{
  MY_INFO(ACE_TEXT ("running %s::svc()\n"), name());

  for (ACE_Message_Block *mb; getq(mb) != -1;)
  {
    int task_type;
    void * p;
    {
      MyMessageBlockGuard guard(mb);
      p = get_task(mb, task_type);
    }

    if (unlikely(!p))
    {
      MY_ERROR("null pointer get @%s::get_task(mb)\n", name());
      continue;
    }

    if (task_type == TASK_MD5)
      do_md5_task((MyDistInfoMD5 *)p);
    else
      MY_ERROR("unknown task type = %d @%s::svc()\n", task_type, name());
  }

  MY_INFO(ACE_TEXT ("exiting %s::svc()\n"), name());
  return 0;
}

const char * MyClientToDistService::name() const
{
  return "MyClientToDistService";
}

bool MyClientToDistService::add_md5_task(MyDistInfoMD5 * p)
{
  return do_add_task(p, TASK_MD5);
}

void MyClientToDistService::do_md5_task(MyDistInfoMD5 * p)
{
  if (unlikely(!p || p->compare_done()))
  {
    delete p;
    return;
  }

  MyFileMD5s client_md5s;
  if (!MyDistInfoMD5Comparer::compute(p, client_md5s))
    MY_INFO("md5 file list generation error\n");

  MyDistInfoMD5Comparer::compare(p, p->md5list(), client_md5s);
  post_md5_list_message(p);
  delete p;
}

void MyClientToDistService::post_md5_list_message(MyDistInfoMD5 * dist_md5) const
{
  int dist_id_len = ACE_OS::strlen(dist_md5->dist_id.data());
  int md5_len = dist_md5->md5list().total_size(false);
  int total_len = sizeof(MyDataPacketHeader) + dist_id_len + 1 + md5_len;
  ACE_Message_Block * mb = MyMemPoolFactoryX::instance()->get_message_block(total_len, MyDataPacketHeader::CMD_SERVER_FILE_MD5_LIST);
  MyDataPacketExt * dpe = (MyDataPacketExt*) mb->base();
#ifdef MY_client_test
  dpe->magic = dist_md5->client_id_index;
#endif
  ACE_OS::memcpy(dpe->data, dist_md5->dist_id.data(), dist_id_len);
  dpe->data[dist_id_len] = MyDataPacketHeader::ITEM_SEPARATOR;
  dist_md5->md5list().to_buffer(dpe->data + dist_id_len + 1, md5_len, false);
  MyClientAppX::instance()->send_mb_to_dist(mb);
}



void MyClientToDistService::do_server_file_md5_list(ACE_Message_Block * mb)
{
  MyMessageBlockGuard guard(mb);
/*
  MyServerFileMD5ListProc proc;
  proc.attach(mb->base());
  const char * client_path;

#ifdef MY_client_test
  MyClientID client_id;

  if (!MyClientAppX::instance()->client_id_table().value(proc.data()->magic, &client_id))
  {
    MY_ERROR("can not find client_id @MyClientToDistService::do_server_file_md5_list(), index = %d\n",
        proc.data()->magic);
    return;
  }

//  MY_DEBUG("do_server_file_md5_list: client_id =%s\n", client_id.as_string());

  char client_path_by_id[PATH_MAX];
  ACE_OS::strsncpy(client_path_by_id, MyConfigX::instance()->app_test_data_path.c_str(), PATH_MAX);
  int len = ACE_OS::strlen(client_path_by_id);
  if (unlikely(len + sizeof(MyClientID) + 10 > PATH_MAX))
  {
    MY_ERROR("name too long for client sub path\n");
    return;
  }
  client_path_by_id[len++] = '/';
  client_path_by_id[len] = '0';
  MyTestClientPathGenerator::client_id_to_path(client_id.as_string(), client_path_by_id + len, PATH_MAX - 1 - len);
  client_path = client_path_by_id;
#else
  //todo: calculate client path here
#endif
  MyFileMD5s md5s_server;
  md5s_server.base_dir(client_path);
  md5s_server.from_buffer(proc.data()->data);

  MyFileMD5s md5s_client;
  md5s_client.calculate(client_path, NULL, false);
  md5s_client.sort();

  md5s_server.minus(md5s_client);
  int buff_size = md5s_server.total_size(false);

//  MyPooledMemGuard mem_guard;
//  if (!MyMemPoolFactoryX::instance()->get_mem(buff_size, &mem_guard))
//  {
//    MY_ERROR("can not alloc output memory of size = %d @%s::do_server_file_md5_list()\n", buff_size, name());
//    return;
//  }
//  if (md5s_server.to_buffer(mem_guard.data(), buff_size, false))
//    MY_INFO("dist files by md5 for client_id: [%s] = %s\n", client_id.as_string(), mem_guard.data());

  ACE_Message_Block * reply_mb = MyMemPoolFactoryX::instance()->get_message_block(sizeof(MyServerFileMD5List) + buff_size);
  MyServerFileMD5ListProc vcr;
  vcr.attach(reply_mb->base());
  vcr.init_header();
  vcr.data()->length = sizeof(MyServerFileMD5List) + buff_size;
#ifdef MY_client_test
  vcr.data()->magic = proc.data()->magic;
#endif
  reply_mb->wr_ptr(reply_mb->capacity());
  if (!md5s_server.to_buffer(vcr.data()->data, buff_size, false))
  {
    MY_ERROR("md5 file list .to_buffer() failed\n");
    reply_mb->release();
  } else
  {
    MY_INFO("sending md5 file list to dist server for client_id [%s]: = %s\n", client_id.as_string(), vcr.data()->data);
    ACE_Time_Value tv(ACE_Time_Value::zero);
    if (((MyClientToDistModule*)module_x())->dispatcher()->putq(reply_mb, &tv) == -1)
    {
      MY_ERROR("failed to send md5 file list to dispatcher target queue\n");
      reply_mb->release();
    }
  }*/
}


//MyClientFtpService//

MyClientFtpService::MyClientFtpService(MyBaseModule * module, int numThreads):
    MyBaseService(module, numThreads)
{

}

int MyClientFtpService::svc()
{
  static bool bprinted = false;
  if (!bprinted)
  {
    MY_INFO(ACE_TEXT ("running %s::svc()\n"), name());
    bprinted = true;
  }
  std::string server_addr = ((MyClientToDistModule*)module_x())->server_addr_list().begin_ftp();
  int failed_count = 0;

  for (ACE_Message_Block *mb; getq(mb) != -1;)
  {
    int task_type;
    void * p;
    {
      MyMessageBlockGuard guard(mb);
      p = get_task(mb, task_type);
    }

    if (unlikely(!p))
    {
      MY_ERROR("null pointer get @%s::get_task(mb)\n", name());
      continue;
    }

    if (task_type == TASK_FTP)
      do_ftp_task((MyDistInfoFtp *)p, server_addr, failed_count);
    else
      MY_ERROR("unknown task type = %d @%s::svc()\n", task_type, name());
  }

  if (bprinted)
  {
    MY_INFO(ACE_TEXT ("exiting %s::svc()\n"), name());
    bprinted = false;
  }
  return 0;
}

void MyClientFtpService::do_ftp_task(MyDistInfoFtp * dist_info, std::string & server_addr, int & failed_count)
{
  if (dist_info->status == 0)
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

  if (dist_info->status == 1)
  {
    dist_info->status = do_extract_file(dist_info) ? 2:3;
    MyClientDBGuard dbg;
    if (dbg.db().open_db(dist_info->client_id.as_string()))
      dbg.db().set_ftp_command_status(dist_info->dist_id.data(), dist_info->status);
  }

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

void MyClientFtpService::post_ftp_status_message(MyDistInfoFtp * dist_info) const
{
  int dist_id_len = ACE_OS::strlen(dist_info->dist_id.data());
  int total_len = sizeof(MyDataPacketHeader) + dist_id_len + 1 + 2;
  ACE_Message_Block * mb = MyMemPoolFactoryX::instance()->get_message_block(total_len, MyDataPacketHeader::CMD_FTP_FILE);
  MyDataPacketExt * dpe = (MyDataPacketExt*) mb->base();
#ifdef MY_client_test
  dpe->magic = dist_info->client_id_index;
#endif
  ACE_OS::memcpy(dpe->data, dist_info->dist_id.data(), dist_id_len);
  dpe->data[dist_id_len] = MyDataPacketHeader::ITEM_SEPARATOR;
  dpe->data[dist_id_len + 1] = (dist_info->status == 0? '0': '1');
  dpe->data[dist_id_len + 2] = 0;
  MyClientAppX::instance()->send_mb_to_dist(mb);
}

bool MyClientFtpService::do_ftp_download(MyDistInfoFtp * dist_info, const char * server_ip)
{
  if (unlikely(dist_info->status > 0))
    return true;

  MY_INFO("processing ftp download for dist_id=%s, filename=%s, password=%s\n",
      dist_info->dist_id.data(), dist_info->file_name.data(), dist_info->file_password.data());
  dist_info->calc_local_file_name();
  bool result = MyFTPClient::download(dist_info->dist_id.data(), server_ip, dist_info->file_name.data(), dist_info->local_file_name.data());
  dist_info->touch();
  if (result)
  {
    dist_info->status = 1;
    MyClientDBGuard dbg;
    if (dbg.db().open_db(dist_info->client_id.as_string()))
      dbg.db().set_ftp_command_status(dist_info->dist_id.data(), 1);
    post_ftp_status_message(dist_info);
  }
  else
    dist_info->inc_failed();
  return result;
}

bool MyClientFtpService::do_extract_file(MyDistInfoFtp * p)
{
  MyDistFtpFileExtractor extractor;
  return extractor.extract(p);
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

MyClientToDistConnector::MyClientToDistConnector(MyBaseDispatcher * _dispatcher, MyBaseConnectionManager * _manager):
    MyBaseConnector(_dispatcher, _manager)
{
  m_tcp_port = MyConfigX::instance()->dist_server_heart_beat_port;
  m_reconnect_interval = RECONNECT_INTERVAL;
#ifdef MY_client_test
  m_num_connection = MyConfigX::instance()->test_client_connection_number;
#endif
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

int MyClientToDistConnector::make_svc_handler(MyBaseHandler *& sh)
{
  sh = new MyClientToDistHandler(m_connection_manager);
  if (!sh)
  {
    MY_ERROR("can not alloc MyClientToDistHandler from %s\n", name());
    return -1;
  }
//  MY_DEBUG("MyClientToDistConnector::make_svc_handler(%X)...\n", long(sh));
  sh->parent((void*)this);
  sh->reactor(reactor());
  return 0;
}

bool MyClientToDistConnector::before_reconnect()
{
  if (m_reconnect_retry_count <= 3)
    return true;

  MyDistServerAddrList & addr_list = ((MyClientToDistModule*)(m_module))->server_addr_list();
  const char * new_addr = addr_list.next();
  if (!new_addr || !*new_addr)
    new_addr = addr_list.begin();
  if (new_addr && *new_addr)
  {
    if (ACE_OS::strcmp("127.0.0.1", new_addr) == 0)
      new_addr = MyConfigX::instance()->middle_server_addr.c_str();
    MY_INFO("maximum connect to %s:%d retry count reached , now trying next addr %s:%d...\n",
        m_tcp_addr.c_str(), m_tcp_port, new_addr, m_tcp_port);
    m_tcp_addr = new_addr;
    m_reconnect_retry_count = 1;
  }
  return true;
}


//MyClientToDistDispatcher//

MyClientToDistDispatcher::MyClientToDistDispatcher(MyBaseModule * pModule, int numThreads):
    MyBaseDispatcher(pModule, numThreads)
{
  m_connector = NULL;
  m_middle_connector = NULL;
  m_clock_interval = FTP_CHECK_INTERVAL * 60;
}

MyClientToDistDispatcher::~MyClientToDistDispatcher()
{

}

bool MyClientToDistDispatcher::on_start()
{
  m_middle_connector = new MyClientToMiddleConnector(this, new MyBaseConnectionManager());
  add_connector(m_middle_connector);
  return true;
}

const char * MyClientToDistDispatcher::name() const
{
  return "MyClientToDistDispatcher";
}


int MyClientToDistDispatcher::handle_timeout(const ACE_Time_Value &, const void *)
{
  ((MyClientToDistModule*)module_x())->check_ftp_timed_task();
  return 0;
}

void MyClientToDistDispatcher::ask_for_server_addr_list_done(bool success)
{
  m_middle_connector->finish();
  MyDistServerAddrList & addr_list = ((MyClientToDistModule*)m_module)->server_addr_list();
  if (!success)
  {
    MY_INFO("failed to get any dist server addr from middle server, trying local cache...\n");
    addr_list.load();
  }

  if (addr_list.empty())
  {
    MY_ERROR("no dist server addresses exist @%s\n", name());
    return;
  }

  MY_INFO("starting connection to dist server from addr list...\n");
  if (!m_connector)
    m_connector = new MyClientToDistConnector(this, new MyBaseConnectionManager());
  add_connector(m_connector);
  const char * addr = addr_list.begin();
  if (ACE_OS::strcmp("127.0.0.1", addr) == 0)
        addr = MyConfigX::instance()->middle_server_addr.c_str();
  m_connector->dist_server_addr(addr);
  m_connector->start();
}

void MyClientToDistDispatcher::on_stop()
{
  m_connector = NULL;
  m_middle_connector = NULL;
}

bool MyClientToDistDispatcher::on_event_loop()
{
  ACE_Message_Block * mb;
  const int const_batch_count = 10;
  for (int i = 0; i < const_batch_count; ++ i)
  {
    ACE_Time_Value tv(ACE_Time_Value::zero);
    if (this->getq(mb, &tv) != -1)
    {
#ifdef MY_client_test
      int index = ((MyDataPacketHeader*)mb->base())->magic;
      MyBaseHandler * handler = m_connector->connection_manager()->find_handler_by_index(index);
      if (!handler)
      {
        MY_WARNING("can not send data to client since connection is lost @ %s::on_event_loop\n", name());
        mb->release();
        continue;
      }

      ((MyDataPacketHeader*)mb->base())->magic = MyDataPacketHeader::DATAPACKET_MAGIC;
      if (handler->send_data(mb) < 0)
        handler->handle_close();
#else
      m_connector->connection_manager()->send_single(mb);
#endif
    } else
      break;
  }
  return true;
}


//MyClientToDistModule//

MyClientToDistModule::MyClientToDistModule(MyBaseApp * app): MyBaseModule(app)
#ifdef MY_client_test
   , m_id_generator(MyConfigX::instance()->test_client_start_client_id,
                    MyConfigX::instance()->test_client_connection_number)
#endif
{
  m_service = NULL;
  m_dispatcher = NULL;
  m_client_ftp_service = NULL;
}

MyClientToDistModule::~MyClientToDistModule()
{

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
#ifdef MY_client_test
  add_service(m_client_ftp_service = new MyClientFtpService(this, MyConfigX::instance()->test_client_ftp_thread_number));
#else
  add_service(m_client_ftp_service = new MyClientFtpService(this, 1));
#endif
  m_client_ftp_service->start();
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

  MyDistInfoFtp * p;
  ACE_MT(ACE_GUARD(ACE_Thread_Mutex, ace_mon, m_dist_info_ftps.m_mutex));
  m_dist_info_ftps.begin();
  time_t now = time(NULL);
  while ((p = m_dist_info_ftps.get(now)) != NULL)
  {
    if (!m_client_ftp_service->add_ftp_task(p))
    {
      m_dist_info_ftps.add(p);
      return;
    }
  }
}

bool MyClientToDistModule::on_start()
{
  add_service(m_service = new MyClientToDistService(this, 1));
  add_dispatcher(m_dispatcher = new MyClientToDistDispatcher(this));
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


/////////////////////////////////////
//client to middle
/////////////////////////////////////

//MyClientToMiddleProcessor//

MyClientToMiddleProcessor::MyClientToMiddleProcessor(MyBaseHandler * handler): MyBaseClientProcessor(handler)
{

}

int MyClientToMiddleProcessor::on_open()
{
  if (super::on_open() < 0)
    return -1;

#ifdef MY_client_test
  MyTestClientIDGenerator & id_generator = MyClientAppX::instance()->client_to_dist_module()->id_generator();
  const char * myid = id_generator.get();
  if (!myid)
  {
    MY_ERROR(ACE_TEXT("can not fetch a test client id @MyClientToDistHandler::open\n"));
    return -1;
  }
  client_id(myid);
  m_client_id_index = MyClientAppX::instance()->client_id_table().index_of(myid);
  if (m_client_id_index < 0)
  {
    MY_ERROR("MyClientToDistProcessor::on_open() can not find client_id_index for id = %s\n", myid);
    return -1;
  }
  m_handler->connection_manager()->set_connection_client_id_index(m_handler, m_client_id_index, NULL);
  id_generator.put(myid);
#endif

  return send_version_check_req();
}

MyBaseProcessor::EVENT_RESULT MyClientToMiddleProcessor::on_recv_header()
{
  MyBaseProcessor::EVENT_RESULT result = super::on_recv_header();
  if (result != ER_CONTINUE)
    return ER_ERROR;

  bool bVersionCheckReply = m_packet_header.command == MyDataPacketHeader::CMD_CLIENT_VERSION_CHECK_REPLY;

  if (bVersionCheckReply)
  {
    MyClientVersionCheckReplyProc proc;
    proc.attach((const char*)&m_packet_header);
    if (!proc.validate_header())
    {
      MY_ERROR("failed to validate header for version check reply\n");
      return ER_ERROR;
    }
    return ER_OK;
  }

  MY_ERROR("unexpected packet header from dist server, header.command = %d\n", m_packet_header.command);
  return ER_ERROR;
}

MyBaseProcessor::EVENT_RESULT MyClientToMiddleProcessor::on_recv_packet_i(ACE_Message_Block * mb)
{
  MyBasePacketProcessor::on_recv_packet_i(mb);
  m_wait_for_close = true;
  MyMessageBlockGuard guard(mb);

  MyDataPacketHeader * header = (MyDataPacketHeader *)mb->base();
  if (header->command == MyDataPacketHeader::CMD_CLIENT_VERSION_CHECK_REPLY)
    do_version_check_reply(mb);
  else
    MY_ERROR("unsupported command received @MyClientToDistProcessor::on_recv_packet_i(), command = %d\n",
        header->command);
  return ER_ERROR;
}

void MyClientToMiddleProcessor::do_version_check_reply(ACE_Message_Block * mb)
{
  const char * prefix_msg = "middle server version check reply:";
  MyClientVersionCheckReplyProc vcr;
  vcr.attach(mb->base());
  switch (vcr.data()->reply_code)
  {
  case MyClientVersionCheckReply::VER_MISMATCH:
    MY_ERROR("%s get version mismatch response\n", prefix_msg);
    return;

  case MyClientVersionCheckReply::VER_ACCESS_DENIED:
    MY_ERROR("%s get access denied response\n", prefix_msg);
    return;

  case MyClientVersionCheckReply::VER_SERVER_BUSY:
    MY_ERROR("%s get server busy response\n", prefix_msg);
    return;

  case MyClientVersionCheckReply::VER_SERVER_LIST:
    do_handle_server_list(mb);
    return;

  default:
    MY_ERROR("%s get unexpected reply code = %d\n", prefix_msg, vcr.data()->reply_code);
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
    MY_WARNING("middle server returns empty dist server addr list\n");
    module->ask_for_server_addr_list_done(false);
    return;
  }
  ((char*)vcr)[len - 1] = 0;
  MY_INFO("middle server returns dist server addr list as: %s\n", vcr->data);
  module->server_addr_list().addr_list(vcr->data);
  module->server_addr_list().save();
  module->ask_for_server_addr_list_done(true);
}

int MyClientToMiddleProcessor::send_version_check_req()
{
  ACE_Message_Block * mb = make_version_check_request_mb();
  MyClientVersionCheckRequestProc proc;
  proc.attach(mb->base());
  proc.data()->client_version = const_client_version;
  proc.data()->client_id = m_client_id;
  MY_INFO("sending handshake request to middle server...\n");
  return (m_handler->send_data(mb) < 0? -1: 0);
}


//MyClientToMiddleHandler//

MyClientToMiddleHandler::MyClientToMiddleHandler(MyBaseConnectionManager * xptr): MyBaseHandler(xptr)
{
  m_processor = new MyClientToMiddleProcessor(this);
  m_timer_out_timer_id = -1;
}

void MyClientToMiddleHandler::setup_timer()
{
  ACE_Time_Value interval (MyConfigX::instance()->client_heart_beat_interval);
  m_timer_out_timer_id = reactor()->schedule_timer(this, (void*)TIMER_OUT_TIMER, interval, interval);
  if (m_timer_out_timer_id < 0)
    MY_ERROR(ACE_TEXT("MyClientToDistHandler setup heart beat timer failed, %s"), (const char*)MyErrno());
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
  if (long(act) != TIMER_OUT_TIMER)
    MY_ERROR("unexpected timer call @MyClientToMiddleHandler::handle_timeout, timer id = %d\n", long(act));
  return handle_close();
}

void MyClientToMiddleHandler::on_close()
{

}

PREPARE_MEMORY_POOL(MyClientToMiddleHandler);


//MyClientToMiddleConnector//

MyClientToMiddleConnector::MyClientToMiddleConnector(MyBaseDispatcher * _dispatcher, MyBaseConnectionManager * _manager):
    MyBaseConnector(_dispatcher, _manager)
{
  m_tcp_port = MyConfigX::instance()->middle_server_client_port;
  m_tcp_addr = MyConfigX::instance()->middle_server_addr;
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

int MyClientToMiddleConnector::make_svc_handler(MyBaseHandler *& sh)
{
  sh = new MyClientToMiddleHandler(m_connection_manager);
  if (!sh)
  {
    MY_ERROR("can not alloc MyClientToMiddleHandler from %s\n", name());
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

  finish();
  MyClientAppX::instance()->client_to_dist_module()->ask_for_server_addr_list_done(false);
  return false;
}
