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

bool MyClientDB::open_db(const char * client_id)
{
  ACE_UNUSED_ARG(client_id);
  return true;
}

void MyClientDB::close_db()
{

}

bool MyClientDB::save_ftp_command(const char * ftp_command)
{
  ACE_UNUSED_ARG(ftp_command);
  return true;
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

int MyDistInfoHeader::load_header_from_string(char * src)
{
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

  return end - src + 1;
}


//MyDistInfoFtp//

MyDistInfoFtp::MyDistInfoFtp()
{
  failed_count = 0;
  last_update = time(NULL);
}

bool MyDistInfoFtp::load_from_string(char * src)
{
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
  m_dist_info_ftps.push_back(p);
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
  {
    ACE_Time_Value tv(ACE_Time_Value::zero);
    if (((MyClientToDistHandler*)m_handler)->module_x()->service()->putq(mb, &tv) == -1)
    {
      MY_ERROR("failed to put server file md5 list message to service queue.\n");
      mb->release();
    }
    return ER_OK;
  }

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
  ACE_Message_Block * mb = MyMemPoolFactoryX::instance()->get_message_block(sizeof(MyDataPacketHeader));
  MyHeartBeatPingProc proc;
  proc.attach(mb->base());
  proc.init_header();
  mb->wr_ptr(sizeof(MyDataPacketHeader));
  int ret = (m_handler->send_data(mb) < 0? -1: 0);
//  MY_DEBUG("send_heart_beat = %d\n", ret);
  return ret;
}

MyBaseProcessor::EVENT_RESULT MyClientToDistProcessor::do_ftp_file_request(ACE_Message_Block * mb)
{
  MyMessageBlockGuard guard(mb);
  MyFtpFile * ftp_file = (MyFtpFile *) mb->base();
  int data_len = ftp_file->length - sizeof(MyFtpFile);
  ftp_file->data[data_len - 1] = 0;


  MyDistInfoFtp * dist_ftp = new MyDistInfoFtp();
#ifdef MY_client_test
  dist_ftp->client_id = m_client_id;
#endif
  if (dist_ftp->load_from_string(ftp_file->data))
    MY_INFO("recieved one ftp command for dist %s: password = %s, file name = %s\n",
            dist_ftp->dist_id.data(), dist_ftp->file_password.data(), dist_ftp->file_name.data());
  else
    MY_ERROR("bad ftp command packet received\n");
  MyClientAppX::instance()->client_to_dist_module()->dist_info_ftps().add(dist_ftp);

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
    MyDataPacketBaseProc proc;
    proc.attach(mb->base());
    if (proc.data()->command == MyDataPacketHeader::CMD_SERVER_FILE_MD5_LIST)
    {
      do_server_file_md5_list(mb);
      continue;
    }

    MY_ERROR("unexpected message block type @MyClientToDistService::svc()\n");
    mb->release();
  }

  MY_INFO(ACE_TEXT ("exiting %s::svc()\n"), name());
  return 0;
}

const char * MyClientToDistService::name() const
{
  return "MyClientToDistService";
}

void MyClientToDistService::do_server_file_md5_list(ACE_Message_Block * mb)
{
  MyMessageBlockGuard guard(mb);

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
  }
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
    if (!do_ftp_download(mb, server_addr.c_str()))
    {
      if (++ failed_count > 3)
      {
        failed_count = 0;
        const char * p = ((MyClientToDistModule*)module_x())->server_addr_list().next_ftp();
        if (p)
          server_addr = p;
        else
          server_addr = ((MyClientToDistModule*)module_x())->server_addr_list().begin_ftp();
      }
    }
  }

  if (bprinted)
  {
    MY_INFO(ACE_TEXT ("exiting %s::svc()\n"), name());
    bprinted = false;
  }
  return 0;
}

const char * MyClientFtpService::name() const
{
  return "MyClientFtpService";
}

bool MyClientFtpService::add_ftp_task(MyDistInfoFtp * p)
{
  if (unlikely(!p))
    return true;

  ACE_Message_Block * mb = MyMemPoolFactoryX::instance()->get_message_block(sizeof(void *));
  *(MyDistInfoFtp **)mb->base() = p;

  ACE_Time_Value tv(ACE_Time_Value::zero);
  if (putq(mb, &tv) < 0)
  {
    MY_ERROR("failed to place ftp command packet to %s %s", name(), (const char*)MyErrno());
    return false;
  } else
    return true;
}

bool MyClientFtpService::do_ftp_download(ACE_Message_Block * mb, const char * server_ip)
{
  MyMessageBlockGuard guard(mb);
  MyDistInfoFtp * p = *((MyDistInfoFtp **)mb->base());
  if (unlikely(!server_ip || !*server_ip))
  {
    ((MyClientToDistModule*)module_x())->dist_info_ftps().add(p);
    return false;
  }

  MY_INFO("processing ftp download for dist_id=%s, filename=%s, password=%s\n",
      p->dist_id.data(), p->file_name.data(), p->file_password.data());
  MyPooledMemGuard local_file_name, app_data_path;
#ifdef MY_client_test
  MyClientApp::data_path(app_data_path, p->client_id.as_string());
#else
  MyClientApp::data_path(app_data_path);
#endif
  local_file_name.init_from_string(app_data_path.data(), "/", p->dist_id.data(), ".mbz");
  bool result = MyFTPClient::download(p->dist_id.data(), server_ip, p->file_name.data(), local_file_name.data());
  if (result)
    p->status = 1;
  else
    p->inc_failed();
  ((MyClientToDistModule*)module_x())->dist_info_ftps().add(p);
  return result;
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
