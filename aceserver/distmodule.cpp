/*
 * heartbeatmodule.cpp
 *
 *  Created on: Dec 26, 2011
 *      Author: root
 */

#include "distmodule.h"
#include "baseapp.h"
#include "server.h"

//MyDistClient//

MyDistClient::MyDistClient(MyHttpDistInfo * _dist_info, MyDistClientOne * _dist_one)
{
  dist_info = _dist_info;
  status = -1;
  last_update = 0;
  dist_one = _dist_one;
}

bool MyDistClient::check_valid() const
{
  return ((dist_info != NULL) && (status >= 0 && status <= 4));
}

bool MyDistClient::active()
{
  return dist_one->active();
}

const char * MyDistClient::client_id() const
{
  return dist_one->client_id();
}

int MyDistClient::client_id_index() const
{
  return dist_one->client_id_index();
}

void MyDistClient::update_status(int _status)
{
  if (_status > status)
    status = _status;
}

void MyDistClient::delete_self()
{
  dist_one->delete_dist_client(this);
}

void MyDistClient::update_md5_list(const char * _md5)
{
  if (unlikely(!dist_info->need_md5()))
  {
    MY_WARNING("got unexpected md5 reply packet on client_id(%s) dist_id(%s)\n",
        client_id(), dist_info->ver.data());
    return;
  }

  if (unlikely(md5.data() && md5.data()[0]))
    return;

  md5.init_from_string(_md5);
  update_status(2);
}

void MyDistClient::dist_ftp_md5_reply(const char * md5list)
{
  if (unlikely(*md5list == 0))
  {
    char buff[50];
    mycomutil_generate_time_string(buff, 50);
    MyServerAppX::instance()->heart_beat_module()->ftp_feedback_submitter().add(
        dist_info->ver.data(),
        dist_info->ftype[0],
        client_id(),
        2, '1', buff);

    MyServerAppX::instance()->heart_beat_module()->ftp_feedback_submitter().add(
        dist_info->ver.data(),
        dist_info->ftype[0],
        client_id(),
        3, '1', buff);

    MyServerAppX::instance()->heart_beat_module()->ftp_feedback_submitter().add(
        dist_info->ver.data(),
        dist_info->ftype[0],
        client_id(),
        4, '1', buff);

    dist_one->delete_dist_client(this);
//    MyServerAppX::instance()->db().set_dist_client_status(*this, 5);
//    update_status(5);
    return;
  }

  if (!md5.data() || !md5.data()[0])
  {
    update_md5_list(md5list);
    MyServerAppX::instance()->db().set_dist_client_md5(client_id(), dist_info->ver.data(), md5list, 2);
  }

  do_stage_2();
}

bool MyDistClient::dist_file()
{
  if (!active())
    return true;

  switch (status)
  {
  case 0:
    return do_stage_0();

  case 1:
    return do_stage_1();

  case 2:
    return do_stage_2();

  case 3:
    return do_stage_3();

  case 4:
    return do_stage_4();

  case 5:
    return false;

  default:
    MY_ERROR("unexpected status value = %d @MyDistClient::dist_file\n", status);
    return false;
  }
}

bool MyDistClient::do_stage_0()
{
  if (dist_info->need_md5())
  {
    if(send_md5())
    {
      MyServerAppX::instance()->db().set_dist_client_status(*this, 1);
      update_status(1);
    }
    return true;
  }

  if (send_ftp())
  {
    MyServerAppX::instance()->db().set_dist_client_status(*this, 3);
    update_status(3);
  }
  return true;
}

bool MyDistClient::do_stage_1()
{
  time_t now = time(NULL);
  if (now > last_update + MD5_REPLY_TIME_OUT * 60)
    send_md5();

  return true;
}

bool MyDistClient::do_stage_2()
{
  if (!mbz_file.data() || !mbz_file.data()[0])
  {
    if (!generate_diff_mbz())
    {
      mbz_file.init_from_string(MyDistCompressor::all_in_one_mbz());
      mbz_md5.init_from_string(dist_info->mbz_md5.data());
    }
    MyServerAppX::instance()->db().set_dist_client_mbz(client_id(), dist_info->ver.data(), mbz_file.data(), mbz_md5.data());
  }

  if (send_ftp())
  {
    MyServerAppX::instance()->db().set_dist_client_status(*this, 3);
    update_status(3);
  }
  return true;
}

bool MyDistClient::do_stage_3()
{
  time_t now = time(NULL);
  if (now > last_update + FTP_REPLY_TIME_OUT * 60)
    send_ftp();

  return true;
}

bool MyDistClient::do_stage_4()
{
  return false;
}

int MyDistClient::dist_out_leading_length()
{
  int adir_len = adir.data() ? ACE_OS::strlen(adir.data()) : (int)MyDataPacketHeader::NULL_ITEM_LENGTH;
  int aindex_len = dist_info->aindex_len > 0 ? dist_info->aindex_len : (int)MyDataPacketHeader::NULL_ITEM_LENGTH;
  return dist_info->ver_len + dist_info->findex_len + aindex_len + adir_len + 4 + 2 + 2;
}

void MyDistClient::dist_out_leading_data(char * data)
{
  sprintf(data, "%s%c%s%c%s%c%s%c%c%c%c%c",
      dist_info->ver.data(), MyDataPacketHeader::ITEM_SEPARATOR,
      dist_info->findex.data(), MyDataPacketHeader::ITEM_SEPARATOR,
      adir.data()? adir.data(): Null_Item, MyDataPacketHeader::ITEM_SEPARATOR,
      dist_info->aindex.data()? dist_info->aindex.data(): Null_Item, MyDataPacketHeader::ITEM_SEPARATOR,
      dist_info->ftype[0], MyDataPacketHeader::ITEM_SEPARATOR,
      dist_info->type[0], MyDataPacketHeader::FINISH_SEPARATOR);
}

bool MyDistClient::send_md5()
{
  if (!dist_info->md5.data() || !dist_info->md5.data()[0] || dist_info->md5_len <= 0)
    return false;

  int md5_len = dist_info->md5_len + 1;
  int data_len = dist_out_leading_length() + md5_len;
  int total_len = sizeof(MyServerFileMD5List) + data_len;
  ACE_Message_Block * mb = MyMemPoolFactoryX::instance()->get_message_block(total_len, MyDataPacketHeader::CMD_SERVER_FILE_MD5_LIST);
  MyServerFileMD5List * md5_packet = (MyServerFileMD5List *)mb->base();
  md5_packet->magic = client_id_index();
  dist_out_leading_data(md5_packet->data);
  ACE_OS::memcpy(md5_packet->data + data_len - md5_len, dist_info->md5.data(), md5_len);

  last_update = time(NULL);

  ACE_Time_Value tv(ACE_Time_Value::zero);
  if (MyServerAppX::instance()->heart_beat_module()->dispatcher()->putq(mb, &tv) == -1)
  {
    MY_ERROR("can not put file md5 list message to disatcher's queue\n");
    mb->release();
    return false;
  } else
    return true;
}

bool MyDistClient::generate_diff_mbz()
{
  MyPooledMemGuard destdir;
  MyPooledMemGuard composite_dir;
  MyPooledMemGuard mdestfile;
  destdir.init_from_string(MyConfigX::instance()->compressed_store_path.c_str(), "/", dist_info->ver.data());
  composite_dir.init_from_string(destdir.data(), "/", MyDistCompressor::composite_path());
  mdestfile.init_from_string(composite_dir.data(), "/", client_id(), ".mbz");
  MyBZCompositor compositor;
  if (!compositor.open(mdestfile.data()))
    return false;
  MyPooledMemGuard md5_copy;
  md5_copy.init_from_string(md5.data());
  char separators[2] = { MyDataPacketHeader::ITEM_SEPARATOR, 0 };
  MyStringTokenizer tokenizer(md5_copy.data(), separators);
  char * token;
  MyPooledMemGuard filename;
  while ((token =tokenizer.get_token()) != NULL)
  {
    filename.init_from_string(destdir.data(), "/", token, ".mbz");
    if (!compositor.add(filename.data()))
    {
      MyFilePaths::remove(mdestfile.data());
      return false;
    }
  }

  MyPooledMemGuard md5_result;
  if (!mycomutil_calculate_file_md5(mdestfile.data(), md5_result))
  {
    MY_ERROR("failed to calculate md5 for file %s\n", mdestfile.data());
    MyFilePaths::remove(mdestfile.data());
    return false;
  }

  mbz_file.init_from_string(mdestfile.data() + ACE_OS::strlen(destdir.data()) + 1);
  mbz_md5.init_from_string(md5_result.data());
  return true;
}

bool MyDistClient::send_ftp()
{
  const char * ftp_file_name;
  const char * _mbz_md5;

  if (!dist_info->need_md5())
  {
    ftp_file_name = MyDistCompressor::all_in_one_mbz();
    _mbz_md5 = dist_info->mbz_md5.data();
  } else
  {
    ftp_file_name = mbz_file.data();
    _mbz_md5 = mbz_md5.data();
  }

  int _mbz_md5_len = ACE_OS::strlen(_mbz_md5) + 1;
  int leading_length = dist_out_leading_length();
  int ftp_file_name_len = ACE_OS::strlen(ftp_file_name) + 1;
  int data_len = leading_length + ftp_file_name_len + dist_info->password_len + 1 + _mbz_md5_len;
  int total_len = sizeof(MyFtpFile) + data_len;
  ACE_Message_Block * mb = MyMemPoolFactoryX::instance()->get_message_block(total_len, MyDataPacketHeader::CMD_FTP_FILE);
  MyFtpFile * packet = (MyFtpFile *)mb->base();
  packet->magic = client_id_index();
  dist_out_leading_data(packet->data);
  char * ptr = packet->data + leading_length;
  ACE_OS::memcpy(ptr, ftp_file_name, ftp_file_name_len);
  ptr += ftp_file_name_len;
  *(ptr - 1) = MyDataPacketHeader::ITEM_SEPARATOR;
  ACE_OS::memcpy(ptr, _mbz_md5, _mbz_md5_len);
  ptr += _mbz_md5_len;
  *(ptr - 1) = MyDataPacketHeader::FINISH_SEPARATOR;
  ACE_OS::memcpy(ptr, dist_info->password.data(), dist_info->password_len + 1);

  last_update = time(NULL);

  ACE_Time_Value tv(ACE_Time_Value::zero);
  if (MyServerAppX::instance()->heart_beat_module()->dispatcher()->putq(mb, &tv) == -1)
  {
    MY_ERROR("can not put file md5 list message to disatcher's queue\n");
    mb->release();
    return false;
  } else
    return true;
}


//MyDistClientOne//

MyDistClientOne::MyDistClientOne(MyDistClients * dist_clients, const char * client_id): m_client_id(client_id)
{
  m_dist_clients = dist_clients;
  m_client_id_index = -1;
}

MyDistClientOne::~MyDistClientOne()
{
  clear();
}

const char * MyDistClientOne::client_id() const
{
  return m_client_id.as_string();
}

int MyDistClientOne::client_id_index() const
{
  return m_client_id_index;
}

bool MyDistClientOne::active()
{
  bool switched;
  return g_client_id_table->active(m_client_id, m_client_id_index, switched);
}

bool MyDistClientOne::is_client_id(const char * _client_id) const
{
  return ACE_OS::strcmp(m_client_id.as_string(), _client_id) == 0;
}

MyDistClient * MyDistClientOne::create_dist_client(MyHttpDistInfo * _dist_info)
{
  void * p = MyMemPoolFactoryX::instance()->get_mem_x(sizeof(MyDistClient));
  MyDistClient * result = new (p) MyDistClient(_dist_info, this);
  m_client_ones.push_back(result);
  m_dist_clients->on_create_dist_client(result);
  return result;
}

void MyDistClientOne::delete_dist_client(MyDistClient * dc)
{
  m_dist_clients->on_remove_dist_client(dc, false);
  m_client_ones.remove(dc);
  MyServerAppX::instance()->db().delete_dist_client(m_client_id.as_string(), dc->dist_info->ver.data());
  MyPooledObjectDeletor dlt;
  dlt(dc);
//  if (m_client_ones.empty())
//    m_dist_clients->delete_client_one(this);
}

void MyDistClientOne::clear()
{
  std::for_each(m_client_ones.begin(), m_client_ones.end(), MyPooledObjectDeletor());
  m_client_ones.clear();
}

bool MyDistClientOne::dist_files()
{
  bool switched;
  if (!g_client_id_table->active(m_client_id, m_client_id_index, switched))
    return !m_client_ones.empty();

  MyDistClientOneList::iterator it;

  if (unlikely(switched))
  {
    g_client_id_table->switched(m_client_id_index, false);
    for (it = m_client_ones.begin(); it != m_client_ones.end(); ++it)
      m_dist_clients->on_remove_dist_client(*it, false);
    clear();
    MyServerAppX::instance()->db().load_dist_clients(m_dist_clients, this);
    MY_INFO("reloading client one db for client id (%s)\n", m_client_id.as_string());
  }

  for (it = m_client_ones.begin(); it != m_client_ones.end(); )
  {
    if (!(*it)->dist_file())
    {
      m_dist_clients->on_remove_dist_client(*it, true);
      MyPooledObjectDeletor dlt;
      dlt(*it);
      it = m_client_ones.erase(it);
    } else
      ++it;
  }
  return !m_client_ones.empty();
}


//MyClientMapKey//

MyClientMapKey::MyClientMapKey(const char * _dist_id, const char * _client_id)
{
  dist_id = _dist_id;
  client_id = _client_id;
}

bool MyClientMapKey::operator == (const MyClientMapKey & rhs) const
{
  return ACE_OS::strcmp(dist_id, rhs.dist_id) == 0 &&
      ACE_OS::strcmp(client_id, rhs.client_id) == 0;
}


//MyDistClients//

MyDistClients::MyDistClients(MyHttpDistInfos * dist_infos)
{
  m_dist_infos = dist_infos;
  db_time = 0;
}

MyDistClients::~MyDistClients()
{
  clear();
}

void MyDistClients::clear()
{
  std::for_each(dist_clients.begin(), dist_clients.end(), MyPooledObjectDeletor());
  dist_clients.clear();
  m_dist_clients_map.clear();
  m_dist_client_ones_map.clear();
  db_time = 0;
}

void MyDistClients::on_create_dist_client(MyDistClient * dc)
{
  m_dist_clients_map.insert(std::pair<const MyClientMapKey, MyDistClient *>
     (MyClientMapKey(dc->dist_info->ver.data(), dc->client_id()), dc));
}

void MyDistClients::on_remove_dist_client(MyDistClient * dc, bool finished)
{
  if (finished)
    ++m_dist_client_finished;
  m_dist_clients_map.erase(MyClientMapKey(dc->dist_info->ver.data(), dc->client_id()));
}

MyHttpDistInfo * MyDistClients::find_dist_info(const char * dist_id)
{
  MY_ASSERT_RETURN(m_dist_infos, "", NULL);
  return m_dist_infos->find(dist_id);
}

MyDistClient * MyDistClients::find_dist_client(const char * client_id, const char * dist_id)
{
  MyDistClientMap::iterator it;
  it = m_dist_clients_map.find(MyClientMapKey(dist_id, client_id));
  if (it == m_dist_clients_map.end())
    return NULL;
  else
    return it->second;
}

MyDistClientOne * MyDistClients::find_client_one(const char * client_id)
{
  MyDistClientOneMap::iterator it;
  it = m_dist_client_ones_map.find(client_id);
  if (it == m_dist_client_ones_map.end())
    return NULL;
  else
    return it->second;
}

MyDistClientOne * MyDistClients::create_client_one(const char * client_id)
{
  void * p = MyMemPoolFactoryX::instance()->get_mem_x(sizeof(MyDistClientOne));
  MyDistClientOne * result = new (p) MyDistClientOne(this, client_id);
  dist_clients.push_back(result);
  m_dist_client_ones_map.insert(std::pair<const char *, MyDistClientOne *>(result->client_id(), result));
  return result;
}

void MyDistClients::delete_client_one(MyDistClientOne * dco)
{
  m_dist_client_ones_map.erase(dco->client_id());
  MyPooledObjectDeletor dlt;
  dlt(dco);
}

void MyDistClients::dist_files()
{
  m_dist_client_finished = 0;
  MyDistClientOneList::iterator it;
  for (it = dist_clients.begin(); it != dist_clients.end(); )
  {
    if (!(*it)->dist_files())
    {
      m_dist_client_ones_map.erase((*it)->client_id());
      MyPooledObjectDeletor dlt;
      dlt(*it);
      it = dist_clients.erase(it);
    } else
      ++it;
  }
  if (m_dist_client_finished > 0)
    MY_INFO("number of dist client(s) finished in this round = %d\n", m_dist_client_finished);
  MY_INFO("after dist_files(), client one = %d, dist client = %d\n", m_dist_client_ones_map.size(), m_dist_clients_map.size());
}


//MyClientFileDistributor//

MyClientFileDistributor::MyClientFileDistributor(): m_dist_clients(&m_dist_infos)
{
  m_last_begin = 0;
  m_last_end = 0;
}

bool MyClientFileDistributor::distribute(bool check_reload)
{
  time_t now = time(NULL);
  bool reload = false;
  if (check_reload)
    reload = m_dist_infos.need_reload();
  else if (now - m_last_end < 5 * 60)
    return false;

  m_last_begin = now;
  check_dist_info(reload);
  check_dist_clients(reload);
  m_last_end = time(NULL);
  return true;
}

bool MyClientFileDistributor::check_dist_info(bool reload)
{
  if (reload)
  {
    m_dist_infos.prepare_update(0);
    return (MyServerAppX::instance()->db().load_dist_infos(m_dist_infos) < 0)? false:true;
  }

  return true;
}

bool MyClientFileDistributor::check_dist_clients(bool reload)
{
  if (reload)
  {
    m_dist_clients.clear();
    if (!MyServerAppX::instance()->db().load_dist_clients(&m_dist_clients, NULL))
      return false;
  }

  m_dist_clients.dist_files();
  return true;
}

void MyClientFileDistributor::dist_ftp_file_reply(const char * client_id, const char * dist_id, int _status)
{
  MyDistClient * dc = m_dist_clients.find_dist_client(client_id, dist_id);
  if (unlikely(dc == NULL))
    return;

  if (_status <= 3)
  {
    dc->update_status(_status);
    MyServerAppX::instance()->db().set_dist_client_status(client_id, dist_id, _status);
  }
  else
    dc->delete_self();
}

void MyClientFileDistributor::dist_ftp_md5_reply(const char * client_id, const char * dist_id, const char * md5list)
{
  MyDistClient * dc = m_dist_clients.find_dist_client(client_id, dist_id);
  if (likely(dc != NULL))
    dc->dist_ftp_md5_reply(md5list);
}


//MyHeartBeatProcessor//

MyPingSubmitter * MyHeartBeatProcessor::m_heart_beat_submitter = NULL;
MyIPVerSubmitter * MyHeartBeatProcessor::m_ip_ver_submitter = NULL;

MyHeartBeatProcessor::MyHeartBeatProcessor(MyBaseHandler * handler): MyBaseServerProcessor(handler)
{

}

MyBaseProcessor::EVENT_RESULT MyHeartBeatProcessor::on_recv_header()
{
  if (super::on_recv_header() == ER_ERROR)
    return ER_ERROR;

  if (m_packet_header.command == MyDataPacketHeader::CMD_HEARTBEAT_PING)
  {
    MyHeartBeatPingProc proc;
    proc.attach((const char*)&m_packet_header);
    bool result = proc.validate_header();
    if (!result)
    {
      MyPooledMemGuard info;
      info_string(info);
      MY_ERROR("bad heart beat packet received from %s\n", info.data());
      return ER_ERROR;
    }

    //the thread context switching and synchronization cost outbeat the benefit of using another thread
    do_ping();
    return ER_OK_FINISHED;
  }

  if (m_packet_header.command == MyDataPacketHeader::CMD_CLIENT_VERSION_CHECK_REQ)
  {
    MyClientVersionCheckRequestProc proc;
    proc.attach((const char*)&m_packet_header);
    bool result = proc.validate_header();
    if (!result)
    {
      MyPooledMemGuard info;
      info_string(info);
      MY_ERROR("bad client version check req packet received from %s\n", info.data());
      return ER_ERROR;
    }
    return ER_OK;
  }

  if (m_packet_header.command == MyDataPacketHeader::CMD_SERVER_FILE_MD5_LIST)
  {
    MyServerFileMD5ListProc proc;
    proc.attach((const char*)&m_packet_header);
    bool result = proc.validate_header();
    if (!result)
    {
      MyPooledMemGuard info;
      info_string(info);
      MY_ERROR("bad md5 file list packet received from %s\n", info.data());
      return ER_ERROR;
    }
    return ER_OK;
  }

  if (m_packet_header.command == MyDataPacketHeader::CMD_FTP_FILE)
  {
    MyFtpFileProc proc;
    proc.attach((const char*)&m_packet_header);
    bool result = proc.validate_header();
    if (!result)
    {
      MyPooledMemGuard info;
      info_string(info);
      MY_ERROR("bad file ftp packet received from %s\n", info.data());
      return ER_ERROR;
    }
    return ER_OK;
  }

  if (m_packet_header.command == MyDataPacketHeader::CMD_IP_VER_REQ)
  {
    if (m_packet_header.length != sizeof(MyIpVerRequest) || m_packet_header.magic != MyDataPacketHeader::DATAPACKET_MAGIC)
    {
      MyPooledMemGuard info;
      info_string(info);
      MY_ERROR("bad ip ver request packet received from %s\n", info.data());
      return ER_ERROR;
    }
    return ER_OK;
  }

  if (m_packet_header.command == MyDataPacketHeader::CMD_UI_CLICK)
  {
    if (m_packet_header.length <= (int)sizeof(MyIpVerRequest)
        || m_packet_header.length >= 1 * 1024 * 1024
        || m_packet_header.magic != MyDataPacketHeader::DATAPACKET_MAGIC)
    {
      MyPooledMemGuard info;
      info_string(info);
      MY_ERROR("bad adv click request packet received from %s\n", info.data());
      return ER_ERROR;
    }
    return ER_OK;
  }

  MY_ERROR(ACE_TEXT("unexpected packet header received @MyHeartBeatProcessor.on_recv_header, cmd = %d\n"),
      m_packet_header.command);

  return ER_ERROR;
}

MyBaseProcessor::EVENT_RESULT MyHeartBeatProcessor::on_recv_packet_i(ACE_Message_Block * mb)
{
  MyBaseServerProcessor::on_recv_packet_i(mb);

  MyDataPacketHeader * header = (MyDataPacketHeader *)mb->base();
  if (header->command == MyDataPacketHeader::CMD_CLIENT_VERSION_CHECK_REQ)
    return do_version_check(mb);

  if (header->command == MyDataPacketHeader::CMD_SERVER_FILE_MD5_LIST)
    return do_md5_file_list(mb);

  if (header->command == MyDataPacketHeader::CMD_FTP_FILE)
    return do_ftp_reply(mb);

  if (header->command == MyDataPacketHeader::CMD_IP_VER_REQ)
    return do_ip_ver_req(mb);

  if (header->command == MyDataPacketHeader::CMD_UI_CLICK)
    return do_adv_click_req(mb);

  MyMessageBlockGuard guard(mb);
  MY_ERROR("unsupported command received @MyHeartBeatProcessor::on_recv_packet_i, command = %d\n",
      header->command);
  return ER_ERROR;
}

void MyHeartBeatProcessor::do_ping()
{
//  MY_DEBUG(ACE_TEXT("got a heart beat from %s\n"), info_string().c_str());
  m_heart_beat_submitter->add_ping(m_client_id.as_string(), m_client_id_length);
}

MyBaseProcessor::EVENT_RESULT MyHeartBeatProcessor::do_version_check(ACE_Message_Block * mb)
{
  MyMessageBlockGuard guard(mb);

  MyClientIDTable & client_id_table = MyServerAppX::instance()->client_id_table();

  MyBaseProcessor::EVENT_RESULT ret = do_version_check_common(mb, client_id_table);
  m_ip_ver_submitter->add_data(m_client_id.as_string(), m_client_id_length, m_peer_addr, m_client_version.to_string());

  if (ret != ER_CONTINUE)
    return ret;

  MyClientInfo client_info;
  client_id_table.value_all(m_client_id_index, client_info);

  ACE_Message_Block * reply_mb;
  if (m_client_version < MyConfigX::instance()->client_version_minimum)
  {
    reply_mb = make_version_check_reply_mb(MyClientVersionCheckReply::VER_MISMATCH, client_info.password_len + 2);
    m_wait_for_close = true;
  }
  else if (m_client_version < MyConfigX::instance()->client_version_current)
    reply_mb = make_version_check_reply_mb(MyClientVersionCheckReply::VER_OK_CAN_UPGRADE, client_info.password_len + 2);
  else
    reply_mb = make_version_check_reply_mb(MyClientVersionCheckReply::VER_OK, client_info.password_len + 2);

  if (!m_wait_for_close)
  {
    MyClientVersionCheckRequest * vc = (MyClientVersionCheckRequest *)mb->base();
    if (vc->server_id != MyConfigX::instance()->server_id)
      client_id_table.switched(m_client_id_index, true);

    MyPooledMemGuard info;
    info_string(info);
    MY_INFO(ACE_TEXT("client version check ok: %s\n"), info.data());
  }

  MyClientVersionCheckReply * vcr = (MyClientVersionCheckReply *) reply_mb->base();
  *((u_int8_t*)vcr->data) = MyConfigX::instance()->server_id;
  ACE_OS::memcpy(vcr->data + 1, client_info.ftp_password, client_info.password_len + 1);
  if (m_handler->send_data(reply_mb) < 0)
    return ER_ERROR;
  else
    return ER_OK;
}

MyBaseProcessor::EVENT_RESULT MyHeartBeatProcessor::do_md5_file_list(ACE_Message_Block * mb)
{
  MyDataPacketExt * md5filelist = (MyDataPacketExt *)mb->base();
  if (unlikely(!md5filelist->guard()))
    return ER_OK;
  //todo: process md5 file list reply from client
  MyPooledMemGuard info;
  info_string(info);
  MyServerAppX::instance()->dist_put_to_service(mb);
  return ER_OK;
}

MyBaseProcessor::EVENT_RESULT MyHeartBeatProcessor::do_ftp_reply(ACE_Message_Block * mb)
{
  MyDataPacketExt * md5filelist = (MyDataPacketExt *)mb->base();
  if (unlikely(!md5filelist->guard()))
    return ER_OK;

  MyServerAppX::instance()->dist_put_to_service(mb);
  return ER_OK;
}

MyBaseProcessor::EVENT_RESULT MyHeartBeatProcessor::do_ip_ver_req(ACE_Message_Block * mb)
{
  MyMessageBlockGuard guard(mb);
  m_ip_ver_submitter->add_data(m_client_id.as_string(), m_client_id_length, m_peer_addr, m_client_version.to_string());
  return ER_OK;
}

MyBaseProcessor::EVENT_RESULT MyHeartBeatProcessor::do_adv_click_req(ACE_Message_Block * mb)
{
  MyMessageBlockGuard guard(mb);
  //todo: add adv click submitter here
  return ER_OK;
}


//MyAccumulatorBlock//

MyAccumulatorBlock::MyAccumulatorBlock(int block_size, int max_item_length, MyBaseSubmitter * submitter, bool auto_submit)
{
  m_block_size = block_size;
  m_max_item_length = max_item_length + 1;
  m_submitter = submitter;
  m_auto_submit = auto_submit;
  m_current_block = MyMemPoolFactoryX::instance()->get_message_block(m_block_size);
  submitter->add_block(this);
  reset();
}

MyAccumulatorBlock::~MyAccumulatorBlock()
{
  if (m_current_block)
    m_current_block->release();
}

void MyAccumulatorBlock::reset()
{
  m_current_ptr = m_current_block->base();
}

bool MyAccumulatorBlock::add(const char * item, int len)
{
  if (len == 0)
    len = ACE_OS::strlen(item);
  ++len;
  int remain_len = m_block_size - (m_current_ptr - m_current_block->base());
  if (unlikely(len > remain_len))
  {
    if (m_auto_submit)
    {
      m_submitter->submit();
      remain_len = m_block_size;
    } else
    {
      MY_FATAL("expected long item @MyAccumulatorBlock::add(), remain_len=%d, item=%s\n", remain_len, item);
      return false;
    }
  }
  ACE_OS::memcpy(m_current_ptr, item, len - 1);
  m_current_ptr += len;
  *(m_current_ptr - 1) = ITEM_SEPARATOR;
  return (remain_len - len > m_max_item_length);
}

bool MyAccumulatorBlock::add(char c)
{
  char buff[2];
  buff[0] = c;
  buff[1] = 0;
  return add(buff, 1);
}

const char * MyAccumulatorBlock::data()
{
  return m_current_block->base();
}

int MyAccumulatorBlock::data_len() const
{
  int result = (m_current_ptr - m_current_block->base());
  return std::max(result - 1, 0);
}


//MyBaseSubmitter//

MyBaseSubmitter::~MyBaseSubmitter()
{

}

void MyBaseSubmitter::submit()
{
  do_submit(get_command());
  reset();
}

void MyBaseSubmitter::check_time_out()
{
  if ((*m_blocks.begin())->data_len() == 0)
    return;

  submit();
}

void MyBaseSubmitter::add_block(MyAccumulatorBlock * block)
{
  m_blocks.push_back(block);
}

void MyBaseSubmitter::do_submit(const char * cmd)
{
  if (unlikely((*m_blocks.begin())->data_len() == 0))
    return;
  MyBlockList::iterator it;

  int total_len = 0;
  for (it = m_blocks.begin(); it != m_blocks.end(); ++it)
    total_len += (*it)->data_len() + 1;
  --total_len;

  ACE_Message_Block * mb = MyMemPoolFactoryX::instance()->get_message_block_bs(total_len, cmd);
  char * dest = mb->base() + MyBSBasePacket::DATA_OFFSET;
  for (it = m_blocks.begin(); ; )
  {
    int len = (*it)->data_len();
    ACE_OS::memcpy(dest, (*it)->data(), len);
    if (++it != m_blocks.end())
    {
      dest[len] = MyBSBasePacket::BS_PARAMETER_SEPARATOR;
      dest += (len + 1);
    } else
      break;
  }
  MyServerAppX::instance()->dist_to_middle_module()->send_to_bs(mb);
}

void MyBaseSubmitter::reset()
{
  std::for_each(m_blocks.begin(), m_blocks.end(), std::mem_fun(&MyAccumulatorBlock::reset));
};


//MyFtpFeedbackSubmitter//

MyFtpFeedbackSubmitter::MyFtpFeedbackSubmitter():
  m_dist_id_block(BLOCK_SIZE, 32, this), m_client_id_block(BLOCK_SIZE, sizeof(MyClientID), this), m_ftype_block(BLOCK_SIZE, 1, this),
  m_step_block(BLOCK_SIZE, 1, this), m_ok_flag_block(BLOCK_SIZE, 1, this), m_date_block(BLOCK_SIZE, 15, this)
{

}

MyFtpFeedbackSubmitter::~MyFtpFeedbackSubmitter()
{

}

const char * MyFtpFeedbackSubmitter::get_command() const
{
  return MY_BS_DIST_FEEDBACK_CMD;
}

void MyFtpFeedbackSubmitter::add(const char *dist_id, char ftype, const char *client_id, char step, char ok_flag, const char * date)
{
  bool ret = true;

  if (!m_dist_id_block.add(dist_id))
    ret = false;
  if (!m_client_id_block.add(client_id))
    ret = false;
  if (!m_ftype_block.add(ftype))
    ret = false;
  if (!m_step_block.add(step))
    ret = false;
  if (!m_ok_flag_block.add(ok_flag))
    ret = false;
  if (!m_date_block.add(date))
    ret = false;

  if (!ret)
    submit();
}


//MyPingSubmitter//

MyPingSubmitter::MyPingSubmitter(): m_block(BLOCK_SIZE, sizeof(MyClientID), this, true)
{

}

MyPingSubmitter::~MyPingSubmitter()
{

}

void MyPingSubmitter::add_ping(const char * client_id, const int len)
{
  if (unlikely(!client_id || !*client_id || len <= 0))
    return;
  if (!m_block.add(client_id, len))
    submit();
}

const char * MyPingSubmitter::get_command() const
{
  return MY_BS_HEART_BEAT_CMD;
}


//MyIPVerSubmitter//

MyIPVerSubmitter::MyIPVerSubmitter():
    m_id_block(BLOCK_SIZE, sizeof(MyClientID), this),
    m_ip_block(BLOCK_SIZE, INET_ADDRSTRLEN, this),
    m_ver_block(BLOCK_SIZE * 7 / sizeof(MyClientID) + 1, 7, this)
{

}

void MyIPVerSubmitter::add_data(const char * client_id, int id_len, const char * ip, const char * ver)
{
  bool ret = true;
  if (!m_id_block.add(client_id, id_len))
    ret = false;
  if (!m_ip_block.add(ip, 0))
    ret = false;
  if (!m_ver_block.add(ver, 0))
    ret = false;

  if (!ret)
    submit();
}

const char * MyIPVerSubmitter::get_command() const
{
  return MY_BS_IP_VER_CMD;
}


//MyHeartBeatHandler//

MyHeartBeatHandler::MyHeartBeatHandler(MyBaseConnectionManager * xptr): MyBaseHandler(xptr)
{
  m_processor = new MyHeartBeatProcessor(this);
}

PREPARE_MEMORY_POOL(MyHeartBeatHandler);


//MyHeartBeatService//

MyHeartBeatService::MyHeartBeatService(MyBaseModule * module, int numThreads):
    MyBaseService(module, numThreads)
{
  msg_queue()->high_water_mark(MSG_QUEUE_MAX_SIZE);
}

int MyHeartBeatService::svc()
{
  MY_INFO("running %s::svc()\n", name());

  for (ACE_Message_Block * mb; getq(mb) != -1; )
  {
    MyMessageBlockGuard guard(mb);
    if (mb->capacity() == sizeof(int))
    {
      int cmd = *(int*)mb->base();
      if (cmd == TIMED_DIST_TASK)
      {
        m_distributor.distribute(false);
      } else
        MY_ERROR("unknown command recieved(%d)\n", cmd);
    } else
    {
      MyDataPacketHeader * dph = (MyDataPacketHeader *) mb->base();
      if (dph->command == MyDataPacketHeader::CMD_HAVE_DIST_TASK)
      {
        do_have_dist_task();
      } else if ((dph->command == MyDataPacketHeader::CMD_FTP_FILE))
      {
        do_ftp_file_reply(mb);
      } else if ((dph->command == MyDataPacketHeader::CMD_SERVER_FILE_MD5_LIST))
      {
        do_file_md5_reply(mb);
      } else
        MY_ERROR("unknown packet recieved @%s, cmd = %d\n", name(), dph->command);
    }
  }

  MY_INFO("exiting %s::svc()\n", name());
  return 0;
}

void MyHeartBeatService::do_have_dist_task()
{
  m_distributor.distribute(true);
}

void MyHeartBeatService::do_ftp_file_reply(ACE_Message_Block * mb)
{
  MyDataPacketExt * dpe = (MyDataPacketExt*) mb->base();
  MyClientID client_id;
  if (unlikely(!MyServerAppX::instance()->client_id_table().value(dpe->magic, &client_id)))
  {
    MY_FATAL("can not find client id @MyHeartBeatService::do_ftp_file_reply()\n");
    return;
  } //todo: optimize: pass client_id directly from processor

  int len = dpe->length - sizeof(MyDataPacketHeader);
  if (unlikely(dpe->data[len - 5] != MyDataPacketHeader::ITEM_SEPARATOR))
  {
    MY_ERROR("bad ftp file reply packet @%s::do_ftp_file_reply()\n", name());
    return;
  }
  dpe->data[len - 5] = 0;
  if (unlikely(!dpe->data[0]))
  {
    MY_ERROR("bad ftp file reply packet @%s::do_ftp_file_reply(), no dist_id\n", name());
    return;
  }

  const char * dist_id = dpe->data;
  char ok = dpe->data[len - 4];
  char recv_status = dpe->data[len - 3];
  char ftype = dpe->data[len - 2];
  char step = 0;
  int status;

  if (unlikely(ok != '0' && ok != '1'))
  {
    MY_ERROR("bad ok flag(%c) on client ftp reply @%s\n", ok, name());
    return;
  }
  if (unlikely(!ftype_is_valid(ftype) && ftype != 'x'))
  {
    MY_ERROR("bad ftype(%c) on client ftp reply @%s\n", ftype, name());
    return;
  }

  if (recv_status == '2')
  {
    MY_DEBUG("ftp download started client_id(%s) dist_id(%s)\n", client_id.as_string(), dist_id);
    status = 4;
  } else if (recv_status == '3')
  {
    status = 5;
    step = '3';
    MY_DEBUG("ftp download completed client_id(%s) dist_id(%s)\n", client_id.as_string(), dist_id);
  } else if (recv_status == '4')
  {
    status = 5;
    MY_DEBUG("dist extract completed client_id(%s) dist_id(%s)\n", client_id.as_string(), dist_id);
  } else if (recv_status == '5')
  {
    status = 5;
    MY_DEBUG("dist extract failed client_id(%s) dist_id(%s)\n", client_id.as_string(), dist_id);
  } else if (recv_status == '9')
  {
    step = '2';
  }
  else
  {
    MY_ERROR("unknown ftp reply status code: %c\n", recv_status);
    return;
  }

  if ((ftype != 'x') && step != 0)
  {
    char buff[32];
    mycomutil_generate_time_string(buff, 32);
    ((MyHeartBeatModule *)module_x())->ftp_feedback_submitter().add(dist_id, ftype, client_id.as_string(), step, ok, buff);
  }
  if (recv_status == '9')
    return;

  m_distributor.dist_ftp_file_reply(client_id.as_string(), dist_id, status);
}

void MyHeartBeatService::do_file_md5_reply(ACE_Message_Block * mb)
{
  MyDataPacketExt * dpe = (MyDataPacketExt*) mb->base();
  MyClientID client_id;
  if (unlikely(!MyServerAppX::instance()->client_id_table().value(dpe->magic, &client_id)))
  {
    MY_FATAL("can not find client id @MyHeartBeatService::do_file_md5_reply()\n");
    return;
  } //todo: optimize: pass client_id directly from processor

  if (unlikely(!dpe->data[0]))
  {
    MY_ERROR("bad file md5 list reply packet @%s::do_file_md5_reply(), no dist_id\n", name());
    return;
  }
  char * md5list = ACE_OS::strchr(dpe->data, MyDataPacketHeader::ITEM_SEPARATOR);
  if (unlikely(!md5list))
  {
    MY_ERROR("bad file md5 list reply packet @%s::do_file_md5_reply(), no dist_id mark\n", name());
    return;
  }
  *md5list ++ = 0;
  const char * dist_id = dpe->data;
  MY_DEBUG("file md5 list value from client_id(%s) dist_id(%s): %s\n", client_id.as_string(), dist_id, md5list);
  m_distributor.dist_ftp_md5_reply(client_id.as_string(), dist_id, md5list);
}


//MyHeartBeatAcceptor//

MyHeartBeatAcceptor::MyHeartBeatAcceptor(MyBaseDispatcher * _dispatcher, MyBaseConnectionManager * _manager):
    MyBaseAcceptor(_dispatcher, _manager)
{
  m_tcp_port = MyConfigX::instance()->dist_server_heart_beat_port;
  m_idle_time_as_dead = IDLE_TIME_AS_DEAD;
}

int MyHeartBeatAcceptor::make_svc_handler(MyBaseHandler *& sh)
{
  sh = new MyHeartBeatHandler(m_connection_manager);
  if (!sh)
  {
    MY_ERROR("can not alloc MyHeartBeatHandler from %s\n", name());
    return -1;
  }
  sh->parent((void*)this);
  sh->reactor(reactor());
  return 0;
}

const char * MyHeartBeatAcceptor::name() const
{
  return "MyHeartBeatAcceptor";
}


//MyHeartBeatDispatcher//

MyHeartBeatDispatcher::MyHeartBeatDispatcher(MyBaseModule * pModule, int numThreads):
    MyBaseDispatcher(pModule, numThreads)
{
  m_acceptor = NULL;
  m_clock_interval = CLOCK_INTERVAL;
  msg_queue()->high_water_mark(MSG_QUEUE_MAX_SIZE); //20 Megabytes
}

const char * MyHeartBeatDispatcher::name() const
{
  return "MyHeartBeatDispatcher";
}

MyHeartBeatAcceptor * MyHeartBeatDispatcher::acceptor() const
{
  return m_acceptor;
}

int MyHeartBeatDispatcher::handle_timeout(const ACE_Time_Value &tv, const void *act)
{
  ACE_UNUSED_ARG(tv);
  ACE_UNUSED_ARG(act);
  if ((long)act == MyBaseDispatcher::TIMER_ID_BASE)
  {
    ACE_Message_Block *mb;
    ACE_Time_Value nowait(ACE_Time_Value::zero);
    while (-1 != this->getq(mb, &nowait))
    {
      if (unlikely(mb->size() < sizeof(MyDataPacketHeader)))
      {
        MY_ERROR("invalid message block size @ %s::handle_timeout\n", name());
        mb->release();
        continue;
      }
      int index = ((MyDataPacketHeader*)mb->base())->magic;
      MyBaseHandler * handler = m_acceptor->connection_manager()->find_handler_by_index(index);
      if (!handler)
      {
        MY_WARNING("can not send data to client since connection is lost @ %s::handle_timeout\n", name());
        mb->release();
        continue;
      }

      if (unlikely(MyDataPacketHeader::CMD_DISCONNECT_INTERNAL == ((MyDataPacketHeader*)mb->base())->command))
      {
        //handler->processor()->prepare_to_close();
        handler->handle_close(ACE_INVALID_HANDLE, 0);
        mb->release();
        continue;
      }

      ((MyDataPacketHeader*)mb->base())->magic = MyDataPacketHeader::DATAPACKET_MAGIC;

      if (handler->send_data(mb) < 0)
        handler->handle_close(handler->get_handle(), 0);
    }
  } else if ((long)act == TIMER_ID_HEART_BEAT)
  {
    MyHeartBeatProcessor::m_heart_beat_submitter->check_time_out();
  } else if ((long)act == TIMER_ID_IP_VER)
  {
    MyHeartBeatProcessor::m_ip_ver_submitter->check_time_out();
  } else if ((long)act == TIMER_ID_DIST_SERVICE)
  {
    ACE_Message_Block * mb = MyMemPoolFactoryX::instance()->get_message_block(sizeof(int));
    *(int*)mb->base() = MyHeartBeatService::TIMED_DIST_TASK;
    ACE_Time_Value tv(ACE_Time_Value::zero);
    if (((MyHeartBeatModule*)module_x())->service()->putq(mb, &tv) < 0)
      mb->release();
  }
  return 0;
}

void MyHeartBeatDispatcher::on_stop()
{
  m_acceptor = NULL;
}

void MyHeartBeatDispatcher::on_stop_stage_1()
{

}

bool MyHeartBeatDispatcher::on_start()
{
  if (!m_acceptor)
    m_acceptor = new MyHeartBeatAcceptor(this, new MyBaseConnectionManager());
  add_acceptor(m_acceptor);

  {
    ACE_Time_Value interval(CLOCK_TICK_HEART_BEAT);
    if (reactor()->schedule_timer(this, (const void*)TIMER_ID_HEART_BEAT, interval, interval) < 0)
    {
      MY_ERROR("setup heart beat timer failed %s %s\n", name(), (const char*)MyErrno());
      return false;
    }
  }

  {
    ACE_Time_Value interval(CLOCK_TICK_IP_VER);
    if (reactor()->schedule_timer(this, (const void*)TIMER_ID_IP_VER, interval, interval) < 0)
    {
      MY_ERROR("setup heart beat timer failed %s %s\n", name(), (const char*)MyErrno());
      return false;
    }
  }

  {
    ACE_Time_Value interval(CLOCK_TICK_DIST_SERVICE * 60);
    if (reactor()->schedule_timer(this, (const void*)TIMER_ID_DIST_SERVICE, interval, interval) < 0)
    {
      MY_ERROR("setup heart beat timer failed %s %s\n", name(), (const char*)MyErrno());
      return false;
    }
  }

  return true;
}


//MyHeartBeatModule//

MyHeartBeatModule::MyHeartBeatModule(MyBaseApp * app): MyBaseModule(app)
{
  m_service = NULL;
  m_dispatcher = NULL;
  MyHeartBeatProcessor::m_heart_beat_submitter = &m_ping_sumbitter;
  MyHeartBeatProcessor::m_ip_ver_submitter = &m_ip_ver_submitter;
}

MyHeartBeatModule::~MyHeartBeatModule()
{

}

MyHeartBeatDispatcher * MyHeartBeatModule::dispatcher() const
{
  return m_dispatcher;
}

MyHeartBeatService * MyHeartBeatModule::service() const
{
  return m_service;
}

int MyHeartBeatModule::num_active_clients() const
{
  if (unlikely(!m_dispatcher || !m_dispatcher->acceptor() || !m_dispatcher->acceptor()->connection_manager()))
    return 0xFFFFFF;
  return m_dispatcher->acceptor()->connection_manager()->active_connections();
}

MyFtpFeedbackSubmitter & MyHeartBeatModule::ftp_feedback_submitter()
{
  return m_ftp_feedback_submitter;
}

const char * MyHeartBeatModule::name() const
{
  return "MyHeartBeatModule";
}

bool MyHeartBeatModule::on_start()
{
  add_service(m_service = new MyHeartBeatService(this, 1));
  add_dispatcher(m_dispatcher = new MyHeartBeatDispatcher(this));
  return true;
}

void MyHeartBeatModule::on_stop()
{
  m_service = NULL;
  m_dispatcher = NULL;
}


/////////////////////////////////////
//dist to BS
/////////////////////////////////////

//MyDistToBSProcessor//

MyDistToBSProcessor::MyDistToBSProcessor(MyBaseHandler * handler): super(handler)
{

}

MyBaseProcessor::EVENT_RESULT MyDistToBSProcessor::on_recv_packet_i(ACE_Message_Block * mb)
{
  MyMessageBlockGuard guard(mb);

  if (super::on_recv_packet_i(mb) != ER_OK)
    return ER_ERROR;
  MyBSBasePacket * bspacket = (MyBSBasePacket *) mb->base();
  if (ACE_OS::memcmp(bspacket->cmd, MY_BS_IP_VER_CMD, sizeof(bspacket->cmd)) == 0)
    process_ip_ver_reply(bspacket);
//  MY_INFO("got a bs reply packet:%s\n", mb->base());

  return ER_OK;
}

void MyDistToBSProcessor::process_ip_ver_reply(MyBSBasePacket * bspacket)
{
  char separator[2] = {';', 0};
  MyStringTokenizer tknizer(bspacket->data, separator);
  char * token;
  while ((token = tknizer.get_token()) != NULL)
    process_ip_ver_reply_one(token);
}

void MyDistToBSProcessor::process_ip_ver_reply_one(char * item)
{
  char * id, * data;
  id = item;
  data = strchr(item, ':');
  if (unlikely(!data || data == item || *(data + 1) == 0))
    return;
  *data++ = 0;
  bool client_valid = !(data[0] == '*' && data[1] == 0);
  MyClientIDTable & id_table = MyServerAppX::instance()->client_id_table();
  MyClientID client_id(id);
  int index;
  if (unlikely(!id_table.mark_valid(client_id, client_valid, index)))
    MyServerAppX::instance()->db().mark_client_valid(id, client_valid);

  if (likely(client_valid))
  {
    int len = ACE_OS::strlen(data) + 1;
    ACE_Message_Block * mb = MyMemPoolFactoryX::instance()->get_message_block(len + sizeof(MyDataPacketHeader), MyDataPacketHeader::CMD_IP_VER_REQ);
    MyDataPacketExt * dpe = (MyDataPacketExt *) mb->base();
    ACE_OS::memcpy(dpe->data, data, len);
    dpe->magic = index;
    ACE_Time_Value tv(ACE_Time_Value::zero);
    if (MyServerAppX::instance()->heart_beat_module()->dispatcher()->putq(mb, &tv) == -1)
      mb->release();
  } else
  {
    if (index >= 0)
    {
      ACE_Message_Block * mb = MyMemPoolFactoryX::instance()->get_message_block(sizeof(MyDataPacketHeader), MyDataPacketHeader::CMD_DISCONNECT_INTERNAL);
      MyDataPacketExt * dpe = (MyDataPacketExt *) mb->base();
      dpe->magic = index;
      ACE_Time_Value tv(ACE_Time_Value::zero);
      if (MyServerAppX::instance()->heart_beat_module()->dispatcher()->putq(mb, &tv) == -1)
        mb->release();
    }
  }
}


//MyDistToBSHandler//

MyDistToBSHandler::MyDistToBSHandler(MyBaseConnectionManager * xptr): MyBaseHandler(xptr)
{
  m_processor = new MyDistToBSProcessor(this);
}

MyDistToMiddleModule * MyDistToBSHandler::module_x() const
{
  return (MyDistToMiddleModule *)connector()->module_x();
}

int MyDistToBSHandler::on_open()
{
  return 0;
}


void MyDistToBSHandler::on_close()
{

}

PREPARE_MEMORY_POOL(MyDistToBSHandler);


//MyDistToBSConnector//

MyDistToBSConnector::MyDistToBSConnector(MyBaseDispatcher * _dispatcher, MyBaseConnectionManager * _manager):
    MyBaseConnector(_dispatcher, _manager)
{
  m_tcp_port = MyConfigX::instance()->bs_server_port;
  m_reconnect_interval = RECONNECT_INTERVAL;
  m_tcp_addr = MyConfigX::instance()->bs_server_addr;
}

const char * MyDistToBSConnector::name() const
{
  return "MyDistToBSConnector";
}

int MyDistToBSConnector::make_svc_handler(MyBaseHandler *& sh)
{
  sh = new MyDistToBSHandler(m_connection_manager);
  if (!sh)
  {
    MY_ERROR("can not alloc MyDistToBSHandler from %s\n", name());
    return -1;
  }
  sh->parent((void*)this);
  sh->reactor(reactor());
  return 0;
}


/////////////////////////////////////
//remote access module
/////////////////////////////////////


//MyDistRemoteAccessProcessor//

MyDistRemoteAccessProcessor::MyDistRemoteAccessProcessor(MyBaseHandler * handler):
    MyBaseRemoteAccessProcessor(handler)
{

}

int MyDistRemoteAccessProcessor::on_command(const char * cmd, char * parameter)
{

  if (!ACE_OS::strcmp(cmd, "dist"))
    return on_command_dist_file_md5(parameter);
  if (!ACE_OS::strcmp(cmd, "dist_batch"))
    return on_command_dist_batch_file_md5(parameter);

  return on_unsupported_command(cmd);
}

int MyDistRemoteAccessProcessor::on_command_help()
{
  const char * help_msg = "the following commands are supported:\n"
                          "  help\n"
                          "  exit (or quit)\n"
                          "  dist client_id1 [client_id2] [client_id3] ...\n"
                          "  dist_batch start_client_id number_of_clients\n>";
  return send_string(help_msg);
}

int MyDistRemoteAccessProcessor::on_command_dist_file_md5(char * parameter)
{
  if (!*parameter)
    return send_string("  usage: dist client_id1 [client_id2] [client_id3] ...\n>");

  const char * CONST_seperator = ",\t ";
  char *str, *token, *saveptr;

  std::vector<MyClientID> vec;

  for (str = parameter; ; str = NULL)
  {
    token = strtok_r(str, CONST_seperator, &saveptr);
    if (token == NULL)
      break;
    if (!*token)
      continue;
    vec.push_back(MyClientID(token));
  }
  if (vec.empty())
    return send_string("  usage: dist client_id1 [client_id2] [client_id3] ...\n>");

  std::sort(vec.begin(), vec.end());
  vec.erase(std::unique(vec.begin(), vec.end()), vec.end());

  const int BUFF_SIZE = 5000;
  char buff[BUFF_SIZE];

  if (send_string("  user requested client_id(s):") < 0)
    return -1;
  std::vector<MyClientID>::iterator it;
  buff[0] = 0;
  for (it = vec.begin(); it != vec.end(); ++it)
  {
    int len = strlen(buff);
    ACE_OS::snprintf(buff + len, BUFF_SIZE - 1 - len, " %s", it->client_id.as_string);
  }
  ACE_OS::strncat(buff, "\n",  BUFF_SIZE - 1);
  if (send_string(buff) < 0)
    return -1;

  for (it = vec.begin(); it != vec.end();)
  {
    if (!MyServerAppX::instance()->client_id_table().contains(it->client_id.as_string))
      it = vec.erase(it);
    else
      ++it;
  }

  if (vec.empty())
    return send_string("  no valid client_id(s) found\n>");

  if (send_string("  processing valid client_id(s):") < 0)
    return -1;
  buff[0] = 0;
  for (it = vec.begin(); it != vec.end(); ++it)
  {
    int len = strlen(buff);
    ACE_OS::snprintf(buff + len, BUFF_SIZE - 1 - len, " %s", it->client_id.as_string);
  }

  int message_len = strlen(buff) + 1;
  ACE_Message_Block * mb = MyMemPoolFactoryX::instance()->get_message_block(message_len);
  mb->copy(buff, message_len);


  ACE_OS::strncat(buff, "\n",  BUFF_SIZE - 1);
  if (send_string(buff) < 0)
    return -1;

  ACE_Time_Value tv(ACE_Time_Value::zero);
  if (MyServerAppX::instance()->heart_beat_module()->service()->putq(mb, &tv) == -1)
  {
    mb->release();
    return send_string("  Error: can not place the request message to target.\n>");
  }

  return send_string("  OK: request placed into target for later processing\n>");
}

int MyDistRemoteAccessProcessor::on_command_dist_batch_file_md5(char * /*parameter*/)
{
  return 0;
}

//MyDistRemoteAccessHandler//

MyDistRemoteAccessHandler::MyDistRemoteAccessHandler(MyBaseConnectionManager * xptr)
  : MyBaseHandler(xptr)
{
  m_processor = new MyDistRemoteAccessProcessor(this);
}


//MyDistRemoteAccessAcceptor//

MyDistRemoteAccessAcceptor::MyDistRemoteAccessAcceptor(MyBaseDispatcher * _dispatcher, MyBaseConnectionManager * manager)
  : MyBaseAcceptor(_dispatcher, manager)
{
  m_tcp_port = MyConfigX::instance()->remote_access_port;
  m_idle_time_as_dead = IDLE_TIME_AS_DEAD;
}

int MyDistRemoteAccessAcceptor::make_svc_handler(MyBaseHandler *& sh)
{
  sh = new MyDistRemoteAccessHandler(m_connection_manager);
  if (!sh)
  {
    MY_ERROR("can not alloc MyHeartBeatHandler from %s\n", name());
    return -1;
  }
  sh->parent((void*)this);
  sh->reactor(reactor());
  return 0;
}

const char * MyDistRemoteAccessAcceptor::name() const
{
  return "MyDistRemoteAccessAcceptor";
}


//MyDistRemoteAccessDispatcher//

MyDistRemoteAccessDispatcher::MyDistRemoteAccessDispatcher(MyBaseModule * pModule)
    : MyBaseDispatcher(pModule, 1)
{

}

const char * MyDistRemoteAccessDispatcher::name() const
{
  return "MyDistRemoteAccessDispatcher";
}


bool MyDistRemoteAccessDispatcher::on_start()
{
  add_acceptor(new MyDistRemoteAccessAcceptor(this, new MyBaseConnectionManager()));
  return true;
}


//MyDistRemoteAccessModule//

MyDistRemoteAccessModule::MyDistRemoteAccessModule(MyBaseApp * app) : MyBaseModule(app)
{

}

const char * MyDistRemoteAccessModule::name() const
{
  return "MyDistRemoteAccessModule";
}

bool MyDistRemoteAccessModule::on_start()
{
  add_dispatcher(new MyDistRemoteAccessDispatcher(this));
  return true;
}

/////////////////////////////////////
//dist to middle module
/////////////////////////////////////

//MyDistToMiddleProcessor//


MyDistToMiddleProcessor::MyDistToMiddleProcessor(MyBaseHandler * handler): MyBaseClientProcessor(handler)
{
  m_version_check_reply_done = false;
  m_local_addr[0] = 0;
}

int MyDistToMiddleProcessor::on_open()
{
  if (super::on_open() < 0)
    return -1;

  ACE_INET_Addr local_addr;
  if (m_handler->peer().get_local_addr(local_addr) == 0)
    local_addr.get_host_addr((char*)m_local_addr, IP_ADDR_LENGTH);

  return send_version_check_req();
}

MyBaseProcessor::EVENT_RESULT MyDistToMiddleProcessor::on_recv_header()
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
      MY_ERROR("failed to validate header for version check reply packet\n");
      return ER_ERROR;
    }
    return ER_OK;
  }

  if (m_packet_header.command == MyDataPacketHeader::CMD_HAVE_DIST_TASK)
  {
    MyHaveDistTaskProc proc;
    proc.attach((const char*)&m_packet_header);
    if (!proc.validate_header())
    {
      MY_ERROR("failed to validate header for dist task notify packet\n");
      return ER_ERROR;
    }
    return ER_OK;
  }

  MY_ERROR("unexpected packet header from dist server, header.command = %d\n", m_packet_header.command);
  return ER_ERROR;
}

MyBaseProcessor::EVENT_RESULT MyDistToMiddleProcessor::on_recv_packet_i(ACE_Message_Block * mb)
{
  MyBasePacketProcessor::on_recv_packet_i(mb);

  MyDataPacketHeader * header = (MyDataPacketHeader *)mb->base();

  if (header->command == MyDataPacketHeader::CMD_CLIENT_VERSION_CHECK_REPLY)
  {
    MyBaseProcessor::EVENT_RESULT result = do_version_check_reply(mb);
    MY_INFO("handshake response from middle server: %s\n", (result == ER_OK? "OK":"Failed"));
    if (result == ER_OK)
    {
      ((MyDistToMiddleHandler*)m_handler)->setup_timer();
      client_id_verified(true);
    }
    return result;
  }

  if (header->command == MyDataPacketHeader::CMD_HAVE_DIST_TASK)
  {
    MyBaseProcessor::EVENT_RESULT result = do_have_dist_task(mb);
    MY_INFO("got notification from middle server on new dist task\n");
    return result;
  }

  MyMessageBlockGuard guard(mb);
  MY_ERROR("unsupported command received @MyDistToMiddleProcessor::on_recv_packet_i(), command = %d\n",
      header->command);
  return ER_ERROR;
}

int MyDistToMiddleProcessor::send_server_load()
{
  if (!m_version_check_reply_done)
    return 0;

  ACE_Message_Block * mb = MyMemPoolFactoryX::instance()->get_message_block(sizeof(MyLoadBalanceRequest), MyDataPacketHeader::CMD_LOAD_BALANCE_REQ);
  MyLoadBalanceRequestProc proc;
  proc.attach(mb->base());
  proc.ip_addr(m_local_addr);
  proc.data()->clients_connected = MyServerAppX::instance()->heart_beat_module()->num_active_clients();
  MY_INFO("sending dist server load number [%d] to middle server...\n", proc.data()->clients_connected);
  return (m_handler->send_data(mb) < 0 ? -1: 0);
}

MyBaseProcessor::EVENT_RESULT MyDistToMiddleProcessor::do_version_check_reply(ACE_Message_Block * mb)
{
  MyMessageBlockGuard guard(mb);
  m_version_check_reply_done = true;

  const char * prefix_msg = "dist server version check reply:";
  MyClientVersionCheckReplyProc vcr;
  vcr.attach(mb->base());
  switch (vcr.data()->reply_code)
  {
  case MyClientVersionCheckReply::VER_OK:
    return MyBaseProcessor::ER_OK;

  case MyClientVersionCheckReply::VER_OK_CAN_UPGRADE:
    MY_INFO("%s get version can upgrade response\n", prefix_msg);
    return MyBaseProcessor::ER_OK;

  case MyClientVersionCheckReply::VER_MISMATCH:
    MY_ERROR("%s get version mismatch response\n", prefix_msg);
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

MyBaseProcessor::EVENT_RESULT MyDistToMiddleProcessor::do_have_dist_task(ACE_Message_Block * mb)
{
  ACE_Time_Value tv(ACE_Time_Value::zero);
  if (MyServerAppX::instance()->heart_beat_module()->service()->putq(mb, &tv) == -1)
  {
    MY_ERROR("can not put file md5 list message to disatcher's queue\n");
    mb->release();
  }
  return ER_OK;
}

int MyDistToMiddleProcessor::send_version_check_req()
{
  ACE_Message_Block * mb = make_version_check_request_mb();
  MyClientVersionCheckRequestProc proc;
  proc.attach(mb->base());
  proc.data()->client_version_major = 1;
  proc.data()->client_version_minor = 0;
  proc.data()->client_id = MyConfigX::instance()->middle_server_key.c_str();
  proc.data()->server_id = MyConfigX::instance()->server_id;
  MY_INFO("sending handshake request to middle server...\n");
  return (m_handler->send_data(mb) < 0? -1: 0);
}


//MyDistToMiddleHandler//

MyDistToMiddleHandler::MyDistToMiddleHandler(MyBaseConnectionManager * xptr): MyBaseHandler(xptr)
{
  m_processor = new MyDistToMiddleProcessor(this);
  m_load_balance_req_timer_id = -1;
}

void MyDistToMiddleHandler::setup_timer()
{
  ACE_Time_Value tv_start(ACE_Time_Value::zero);
  ACE_Time_Value interval(LOAD_BALANCE_REQ_INTERVAL * 60);
  m_load_balance_req_timer_id = reactor()->schedule_timer(this, (void*)LOAD_BALANCE_REQ_TIMER, tv_start, interval);
  if (m_load_balance_req_timer_id < 0)
    MY_ERROR(ACE_TEXT("MyDistToMiddleHandler setup load balance req timer failed, %s"), (const char*)MyErrno());
}

MyDistToMiddleModule * MyDistToMiddleHandler::module_x() const
{
  return (MyDistToMiddleModule *)connector()->module_x();
}

int MyDistToMiddleHandler::on_open()
{
  return 0;
}

int MyDistToMiddleHandler::handle_timeout(const ACE_Time_Value &current_time, const void *act)
{
  ACE_UNUSED_ARG(current_time);
  if (long(act) == LOAD_BALANCE_REQ_TIMER)
    return ((MyDistToMiddleProcessor*)m_processor)->send_server_load();
  else
  {
    MY_ERROR("unexpected timer call @MyDistToMiddleHandler::handle_timeout, timer id = %d\n", long(act));
    return 0;
  }
}

void MyDistToMiddleHandler::on_close()
{
  if (m_load_balance_req_timer_id >= 0)
    reactor()->cancel_timer(m_load_balance_req_timer_id);
}

PREPARE_MEMORY_POOL(MyDistToMiddleHandler);



//MyDistToMiddleConnector//

MyDistToMiddleConnector::MyDistToMiddleConnector(MyBaseDispatcher * _dispatcher, MyBaseConnectionManager * _manager):
    MyBaseConnector(_dispatcher, _manager)
{
  m_tcp_port = MyConfigX::instance()->middle_server_dist_port;
  m_reconnect_interval = RECONNECT_INTERVAL;
  m_tcp_addr = MyConfigX::instance()->middle_server_addr;
}

const char * MyDistToMiddleConnector::name() const
{
  return "MyDistToMiddleConnector";
}

int MyDistToMiddleConnector::make_svc_handler(MyBaseHandler *& sh)
{
  sh = new MyDistToMiddleHandler(m_connection_manager);
  if (!sh)
  {
    MY_ERROR("can not alloc MyDistToMiddleHandler from %s\n", name());
    return -1;
  }
//  MY_DEBUG("MyDistToMiddleConnector::make_svc_handler(%X)...\n", long(sh));
  sh->parent((void*)this);
  sh->reactor(reactor());
  return 0;
}


//MyDistToMiddleDispatcher//

MyDistToMiddleDispatcher::MyDistToMiddleDispatcher(MyBaseModule * pModule, int numThreads):
    MyBaseDispatcher(pModule, numThreads)
{
  m_connector = NULL;
  m_bs_connector = NULL;
  msg_queue()->high_water_mark(MSG_QUEUE_MAX_SIZE);
  m_to_bs_queue.high_water_mark(MSG_QUEUE_MAX_SIZE);
}

bool MyDistToMiddleDispatcher::on_start()
{
  if (!m_connector)
    m_connector = new MyDistToMiddleConnector(this, new MyBaseConnectionManager());
  add_connector(m_connector);
  if (!m_bs_connector)
    m_bs_connector = new MyDistToBSConnector(this, new MyBaseConnectionManager());
  add_connector(m_bs_connector);
  return true;
}

bool MyDistToMiddleDispatcher::on_event_loop()
{
  ACE_Time_Value tv(ACE_Time_Value::zero);
  ACE_Message_Block * mb;
  if (this->getq(mb, &tv) == 0)
    m_connector->connection_manager()->broadcast(mb);

  tv = ACE_Time_Value::zero;
  if (m_to_bs_queue.dequeue(mb, &tv) == 0)
    m_bs_connector->connection_manager()->broadcast(mb);

  return true;
}

const char * MyDistToMiddleDispatcher::name() const
{
  return "MyDistToMiddleDispatcher";
}

void MyDistToMiddleDispatcher::send_to_bs(ACE_Message_Block * mb)
{
  ACE_Time_Value tv(ACE_Time_Value::zero);
  if (m_to_bs_queue.enqueue(mb, &tv) == -1)
    mb->release();
}

void MyDistToMiddleDispatcher::send_to_middle(ACE_Message_Block * mb)
{
  ACE_Time_Value tv(ACE_Time_Value::zero);
  if (this->putq(mb, &tv) == -1)
    mb->release();
}

void MyDistToMiddleDispatcher::on_stop()
{
  m_connector = NULL;
  m_bs_connector = NULL;
}


//MyDistToMiddleModule//

MyDistToMiddleModule::MyDistToMiddleModule(MyBaseApp * app): MyBaseModule(app)
{
  m_dispatcher = NULL;
}

MyDistToMiddleModule::~MyDistToMiddleModule()
{

}

const char * MyDistToMiddleModule::name() const
{
  return "MyDistToMiddleModule";
}

void MyDistToMiddleModule::send_to_bs(ACE_Message_Block * mb)
{
  m_dispatcher->send_to_bs(mb);
}

void MyDistToMiddleModule::send_to_middle(ACE_Message_Block * mb)
{
  m_dispatcher->send_to_middle(mb);
}

bool MyDistToMiddleModule::on_start()
{
  add_dispatcher(m_dispatcher = new MyDistToMiddleDispatcher(this));
  return true;
}

void MyDistToMiddleModule::on_stop()
{
  m_dispatcher = NULL;
}
