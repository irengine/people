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

MyDistClient::MyDistClient(MyHttpDistInfo * _dist_info)
{
  dist_info = _dist_info;
  status = -1;
  last_update = 0;
  m_client_id_index = -1;
}

bool MyDistClient::check_valid() const
{
  return ((dist_info != NULL) && (status >= 0 && status <= 4) && (!client_id.is_null()));
}

bool MyDistClient::active()
{
  return g_client_id_table->active(client_id, m_client_id_index);
}

void MyDistClient::update_status(int _status)
{
  if (_status > status)
    status = _status;
}

void MyDistClient::update_md5_list(const char * _md5)
{
  if (unlikely(!dist_info->need_md5()))
  {
    MY_WARNING("got unexpected md5 reply packet on client_id(%s) dist_id(%s)\n",
        client_id.as_string(), dist_info->ver.data());
    return;
  }

  if (unlikely(md5.data() && md5.data()[0]))
    return;

  md5.init_from_string(_md5);
  update_status(2);
}

int MyDistClient::dist_file(MyDistClients & dist_clients)
{
  if (!active())
    return 0;

  switch (status)
  {
  case 0:
    return do_stage_0(dist_clients);

  case 1:
    return do_stage_1(dist_clients);

  case 2:
    return do_stage_2(dist_clients);

  case 3:
    return do_stage_3(dist_clients);

  case 4:
    return do_stage_4(dist_clients);

  default:
    MY_ERROR("unexpected status value = %d @MyDistClient::dist_file\n", status);
    return 0;
  }
}

int MyDistClient::do_stage_0(MyDistClients & dist_clients)
{
  if (dist_info->need_md5())
    return send_md5();

  return send_ftp();
}

int MyDistClient::do_stage_1(MyDistClients & dist_clients)
{

  return 0;
}

int MyDistClient::do_stage_2(MyDistClients & dist_clients)
{
  return 0;
}

int MyDistClient::do_stage_3(MyDistClients & dist_clients)
{

  return 0;
}

int MyDistClient::do_stage_4(MyDistClients & dist_clients)
{
  return 0;
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

int MyDistClient::send_md5()
{
  if (!dist_info->md5.data() || !dist_info->md5.data()[0] || dist_info->md5_len <= 0)
    return 0;

  int data_len = dist_out_leading_length() + dist_info->md5_len;
  int total_len = sizeof(MyServerFileMD5List) + data_len;
  ACE_Message_Block * mb = MyMemPoolFactoryX::instance()->get_message_block(total_len, MyDataPacketHeader::CMD_SERVER_FILE_MD5_LIST);
  MyServerFileMD5List * md5_packet = (MyServerFileMD5List *)mb->base();
  md5_packet->magic = m_client_id_index;
  dist_out_leading_data(md5_packet->data);
  ACE_OS::memcpy(md5_packet->data + data_len - dist_info->md5_len, dist_info->md5.data(), dist_info->md5_len);

  ACE_Time_Value tv(ACE_Time_Value::zero);
  if (MyServerAppX::instance()->heart_beat_module()->dispatcher()->putq(mb, &tv) == -1)
  {
    MY_ERROR("can not put file md5 list message to disatcher's queue\n");
    mb->release();
    return -1;
  } else
  {
    MyServerAppX::instance()->db().set_dist_client_status(*this, 1);
    status = 1;
    return 1;
  }
}

int MyDistClient::send_ftp()
{
  if (!dist_info->need_md5())
  {
    if (!dist_info->is_cmp_done())
      return 0;

    const char * ftp_file_name = MyDistCompressor::all_in_one_mbz();
    int leading_length = dist_out_leading_length();
    int ftp_file_name_len = ACE_OS::strlen(ftp_file_name) + 1;
    int data_len = leading_length + ftp_file_name_len + dist_info->password_len + 1;
    int total_len = sizeof(MyFtpFile) + data_len;
    ACE_Message_Block * mb = MyMemPoolFactoryX::instance()->get_message_block(total_len, MyDataPacketHeader::CMD_FTP_FILE);
    MyFtpFile * packet = (MyFtpFile *)mb->base();
    packet->magic = m_client_id_index;
    dist_out_leading_data(packet->data);
    ACE_OS::memcpy(packet->data + leading_length, ftp_file_name, ftp_file_name_len);
    packet->data[leading_length + ftp_file_name_len - 1] = MyDataPacketHeader::FINISH_SEPARATOR;
    ACE_OS::memcpy(packet->data + leading_length + ftp_file_name_len, dist_info->password.data(), dist_info->password_len + 1);

    ACE_Time_Value tv(ACE_Time_Value::zero);
    if (MyServerAppX::instance()->heart_beat_module()->dispatcher()->putq(mb, &tv) == -1)
    {
      MY_ERROR("can not put file md5 list message to disatcher's queue\n");
      mb->release();
      return -1;
    } else
    {
      MyServerAppX::instance()->db().set_dist_client_status(*this, 1);
      status = 1;
      return 1;
    }
  }

  //todo: handle ftp of need md5
  return 0;
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
  MyDistClientList x;
  x.swap(dist_clients);
  db_time = 0;
}

bool MyDistClients::add(MyDistClient * dc)
{
  if (unlikely(!dc->check_valid()))
  {
    MyPooledObjectDeletor dt;
    dt(dc);
    return false;
  }
  dist_clients.push_back(dc);
  return true;
}

MyHttpDistInfo * MyDistClients::find(const char * dist_id)
{
  MY_ASSERT_RETURN(m_dist_infos, "", NULL);
  return m_dist_infos->find(dist_id);
}

MyDistClient * MyDistClients::find(const char * client_id, const char * dist_id)
{
  MyDistClientList::iterator it; //todo optimize
  for (it = dist_clients.begin(); it != dist_clients.end(); ++ it)
  {
    if (ACE_OS::strcmp((*it)->client_id.as_string(), client_id) == 0 &&
        ACE_OS::strcmp((*it)->dist_info->ver.data(), dist_id) == 0)
      return *it;
  }
  return NULL;
}

void MyDistClients::dist_files()
{
  int count = dist_clients.size();
  for (int i = 0; i < count; ++ i)
    dist_clients[i]->dist_file(*this);
}


//MyClientFileDistributor//

MyClientFileDistributor::MyClientFileDistributor(): m_dist_clients(&m_dist_infos)
{

}

bool MyClientFileDistributor::distribute()
{
  bool reload = m_dist_infos.need_reload();

  check_dist_info(reload);
  return check_dist_clients(reload);
}

bool MyClientFileDistributor::check_dist_info(bool reload)
{
  if (reload)
  {
    m_dist_infos.prepare_update();
    if (MyServerAppX::instance()->db().load_dist_infos(m_dist_infos) <= 0)
      return true;
  }

  int count = m_dist_infos.dist_infos.size();
  bool result = false;
  for (int i = count - 1; i >= 0; -- i)
    if (check_dist_info_one(m_dist_infos.dist_infos[i]))
      result = true;

  return result;
}

bool MyClientFileDistributor::check_dist_info_one(MyHttpDistInfo * info)
{
  if (unlikely(!info))
    return false;
  MyDB & db = MyServerAppX::instance()->db();
  if (info->cmp_needed)
  {
    if (db.dist_take_cmp_ownership(info))
    {
      MyHttpDistRequest http_dist_request(*info);
      MyDistCompressor compressor;
      if (!compressor.compress(http_dist_request))
        return false;
    }
    info->cmp_done[0] = '1';
    db.dist_mark_cmp_done(info->ver.data());
    info->cmp_needed = false;
  }

  if (info->md5_needed)
  {
    if (db.dist_take_md5_ownership(info))
    {
      MyHttpDistRequest http_dist_request(*info);
      MyDistMd5Calculator calc;
      if (!calc.calculate(http_dist_request, info->md5, info->md5_len))
        return false;
    }
    info->md5_needed = false;
  }

  return true;
}

bool MyClientFileDistributor::check_dist_clients(bool reload)
{
  if (reload)
  {
    m_dist_clients.clear();
    if (!MyServerAppX::instance()->db().load_dist_clients(&m_dist_clients))
      return false;
  }

  m_dist_clients.dist_files();
  return true;
}

void MyClientFileDistributor::dist_ftp_file_reply(const char * client_id, const char * dist_id, int _status)
{
  MyDistClient * dc = m_dist_clients.find(client_id, dist_id);
  int new_status = (_status == 1)? 5:4;
  if (likely(dc != NULL))
    dc->update_status(_status);
  if (new_status != 5)
    MyServerAppX::instance()->db().set_dist_client_status(client_id, dist_id, _status);
  else
    MyServerAppX::instance()->db().delete_dist_client(client_id, dist_id);
  //todo: notify bs about progress
}

void MyClientFileDistributor::dist_ftp_md5_reply(const char * client_id, const char * dist_id, const char * md5list)
{
  MyDistClient * dc = m_dist_clients.find(client_id, dist_id);
  if (likely(dc != NULL))
    dc->update_md5_list(md5list);
  MyServerAppX::instance()->db().set_dist_client_md5(client_id, dist_id, md5list, 2);
  //todo: generate mbz and notifify client to download
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
  if (ret != ER_CONTINUE)
    return ret;

  {
    MyPooledMemGuard info;
    info_string(info);
    MY_INFO(ACE_TEXT("client version check ok: %s\n"), info.data());
  }

  m_ip_ver_submitter->add_data(m_client_id.as_string(), m_client_id_length, m_peer_addr, m_client_version.to_string());

  MyClientInfo client_info;
  client_id_table.value_all(m_client_id_index, client_info);

  ACE_Message_Block * reply_mb;
  if (m_client_version < MyConfigX::instance()->client_version_minimum)
    reply_mb = make_version_check_reply_mb(MyClientVersionCheckReply::VER_MISMATCH, client_info.password_len + 1);
  else if (m_client_version < MyConfigX::instance()->client_version_current)
    reply_mb = make_version_check_reply_mb(MyClientVersionCheckReply::VER_OK_CAN_UPGRADE, client_info.password_len + 1);
  else
    reply_mb = make_version_check_reply_mb(MyClientVersionCheckReply::VER_OK, client_info.password_len + 1);

  MyClientVersionCheckReply * vcr = (MyClientVersionCheckReply *) reply_mb->base();
  ACE_OS::memcpy(vcr->data, client_info.ftp_password, client_info.password_len + 1);
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


//MyAccumulatorBlock//

MyAccumulatorBlock::MyAccumulatorBlock(int block_size, int max_item_length)
{
  m_current_block = NULL;
  m_block_size = block_size;
  m_max_item_length = max_item_length + 1;
  reset();
}

MyAccumulatorBlock::~MyAccumulatorBlock()
{
  if (m_current_block)
    m_current_block->release();
}

void MyAccumulatorBlock::reset()
{
  if (unlikely(!m_current_block))
    m_current_block = MyMemPoolFactoryX::instance()->get_message_block(m_block_size);
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
    MY_FATAL("expected long item @MyAccumulatorBlock::add(), remain_len=%d, item=%s\n", remain_len, item);
    return false;
  }
  ACE_OS::memcpy(m_current_ptr, item, len - 1);
  m_current_ptr += len;
  *(m_current_ptr - 1) = ITEM_SEPARATOR;
  return (remain_len - len > m_max_item_length);
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
  reset();
}

void MyBaseSubmitter::submit()
{
  do_submit();
  reset();
}

void MyBaseSubmitter::check_time_out()
{

}

void MyBaseSubmitter::do_submit()
{

}

void MyBaseSubmitter::reset()
{

};


//MyPingSubmitter//

MyPingSubmitter::MyPingSubmitter(): m_block(BLOCK_SIZE, sizeof(MyClientID))
{

}

MyPingSubmitter::~MyPingSubmitter()
{

}

void MyPingSubmitter::reset()
{
  m_block.reset();
}

void MyPingSubmitter::add_ping(const char * client_id, const int len)
{
  if (unlikely(!client_id || !*client_id || len <= 0))
    return;
  if (!m_block.add(client_id, len))
    submit();
}

void MyPingSubmitter::do_submit()
{
  int len = m_block.data_len();
  if (unlikely(len == 0))
    return;
  ACE_Message_Block * mb = MyMemPoolFactoryX::instance()->get_message_block_bs(len, MY_BS_HEART_BEAT_CMD);
  ACE_OS::memcpy(mb->base() + MyBSBasePacket::DATA_OFFSET, m_block.data(), len);
  MyServerAppX::instance()->dist_to_middle_module()->send_to_bs(mb);
}

void MyPingSubmitter::check_time_out()
{
  if (m_block.data_len() == 0)
    return;
  submit();
}


//MyIPVerSubmitter//

MyIPVerSubmitter::MyIPVerSubmitter():
    m_id_block(BLOCK_SIZE, sizeof(MyClientID)),
    m_ip_block(BLOCK_SIZE, INET_ADDRSTRLEN),
    m_ver_block(BLOCK_SIZE * 7 / sizeof(MyClientID) + 1, 7)
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

void MyIPVerSubmitter::check_time_out()
{
  if (m_ip_block.data_len() == 0)
    return;
  submit();
}


void MyIPVerSubmitter::do_submit()
{
  int id_len = m_id_block.data_len();
  if (unlikely(id_len == 0))
    return;
  int ip_len = m_ip_block.data_len();
  int ver_len = m_ver_block.data_len();
  ACE_Message_Block * mb = MyMemPoolFactoryX::instance()->get_message_block_bs(
      id_len + ip_len + ver_len + 2, MY_BS_IP_VER_CMD);
  char * dest = mb->base() + MyBSBasePacket::DATA_OFFSET;
  ACE_OS::memcpy(dest, m_id_block.data(), id_len);
  dest[id_len] = MyBSBasePacket::BS_PARAMETER_SEPARATOR;
  ACE_OS::memcpy(dest + id_len + 1, m_ip_block.data(), ip_len);
  dest[id_len + 1 + ip_len] = MyBSBasePacket::BS_PARAMETER_SEPARATOR;
  ACE_OS::memcpy(dest + id_len + 1 + ip_len + 1, m_ver_block.data(), ver_len);
  MyServerAppX::instance()->dist_to_middle_module()->send_to_bs(mb);
}


void MyIPVerSubmitter::reset()
{
  m_id_block.reset();
  m_ip_block.reset();
  m_ver_block.reset();
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

  MY_INFO("exiting %s::svc()\n", name());
  return 0;
}

void MyHeartBeatService::do_have_dist_task()
{
  m_distributor.distribute();
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
  if (unlikely(dpe->data[len - 3] != MyDataPacketHeader::ITEM_SEPARATOR))
  {
    MY_ERROR("bad ftp file reply packet @%s::do_ftp_file_reply()\n", name());
    return;
  }
  dpe->data[len - 3] = 0;
  if (unlikely(!dpe->data[0]))
  {
    MY_ERROR("bad ftp file reply packet @%s::do_ftp_file_reply(), no dist_id\n", name());
    return;
  }

  const char * dist_id = dpe->data;
  int status = (dpe->data[len - 2] == '0' ? 0 : 1);
  m_distributor.dist_ftp_file_reply(client_id.as_string(), dist_id, status);
  MY_DEBUG("ftp download completed client_id(%s) dist_id(%s)\n", client_id.as_string(), dist_id);
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

void MyHeartBeatService::calc_server_file_md5_list(ACE_Message_Block * mb)
{
  MyMessageBlockGuard guard(mb);

  if (mb->size() <= 0)
    return;

  const char *seperator = "% #,*";
  char *str, *token, *saveptr;

  for (str = mb->base(); ; str = NULL)
  {
    token = strtok_r(str, seperator, &saveptr);
    if (token == NULL)
      break;
    if (!*token)
      continue;
    calc_server_file_md5_list_one(token);
  }
}

void MyHeartBeatService::calc_server_file_md5_list_one(const char * client_id)
{
  MyClientID id(client_id);
  int index = MyServerAppX::instance()->client_id_table().index_of(id);
  if (index < 0)
  {
    MY_ERROR("invalid client id = %s\n", client_id);
    return;
  }

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
  MyTestClientPathGenerator::client_id_to_path(id.as_string(), client_path_by_id + len, PATH_MAX - 1 - len);

  MyFileMD5s md5s_server;
  md5s_server.calculate(client_path_by_id, NULL, false);
  md5s_server.sort();
  if (!module_x()->running_with_app())
    return;
  int buff_len = md5s_server.total_size(true);
  ACE_Message_Block * mb = make_server_file_md5_list_mb(buff_len, index);
  md5s_server.to_buffer(mb->base() + sizeof(MyServerFileMD5List), buff_len, true);
  ACE_Time_Value tv(ACE_Time_Value::zero);
  if (((MyHeartBeatModule*)module_x())->dispatcher()->putq(mb, &tv) == -1)
  {
    MY_ERROR("can not put file md5 list message to disatcher's queue\n");
    mb->release();
  }
}

ACE_Message_Block * MyHeartBeatService::make_server_file_md5_list_mb(int list_len, int client_id_index)
{
  ACE_Message_Block * mb = MyMemPoolFactoryX::instance()->get_message_block(sizeof(MyServerFileMD5List) + list_len, MyDataPacketHeader::CMD_SERVER_FILE_MD5_LIST);
  MyServerFileMD5List * pkt = (MyServerFileMD5List *) mb->base();
  pkt->magic = client_id_index;
  return mb;
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
      if (mb->size() < sizeof(MyDataPacketHeader))
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
  //MyBSBasePacket * bspacket = (MyBSBasePacket *) mb->base();
  MY_INFO("got a bs reply packet:%s\n", mb->base());
  return ER_OK;
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
