/*
 * clientmodule.cpp
 *
 *  Created on: Jan 8, 2012
 *      Author: root
 */

#include "clientmodule.h"
#include "baseapp.h"
#include "client.h"

#ifdef MY_client_test

class MyTestClientToDistConnectionManager: public MyBaseConnectionManager
{
public:
  MyTestClientToDistConnectionManager(int64_t start_id, int count):m_id_generator(start_id, count)
  {}
  MyTestClientIDGenerator & id_generator()
  {
    return m_id_generator;
  }

private:
  MyTestClientIDGenerator m_id_generator;
};

#endif

//MyClientToDistProcessor//

//MyPingSubmitter * MyClientToDistProcessor::m_sumbitter = NULL;

MyClientToDistProcessor::MyClientToDistProcessor(MyBaseHandler * handler): MyBaseClientProcessor(handler)
{
  m_version_check_reply_done = false;
}

int MyClientToDistProcessor::on_open()
{
  if (super::on_open() < 0)
    return -1;

#ifdef MY_client_test
  const char * myid = ((MyTestClientToDistConnectionManager*)m_handler->connection_manager())->id_generator().get();
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
  m_handler->connection_manager()->set_connection_client_id_index(m_handler, m_client_id_index);
#endif

  return send_version_check_req();
}

MyBaseProcessor::EVENT_RESULT MyClientToDistProcessor::on_recv_header(const MyDataPacketHeader & header)
{
  MyBaseProcessor::EVENT_RESULT result = super::on_recv_header(header);
  if (result != ER_CONTINUE)
    return ER_ERROR;

  bool bVersionCheckReply = header.command == MyDataPacketHeader::CMD_CLIENT_VERSION_CHECK_REPLY; //m_version_check_reply_done
  if (bVersionCheckReply == m_version_check_reply_done)
  {
    MY_ERROR(ACE_TEXT("unexpected packet header from dist server, version_check_reply_done = %d, "
                      "packet is version_check_reply = %d.\n"), m_version_check_reply_done, bVersionCheckReply);
    return ER_ERROR;
  }

  if (bVersionCheckReply)
    return ER_OK;

  if (header.command == MyDataPacketHeader::CMD_SERVER_FILE_MD5_LIST)
    return ER_OK;

  MY_ERROR("unexpected packet header from dist server, header.command = %d\n", header.command);
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
      MY_ERROR("failed to put server file md5 list message block to service queue.\n");
      mb->release();
    }
    return ER_OK;
  }

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


MyDistServerAddrList::MyDistServerAddrList()
{
  m_index = -1;
}

void MyDistServerAddrList::addr_list(char *list)
{
  m_index = -1;
  m_server_addrs.clear();
  if (!list)
    return;

  char seperator[2] = {MyClientVersionCheckReply::SERVER_LIST_SEPERATOR, 0};
  char *str, *token, *saveptr;

//  ACE_WRITE_GUARD(ACE_RW_Thread_Mutex, ace_mon, m_mutex);
  for (str = list; ; str = NULL)
  {
    token = strtok_r(str, seperator, &saveptr);
    if (token == NULL)
      break;
    if (!*token)
      continue;
    m_server_addrs.push_back(token);
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
  ((MyTestClientToDistConnectionManager*)m_connection_manager)->id_generator().put
      (
        ((MyClientToDistProcessor*)m_processor)->client_id().as_string()
      );
#endif
  MY_INFO("MyClientToDistHandler::on_close. this = %d\n", long(this));
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
  MY_INFO("MyClientToDistService::svc() start\n");
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
  MY_INFO("MyClientToDistService::svc() end\n");
  return 0;
}

void MyClientToDistService::do_server_file_md5_list(ACE_Message_Block * mb)
{
  MyMessageBlockGuard guard(mb);

  MyServerFileMD5ListProc proc;
  proc.attach(mb->base());

#ifdef MY_client_test
  MyClientID client_id;

  if (!MyClientAppX::instance()->client_id_table().value(proc.data()->magic, &client_id))
  {
    MY_ERROR("can not find client_id @MyClientToDistService::do_server_file_md5_list(), index = %d\n",
        proc.data()->magic);
    return;
  }

  MY_DEBUG("do_server_file_md5_list: client_id =%s\n", client_id.as_string());

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

  MyFileMD5s md5s_server;
  md5s_server.base_dir(client_path_by_id);
  md5s_server.from_buffer(proc.data()->data);

  MyFileMD5s md5s_client;
  md5s_client.scan_directory(client_path_by_id);
  md5s_client.sort();

  md5s_server.minus(md5s_client);
  char temp[4096];
  if (md5s_server.to_buffer(temp, 4096, false))
    MY_INFO("md5 minus for client_id: [%s] = %s\n", client_id.as_string(), temp);

#else
  #error "client_id need to set globally"
#endif
}


//MyClientToDistConnector//

MyClientToDistConnector::MyClientToDistConnector(MyBaseDispatcher * _dispatcher, MyBaseConnectionManager * _manager):
    MyBaseConnector(_dispatcher, _manager)
{
  m_tcp_port = MyConfigX::instance()->dist_server_heart_beat_port;
  //m_tcp_addr = "localhost"; //todo
  m_reconnect_interval = 0;
#ifdef MY_client_test
  m_tcp_addr = MyConfigX::instance()->dist_server_addr;
  m_num_connection = MyConfigX::instance()->test_client_connection_number;
#endif
}

const char * MyClientToDistConnector::name() const
{
  return "MyClientToDistConnector";
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
#if 0
  if (m_reconnect_retry_count <= 3)
    return true;

  MyDistServerAddrList & addr_list = ((MyClientToDistModule*)(m_module))->server_addr_list();
  const char * new_addr = addr_list.next();
  if (new_addr && *new_addr)
  {
    MY_INFO("maximum connect to %s:%d retry count reached , now trying next addr %s:%d...\n",
        m_tcp_addr.c_str(), m_tcp_port, new_addr, m_tcp_port);
    m_tcp_addr = new_addr;
    m_reconnect_retry_count = 1;
  }
#endif
  return true;
}


//MyClientToDistDispatcher//

MyClientToDistDispatcher::MyClientToDistDispatcher(MyBaseModule * pModule, int numThreads):
    MyBaseDispatcher(pModule, numThreads)
{
  m_connector = NULL;
}

bool MyClientToDistDispatcher::on_start()
{
  if (!m_connector)
    m_connector = new MyClientToDistConnector(this,
#ifdef MY_client_test
         new MyTestClientToDistConnectionManager(
             MyConfigX::instance()->test_client_start_client_id,
             MyConfigX::instance()->test_client_connection_number));
#else
         new MyBaseConnectionManager());
#endif
  add_connector(m_connector);
  return true;
}

const char * MyClientToDistDispatcher::name() const
{
  return "MyClientToDistDispatcher";
}

void MyClientToDistDispatcher::on_stop()
{
  m_connector = NULL;
}


//MyClientToDistModule//

MyClientToDistModule::MyClientToDistModule(MyBaseApp * app): MyBaseModule(app)
{
  m_service = NULL;
  m_dispatcher = NULL;
}

MyClientToDistModule::~MyClientToDistModule()
{

}

const char * MyClientToDistModule::name() const
{
  return "MyClientToDistModule";
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
}


MyDistServerAddrList & MyClientToDistModule::server_addr_list()
{
  return m_server_addr_list;
}


