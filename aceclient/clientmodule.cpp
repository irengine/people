/*
 * clientmodule.cpp
 *
 *  Created on: Jan 8, 2012
 *      Author: root
 */

#include "clientmodule.h"
#include "baseapp.h"

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
  virtual void on_new_connection(MyBaseHandler * handler)
  {
    MyBaseConnectionManager::on_new_connection(handler);
    ((MyTestClientToDistConnectionManager*)(handler->connection_manager()))->id_generator().get();
  }

  virtual void on_close_connection(MyBaseHandler *)
  {

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

MyBaseProcessor::EVENT_RESULT MyClientToDistProcessor::on_recv_header(const MyDataPacketHeader & header)
{
  if (MyBasePacketProcessor::on_recv_header(header) == ER_ERROR)
    return ER_ERROR;

  bool bVersionCheckReply = header.command == MyDataPacketHeader::CMD_CLIENT_VERSION_CHECK_REPLY; //m_version_check_reply_done
  if ((bVersionCheckReply && m_version_check_reply_done) || (!bVersionCheckReply && !m_version_check_reply_done))
  {
    MY_ERROR(ACE_TEXT("unexpected packet from dist server, version_check_reply_done = %d, "
                      "packet is version_check_reply = %d.\n"), m_version_check_reply_done, bVersionCheckReply);
    return ER_ERROR;
  }

  return ER_ERROR;
}

MyBaseProcessor::EVENT_RESULT MyClientToDistProcessor::on_recv_packet_i(ACE_Message_Block * mb)
{
  MyBasePacketProcessor::on_recv_packet_i(mb);

  MyDataPacketHeader * header = (MyDataPacketHeader *)mb->base();

  if (header->command == MyDataPacketHeader::CMD_CLIENT_VERSION_CHECK_REPLY)
    return do_version_check_reply(mb);

  MY_ERROR("unsupported command received, command = %d\n", header->command);
  return ER_ERROR;
}

int MyClientToDistProcessor::send_heart_beat()
{
  ACE_Message_Block * mb = MyMemPoolFactoryX::instance()->get_message_block(sizeof(MyDataPacketHeader));
  MyHeartBeatPingProc proc;
  proc.attach(mb->base());
  proc.init_header();
  mb->wr_ptr(sizeof(MyDataPacketHeader));
  return (m_handler->send_data(mb) < 0? -1: 0);
}

MyBaseProcessor::EVENT_RESULT MyClientToDistProcessor::do_version_check_reply(ACE_Message_Block * mb)
{
  const char * prefix_msg = "dist server version check reply:";
  MyClientVersionCheckReplyProc vcr;
  vcr.attach(mb->base());
  switch (vcr.data()->reply_code)
  {
  case MyClientVersionCheckReply::VER_OK:
    MY_ERROR("%s get version mismatch response\n", prefix_msg);
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
    MY_INFO("%s get server busy response\n", prefix_msg);
    return MyBaseProcessor::ER_ERROR;

  default: //server_list
    MY_ERROR("%s get unknown reply code = %d\n", prefix_msg, vcr.data()->reply_code);
    return MyBaseProcessor::ER_ERROR;
  }

}

MyBaseProcessor::EVENT_RESULT MyClientToDistProcessor::send_version_check_req()
{
  ACE_Message_Block * mb = make_version_check_request_mb();
  MyClientVersionCheckRequestProc proc;
  proc.attach(mb->base());
  proc.data()->client_version = const_client_version;
  proc.data()->client_id = m_client_id;

  if (m_handler->send_data(mb) < 0)
    return ER_ERROR;
  else
    return ER_OK;
}

/*
//MyPingSubmitter//

MyPingSubmitter::MyPingSubmitter()
{
  reset();
}

MyPingSubmitter::~MyPingSubmitter()
{
  if (m_current_block)
    m_current_block->release();
}

void MyPingSubmitter::reset()
{
  m_current_block = MyMemPoolFactoryX::instance()->get_message_block(BLOCK_SIZE);
  m_current_length = 0;
  m_current_ptr = m_current_block->base();
  m_last_add = 0;
}

void MyPingSubmitter::add_ping(const char * client_id, const int len)
{
  if (!client_id || !*client_id)
    return;
  if (len + m_current_length > BLOCK_SIZE)// not zero-terminated// - 1)
  {
    do_submit();
    m_last_add = g_clock_tick;
  }
  ACE_OS::memcpy(m_current_ptr, client_id, len);
  m_current_length += len;
  m_current_ptr += len;
  *(m_current_ptr - 1) = ';';
}

void MyPingSubmitter::do_submit()
{
  m_current_block->wr_ptr(m_current_length);
  //todo: do sumbit now
  m_current_block->release(); //just a test
  //
  reset();
}

void MyPingSubmitter::check_time_out()
{
  if (m_current_length == 0)
    return;
  if (g_clock_tick > m_last_add + 4)
    do_submit();
}
*/

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

int MyClientToDistHandler::open (void * p)
{
  if (MyBaseHandler::open(p) < 0)
    return -1;
  ACE_Time_Value interval (MyConfigX::instance()->client_heart_beat_interval);
  m_heat_beat_ping_timer_id = reactor()->schedule_timer(this, (void*)HEART_BEAT_PING_TIMER, interval, interval);
  if (m_heat_beat_ping_timer_id < 0)
    MY_ERROR(ACE_TEXT("MyClientToDistHandler setup heart beat timer failed, %s"), (const char*)MyErrno());

#ifdef MY_client_test
  const char * myid = ((MyTestClientToDistConnectionManager*)m_connection_manager)->id_generator().get();
  if (!myid)
  {
    MY_ERROR(ACE_TEXT("can not fetch a test client id @MyClientToDistHandler::open\n"));
    return -1;
  }
  ((MyClientToDistProcessor*)m_processor)->client_id(myid);
#endif

  return 0;
}

int MyClientToDistHandler::handle_timeout(const ACE_Time_Value &current_time, const void *act)
{
  ACE_UNUSED_ARG(current_time);
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
}

PREPARE_MEMORY_POOL(MyClientToDistHandler);


//MyClientToDistService//

MyClientToDistService::MyClientToDistService(MyBaseModule * module, int numThreads):
    MyBaseService(module, numThreads)
{

}

int MyClientToDistService::svc()
{
  ACE_DEBUG ((LM_DEBUG,
             ACE_TEXT ("(%P|%t) running svc()\n")));

  for (ACE_Message_Block *log_blk; getq (log_blk) != -1; )
  {
//    ACE_DEBUG ((LM_DEBUG,
//               ACE_TEXT ("(%P|%t) svc data from queue, size = %d\n"),
//               log_blk->size()));


    log_blk->release ();
  }
  ACE_DEBUG ((LM_DEBUG,
               ACE_TEXT ("(%P|%t) quitting svc()\n")));
  return 0;
}


//MyClientToDistConnector//

MyClientToDistConnector::MyClientToDistConnector(MyClientToDistModule * _module, MyBaseConnectionManager * _manager):
    MyBaseConnector(_module, _manager)
{
  m_tcp_port = MyConfigX::instance()->dist_server_heart_beat_port;
  m_tcp_addr = "localhost"; //todo
#ifdef MY_client_test
  m_num_connection = MyConfigX::instance()->test_client_connection_number;
#endif
}

int MyClientToDistConnector::make_svc_handler(MyBaseHandler *& sh)
{
  ACE_NEW_RETURN(sh, MyClientToDistHandler(m_connection_manager), -1);
  sh->reactor(reactor());
  return 0;
}

bool MyClientToDistConnector::before_reconnect()
{
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
  return true;
}


//MyClientToDistDispatcher//

MyClientToDistDispatcher::MyClientToDistDispatcher(MyBaseModule * pModule, int numThreads):
    MyBaseDispatcher(pModule, numThreads)
{
  m_connector = NULL;
}

/*
int MyClientToDistDispatcher::open(void * p)
{
  if (MyBaseDispatcher::open(p) == -1)
    return -1;
  m_connector = new MyClientToDistConnector((MyClientToDistModule *)m_module,
#ifdef MY_client_test
      new MyTestClientToDistConnectionManager(
          MyConfigX::instance()->test_client_start_client_id,
          MyConfigX::instance()->test_client_connection_number)
#else
      new MyBaseConnectionManager()
#endif
      );
  return 0;
}
*/

int MyClientToDistDispatcher::on_start()
{
  if (!m_connector)
    m_connector = new MyClientToDistConnector((MyClientToDistModule *)m_module,
#ifdef MY_client_test
         new MyTestClientToDistConnectionManager(
             MyConfigX::instance()->test_client_start_client_id,
             MyConfigX::instance()->test_client_connection_number));
#else
         new MyBaseConnectionManager());
#endif

  return m_connector->start();
}

void MyClientToDistDispatcher::on_stop()
{
  if (m_connector)
  {
    m_connector->stop();
    delete m_connector;
    m_connector = NULL;
  }
}


//MyClientToDistModule//

MyClientToDistModule::MyClientToDistModule(MyBaseApp * app): MyBaseModule(app)
{
  m_service = new MyClientToDistService(this, 1);
  m_dispatcher = new MyClientToDistDispatcher(this);
//  MyClientToDistProcessor::m_sumbitter = &m_ping_sumbitter;
}

MyClientToDistModule::~MyClientToDistModule()
{

}

MyDistServerAddrList & MyClientToDistModule::server_addr_list()
{
  return m_server_addr_list;
}


