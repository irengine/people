/*
 * distmodule.cpp
 *
 *  Created on: Jan 7, 2012
 *      Author: root
 */

#include "middlemodule.h"
#include "server.h"


//MyFindDistLoad//

class MyFindDistLoad
{
public:
  MyFindDistLoad(const char * addr)
  {
    m_addr = addr;
  }

  bool operator()(MyDistLoad& load) const
  {
    if (!m_addr)
      return false;
    return (strcmp(m_addr, load.m_ip_addr) == 0);
  }

private:
  const char * m_addr;
};


//MyDistLoads//

MyDistLoads::MyDistLoads()
{
  m_loads.reserve(4);
  m_server_list_length = 0;
  m_server_list[0] = 0;
}

void MyDistLoads::update(const MyDistLoad & load)
{
  if (load.m_ip_addr[0] == 0)
    return;
  ACE_MT(ACE_GUARD(ACE_Thread_Mutex, ace_mon, m_mutex));
  MyDistLoadVecIt it = find_i(load.m_ip_addr);
  if (it == m_loads.end())
    m_loads.push_back(load);
  else
  {
    it->clients_connected(load.m_clients_connected);
    it->m_last_access = g_clock_tick;
  }

  calc_server_list();
}

void MyDistLoads::remove(const char * addr)
{
  if (!addr || !*addr)
    return;
  ACE_MT(ACE_GUARD(ACE_Thread_Mutex, ace_mon, m_mutex));
  MyDistLoadVecIt it = find_i(addr);
  if (it == m_loads.end())
    return;
  m_loads.erase(it);

  calc_server_list();
}

MyDistLoads::MyDistLoadVecIt MyDistLoads::find_i(const char * addr)
{
  return find_if(m_loads.begin(), m_loads.end(), MyFindDistLoad(addr));
}

void MyDistLoads::calc_server_list()
{
  m_server_list[0] = 0;
  sort(m_loads.begin(), m_loads.end());
  MyDistLoadVecIt it;
  int remain_len = SERVER_LIST_LENGTH - 2;
  char * ptr = m_server_list;
  for (it = m_loads.begin(); it != m_loads.end(); ++it)
  {
    int len = strlen(it->m_ip_addr);
    if (len == 0)
      continue;
    if (len > remain_len)
      break;
    ACE_OS::memcpy(ptr, it->m_ip_addr, len + 1);
    ptr += len;
    *ptr = MyClientVersionCheckReply::SERVER_LIST_SEPERATOR;
    ++ptr;
  }
  *ptr = 0;

  m_server_list_length = ACE_OS::strlen(m_server_list);
  if (m_server_list_length > 0)
    ++m_server_list_length;
}

int MyDistLoads::get_server_list(char * buffer, int buffer_len)
{
  ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, m_mutex, 0);
  if (!buffer || buffer_len < m_server_list_length)
    return 0;
  ACE_OS::strsncpy(buffer, m_server_list, buffer_len);
  return m_server_list_length;
}

void MyDistLoads::scan_for_dead()
{
  ACE_MT(ACE_GUARD(ACE_Thread_Mutex, ace_mon, m_mutex));
  MyDistLoadVecIt it;
  for (it = m_loads.begin(); it != m_loads.end(); )
  {
    if (it->m_last_access + int(DEAD_TIME * 60 / MyBaseApp::CLOCK_INTERVAL) < g_clock_tick)
      it = m_loads.erase(it);
    else
      ++it;
  };

  calc_server_list();
}


//MyLocationProcessor//

MyDistLoads * MyLocationProcessor::m_dist_loads = NULL;

MyLocationProcessor::MyLocationProcessor(MyBaseHandler * handler): MyBaseServerProcessor(handler)
{

}

MyBaseProcessor::EVENT_RESULT MyLocationProcessor::on_recv_header(const MyDataPacketHeader & header)
{
  if (MyBaseServerProcessor::on_recv_header(header) == ER_ERROR)
    return ER_ERROR;

  if (header.command == MyDataPacketHeader::CMD_CLIENT_VERSION_CHECK_REQ)
    return ER_OK;

  return ER_ERROR;
}

MyBaseProcessor::EVENT_RESULT MyLocationProcessor::on_recv_packet_i(ACE_Message_Block * mb)
{
  MyBaseServerProcessor::on_recv_packet_i(mb);

  MyDataPacketHeader * header = (MyDataPacketHeader *)mb->base();
  if (header->command == MyDataPacketHeader::CMD_CLIENT_VERSION_CHECK_REQ)
    return do_version_check(mb);

  MY_ERROR("unsupported command received, command = %d\n", header->command);
  return ER_ERROR;
}


MyBaseProcessor::EVENT_RESULT MyLocationProcessor::do_version_check(ACE_Message_Block * mb)
{
  MyBaseProcessor::EVENT_RESULT ret = do_version_check_common(mb, MyServerAppX::instance()->client_id_table());
  if (ret != ER_CONTINUE)
    return ret;

  char server_list[MyDistLoads::SERVER_LIST_LENGTH];
  int len = m_dist_loads->get_server_list(server_list, MyDistLoads::SERVER_LIST_LENGTH); //double copy
  ACE_Message_Block * reply_mb = make_version_check_reply_mb(MyClientVersionCheckReply::VER_SERVER_LIST, len);

  MyClientVersionCheckReplyProc proc;
  proc.attach(reply_mb->base());
  proc.init_header(len);
  if (len > 0)
    ACE_OS::memcpy(proc.data()->data, server_list, len);
  reply_mb->wr_ptr(reply_mb->capacity());
  if (m_handler->send_data(reply_mb) <= 0)
    return ER_ERROR; //no unsent data, force a close
  else
    return ER_OK;
}


//MyLocationHandler//

MyLocationHandler::MyLocationHandler(MyBaseConnectionManager * xptr): MyBaseHandler(xptr)
{
  m_processor = new MyLocationProcessor(this);
}

PREPARE_MEMORY_POOL(MyLocationHandler);

//MyLocationService//

MyLocationService::MyLocationService(MyBaseModule * module, int numThreads):
    MyBaseService(module, numThreads)
{

}

int MyLocationService::svc()
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


//MyLocationAcceptor//

MyLocationAcceptor::MyLocationAcceptor(MyBaseDispatcher * _dispatcher, MyBaseConnectionManager * _manager):
    MyBaseAcceptor(_dispatcher, _manager)
{
  m_tcp_port = MyConfigX::instance()->dist_server_heart_beat_port;
  m_idle_time_as_dead = IDLE_TIME_AS_DEAD;
}

int MyLocationAcceptor::make_svc_handler(MyBaseHandler *& sh)
{
  sh = new MyLocationHandler(m_connection_manager);
  if (!sh)
  {
    MY_ERROR("can not alloc MyLocationHandler from %s\n", name());
    return -1;
  }
  sh->parent((void*)this);
  sh->reactor(reactor());
  return 0;
}

const char * MyLocationAcceptor::name() const
{
  return "MyLocationAcceptor";
}


//MyLocationDispatcher//

MyLocationDispatcher::MyLocationDispatcher(MyBaseModule * _module, int numThreads):
    MyBaseDispatcher(_module, numThreads)
{
  m_acceptor = NULL;
}

bool MyLocationDispatcher::on_start()
{
  if (!m_acceptor)
    m_acceptor = new MyLocationAcceptor(this, new MyBaseConnectionManager());
  add_acceptor(m_acceptor);
  return true;
}

void MyLocationDispatcher::on_stop()
{
  m_acceptor = NULL;
}

const char * MyLocationDispatcher::name() const
{
  return "MyLocationDispatcher";
}

//MyLocationModule//

MyLocationModule::MyLocationModule(MyBaseApp * app): MyBaseModule(app)
{
  m_service = NULL;
  m_dispatcher = NULL;
  MyLocationProcessor::m_dist_loads = &m_dist_loads;
}

MyLocationModule::~MyLocationModule()
{

}

MyDistLoads * MyLocationModule::dist_loads()
{
  return &m_dist_loads;
}

bool MyLocationModule::on_start()
{
  add_service(m_service = new MyLocationService(this, 1));
  add_dispatcher(m_dispatcher = new MyLocationDispatcher(this));
  return true;
}

void MyLocationModule::on_stop()
{
  m_service = NULL;
  m_dispatcher = NULL;
}

const char * MyLocationModule::name() const
{
  return "MyLocationModule";
}

//============================//
//http module stuff begins here
//============================//

//MyHttpProcessor//

MyHttpProcessor::MyHttpProcessor(MyBaseHandler * handler): MyBaseProcessor(handler)
{
  m_current_block = NULL;
}

MyHttpProcessor::~MyHttpProcessor()
{
  if (m_current_block)
    m_current_block->release();
}

int MyHttpProcessor::handle_input()
{
  const size_t BLOCK_SIZE = 4096;
  if (m_wait_for_close)
    return handle_input_wait_for_close();

  if (!m_current_block)
  {
    m_current_block = MyMemPoolFactoryX::instance()->get_message_block(BLOCK_SIZE);
    if (!m_current_block)
      return -1;
  }
  update_last_activity();
  if (mycomutil_recv_message_block(m_handler, m_current_block) < 0)
    return -1;
  if (m_current_block->length() > 0)
  {
    if (*(m_current_block->wr_ptr() - 1) == 0x10)
    {
      if (do_process_input_data())
      {
        ACE_Message_Block * reply_mb = MyMemPoolFactoryX::instance()->get_message_block(32);
        if (!reply_mb)
        {
          MY_ERROR(ACE_TEXT("failed to allocate 32 bytes sized memory block @MyHttpProcessor::handle_input().\n"));
          return -1;
        }
        m_wait_for_close = true;
        const char reply_str[] = "200 OK\r\n";
        const int reply_len = sizeof(reply_str) / sizeof(char);
        ACE_OS::strsncpy(reply_mb->base(), reply_str, reply_len);
        reply_mb->wr_ptr(reply_len);
        return (m_handler->send_data(reply_mb) <= 0 ? -1:0);
      } else
        return -1;
    }
  }

  if (m_current_block->length() == BLOCK_SIZE) //too large to fit in one block
    return -1; //todo: need to know the largest incoming data length

  return 0;
}

bool MyHttpProcessor::do_process_input_data()
{
  //todo: add logic here
  return true;
}

//MyHttpHandler//

MyHttpHandler::MyHttpHandler(MyBaseConnectionManager * xptr): MyBaseHandler(xptr)
{
  m_processor = new MyHttpProcessor(this);
}

PREPARE_MEMORY_POOL(MyHttpHandler);


//MyHttpAcceptor//

MyHttpAcceptor::MyHttpAcceptor(MyBaseDispatcher * _dispatcher, MyBaseConnectionManager * _manager):
    MyBaseAcceptor(_dispatcher, _manager)
{
  m_tcp_port = MyConfigX::instance()->http_port;
  m_idle_time_as_dead = IDLE_TIME_AS_DEAD;
}

int MyHttpAcceptor::make_svc_handler(MyBaseHandler *& sh)
{
  sh = new MyHttpHandler(m_connection_manager);
  if (!sh)
  {
    MY_ERROR("not enough memory to create MyHttpHandler object\n");
    return -1;
  }
  sh->parent((void*)this);
  sh->reactor(reactor());
  return 0;
}

const char * MyHttpAcceptor::name() const
{
  return "MyHttpAcceptor";
}


//MyHttpService//

MyHttpService::MyHttpService(MyBaseModule * module, int numThreads)
  : MyBaseService(module, numThreads)
{

}

int MyHttpService::svc()
{
  MY_INFO("running %s::svc()\n", name());

  for (ACE_Message_Block * mb; getq(mb) != -1; )
  {

  }

  MY_INFO("exiting %s::svc()\n", name());
  return 0;
};

const char * MyHttpService::name() const
{
  return "MyHttpService";
}

//MyHttpDispatcher//

MyHttpDispatcher::MyHttpDispatcher(MyBaseModule * pModule, int numThreads):
    MyBaseDispatcher(pModule, numThreads)
{
  m_acceptor = NULL;
}

const char * MyHttpDispatcher::name() const
{
  return "MyHttpDispatcher";
}

void MyHttpDispatcher::on_stop()
{
  m_acceptor = NULL;
}

bool MyHttpDispatcher::on_start()
{
  if (!m_acceptor)
    m_acceptor = new MyHttpAcceptor(this, new MyBaseConnectionManager());
  add_acceptor(m_acceptor);
  return true;
}


//MyHttpModule//

MyHttpModule::MyHttpModule(MyBaseApp * app): MyBaseModule(app)
{
  m_dispatcher = NULL;
  m_service = NULL;
}

MyHttpModule::~MyHttpModule()
{

}

const char * MyHttpModule::name() const
{
  return "MyHttpModule";
}

bool MyHttpModule::on_start()
{
  add_service(m_service = new MyHttpService(this, 1));
  add_dispatcher(m_dispatcher = new MyHttpDispatcher(this));
  return true;
}

void MyHttpModule::on_stop()
{
  m_dispatcher = NULL;
  m_service = NULL;
}


//============================//
//DistLoad module stuff begins here
//============================//

//MyDistLoadProcessor//

MyDistLoadProcessor::MyDistLoadProcessor(MyBaseHandler * handler): MyBaseServerProcessor(handler)
{
  m_client_id_verified = false;
  m_dist_loads = NULL;
}

MyDistLoadProcessor::~MyDistLoadProcessor()
{

}

void MyDistLoadProcessor::dist_loads(MyDistLoads * dist_loads)
{
  m_dist_loads = dist_loads;
}

MyBaseProcessor::EVENT_RESULT MyDistLoadProcessor::on_recv_header(const MyDataPacketHeader & header)
{
  if (super::on_recv_header(header) == ER_ERROR)
    return ER_ERROR;

  if (header.command == MyDataPacketHeader::CMD_CLIENT_VERSION_CHECK_REQ)
  {
    MyClientVersionCheckRequestProc proc;
    proc.attach((const char*)&header);
    bool result = proc.validate_data();
    if (!result)
    {
      MY_ERROR("bad load_balance package received from %s\n", info_string().c_str());
      return ER_ERROR;
    }
    return ER_OK;
  }

  if (header.command == MyDataPacketHeader::CMD_LOAD_BALANCE_REQ)
    return ER_OK;

  MY_ERROR(ACE_TEXT("unexpected packet header received @MyDistLoadProcessor.on_recv_header, cmd = %d\n"),
      header.command);
  return ER_ERROR;
}

MyBaseProcessor::EVENT_RESULT MyDistLoadProcessor::on_recv_packet_i(ACE_Message_Block * mb)
{
  MyBaseServerProcessor::on_recv_packet_i(mb);
  MyMessageBlockGuard guard(mb);

  MyDataPacketHeader * header = (MyDataPacketHeader *)mb->base();
  if (header->command == MyDataPacketHeader::CMD_CLIENT_VERSION_CHECK_REQ)
    return do_version_check(mb);

  if (header->command == MyDataPacketHeader::CMD_LOAD_BALANCE_REQ)
    return do_load_balance(mb);

  MY_ERROR("unsupported command received @MyDistLoadProcessor::on_recv_packet_i, command = %d\n",
      header->command);
  return ER_ERROR;
}

MyBaseProcessor::EVENT_RESULT MyDistLoadProcessor::do_version_check(ACE_Message_Block * mb)
{
  MyClientVersionCheckRequest * p = (MyClientVersionCheckRequest *) mb->base();
  m_client_id = "DistServer";
  bool result = (p->client_id == MyConfigX::instance()->middle_server_key.c_str());
  if (!result)
  {
    MY_ERROR("bad load_balance version check (bad key) received from %s\n", info_string().c_str());
    return ER_ERROR;
  }
  m_client_id_verified = true;
  return ER_OK;
}

bool MyDistLoadProcessor::client_id_verified() const
{
  return m_client_id_verified;
}

MyBaseProcessor::EVENT_RESULT MyDistLoadProcessor::do_load_balance(ACE_Message_Block * mb)
{
  MyLoadBalanceRequest * br = (MyLoadBalanceRequest *)mb->base();
  MyDistLoad dl;
  dl.clients_connected(br->clients_connected);
  dl.ip_addr(br->ip_addr);
  m_dist_loads->update(dl);
  return ER_OK;
}


//MyDistLoadHandler//

MyDistLoadHandler::MyDistLoadHandler(MyBaseConnectionManager * xptr): MyBaseHandler(xptr)
{
  m_processor = new MyDistLoadProcessor(this);
}

void MyDistLoadHandler::dist_loads(MyDistLoads * dist_loads)
{
  ((MyDistLoadProcessor*)m_processor)->dist_loads(dist_loads);
}

PREPARE_MEMORY_POOL(MyDistLoadHandler);

//MyDistLoadAcceptor//

MyDistLoadAcceptor::MyDistLoadAcceptor(MyBaseDispatcher * _dispatcher, MyBaseConnectionManager * _manager):
    MyBaseAcceptor(_dispatcher, _manager)
{
  m_tcp_port = MyConfigX::instance()->dist_server_heart_beat_port;
  m_idle_time_as_dead = IDLE_TIME_AS_DEAD;
}

int MyDistLoadAcceptor::make_svc_handler(MyBaseHandler *& sh)
{
  sh = new MyDistLoadHandler(m_connection_manager);
  if (!sh)
  {
    MY_ERROR("not enough memory to create MyDistLoadHandler object\n");
    return -1;
  }
  sh->parent((void*)this);
  sh->reactor(reactor());
  ((MyDistLoadHandler*)sh)->dist_loads(MyServerAppX::instance()->location_module()->dist_loads());
  return 0;
}

const char * MyDistLoadAcceptor::name() const
{
  return "MyDistLoadAcceptor";
}


//MyDistLoadDispatcher//

MyDistLoadDispatcher::MyDistLoadDispatcher(MyBaseModule * pModule, int numThreads):
    MyBaseDispatcher(pModule, numThreads)
{
  m_acceptor = NULL;
}

const char * MyDistLoadDispatcher::name() const
{
  return "MyDistLoadDispatcher";
}

int MyDistLoadDispatcher::handle_timeout(const ACE_Time_Value &, const void *)
{
  MyServerAppX::instance()->location_module()->dist_loads()->scan_for_dead();
  return 0;
}

void MyDistLoadDispatcher::on_stop()
{
  m_acceptor = NULL;
  reactor()->cancel_timer(this);
}

bool MyDistLoadDispatcher::on_start()
{
  if (!m_acceptor)
    m_acceptor = new MyDistLoadAcceptor(this, new MyBaseConnectionManager());
  add_acceptor(m_acceptor);

  ACE_Time_Value interval(int(MyDistLoads::DEAD_TIME * 60 / MyBaseApp::CLOCK_INTERVAL / 2));
  if (reactor()->schedule_timer(this, 0, interval, interval) == -1)
  {
    MY_ERROR("can not setup dist load server scan timer\n");
    return false;
  }
  return true;
}


//MyDistLoadModule//

MyDistLoadModule::MyDistLoadModule(MyBaseApp * app): MyBaseModule(app)
{
  m_dispatcher = NULL;
}

MyDistLoadModule::~MyDistLoadModule()
{

}

const char * MyDistLoadModule::name() const
{
  return "MyDistLoadModule";
}

bool MyDistLoadModule::on_start()
{
  add_dispatcher(m_dispatcher = new MyDistLoadDispatcher(this));
  return true;
}

void MyDistLoadModule::on_stop()
{
  m_dispatcher = NULL;
}
