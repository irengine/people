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
    it->clients_connected(load.m_clients_connected);

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

MyLocationAcceptor::MyLocationAcceptor(MyLocationModule * _module, MyBaseConnectionManager * _manager):
    MyBaseAcceptor(_module, _manager)
{
  m_tcp_port = MyConfigX::instance()->dist_server_heart_beat_port;
}

int MyLocationAcceptor::make_svc_handler(MyBaseHandler *& sh)
{
  ACE_NEW_RETURN(sh, MyLocationHandler(m_connection_manager), -1);
  sh->reactor(reactor());
  return 0;
}


//MyLocationDispatcher//

MyLocationDispatcher::MyLocationDispatcher(MyBaseModule * pModule, int numThreads):
    MyBaseDispatcher(pModule, numThreads)
{
  m_acceptor = NULL;
}

int MyLocationDispatcher::on_start()
{
  if (!m_acceptor)
    m_acceptor = new MyLocationAcceptor((MyLocationModule *)m_module, new MyBaseConnectionManager());
  return m_acceptor->start();
}

void MyLocationDispatcher::on_stop()
{
  if (m_acceptor)
  {
    m_acceptor->stop();
    delete m_acceptor;
    m_acceptor = NULL;
  }
}


//MyLocationModule//

MyLocationModule::MyLocationModule(MyBaseApp * app): MyBaseModule(app)
{
  m_service = new MyLocationService(this, 1);
  m_dispatcher = new MyLocationDispatcher(this);
  MyLocationProcessor::m_dist_loads = &m_dist_loads;
}

MyLocationModule::~MyLocationModule()
{

}


//============================//
//http module stuff begins here
//============================//

//MyHttpProcessor//

//MyPingSubmitter * MyHttpProcessor::m_sumbitter = NULL;

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

//MyHttpService//

MyHttpService::MyHttpService(MyBaseModule * module, int numThreads):
    MyBaseService(module, numThreads)
{

}

int MyHttpService::svc()
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


//MyHttpAcceptor//

MyHttpAcceptor::MyHttpAcceptor(MyHttpModule * _module, MyBaseConnectionManager * _manager):
    MyBaseAcceptor(_module, _manager)
{
  m_tcp_port = MyConfigX::instance()->dist_server_heart_beat_port;
}

int MyHttpAcceptor::make_svc_handler(MyBaseHandler *& sh)
{
  ACE_NEW_RETURN(sh, MyHttpHandler(m_connection_manager), -1);
  sh->reactor(reactor());
  return 0;
}


//MyHttpDispatcher//

MyHttpDispatcher::MyHttpDispatcher(MyBaseModule * pModule, int numThreads):
    MyBaseDispatcher(pModule, numThreads)
{

}

int MyHttpDispatcher::open(void * p)
{
  if (MyBaseDispatcher::open(p) == -1)
    return -1;
  m_acceptor = new MyHttpAcceptor((MyHttpModule *)m_module, new MyBaseConnectionManager());
  return 0;
}

void MyHttpDispatcher::on_stop()
{
  m_acceptor->stop();
  delete m_acceptor;
  m_acceptor = NULL;
}


//MyHttpModule//

MyHttpModule::MyHttpModule(MyBaseApp * app): MyBaseModule(app)
{
  m_service = new MyHttpService(this, 1);
  m_dispatcher = new MyHttpDispatcher(this);
//  MyHttpProcessor::m_sumbitter = &m_ping_sumbitter;
}

MyHttpModule::~MyHttpModule()
{

}
