/*
 * distmodule.cpp
 *
 *  Created on: Jan 7, 2012
 *      Author: root
 */

#include "middlemodule.h"

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
  MyDistLoadVecIt it;
  int remain_len = MyClientVersionCheckReply::REPLY_DATA_LENGTH - 2;
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
}

void MyDistLoads::get_server_list(char * buffer, int buffer_len)
{
  if (!buffer || buffer_len <= 1)
    return;
  ACE_GUARD(ACE_Thread_Mutex, ace_mon, m_mutex);
  ACE_OS::strsncpy(buffer, m_server_list, buffer_len);
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
  MyBaseProcessor::EVENT_RESULT ret = do_version_check_common(mb);
  if (ret != ER_CONTINUE)
    return ret;
  ACE_Message_Block * reply_mb = make_version_check_reply_mb(MyClientVersionCheckReply::VER_SERVER_LIST);

  MyClientVersionCheckReplyProc proc;
  proc.attach(((const char*)reply_mb->base()));
  m_dist_loads->get_server_list(proc.data()->data, MyClientVersionCheckReply::REPLY_DATA_LENGTH);
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
  m_tcp_port = MyServerAppX::instance()->server_config().module_heart_beat_port;
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

}

int MyLocationDispatcher::open(void * p)
{
  if (MyBaseDispatcher::open(p) == -1)
    return -1;
  m_acceptor = new MyLocationAcceptor((MyLocationModule *)m_module, new MyBaseConnectionManager());
  return 0;
}

void MyLocationDispatcher::on_stop()
{
  m_acceptor->stop();
  delete m_acceptor;
  m_acceptor = NULL;
}


//MyLocationModule//

MyLocationModule::MyLocationModule()
{
  m_service = new MyLocationService(this, 1);
  m_dispatcher = new MyLocationDispatcher(this);
  MyLocationProcessor::m_dist_loads = &m_dist_loads;
}

MyLocationModule::~MyLocationModule()
{

}
