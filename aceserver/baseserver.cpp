#include "baseserver.h"


//MyClientInfos//

MyClientInfos::MyClientInfos()
{
  m_infos.reserve(1000);
}

bool MyClientInfos::contains(long id)
{
  return (index_of(id) >= 0);
}

MyBaseHandler * MyClientInfos::find_handler(long id)
{
  int index = index_of(id);
  if (index < 0 || index > (int)m_infos.size())
    return NULL;
  return m_infos[index].handler;
}
void MyClientInfos::set_handler(long id, MyBaseHandler * handler)
{
  int index = index_of(id);
  if (!(index >= 0 && index <(int)m_infos.size()))
    return;
  m_infos[index].handler = handler;
  /*
  ACE_GUARD(ACE_Thread_Mutex, ace_mon, m_mutex);
  ClientInfos_map::iterator it;
  int index = index_of_i(id, &it);
  bool bExisting = (index >= 0 && index <(int)m_infos.size());
  bool bRemove = (handler == NULL);
  if (bRemove)
  {
    if (!bExisting)
      return;
    m_infos[index].handler = handler;
    m_map.
  }else
  {
    m_infos[index].handler = handler;
  }
  */

}

void MyClientInfos::add(MyClientInfo aInfo)
{
  ACE_GUARD(ACE_Thread_Mutex, ace_mon, m_mutex);
  int index = index_of_i(aInfo.client_id_long);
  if (index >= 0)
    return;
  m_infos.push_back(aInfo);
  m_map[aInfo.client_id_long] = m_infos.size() - 1;
}

int MyClientInfos::index_of(long id)
{
  ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, m_mutex, -1);
  return index_of_i(id);
}

int MyClientInfos::index_of_i(long id, ClientInfos_map::iterator * pIt)
{
  ClientInfos_map::iterator it = m_map.find(id);
  if (pIt)
    *pIt = it;
  if (it == m_map.end())
    return -1;
  if (it->second < 0 || it->second >= (int)m_infos.size())
  {
    MY_ERROR("Invalid MyClientInfos map index = %d\n", it->second);
    return -1;
  }
  return it->second;
}


//MyBaseHandler//


MyBaseHandler::MyBaseHandler(MyBaseAcceptor * xptr)
{
  if (xptr)
    m_active_pointer = xptr->m_active_connections.end();
  m_client_id = 0;
}

MyBaseModule * MyBaseHandler::module_x() const
{
  return NULL;
}

MyBaseAcceptor * MyBaseHandler::acceptor() const
{
  return module_x()->dispatcher()->acceptor();
}

void MyBaseHandler::active_pointer(MyActiveConnectionPointer ptr)
{
  m_active_pointer = ptr;
}

MyActiveConnectionPointer MyBaseHandler::active_pointer()
{
  return m_active_pointer;
}

bool MyBaseHandler::client_id_verified() const
{
  return (m_client_id != MyClientInfo::INVALID_CLIENT_ID);
}

long MyBaseHandler::client_id() const
{
  return m_client_id;
}


int MyBaseHandler::open(void * p)
{
  if (super::open(p) == -1)
    return -1;
  acceptor()->on_new_connection(this);
  return 0;
}

int MyBaseHandler::handle_input (ACE_HANDLE)
{
  const size_t INPUT_SIZE = 4096;
  char buffer[INPUT_SIZE];
  ssize_t recv_cnt/*, send_cnt*/;

  recv_cnt = this->peer ().recv (buffer, sizeof(buffer));

  if (recv_cnt <= 0)
  {
//      ACE_DEBUG ((LM_DEBUG,
//                  ACE_TEXT ("(%P|%t) Connection closed\n")));
    return -1;
  }
//  ACE_DEBUG ((LM_DEBUG,
//            ACE_TEXT ("(%P|%t) handle_input, data size= %d\n"), recv_cnt));

  acceptor()->on_data_received(this, long(recv_cnt));
  //g_bytes += recv_cnt;
  ACE_Message_Block * mb;
  ACE_NEW_RETURN(mb, ACE_Message_Block (&buffer[0], recv_cnt), -1);
  ACE_Time_Value nowait (ACE_OS::gettimeofday());

  if (module_x()->service()->putq (mb, &nowait) == -1)
  {
    ACE_DEBUG ((LM_DEBUG,
              ACE_TEXT ("(%P|%t) handle_input.putq error.\n")));

    mb->release ();
    return 0;
  }
  return 0;
}

// Called when this handler is removed from the ACE_Reactor.
int MyBaseHandler::handle_close (ACE_HANDLE handle,
                          ACE_Reactor_Mask close_mask)
{
  ACE_UNUSED_ARG(handle);
  if (close_mask == ACE_Event_Handler::WRITE_MASK)
    return 0;

  acceptor()->on_close_connection(this);
  //here comes the tricky part, parent class will NOT call delete as it normally does
  //since we override the operator new/delete pair, the same thing parent class does
  //see ACE_Svc_Handler @ Svc_Handler.cpp
  //ctor: this->dynamic_ = ACE_Dynamic::instance ()->is_dynamic ();
  //destroy(): if (this->mod_ == 0 && this->dynamic_ && this->closing_ == false)
  //             delete this;
  //so do NOT use the normal method: return super::handle_close (handle, close_mask);
  //for it will cause memory leaks
  delete this;
  return 0;
  //return super::handle_close (handle, close_mask); //do NOT use
}

// Called when output is possible.
int MyBaseHandler::handle_output (ACE_HANDLE fd)
{
  ACE_UNUSED_ARG(fd);
  /*
  ACE_Message_Block *mb;
  ACE_Time_Value nowait (ACE_OS::gettimeofday ());
  while (-1 != this->getq (mb, &nowait))
  {
    ssize_t send_cnt =
      this->peer ().send (mb->rd_ptr (), mb->length ());
    if (send_cnt == -1)
      ACE_ERROR ((LM_ERROR,
                  ACE_TEXT ("(%P|%t) %p\n"),
                  ACE_TEXT ("send")));
    else
      mb->rd_ptr (send_cnt);
    if (mb->length () > 0)
    {
      this->ungetq (mb);
      break;
    }
    mb->release ();
  }
  return (this->msg_queue()->is_empty ()) ? -1 : 0;*/
  return -1;
}

MyBaseHandler::~MyBaseHandler()
{
  ACE_DEBUG ((LM_DEBUG,
              ACE_TEXT ("(%P|%t) deleting MyBaseHandler objects %X\n"),
              (long)this));
}


//MyBaseAcceptor//

int MyBaseAcceptor::num_connections() const
{
  return m_num_connections;
}

long MyBaseAcceptor::bytes_received() const
{
  return m_bytes_received;
}

long MyBaseAcceptor::bytes_processed() const
{
  return m_bytes_processed;
}

void MyBaseAcceptor::on_data_received(MyBaseHandler *, long data_size)
{
  m_bytes_received += data_size;
}

void MyBaseAcceptor::on_data_processed(MyBaseHandler *, long data_size)
{
  m_bytes_processed += data_size;
}

void MyBaseAcceptor::on_new_connection(MyBaseHandler * handler)
{
  if (handler == NULL)
    return;
  MyActiveConnectionPointer it = m_active_connections.insert(m_active_connections.end(), handler);
  handler->active_pointer(it);
//  handler->active_pointer()
  ++m_num_connections;
}

void MyBaseAcceptor::on_close_connection(MyBaseHandler * handler)
{
  if (handler == NULL)
    return;

  if (handler->client_id_verified())
  {
    //todo:
    m_client_infos.set_handler(handler->client_id(), NULL);
  }

  MyActiveConnectionPointer aPointer = handler->active_pointer();
  if (aPointer == m_active_connections.end())
    return;
  if (m_scan_pointer == aPointer)
    next_pointer();
  m_active_connections.erase(aPointer);
  --m_num_connections;
}

bool MyBaseAcceptor::next_pointer()
{
  if (m_scan_pointer == m_active_connections.end())
    m_scan_pointer = m_active_connections.begin();
  else
    ++m_scan_pointer;

  return m_scan_pointer == m_active_connections.end();
}


//MyBaseService//

MyBaseService::MyBaseService(MyBaseModule * module, int numThreads):
    m_module(module), m_numThreads(numThreads)
{

}

MyBaseModule * MyBaseService::module_x() const
{
  return m_module;
}

int MyBaseService::start()
{
  if (open(NULL) == -1)
    return -1;
  if (msg_queue()->deactivated())
    msg_queue()->activate();
  msg_queue()->flush();
  return activate (THR_NEW_LWP, m_numThreads);
}

int MyBaseService::stop()
{
  msg_queue()->deactivate();
  msg_queue()->flush();
  wait();
  return 0;
}


//MyBaseDispatcher//

MyBaseDispatcher::MyBaseDispatcher(MyBaseModule * pModule, int tcp_port, int numThreads):
    m_acceptor(NULL), m_module(pModule), m_numThreads(numThreads), m_numBatchSend(50), m_tcp_port(tcp_port)
{
  m_dev_reactor = NULL;
  m_reactor = NULL;
}

MyBaseDispatcher::~MyBaseDispatcher()
{
  //fixme: cleanup correctly
  if (m_acceptor)
    delete m_acceptor;
  if (m_reactor)
    delete m_reactor;
}

int MyBaseDispatcher::open (void *)
{
  if (m_dev_reactor != NULL)
    return -1;
//  m_dev_reactor = new ACE_Dev_Poll_Reactor(ACE::max_handles());
  m_reactor = new ACE_Reactor(new ACE_Dev_Poll_Reactor(ACE::max_handles()), true);
  reactor(m_reactor);
  m_acceptor = make_acceptor();
  if (m_acceptor == NULL)
    return -1;
  m_acceptor->reactor(m_reactor);

  ACE_INET_Addr port_to_listen (m_tcp_port);

  ACE_DEBUG ((LM_DEBUG,
             ACE_TEXT ("(%P|%t) listening on port: %d\n"),
             port_to_listen.get_port_number()));

  if (m_acceptor->open (port_to_listen, m_reactor) == -1)
    return -1;

  ACE_Time_Value initialDelay (5);
  ACE_Time_Value interval (5);
  m_reactor->schedule_timer (this,
                             0,
                             initialDelay,
                             interval);
  return 0;
}

int MyBaseDispatcher::start()
{
  if (open(NULL) == -1)
    return -1;
  msg_queue()->flush();
  return activate (THR_NEW_LWP, m_numThreads);
}

int MyBaseDispatcher::stop()
{
  wait();
  msg_queue()->flush();
  if (m_reactor)
    m_reactor->cancel_timer(this);
  if (m_acceptor)
    m_acceptor->close();
  if (m_reactor)
    m_reactor->close();

  delete m_acceptor;
  m_acceptor = NULL;
  delete m_reactor;
  m_reactor = NULL;

  return 0;
}


MyBaseAcceptor * MyBaseDispatcher::acceptor() const
{
  return m_acceptor;
}

int MyBaseDispatcher::svc()
{
  ACE_DEBUG ((LM_DEBUG,
             ACE_TEXT ("(%P|%t) entering MyBaseDispatcher::svc()\n")));

  while (m_module->is_running_app())
  {
    ACE_Time_Value timeout(2);
    int ret = m_acceptor->reactor()->handle_events (&timeout);
    if (ret == -1)
    {
      if (errno == EINTR)
        continue;
      break;
    }
  }
  ACE_DEBUG ((LM_DEBUG,
             ACE_TEXT ("(%P|%t) exiting MyBaseDispatcher::svc()\n")));
  return 0;
}



int MyBaseDispatcher::handle_timeout (const ACE_Time_Value &tv,
                            const void *act)
{
  ACE_UNUSED_ARG(tv);
  ACE_UNUSED_ARG(act);
  ACE_Message_Block *mb;
  ACE_Time_Value nowait (ACE_OS::gettimeofday ());
  int i = 0;
  while (-1 != this->getq (mb, &nowait))
  {/*
    ssize_t send_cnt =
      this->peer ().send (mb->rd_ptr (), mb->length ());
    if (send_cnt == -1)
      ACE_ERROR ((LM_ERROR,
                  ACE_TEXT ("(%P|%t) %p\n"),
                  ACE_TEXT ("send")));
    else
      mb->rd_ptr (send_cnt);
    if (mb->length () > 0)
      {
        this->ungetq (mb);
        break;
      }
    mb->release ();*/
    ++i;
    if (i >= m_numBatchSend)
      return 0;
  }
  ACE_DEBUG ((LM_DEBUG,
             ACE_TEXT ("(%P|%t) connections:=%d, received_bytes=%d, processed=%d\n"),
             acceptor()->num_connections(), acceptor()->bytes_received(), acceptor()->bytes_processed()));

  return 0;
//    return (this->msg_queue()->is_empty ()) ? -1 : 0;
}

MyBaseAcceptor * MyBaseDispatcher::make_acceptor()
{
  return NULL;
}


//MyBaseModule//

MyBaseModule::MyBaseModule(): m_service(NULL), m_dispatcher(NULL), m_running(false)
{

}

MyBaseModule::~MyBaseModule()
{
  stop();
  if (m_service)
    delete m_service;
  if (m_dispatcher)
    delete m_dispatcher;
}

bool MyBaseModule::is_running() const
{
  return m_running;
}

bool MyBaseModule::is_running_app() const
{
  return (m_running && MyServerAppX::instance()->running());
}

MyBaseDispatcher * MyBaseModule::dispatcher() const
{
  return m_dispatcher;
}

MyBaseService * MyBaseModule::service() const
{
  return m_service;
}

int MyBaseModule::start()
{
  if (m_running)
    return 0;
  m_running = true;
  if (m_service->start() == -1)
  {
    m_running = false;
    return -1;
  }

  if (m_dispatcher)
  {
    if (m_dispatcher->start() == -1)
    {
      m_running = false;
      m_service->stop();
      return -1;
    }
  }
  return 0;
}

int MyBaseModule::stop()
{
  if (!m_running)
    return 0;
  m_running = false;
  m_service->stop();
  if (m_dispatcher)
    m_dispatcher->stop();
  return 0;
}
