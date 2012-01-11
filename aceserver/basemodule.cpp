#include "basemodule.h"
#include "baseapp.h"

//MyMemPoolFactory//

MyMemPoolFactory::MyMemPoolFactory()
{
//  m_header_pool = NULL;
//  m_four_k_pool = NULL;
  m_message_block_pool = NULL;
  m_data_block_pool = NULL;
  m_use_mem_pool = false;
}

MyMemPoolFactory::~MyMemPoolFactory()
{
  if (m_message_block_pool)
    delete m_message_block_pool;
  if (m_data_block_pool)
    delete m_data_block_pool;
  for (size_t i = 0; i < m_pools.size(); ++i)
    delete m_pools[i];
}

void MyMemPoolFactory::init(MyConfig * config)
{
  m_use_mem_pool = config->use_mem_pool;
  if (!m_use_mem_pool)
    return;

  const int pool_size[] = {32, 64, 128, 256, 512, 1024, 2048, 4096};
  //todo: change default pool size
  int count = sizeof(pool_size) / sizeof(int);
  m_pools.reserve(count);
  for (size_t i = 0; i < sizeof(pool_size) / sizeof(int); ++i)
    m_pools.push_back(new My_Cached_Allocator<ACE_Thread_Mutex>
      (/*config->module_heart_beat_mem_pool_size*/ 3000, pool_size[i]));
//todo: change default pool's chunk number
  m_message_block_pool = new My_Cached_Allocator<ACE_Thread_Mutex>
    (config->message_control_block_mem_pool_size, sizeof(ACE_Message_Block));
  m_data_block_pool = new My_Cached_Allocator<ACE_Thread_Mutex>
    (config->message_control_block_mem_pool_size, sizeof(ACE_Data_Block));
}

ACE_Message_Block * MyMemPoolFactory::get_message_block(int capacity)
{
  if (capacity <= 0)
  {
    MY_ERROR(ACE_TEXT("calling MyMemPoolFactory::get_message_block() with capacity <= 0 (= %d).\n"), capacity);
    return NULL;
  }
  if (!m_use_mem_pool)
    return new ACE_Message_Block(capacity);
  int count = m_pools.size();
  for (int i = 0; i < count; ++i)
  {
    MY_INFO("i = %d, capacity = %d, m_pools[i]->chunk_size() = %d\n", i, capacity, m_pools[i]->chunk_size());
    if (size_t(capacity) <= m_pools[i]->chunk_size())
    {
      void * p = m_message_block_pool->malloc();
      ACE_Message_Block * result = new (p) MyCached_Message_Block(capacity, m_pools[i], m_data_block_pool, m_message_block_pool);
//      result->set_self_flags(ACE_Message_Block::USER_FLAGS);
      return result;
    }
  }
  return new ACE_Message_Block(capacity);
}


//MyClientInfos//

MyClientIDTable::MyClientIDTable()
{
  m_table.reserve(1000);
}

bool MyClientIDTable::contains(const MyClientID & id)
{
  return (index_of(id) >= 0);
}

/*
MyBaseHandler * MyClientIDTable::find_handler(long id)
{
  int index = index_of(id);
  if (index < 0 || index > (int)m_table.size())
    return NULL;
  return m_table[index].handler;
}

void MyClientIDTable::set_handler(long id, MyBaseHandler * handler)
{
  int index = index_of(id);
  if (!(index >= 0 && index <(int)m_table.size()))
    return;
  m_table[index].handler = handler;
========================
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


}
*/

void MyClientIDTable::add_i(const MyClientID & id)
{
  int index = index_of_i(id);
  if (index >= 0)
    return;
  m_table.push_back(id);
  m_map[id] = m_table.size() - 1;
}

void MyClientIDTable::add(const MyClientID &id)
{
  ACE_WRITE_GUARD(ACE_RW_Thread_Mutex, ace_mon, m_mutex);
  add_i(id);
}

void MyClientIDTable::add(const char * str_id)
{
  if (!str_id)
    return;
  MyClientID id(str_id);
  ACE_WRITE_GUARD(ACE_RW_Thread_Mutex, ace_mon, m_mutex);
  add_i(id);
}

void MyClientIDTable::add_batch(char * idlist)
{
  if (!idlist)
    return;
  const char * CONST_seperator = ";\r\n\t ";
  char *str, *token, *saveptr;

  ACE_WRITE_GUARD(ACE_RW_Thread_Mutex, ace_mon, m_mutex);
  for (str = idlist; ; str = NULL)
  {
    token = strtok_r(str, CONST_seperator, &saveptr);
    if (token == NULL)
      break;
    if (!*token)
      continue;
    MyClientID id(token);
    add_i(id);
  }
}

int MyClientIDTable::index_of(const MyClientID & id)
{
  ACE_READ_GUARD_RETURN(ACE_RW_Thread_Mutex, ace_mon, m_mutex, -1);
  return index_of_i(id);
}

int MyClientIDTable::index_of_i(const MyClientID & id, ClientIDTable_map::iterator * pIt)
{
  ClientIDTable_map::iterator it = m_map.find(id);
  if (pIt)
    *pIt = it;
  if (it == m_map.end())
    return -1;
  if (it->second < 0 || it->second >= (int)m_table.size())
  {
    MY_ERROR("Invalid MyClientInfos map index = %d, table size = %d\n", it->second, (int)m_table.size());
    return -1;
  }
  return it->second;
}

int MyClientIDTable::count()
{
  ACE_READ_GUARD_RETURN(ACE_RW_Thread_Mutex, ace_mon, m_mutex, -1);
  return m_table.size();
}

//MyBaseProcessor//

MyBaseProcessor::MyBaseProcessor(MyBaseHandler * handler)
{
  m_handler = handler;
  m_wait_for_close = false;
  m_last_activity = g_clock_tick;
  m_check_activity = true;
}

MyBaseProcessor::~MyBaseProcessor()
{

}

std::string MyBaseProcessor::info_string() const
{
  return "";
}

int MyBaseProcessor::on_open()
{
  return 0;
}

bool MyBaseProcessor::wait_for_close() const
{
  return m_wait_for_close;
}

int MyBaseProcessor::handle_input()
{
  return 0;
}

int MyBaseProcessor::handle_input_wait_for_close()
{
  char buffer[4096];
  ssize_t recv_cnt = m_handler->peer().recv (buffer, 4096);
  //TEMP_FAILURE_RETRY(m_handler->peer().recv (buffer, 4096));
  int ret = mycomutil_translate_tcp_result(recv_cnt);
  if (ret < 0)
    return -1;
  return (m_handler->msg_queue()->is_empty ()) ? -1 : 0;
}


bool MyBaseProcessor::dead() const
{
  return m_last_activity + 100 < g_clock_tick;
}

void MyBaseProcessor::update_last_activity()
{
  m_last_activity = g_clock_tick;
}

long MyBaseProcessor::last_activity() const
{
  return m_last_activity;
}

bool MyBaseProcessor::check_activity() const
{
  return m_check_activity;
}

void MyBaseProcessor::check_activity(bool bCheck)
{
  m_check_activity = bCheck;
}


//MyBasePacketProcessor//

MyBasePacketProcessor::MyBasePacketProcessor(MyBaseHandler * handler): MyBaseProcessor(handler)
{
  m_client_id_index = -1;
  m_peer_addr[0] = 0;
  m_read_next_offset = 0;
  m_current_block = NULL;
}

MyBasePacketProcessor::~MyBasePacketProcessor()
{
  if (m_current_block)
    m_current_block->release();
}

std::string MyBasePacketProcessor::info_string() const
{
  char buff[512];
  const char * str_id = m_client_id.as_string();
  if (!*str_id)
    str_id = "NULL";
  ACE_OS::snprintf(buff, 512, "(remote addr=%s, client_id=%s)", m_peer_addr, m_client_id.as_string());
  std::string result(buff);
  return result;
}

int MyBasePacketProcessor::handle_input()
{
  if (m_wait_for_close)
    return handle_input_wait_for_close();

  int loop_count = 0;
__loop:
  ++loop_count;

  if (loop_count >= 4) //do not bias too much toward this connection, this can starve other clients
    return 0;          //just in case of the malicious/ill-behaved clients
  if (m_read_next_offset < (int)sizeof(m_packet_header))
  {
    int ret = read_req_header();
    if (ret < 0)
      return -1;
    else if (ret > 0)
      return 0;
  }

  if (m_read_next_offset < (int)sizeof(m_packet_header))
    return 0;

  int ret = read_req_body();
  if (ret < 0)
    return -1;
  else if (ret > 0)
    return 0;

  if (handle_req() < 0)
    return -1;

  goto __loop; //burst transfer, in the hope that more are ready in the buffer

  return 0;
}

int MyBasePacketProcessor::copy_header_to_mb(ACE_Message_Block * mb, const MyDataPacketHeader & header)
{
  return mb->copy((const char*)&header, sizeof(MyDataPacketHeader));
}

int MyBasePacketProcessor::on_open()
{
  ACE_INET_Addr peer_addr;
  if (m_handler->peer().get_remote_addr(peer_addr) == 0)
    peer_addr.get_host_addr((char*)m_peer_addr, PEER_ADDR_LEN);
  if (m_peer_addr[0] == 0)
    ACE_OS::strsncpy((char*)m_peer_addr, "unknown", PEER_ADDR_LEN);
  return 0;
}


MyBaseProcessor::EVENT_RESULT MyBasePacketProcessor::on_recv_header(const MyDataPacketHeader & header)
{
  MyDataPacketBaseProc proc((const char*)&header);
  if (!proc.validate_header())
  {
    MY_ERROR(ACE_TEXT("Bad request received (invalid header magic check) from %s, \n"),
             info_string().c_str());
    return ER_ERROR;
  }

  return ER_CONTINUE;
}

MyBaseProcessor::EVENT_RESULT MyBasePacketProcessor::on_recv_packet(ACE_Message_Block * mb)
{
  MyBaseProcessor::EVENT_RESULT result;
  if (mb->size() < sizeof(MyDataPacketHeader))
  {
    MY_ERROR(ACE_TEXT("message block size too little ( = %d)"), mb->size());
    result = ER_ERROR;
    goto _exit_;
  }
  mb->rd_ptr(mb->base());

  result = on_recv_packet_i(mb);
_exit_:
  mb->release();
  return result;
}


MyBaseProcessor::EVENT_RESULT MyBasePacketProcessor::on_recv_packet_i(ACE_Message_Block * mb)
{
  MyDataPacketHeader * header = (MyDataPacketHeader *)mb->base();
  header->magic = m_client_id_index;
  return ER_OK;
}

bool MyBasePacketProcessor::client_id_verified() const
{
  return false;
}

const MyClientID & MyBasePacketProcessor::client_id() const
{
  return m_client_id;
}

void MyBasePacketProcessor::client_id(const char *id)
{
  m_client_id = id;
}

ACE_Message_Block * MyBasePacketProcessor::make_version_check_request_mb()
{
  ACE_Message_Block * mb = MyMemPoolFactoryX::instance()->get_message_block(sizeof(MyClientVersionCheckRequest));
  MyClientVersionCheckRequestProc vcr;
  vcr.attach(mb->base());
  vcr.init_header();
  mb->wr_ptr(mb->capacity());
  return mb;
}


int MyBasePacketProcessor::read_req_header()
{
  update_last_activity();
  ssize_t recv_cnt = m_handler->peer().recv((char*)&m_packet_header + m_read_next_offset,
      sizeof(m_packet_header) - m_read_next_offset);
//      TEMP_FAILURE_RETRY(m_handler->peer().recv((char*)&m_packet_header + m_read_next_offset,
//      sizeof(m_packet_header) - m_read_next_offset));
  int ret = mycomutil_translate_tcp_result(recv_cnt);
  if (ret <= 0)
    return ret;
  m_read_next_offset += recv_cnt;
  if (m_read_next_offset < (int)sizeof(m_packet_header))
    return 0;

  MyDataPacketBaseProc headerProc((char*)&m_packet_header);
  if (!headerProc.validate_header())
  {
    MY_ERROR(ACE_TEXT("Invalid data packet header received %s\n"), info_string().c_str());
    return -1;
  }

  MyBaseProcessor::EVENT_RESULT er = on_recv_header(m_packet_header);
  switch(er)
  {
  case MyBaseProcessor::ER_ERROR:
  case MyBaseProcessor::ER_CONTINUE:
    return -1;
  case MyBaseProcessor::ER_OK_FINISHED:
    if (m_packet_header.length != sizeof(m_packet_header))
    {
      MY_FATAL("got ER_OK_FINISHED.\n");
      return -1;
    }
    if (m_handler->connection_manager())
      m_handler->connection_manager()->on_data_received(sizeof(m_packet_header));
    m_read_next_offset = 0;
    return 1;
  case MyBaseProcessor::ER_OK:
    return 0;
  default:
    MY_FATAL(ACE_TEXT("unexpected MyBaseProcessor::EVENT_RESULT value = %d.\n"), er);
    return -1;
  }
}

int MyBasePacketProcessor::read_req_body()
{
  if (!m_current_block)
  {
    m_current_block = MyMemPoolFactoryX::instance()->get_message_block(m_packet_header.length);
    if (!m_current_block)
      return -1;
    if (copy_header_to_mb(m_current_block, m_packet_header) < 0)
    {
      MY_ERROR(ACE_TEXT("Message block copy header: m_current_block.copy() failed\n"));
      return -1;
    }
  }
  update_last_activity();
  return mycomutil_recv_message_block(m_handler, m_current_block);
}

int MyBasePacketProcessor::handle_req()
{
  if (m_handler->connection_manager())
     m_handler->connection_manager()->on_data_received(m_current_block->size());

  int ret = 0;
  if (on_recv_packet(m_current_block) != MyBaseProcessor::ER_OK)
    ret = -1;

  m_current_block = 0;
  m_read_next_offset = 0;
  return ret;
}


//MyBaseServerProcessor//

MyBaseServerProcessor::MyBaseServerProcessor(MyBaseHandler * handler) : MyBasePacketProcessor(handler)
{

}

MyBaseServerProcessor::~MyBaseServerProcessor()
{

}

bool MyBaseServerProcessor::client_id_verified() const
{
  return !m_client_id.is_null();
}

MyBaseProcessor::EVENT_RESULT MyBaseServerProcessor::on_recv_header(const MyDataPacketHeader & header)
{
  MyBaseProcessor::EVENT_RESULT result = super::on_recv_header(header);
  if (result != ER_CONTINUE)
    return result;

  bool bVerified = client_id_verified();
  bool bVersionCheck = (header.command == MyDataPacketHeader::CMD_CLIENT_VERSION_CHECK_REQ);
  if (bVerified == bVersionCheck)
  {
    MY_ERROR(ACE_TEXT("Bad request received (cmd = %d, verified = %d, request version check = %d) from %s, \n"),
        header.command, bVerified, bVersionCheck, info_string().c_str());
    return ER_ERROR;
  }

  return ER_CONTINUE;
}

MyBaseProcessor::EVENT_RESULT MyBaseServerProcessor::do_version_check_common(ACE_Message_Block * mb, MyClientIDTable & client_id_table)
{
  MyClientVersionCheckRequestProc vcr;
  vcr.attach(mb->base());
  vcr.validate_data();
  int client_id_index = -1;
  ACE_Message_Block * reply_mb = NULL;
  if (vcr.data()->client_version != 1)
  {
    m_wait_for_close = true;
    MY_WARNING(ACE_TEXT("closing connection due to mismatched client_version = %d\n"), vcr.data()->client_version);
    reply_mb = make_version_check_reply_mb(MyClientVersionCheckReply::VER_MISMATCH);
  } else
  {
    client_id_index = client_id_table.index_of(vcr.data()->client_id);
    if (client_id_index < 0)
    {
      m_wait_for_close = true;
      MY_WARNING(ACE_TEXT("closing connection due to invalid client_id = %s\n"), vcr.data()->client_id.as_string());
      reply_mb = make_version_check_reply_mb(MyClientVersionCheckReply::VER_ACCESS_DENIED);
    }
  }

  if (m_wait_for_close)
  {
    if (m_handler->send_data(reply_mb) <= 0)
      return ER_ERROR;
    else
      return ER_OK;
  }

  m_client_id_index = client_id_index;
  m_client_id = vcr.data()->client_id;
  m_client_id_length = strlen(m_client_id.as_string());
  return ER_CONTINUE;
}

ACE_Message_Block * MyBaseServerProcessor::make_version_check_reply_mb
   (MyClientVersionCheckReply::REPLY_CODE code, int extra_len)
{
  int total_len = sizeof(MyClientVersionCheckReply) + extra_len;
  ACE_Message_Block * mb = MyMemPoolFactoryX::instance()->get_message_block(total_len);

  MyClientVersionCheckReplyProc vcr;
  vcr.attach(mb->base());
  vcr.init_header();
  vcr.data()->reply_code = code;
  mb->wr_ptr(mb->capacity());
  return mb;
}

//MyBaseClientProcessor//

MyBaseClientProcessor::MyBaseClientProcessor(MyBaseHandler * handler) : MyBasePacketProcessor(handler)
{
  m_client_id_verified = false;
}

MyBaseClientProcessor::~MyBaseClientProcessor()
{

}

bool MyBaseClientProcessor::client_id_verified() const
{
  return m_client_id_verified;
}

MyBaseProcessor::EVENT_RESULT MyBaseClientProcessor::on_recv_header(const MyDataPacketHeader & header)
{
  MyBaseProcessor::EVENT_RESULT result = super::on_recv_header(header);
  if (result != ER_CONTINUE)
    return result;

  bool bVerified = client_id_verified();
  bool bVersionCheck = (header.command == MyDataPacketHeader::CMD_CLIENT_VERSION_CHECK_REPLY);
  if (bVerified == bVersionCheck)
  {
    MY_ERROR(ACE_TEXT("Bad request received (cmd = %d, verified = %d, request version check = %d) from %s, \n"),
        header.command, bVerified, bVersionCheck, info_string().c_str());
    return ER_ERROR;
  }

  return ER_CONTINUE;
}


//MyBaseConnectionManager//

MyBaseConnectionManager::MyBaseConnectionManager()
{
  m_num_connections = 0;
  m_bytes_received = 0;
  m_bytes_sent = 0;
}

MyBaseConnectionManager::~MyBaseConnectionManager()
{

}

MyActiveConnectionPointer MyBaseConnectionManager::end()
{
  return m_active_connections.end();
}

int MyBaseConnectionManager::num_connections() const
{
  return m_num_connections;
}

long MyBaseConnectionManager::bytes_received() const
{
  return m_bytes_received;
}

long MyBaseConnectionManager::bytes_sent() const
{
  return m_bytes_sent;
}

void MyBaseConnectionManager::on_data_received(long data_size)
{
  m_bytes_received += data_size;
}

void MyBaseConnectionManager::on_data_send(long data_size)
{
  m_bytes_sent += data_size;
}

void MyBaseConnectionManager::on_new_connection(MyBaseHandler * handler)
{
  if (handler == NULL)
    return;
  MyActiveConnectionPointer it = m_active_connections.insert(m_active_connections.end(), handler);
  handler->active_pointer(it);
  ++m_num_connections;
}

void MyBaseConnectionManager::on_close_connection(MyBaseHandler * handler)
{
  if (handler == NULL)
    return;

  MyActiveConnectionPointer aPointer = handler->active_pointer();
  if (aPointer == m_active_connections.end())
    return;
//  if (m_scan_pointer == aPointer)
//    next_pointer();
  m_active_connections.erase(aPointer);
  --m_num_connections;
}


void MyBaseConnectionManager::detect_dead_connections()
{
  MyActiveConnectionPointer aPointer, bPointer;
  for (aPointer = m_active_connections.begin(); aPointer != m_active_connections.end(); )
  {
    if ((*aPointer)->processor()->dead())
    {
      bPointer = aPointer;
      ++aPointer;
      (*bPointer)->handle_close(ACE_INVALID_HANDLE, 0);
    }
  }
}


//MyBaseHandler//

MyBaseHandler::MyBaseHandler(MyBaseConnectionManager * xptr)
{
  if (xptr)
    m_active_pointer = xptr->end();
  m_connection_manager = xptr;
  m_processor = NULL;
}

MyBaseConnectionManager * MyBaseHandler::connection_manager()
{
  return m_connection_manager;
}

void MyBaseHandler::active_pointer(MyActiveConnectionPointer ptr)
{
  m_active_pointer = ptr;
}

MyActiveConnectionPointer MyBaseHandler::active_pointer()
{
  return m_active_pointer;
}

MyBaseProcessor * MyBaseHandler::processor() const
{
  return m_processor;
}

int MyBaseHandler::on_open()
{
  return 0;
}

int MyBaseHandler::open(void * p)
{
  if (super::open(p) == -1)
    return -1;
  if (m_connection_manager)
    m_connection_manager->on_new_connection(this);
  if (on_open() < 0)
    return -1;
  return m_processor->on_open();
}

int MyBaseHandler::send_data(ACE_Message_Block * mb)
{
  m_processor->update_last_activity();
  int sent_len = mb->length();
  int ret = mycomutil_send_message_block_queue(this, mb, true);
  if (ret >= 0)
  {
    if (m_connection_manager)
      m_connection_manager->on_data_send(sent_len);
  }
  return ret;
}

int MyBaseHandler::handle_input(ACE_HANDLE h)
{
  MY_DEBUG("handle_input (handle = %d)\n", h);
  return m_processor->handle_input();
}

void MyBaseHandler::on_close()
{

}

int MyBaseHandler::handle_close (ACE_HANDLE handle,
                          ACE_Reactor_Mask close_mask)
{
  ACE_UNUSED_ARG(handle);
  MY_DEBUG("handle_close.1 (handle = %d, mask=%x)\n", handle, close_mask);
  if (close_mask == ACE_Event_Handler::WRITE_MASK)
  {
    if (!m_processor->wait_for_close())
      return 0;
  } else if (!m_processor->wait_for_close())
  {
    //m_processor->handle_input();
  }
  MY_DEBUG("handle_close.2 (handle = %d, mask=%x)\n", handle, close_mask);
  ACE_Message_Block *mb;
  ACE_Time_Value nowait(ACE_OS::gettimeofday());
  while (-1 != this->getq (mb, &nowait))
    mb->release();

  if (m_connection_manager)
    m_connection_manager->on_close_connection(this);

  on_close();
  //here comes the tricky part, parent class will NOT call delete as it normally does
  //since we override the operator new/delete pair, the same thing parent class does
  //see ACE_Svc_Handler @ Svc_Handler.cpp
  //ctor: this->dynamic_ = ACE_Dynamic::instance ()->is_dynamic ();
  //destroy(): if (this->mod_ == 0 && this->dynamic_ && this->closing_ == false)
  //             delete this;
  //so do NOT use the normal method: return super::handle_close(handle, close_mask);
  //for it will cause memory leaks
  MY_DEBUG("handle_close.3 deleting object (handle = %d, mask=%x)\n", handle, close_mask);
  delete this;
  return 0;
  //return super::handle_close (handle, close_mask); //do NOT use
}

int MyBaseHandler::handle_output (ACE_HANDLE fd)
{
  ACE_UNUSED_ARG(fd);
  ACE_Message_Block *mb;
  ACE_Time_Value nowait (ACE_OS::gettimeofday ());
  while (-1 != this->getq(mb, &nowait))
  {
    if (mycomutil_send_message_block(this, mb) < 0)
    {
      mb->release();
      reactor()->remove_handler(this, ACE_Event_Handler::WRITE_MASK | ACE_Event_Handler::READ_MASK |
                                ACE_Event_Handler::DONT_CALL);
      return handle_close(get_handle(), 0); //todo: more graceful shutdown
    }
    if (mb->length() > 0)
    {
      this->ungetq(mb);
      break;
    }
    mb->release();
  }
  return (this->msg_queue()->is_empty()) ? -1 : 0;
}

MyBaseHandler::~MyBaseHandler()
{
  delete m_processor;
//  ACE_DEBUG ((LM_DEBUG,
//              ACE_TEXT ("(%P|%t) deleting MyBaseHandler objects %X\n"),
//              (long)this));
}


//MyBaseAcceptor//

MyBaseAcceptor::MyBaseAcceptor(MyBaseModule * _module, MyBaseConnectionManager * _manager):
    m_module(_module), m_connection_manager(_manager)
{
  m_tcp_port = 0;
}

MyBaseAcceptor::~MyBaseAcceptor()
{
  if (m_connection_manager)
    delete m_connection_manager;
}

MyBaseModule * MyBaseAcceptor::module_x() const
{
  return m_module;
}

MyBaseConnectionManager * MyBaseAcceptor::connection_manager() const
{
  return m_connection_manager;
}

int MyBaseAcceptor::start()
{
  reactor(m_module->dispatcher()->reactor());

  if (m_tcp_port <= 0)
  {
    MY_FATAL(ACE_TEXT ("attempt to listen on invalid port %d\n"), m_tcp_port);
    return -1;
  }
  ACE_INET_Addr port_to_listen (m_tcp_port);

  int ret = super::open (port_to_listen, m_module->dispatcher()->reactor(), ACE_NONBLOCK);

  if (ret == 0)
    MY_INFO(ACE_TEXT ("listening on port %d... OK\n"), m_tcp_port);
  else if (ret == -1)
    MY_ERROR(ACE_TEXT ("acceptor.open on port %d failed!\n"), m_tcp_port);
  return ret;
}

int MyBaseAcceptor::stop()
{
  close();
  return 0;
}


//////////////
//MyBaseAcceptor//

MyBaseConnector::MyBaseConnector(MyBaseModule * _module, MyBaseConnectionManager * _manager):
    m_module(_module), m_connection_manager(_manager)
{
  m_tcp_port = 0;
  m_num_connection = 1;
  m_unique_handler = NULL;
  m_reconnect_interval = 0;
  m_reconnect_retry_count = 3;
  m_reconnect_timer_id = -1;
}

MyBaseConnector::~MyBaseConnector()
{
  if (m_connection_manager)
    delete m_connection_manager;
}

MyBaseModule * MyBaseConnector::module_x() const
{
  return m_module;
}

MyBaseConnectionManager * MyBaseConnector::connection_manager() const
{
  return m_connection_manager;
}

MyBaseHandler * MyBaseConnector::unique_handler() const
{
  return m_unique_handler;
}

void MyBaseConnector::tcp_addr(const char * addr)
{
  m_tcp_addr = (addr? addr:"");
}

bool MyBaseConnector::before_reconnect()
{
  return true;
}

int MyBaseConnector::handle_timeout(const ACE_Time_Value &current_time, const void *act)
{
  ACE_UNUSED_ARG(current_time);
  if (long(act) == RECONNECT_TIMER && m_reconnect_interval > 0)
  {
    if (m_connection_manager->num_connections() < m_num_connection)
    {
      if (before_reconnect())
      {
        m_reconnect_retry_count++;
        do_connect(m_num_connection - m_connection_manager->num_connections());
      }
    }
  }
  return 0;
}

int MyBaseConnector::start()
{
  if (super::open(m_module->dispatcher()->reactor(), ACE_NONBLOCK) == -1)
    return -1;
  reactor(m_module->dispatcher()->reactor());
  m_reconnect_retry_count = 1;

  if (m_tcp_port <= 0)
  {
    MY_FATAL(ACE_TEXT ("attempt to connect to an invalid port %d\n"), m_tcp_port);
    return -1;
  }

  if (m_tcp_addr.length() == 0)
  {
    MY_FATAL(ACE_TEXT ("attempt to connect to an NULL host\n"));
    return -1;
  }

  int ret = do_connect(m_num_connection);
  if (m_reconnect_interval > 0)
  {
    ACE_Time_Value interval (m_reconnect_interval * 60);
    m_reconnect_timer_id = reactor()->schedule_timer (this, (void*)RECONNECT_TIMER, interval, interval);
    if (m_reconnect_timer_id < 0)
      MY_ERROR(ACE_TEXT("MyBaseConnector setup reconnect timer failed, %s"), (const char*)MyErrno());
  }
  return ret;
}

int MyBaseConnector::stop()
{
  if (m_reconnect_timer_id >= 0)
    reactor()->cancel_timer(m_reconnect_timer_id);

  close();
  return 0;
}

int MyBaseConnector::do_connect(int count)
{
  if (count <= 0 || count > m_num_connection)
  {
    MY_FATAL(ACE_TEXT("invalid connect count = %d, maximum allowed connections = %d"), count, m_num_connection);
    return -1;
  }

  ACE_INET_Addr port_to_connect(m_tcp_port, m_tcp_addr.c_str());
  MyBaseHandler * handler = NULL;
  int ok_count = 0;
  for (int i = 1; i <= count; ++i)
  {
    handler = NULL;
    int ret_i = do_connect_one(handler, port_to_connect); //connect(handler, port_to_connect);
    if (ret_i == 0)
      ++ok_count;
    else if (ret_i == -1)
    {
      MY_ERROR(ACE_TEXT("connecting to %s:%d failed, %s\n"), m_tcp_addr.c_str(), m_tcp_port, (const char*)MyErrno());
    }

  }
  if (ok_count != count)
    MY_ERROR(ACE_TEXT("connecting on %s:%d (%d of %d)... failed!\n"), m_tcp_addr.c_str(), m_tcp_port, count - ok_count, count);
  else
    MY_INFO(ACE_TEXT("connecting on %s:%d (%d of %d)... OK\n"), m_tcp_addr.c_str(), m_tcp_port, count, count);

  if (m_num_connection == 1 && ok_count == 1)
  {
    m_unique_handler = handler;
  }
  return (ok_count > 0 ? 0:-1);
}

int MyBaseConnector::do_connect_one(MyBaseHandler * & handler, const ACE_INET_Addr & addr)
{/*
  const size_t MAX_RETRIES = 3;
  ACE_Time_Value timeout(10);
  size_t i;
  for (i = 0; i < MAX_RETRIES; ++i)
  {
    ACE_Synch_Options options(ACE_Synch_Options::USE_TIMEOUT, timeout);
    if (i > 0)
      ACE_OS::sleep(timeout);
    if (connect(handler, addr, options) == 0)
      break;
    timeout *= 2; // Exponential backoff.
  }
  return i == MAX_RETRIES ? -1 : 0;
  */
   connect(handler, addr);
   ACE_Time_Value timeout(10);
   ACE_OS::sleep(timeout);
   return 0;
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

MyBaseDispatcher::MyBaseDispatcher(MyBaseModule * pModule, int numThreads):
    m_module(pModule), m_numThreads(numThreads), m_numBatchSend(50)
{
  m_reactor = NULL;
  m_clock_interval = 0;
}

MyBaseDispatcher::~MyBaseDispatcher()
{
  //fixme: cleanup correctly
  if (m_reactor)
    delete m_reactor;
}

int MyBaseDispatcher::open (void *)
{
  m_reactor = new ACE_Reactor(new ACE_Dev_Poll_Reactor(ACE::max_handles()), true);
  reactor(m_reactor);

  if (m_clock_interval > 0)
  {
    ACE_Time_Value interval(m_clock_interval);
    m_reactor->schedule_timer (this,
                             0,
                             interval,
                             interval);
  }

  return 0;
}

int MyBaseDispatcher::on_start()
{
  return 0;
}

int MyBaseDispatcher::start()
{
  if (open(NULL) == -1)
    return -1;
  msg_queue()->flush();
  if (on_start() < 0)
    return -1;

  return activate (THR_NEW_LWP, m_numThreads);
}

void MyBaseDispatcher::on_stop()
{

}

int MyBaseDispatcher::stop()
{
  wait();
  msg_queue()->flush();
  if (m_reactor && m_clock_interval > 0)
    m_reactor->cancel_timer(this);
  on_stop();
  if (m_reactor)
    m_reactor->close();

  delete m_reactor;
  m_reactor = NULL;

  return 0;
}


int MyBaseDispatcher::svc()
{/*
  ACE_DEBUG ((LM_DEBUG,
             ACE_TEXT ("(%P|%t) entering MyBaseDispatcher::svc()\n")));

  if (open(NULL) == -1)
    return -1;
  msg_queue()->flush();
  if (on_start() < 0)
    return -1;
  */
  while (m_module->running_with_app())
  {
    ACE_Time_Value timeout(2);
    int ret = reactor()->handle_events (&timeout);
    if (ret == -1)
    {
      if (errno == EINTR)
        continue;
      MY_INFO(ACE_TEXT ("exiting MyBaseDispatcher::svc() due to errno = %d\n"), errno);
      break;
    }
//    MY_DEBUG("    returning from reactor()->handle_events()\n");
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
  MY_DEBUG("MyBaseDispatcher::handle_timeout().\n");
  ACE_Message_Block *mb;
  ACE_Time_Value nowait(ACE_OS::gettimeofday ());
  int i = 0;
  while (-1 != this->getq(mb, &nowait))
  {
    ++i;
    if (i >= m_numBatchSend)
      return 0;
  }
//  ACE_DEBUG ((LM_DEBUG,
//             ACE_TEXT ("(%P|%t) connections:=%d, received_bytes=%d, processed=%d\n"),
//             acceptor()->num_connections(), acceptor()->bytes_received(), acceptor()->bytes_sent()));

  return 0;
//    return (this->msg_queue()->is_empty ()) ? -1 : 0;
}


//MyBaseModule//

MyBaseModule::MyBaseModule(MyBaseApp * app): m_app(app), m_service(NULL), m_dispatcher(NULL), m_running(false)
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

bool MyBaseModule::running() const
{
  return m_running;
}

MyBaseApp * MyBaseModule::app() const
{
  return m_app;
}

bool MyBaseModule::running_with_app() const
{
  return (m_running && m_app->running());
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
  if (m_service)
  {
    if (m_service->start() == -1)
    {
      m_running = false;
      return -1;
    }
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
