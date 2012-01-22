/*
 * heartbeatmodule.cpp
 *
 *  Created on: Dec 26, 2011
 *      Author: root
 */

#include "distmodule.h"
#include "baseapp.h"
#include "server.h"

//MyHeartBeatProcessor//

MyPingSubmitter * MyHeartBeatProcessor::m_sumbitter = NULL;

MyHeartBeatProcessor::MyHeartBeatProcessor(MyBaseHandler * handler): MyBaseServerProcessor(handler)
{

}

MyBaseProcessor::EVENT_RESULT MyHeartBeatProcessor::on_recv_header(const MyDataPacketHeader & header)
{
  if (super::on_recv_header(header) == ER_ERROR)
    return ER_ERROR;

  if (header.command == MyDataPacketHeader::CMD_HEARTBEAT_PING)
  {
    //the thread context switching and synchronization cost outbeat the benefit of using another thread
    do_ping();
    return ER_OK_FINISHED;
  }

  if (header.command == MyDataPacketHeader::CMD_CLIENT_VERSION_CHECK_REQ)
    return ER_OK;

  MY_ERROR(ACE_TEXT("unexpected packet header received @MyHeartBeatProcessor.on_recv_header, cmd = %d\n"),
      header.command);

  return ER_ERROR;
}

MyBaseProcessor::EVENT_RESULT MyHeartBeatProcessor::on_recv_packet_i(ACE_Message_Block * mb)
{
  MyBaseServerProcessor::on_recv_packet_i(mb);

  MyDataPacketHeader * header = (MyDataPacketHeader *)mb->base();
  if (header->command == MyDataPacketHeader::CMD_CLIENT_VERSION_CHECK_REQ)
    return do_version_check(mb);

  MyMessageBlockGuard guard(mb);
  MY_ERROR("unsupported command received @MyHeartBeatProcessor::on_recv_packet_i, command = %d\n",
      header->command);
  return ER_ERROR;
}

void MyHeartBeatProcessor::do_ping()
{
//  MY_DEBUG(ACE_TEXT("got a heart beat from %s\n"), info_string().c_str());
  m_sumbitter->add_ping(m_client_id.as_string(), m_client_id_length + 1);
}

MyBaseProcessor::EVENT_RESULT MyHeartBeatProcessor::do_version_check(ACE_Message_Block * mb)
{
  MyMessageBlockGuard guard(mb);
  MyBaseProcessor::EVENT_RESULT ret = do_version_check_common(mb, MyServerAppX::instance()->client_id_table());
  if (ret != ER_CONTINUE)
    return ret;

  MY_INFO(ACE_TEXT("client version check ok: %s\n"), info_string().c_str());

  ACE_Message_Block * reply_mb = make_version_check_reply_mb(MyClientVersionCheckReply::VER_OK);

  if (m_handler->send_data(reply_mb) < 0)
    return ER_ERROR;
  else
    return ER_OK;
}


//MyPingSubmitter//

MyPingSubmitter::MyPingSubmitter()
{
#ifdef MY_server_test
  std::string s = MyConfigX::instance()->app_test_data_path + "/heartbeat.log";
  m_fd = open(s.c_str(), O_WRONLY | O_APPEND | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
  if (m_fd < 0)
    MY_ERROR("can not open test heart beat logger file: %s %s\n", s.c_str(), (const char*)MyErrno());
#endif

  reset();
}

MyPingSubmitter::~MyPingSubmitter()
{
  if (m_current_block)
    m_current_block->release();
#ifdef MY_server_test
  if (m_fd >= 0)
    close(m_fd);
#endif
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
  if (len + m_current_length > BLOCK_SIZE)// not zero-terminated// - 1)
  {
    do_submit();
    m_last_add = g_clock_tick;
  } else
    check_time_out();
  if (!client_id || !*client_id || len <= 0)
    return;
  ACE_OS::memcpy(m_current_ptr, client_id, len);
  m_current_length += len;
  m_current_ptr += len;
  *(m_current_ptr - 1) = ID_SEPERATOR;
}

void MyPingSubmitter::do_submit()
{
  m_current_block->wr_ptr(m_current_length);
  //todo: do sumbit now
#ifdef MY_server_test
  if (m_fd >= 0)
    write(m_fd, m_current_block->base(), m_current_length);
#endif
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
    calc_server_file_md5_list(mb);
  }

  MY_INFO("exiting %s::svc()\n", name());
  return 0;
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
  md5s_server.scan_directory(client_path_by_id);
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
  ACE_Message_Block * mb = MyMemPoolFactoryX::instance()->get_message_block(sizeof(MyServerFileMD5List) + list_len);
  MyServerFileMD5ListProc vcr;
  vcr.attach(mb->base());
  vcr.init_header();
  vcr.data()->length = sizeof(MyServerFileMD5List) + list_len;
  vcr.data()->magic = client_id_index;
  mb->wr_ptr(mb->capacity());
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

int MyHeartBeatDispatcher::handle_timeout(const ACE_Time_Value &tv, const void *act)
{
  ACE_UNUSED_ARG(tv);
  ACE_UNUSED_ARG(act);

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

  return 0;

}

void MyHeartBeatDispatcher::on_stop()
{
  m_acceptor = NULL;
}

bool MyHeartBeatDispatcher::on_start()
{
  if (!m_acceptor)
    m_acceptor = new MyHeartBeatAcceptor(this, new MyBaseConnectionManager());
  add_acceptor(m_acceptor);
  return true;
}


//MyHeartBeatModule//

MyHeartBeatModule::MyHeartBeatModule(MyBaseApp * app): MyBaseModule(app)
{
  m_service = NULL;
  m_dispatcher = NULL;
  MyHeartBeatProcessor::m_sumbitter = &m_ping_sumbitter;
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
                          "  dist_batch start_client_id number_of_clients\n>"
      ;
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

int MyDistRemoteAccessProcessor::on_command_dist_batch_file_md5(char * parameter)
{
  if (!*parameter)
    return send_string("  usage: dist_batch start_client_id number_of_clients\n>");

  const char * CONST_seperator = ",\t ";
  char *str, *token, *saveptr;

  std::string s_start_id, s_number;

  for (str = parameter; ; str = NULL)
  {
    token = strtok_r(str, CONST_seperator, &saveptr);
    if (token == NULL)
      break;
    if (!*token)
      continue;
    if (s_start_id.empty())
      s_start_id = token;
    else if (s_number.empty())
      s_number = token;
    else
      return send_string("  usage: dist_batch start_client_id number_of_clients\n>");
  }

  if (s_number.empty())
    return send_string("  usage: dist_batch start_client_id number_of_clients\n>");

  long long int start_id = atoll(s_start_id.c_str());
  int number = atoi(s_number.c_str());
  if (number <= 0 || start_id <= 0)
    return send_string("  usage: dist_batch start_client_id number_of_clients\n>");
  long long int end_id = start_id + number - 1;
  long long int valid_start_id = MyConfigX::instance()->test_client_start_client_id;
  long long int valid_end_id = valid_start_id + MyConfigX::instance()->test_client_connection_number - 1;

  valid_start_id = std::max(valid_start_id, start_id);
  valid_end_id = std::min(valid_end_id, end_id);
  if (valid_start_id > valid_end_id)
    return send_string("  dist_batch: no valid client_ids found\n>");

  if (send_string("  processing valid client_id(s):") < 0)
    return -1;

  const int BUFF_SIZE = 4096;
  char buff[BUFF_SIZE];
  int len = 0;
  buff[0] = 0;
  long long int i = valid_start_id;
  while (true)
  {
    ACE_OS::snprintf(buff + len, BUFF_SIZE - 1 - len, " %lld", i);
    len = strlen(buff);
    if (len >= (int)(BUFF_SIZE - sizeof(MyClientID) - 3) || i >= valid_end_id)
    {
      ACE_Message_Block * mb = MyMemPoolFactoryX::instance()->get_message_block(len + 1);
      mb->copy(buff, len + 1);

      ACE_Time_Value tv(ACE_Time_Value::zero);
      if (MyServerAppX::instance()->heart_beat_module()->service()->putq(mb, &tv) == -1)
      {
        mb->release();
        return send_string("  Error: can not place the request message to target.\n>");
      }
      buff[0] = 0;
      len = 0;
    }
    if (i >= valid_end_id)
      break;
    ++i;
  }

  buff[0] = 0;
  snprintf(buff, BUFF_SIZE - 1, " valid_start=%lld number=%d\n", valid_start_id, int(valid_end_id - valid_start_id + 1));
  if (send_string(buff) < 0)
    return -1;
  return send_string("  OK: request placed into target for later processing\n>");
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
