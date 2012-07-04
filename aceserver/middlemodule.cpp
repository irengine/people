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
  m_loads.reserve(6);
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
    if (unlikely(len > remain_len))
    {
      MY_ERROR("dist server addr list is too long @MyDistLoads::calc_server_list()\n");
      break;
    }
    ACE_OS::memcpy(ptr, it->m_ip_addr, len + 1);
    ptr += len;
    remain_len -= (len + 1);
    *ptr = MyDataPacketHeader::ITEM_SEPARATOR;
    ++ptr;
  }
  *ptr = 0;

  int ftp_list_len = MyConfigX::instance()->ftp_addr_list.length();
  if (unlikely(ftp_list_len + 3 > remain_len))
    MY_ERROR("ftp server addr list is too long @MyDistLoads::calc_server_list()\n");
  else
  {
    *ptr++ = MyDataPacketHeader::FINISH_SEPARATOR;
    ACE_OS::strsncpy(ptr, MyConfigX::instance()->ftp_addr_list.c_str(), remain_len + 1);
  }

  m_server_list_length = ACE_OS::strlen(m_server_list);
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


//MyUnusedPathRemover//

MyUnusedPathRemover::~MyUnusedPathRemover()
{
  std::for_each(m_path_list.begin(), m_path_list.end(), MyObjectDeletor());
}

void MyUnusedPathRemover::add_dist_id(const char * dist_id)
{
  MyPooledMemGuard * guard = new MyPooledMemGuard;
  guard->init_from_string(dist_id);
  m_path_list.push_back(guard);
  m_path_set.insert(guard->data());
}

bool MyUnusedPathRemover::path_ok(const char * _path)
{
  return m_path_set.find(_path) != m_path_set.end();
}

void MyUnusedPathRemover::check_path(const char * path)
{
  DIR * dir = opendir(path);
  if (!dir)
  {
    MY_ERROR("can not open directory: %s %s\n", path, (const char*)MyErrno());
    return;
  }

  int count = 0, ok_count = 0;
  struct dirent *entry;
  while ((entry = readdir(dir)) != NULL)
  {
    if (!entry->d_name)
      continue;
    if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
      continue;

    if(entry->d_type == DT_DIR)
    {
      if(!path_ok(entry->d_name))
      {
        ++count;
        MyPooledMemGuard mpath;
        mpath.init_from_string(path, "/", entry->d_name);
        if (MyFilePaths::remove_path(mpath.data(), true))
          ++ ok_count;
      }
    }
  };

  closedir(dir);
  MY_INFO("removed %d/%d unused path(s) from compress_store\n", ok_count, count);
}


//MyLocationProcessor//

MyDistLoads * MyLocationProcessor::m_dist_loads = NULL;

MyLocationProcessor::MyLocationProcessor(MyBaseHandler * handler): MyBaseServerProcessor(handler)
{

}

const char * MyLocationProcessor::name() const
{
  return "MyLocationProcessor";
}

MyBaseProcessor::EVENT_RESULT MyLocationProcessor::on_recv_header()
{
  if (MyBaseServerProcessor::on_recv_header() == ER_ERROR)
    return ER_ERROR;

  if (m_packet_header.command == MyDataPacketHeader::CMD_CLIENT_VERSION_CHECK_REQ)
  {
    if (!my_dph_validate_client_version_check_req(&m_packet_header))
    {
      MY_ERROR("failed to validate header for client version check req\n");
      return ER_ERROR;
    }
    return ER_OK;
  }

  return ER_ERROR;
}

MyBaseProcessor::EVENT_RESULT MyLocationProcessor::on_recv_packet_i(ACE_Message_Block * mb)
{
  MyBaseServerProcessor::on_recv_packet_i(mb);

  MyDataPacketHeader * header = (MyDataPacketHeader *)mb->base();
  if (header->command == MyDataPacketHeader::CMD_CLIENT_VERSION_CHECK_REQ)
    return do_version_check(mb);

  MyMessageBlockGuard guard(mb);
  MY_ERROR("unsupported command received, command = %d\n", header->command);
  return ER_ERROR;
}


MyBaseProcessor::EVENT_RESULT MyLocationProcessor::do_version_check(ACE_Message_Block * mb)
{
  MyMessageBlockGuard guard(mb);

//  MyClientIDTable & client_id_table = MyServerAppX::instance()->client_id_table();
//
//  MyBaseProcessor::EVENT_RESULT ret = do_version_check_common(mb, client_id_table);
//  if (ret != ER_CONTINUE)
//    return ret;
  m_client_id = "dummy";

  char server_list[MyDistLoads::SERVER_LIST_LENGTH];
  int len = m_dist_loads->get_server_list(server_list, MyDistLoads::SERVER_LIST_LENGTH); //double copy
  ACE_Message_Block * reply_mb = make_version_check_reply_mb(MyClientVersionCheckReply::VER_SERVER_LIST, len);

  MyClientVersionCheckReply *reply = (MyClientVersionCheckReply *)reply_mb->base();
  if (likely(len > 0))
    ACE_OS::memcpy(reply->data, server_list, len);

  if (m_handler->send_data(reply_mb) <= 0)
    return ER_ERROR; //no unsent data, force a close
  else
    return ER_OK;
}

PREPARE_MEMORY_POOL(MyLocationProcessor);


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
  MY_INFO("running %s::svc()\n", name());

  for (ACE_Message_Block * mb; getq(mb) != -1;)
  {

    mb->release ();
  }

  MY_INFO("exiting %s::svc()\n", name());
  return 0;
}


//MyLocationAcceptor//

MyLocationAcceptor::MyLocationAcceptor(MyBaseDispatcher * _dispatcher, MyBaseConnectionManager * _manager):
    MyBaseAcceptor(_dispatcher, _manager)
{
  m_tcp_port = MyConfigX::instance()->middle_server_client_port;
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
  msg_queue()->high_water_mark(MSG_QUEUE_MAX_SIZE);
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

MyHttpProcessor::MyHttpProcessor(MyBaseHandler * handler): super(handler)
{

}

MyHttpProcessor::~MyHttpProcessor()
{

}

const char * MyHttpProcessor::name() const
{
  return "MyHttpProcessor";
}

int MyHttpProcessor::packet_length()
{
  return m_packet_header;
}

MyBaseProcessor::EVENT_RESULT MyHttpProcessor::on_recv_header()
{
  int len = packet_length();
  if (len > 1024 * 1024 || len <= 32)
  {
    MY_ERROR("got an invalid http packet with size = %d\n", len);
    return ER_ERROR;
  }
  MY_INFO("http processor got packet len = %d\n", len);
  return ER_OK;
}

MyBaseProcessor::EVENT_RESULT MyHttpProcessor::on_recv_packet_i(ACE_Message_Block * mb)
{
  ACE_UNUSED_ARG(mb);
  MY_INFO("http processor got complete packet, len = %d\n", mb->length());
  m_wait_for_close = true;
  bool ok = do_process_input_data();
  ACE_Message_Block * reply_mb = MyMemPoolFactoryX::instance()->get_message_block(1);
  if (!reply_mb)
  {
    MY_ERROR(ACE_TEXT("failed to allocate 1 bytes sized memory block @MyHttpProcessor::handle_input().\n"));
    return ER_ERROR;
  }
  *(reply_mb->base()) = (ok? '1':'0');
  reply_mb->wr_ptr(1);
  return (m_handler->send_data(reply_mb) <= 0 ? ER_ERROR:ER_OK);
}

bool MyHttpProcessor::do_process_input_data()
{
  bool result = true;
  const char * const_dist_cmd = "http://127.0.0.1:10092/file?";
  const char * const_task_cmd = "http://127.0.0.1:10092/task?";
  const char * const_prio_cmd = "http://127.0.0.1:10092/prio?";
  int ntype = -1;
  if (likely(ACE_OS::strncmp(const_dist_cmd, m_current_block->base() + 4, ACE_OS::strlen(const_dist_cmd)) == 0))
    ntype = 1;
  else if (ACE_OS::strncmp(const_task_cmd, m_current_block->base() + 4, ACE_OS::strlen(const_task_cmd)) == 0)
  {
    ntype = 3;
    m_current_block->set_self_flags(0x2000);
  }
  else if (ACE_OS::strncmp(const_prio_cmd, m_current_block->base() + 4, ACE_OS::strlen(const_prio_cmd)) == 0)
  {
    bool ret = do_prio(m_current_block);
    m_current_block->release();
    m_current_block = NULL;
    return ret;
  }

  if (ntype == -1)
  {
    m_current_block->release();
    m_current_block = NULL;
    return false;
  }
  if (likely(ntype == 1 || ntype == 3))
    result = (mycomutil_mb_putq(MyServerAppX::instance()->http_module()->http_service(), m_current_block,
              "http request into target queue @MyHttpProcessor::do_process_input_data()"));
  m_current_block = NULL;
  return result;
}

bool MyHttpProcessor::do_prio(ACE_Message_Block * mb)
{
  const char const_header[] = "http://127.0.0.1:10092/prio?";
  const int const_header_len = sizeof(const_header) / sizeof(char) - 1;
  int mb_len = mb->length();
  ACE_OS::memmove(mb->base(), mb->base() + 4, mb_len - 4);
  mb->base()[mb_len - 4] = 0;
  if (unlikely((int)(mb->length()) <= const_header_len + 10))
  {
    MY_ERROR("bad http request, packet too short\n", const_header);
    return false;
  }

  char * packet = mb->base();
  if (ACE_OS::memcmp(packet, const_header, const_header_len) != 0)
  {
    MY_ERROR("bad http packet, no match header of (%s) found\n", const_header);
    return false;
  }

  packet += const_header_len;
  const char const_separator = '&';

  const char * const_ver = "ver=";
  char * ver = 0;
  if (!mycomutil_find_tag_value(packet, const_ver, ver, const_separator))
  {
    MY_ERROR("can not find tag %s at http packet\n", const_ver);
    return false;
  }


  const char * const_plist = "plist=";
  char * plist = 0;
  if (!mycomutil_find_tag_value(packet, const_plist, plist, const_separator))
  {
    MY_ERROR("can not find tag %s at http packet\n", const_plist);
    return false;
  }


  MyDB & db = MyServerAppX::instance()->db();
  if (!db.ping_db_server())
  {
    MY_ERROR("no connection to db, aborting processing\n");
    return false;
  }

  MY_INFO("prio list = %s\n", plist? plist:"NULL");
  return db.save_prio(plist);
}

PREPARE_MEMORY_POOL(MyHttpProcessor);


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
  msg_queue()->high_water_mark(MSG_QUEUE_MAX_SIZE);
}

int MyHttpService::svc()
{
  MY_INFO("running %s::svc()\n", name());

  for (ACE_Message_Block * mb; getq(mb) != -1; )
  {
    handle_packet(mb);
    mb->release();
  }

  MY_INFO("exiting %s::svc()\n", name());
  return 0;
};

const char * MyHttpService::name() const
{
  return "MyHttpService";
}

bool MyHttpService::parse_request(ACE_Message_Block * mb, MyHttpDistRequest &http_dist_request)
{
  const char const_header[] = "http://127.0.0.1:10092/file?";
  const int const_header_len = sizeof(const_header) / sizeof(char) - 1;
  int mb_len = mb->length();
  ACE_OS::memmove(mb->base(), mb->base() + 4, mb_len - 4);
  mb->base()[mb_len - 4] = 0;
  if (unlikely((int)(mb->length()) <= const_header_len + 10))
  {
    MY_ERROR("bad http request, packet too short\n", const_header);
    return false;
  }

  char * packet = mb->base();
  if (ACE_OS::memcmp(packet, const_header, const_header_len) != 0)
  {
    MY_ERROR("bad http packet, no match header of (%s) found\n", const_header);
    return false;
  }

  packet += const_header_len;
  const char const_separator = '&';

  const char * const_acode = "acode=";
  if (!mycomutil_find_tag_value(packet, const_acode, http_dist_request.acode, const_separator))
  {
    MY_ERROR("can not find tag %s at http packet\n", const_acode);
    return false;
  }

  const char * const_ftype = "ftype=";
  if (!mycomutil_find_tag_value(packet, const_ftype, http_dist_request.ftype, const_separator))
  {
    MY_ERROR("can not find tag %s at http packet\n", const_ftype);
    return false;
  }

  const char * const_fdir = "fdir=";
  if (!mycomutil_find_tag_value(packet, const_fdir, http_dist_request.fdir, const_separator))
  {
    MY_ERROR("can not find tag %s at http packet\n", const_fdir);
    return false;
  }

  const char * const_findex = "findex=";
  if (!mycomutil_find_tag_value(packet, const_findex, http_dist_request.findex, const_separator))
  {
    MY_ERROR("can not find tag %s at http packet\n", const_findex);
    return false;
  }

  const char * const_adir = "adir=";
  if (!mycomutil_find_tag_value(packet, const_adir, http_dist_request.adir, const_separator))
  {
    MY_ERROR("can not find tag %s at http packet\n", const_adir);
    return false;
  }

  const char * const_aindex = "aindex=";
  if (!mycomutil_find_tag_value(packet, const_aindex, http_dist_request.aindex, const_separator))
  {
    MY_ERROR("can not find tag %s at http packet\n", const_aindex);
    return false;
  }

  const char * const_ver = "ver=";
  if (!mycomutil_find_tag_value(packet, const_ver, http_dist_request.ver, const_separator))
  {
    MY_ERROR("can not find tag %s at http packet\n", const_ver);
    return false;
  }

  const char * const_type = "type=";
  if (!mycomutil_find_tag_value(packet, const_type, http_dist_request.type, const_separator))
  {
    MY_ERROR("can not find tag %s at http packet\n", const_type);
    return false;
  }

  return true;
}

bool MyHttpService::handle_packet(ACE_Message_Block * _mb)
{
  if ((_mb->self_flags() & 0x2000) == 0)
  {
    MyHttpDistRequest http_dist_request;
    bool result = do_handle_packet(_mb, http_dist_request);
    if (unlikely(!result && !http_dist_request.check_valid(true)))
      return false;
    int total_len;
    char buff[32];
    mycomutil_generate_time_string(buff, 32, true);
    total_len = ACE_OS::strlen(buff) + ACE_OS::strlen(http_dist_request.ver) + 8;
    ACE_Message_Block * mb = MyMemPoolFactoryX::instance()->get_message_block_bs(total_len, MY_BS_DIST_FEEDBACK_CMD);
    char * dest = mb->base() + MyBSBasePacket::DATA_OFFSET;
    ACE_OS::sprintf(dest, "%s#%c##1#%c#%s", http_dist_request.ver, *http_dist_request.ftype,
        result? '1':'0', buff);
    dest[total_len] = MyBSBasePacket::BS_PACKET_END_MARK;
    MyServerAppX::instance()->dist_load_module()->dispatcher()->send_to_bs(mb);

    return result;
  } else
  {
    return do_handle_packet2(_mb);
  }
}

bool MyHttpService::do_handle_packet(ACE_Message_Block * mb, MyHttpDistRequest & http_dist_request)
{
  if (!parse_request(mb, http_dist_request))
    return false;

  if (!http_dist_request.check_valid(true))
    return false;

  char password[12];
  mycomutil_generate_random_password(password, 12);
  http_dist_request.password = password;
  MyDB & db = MyServerAppX::instance()->db();

  if (unlikely(!module_x()->running_with_app()))
    return false;

  if (!do_compress(http_dist_request))
    return false;

  if (unlikely(!module_x()->running_with_app()))
    return false;

  MyPooledMemGuard md5_result;
  {
    MyDistMd5Calculator calc;
    int md5_len;
    if (!calc.calculate(http_dist_request, md5_result, md5_len))
      return false;
  }

  if (unlikely(!module_x()->running_with_app()))
    return false;

  MyPooledMemGuard mbz_md5_result;
//  if (http_dist_request.need_mbz_md5()) //generate all in one.mbz md5 anyway
  {
    if (!MyDistMd5Calculator::calculate_all_in_one_ftp_md5(http_dist_request.ver, mbz_md5_result))
      return false;
  }

  if (!db.ping_db_server())
  {
    MY_ERROR("no connection to db, aborting processing of dist %s\n", http_dist_request.ver);
    return false;
  }

  if (!db.save_dist(http_dist_request, md5_result.data(), mbz_md5_result.data()))
  {
    MY_ERROR("can not save_dist to db\n");
    return false;
  }

  if (!db.save_dist_clients(http_dist_request.acode, http_dist_request.adir, http_dist_request.ver))
  {
    MY_ERROR("can not save_dist_clients to db\n");
    return false;
  }

  if (unlikely(!module_x()->running_with_app()))
    return false;

  if (!db.dist_info_update_status())
  {
    MY_ERROR("call to dist_info_update_status() failed\n");
    return false;
  }

  db.remove_orphan_dist_info();

  notify_dist_servers();

  MyUnusedPathRemover path_remover;
  if (db.get_dist_ids(path_remover))
    path_remover.check_path(MyConfigX::instance()->compressed_store_path.c_str());

  return true;
}

bool MyHttpService::do_handle_packet2(ACE_Message_Block * mb)
{
  const char const_header[] = "http://127.0.0.1:10092/task?";
  const int const_header_len = sizeof(const_header) / sizeof(char) - 1;
  int mb_len = mb->length();
  ACE_OS::memmove(mb->base(), mb->base() + 4, mb_len - 4);
  mb->base()[mb_len - 4] = 0;
  if (unlikely((int)(mb->length()) <= const_header_len + 10))
  {
    MY_ERROR("bad http request, packet too short\n", const_header);
    return false;
  }

  char * packet = mb->base();
  if (ACE_OS::memcmp(packet, const_header, const_header_len) != 0)
  {
    MY_ERROR("bad http packet, no match header of (%s) found\n", const_header);
    return false;
  }

  packet += const_header_len;
  const char const_separator = '&';

  const char * const_ver = "ver=";
  char * ver = 0;
  if (!mycomutil_find_tag_value(packet, const_ver, ver, const_separator))
  {
    MY_ERROR("can not find tag %s at http packet\n", const_ver);
    return false;
  }


  const char * const_cmd = "cmd=";
  char * cmd = 0;
  if (!mycomutil_find_tag_value(packet, const_cmd, cmd, const_separator))
  {
    MY_ERROR("can not find tag %s at http packet\n", const_cmd);
    return false;
  }

  const char * const_backid = "backid=";
  char * backid = 0;
  if (!mycomutil_find_tag_value(packet, const_backid, backid, const_separator))
  {
    MY_ERROR("can not find tag %s at http packet\n", const_backid);
    return false;
  }

  const char * const_acode = "acode=";
  char * acode = 0;
  if (!mycomutil_find_tag_value(packet, const_acode, acode, const_separator))
  {
    MY_ERROR("can not find tag %s at http packet\n", const_acode);
    return false;
  }

  MyDB & db = MyServerAppX::instance()->db();
  if (!db.ping_db_server())
  {
    MY_ERROR("no connection to db, aborting processing\n");
    return false;
  }

  db.save_sr(backid, cmd, acode);
  if (!db.dist_info_update_status())
  {
    MY_ERROR("call to dist_info_update_status() failed\n");
    return false;
  }

  notify_dist_servers();
  return true;
}

bool MyHttpService::do_compress(MyHttpDistRequest & http_dist_request)
{
  MyDistCompressor compressor;
  return compressor.compress(http_dist_request);
}

bool MyHttpService::do_calc_md5(MyHttpDistRequest & http_dist_request)
{
  MyDistMd5Calculator calc;
  MyPooledMemGuard md5_result;
  int md5_len;
  return calc.calculate(http_dist_request, md5_result, md5_len);
}

bool MyHttpService::notify_dist_servers()
{
  ACE_Message_Block * mb = MyMemPoolFactoryX::instance()->get_message_block_cmd(0, MyDataPacketHeader::CMD_HAVE_DIST_TASK);
  return mycomutil_mb_putq(MyServerAppX::instance()->dist_load_module()->dispatcher(), mb, "dist task notification to target queue");
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

MyHttpService * MyHttpModule::http_service()
{
  return m_service;
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
  m_handler->msg_queue()->high_water_mark(MSG_QUEUE_MAX_SIZE);
}

MyDistLoadProcessor::~MyDistLoadProcessor()
{

}

const char * MyDistLoadProcessor::name() const
{
  return "MyDistLoadProcessor";
}

void MyDistLoadProcessor::dist_loads(MyDistLoads * dist_loads)
{
  m_dist_loads = dist_loads;
}

MyBaseProcessor::EVENT_RESULT MyDistLoadProcessor::on_recv_header()
{
  if (super::on_recv_header() == ER_ERROR)
    return ER_ERROR;

  if (m_packet_header.command == MyDataPacketHeader::CMD_CLIENT_VERSION_CHECK_REQ)
  {
    if (!my_dph_validate_client_version_check_req(&m_packet_header))
    {
      MyPooledMemGuard info;
      info_string(info);
      MY_ERROR("bad client version check req packet received from %s\n", info.data());
      return ER_ERROR;
    }
    return ER_OK;
  }

  if (m_packet_header.command == MyDataPacketHeader::CMD_LOAD_BALANCE_REQ)
  {
    if (!my_dph_validate_load_balance_req(&m_packet_header))
    {
      MyPooledMemGuard info;
      info_string(info);
      MY_ERROR("bad load_balance packet received from %s\n", info.data());
      return ER_ERROR;
    }
    return ER_OK;
  }

  MY_ERROR(ACE_TEXT("unexpected packet header received @MyDistLoadProcessor.on_recv_header, cmd = %d\n"),
      m_packet_header.command);
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
    MyPooledMemGuard info;
    info_string(info);
    MY_ERROR("bad load_balance version check (bad key) received from %s\n", info.data());
    return ER_ERROR;
  }
  m_client_id_verified = true;

  ACE_Message_Block * reply_mb = make_version_check_reply_mb(MyClientVersionCheckReply::VER_OK);
  return (m_handler->send_data(reply_mb) < 0 ? ER_ERROR: ER_OK);
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
  m_tcp_port = MyConfigX::instance()->middle_server_dist_port;
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
  m_bs_connector = NULL;
  msg_queue()->high_water_mark(MSG_QUEUE_MAX_SIZE);
}

MyDistLoadDispatcher::~MyDistLoadDispatcher()
{
  ACE_Time_Value tv(ACE_Time_Value::zero);
  int i = 0;
  for (ACE_Message_Block * mb; m_to_bs_queue.dequeue(mb, &tv) != -1; )
  {
    ++i;
    mb->release();
  }
  if (i > 0)
    MY_INFO("releasing %d mb on %s::termination\n", i, name());
}

const char * MyDistLoadDispatcher::name() const
{
  return "MyDistLoadDispatcher";
}

void MyDistLoadDispatcher::send_to_bs(ACE_Message_Block * mb)
{
  ACE_Time_Value tv(ACE_Time_Value::zero);
  if (m_to_bs_queue.enqueue(mb, &tv) < 0)
  {
    MY_ERROR("MyDistLoadDispatcher::send_to_bs() failed, %s\n", (const char*)MyErrno());
    mb->release();
  }
}

int MyDistLoadDispatcher::handle_timeout(const ACE_Time_Value &, const void *)
{
  MyServerAppX::instance()->location_module()->dist_loads()->scan_for_dead();
  return 0;
}

void MyDistLoadDispatcher::on_stop()
{
  m_acceptor = NULL;
  m_bs_connector = NULL;
  reactor()->cancel_timer(this);
}

bool MyDistLoadDispatcher::on_start()
{
  if (!m_acceptor)
    m_acceptor = new MyDistLoadAcceptor(this, new MyBaseConnectionManager());
  add_acceptor(m_acceptor);
  if (!m_bs_connector)
    m_bs_connector = new MyMiddleToBSConnector(this, new MyBaseConnectionManager());
  add_connector(m_bs_connector);

  ACE_Time_Value interval(int(MyDistLoads::DEAD_TIME * 60 / MyBaseApp::CLOCK_INTERVAL / 2));
  if (reactor()->schedule_timer(this, 0, interval, interval) == -1)
  {
    MY_ERROR("can not setup dist load server scan timer\n");
    return false;
  }
  return true;
}

bool MyDistLoadDispatcher::on_event_loop()
{
  ACE_Time_Value tv(ACE_Time_Value::zero);
  ACE_Message_Block * mb;
  const int const_max_count = 10;
  int i = 0;
  while (++i < const_max_count && this->getq(mb, &tv) != -1)
    m_acceptor->connection_manager()->broadcast(mb);

  i = 0;
  while (++i < const_max_count && m_to_bs_queue.dequeue(mb, &tv) != -1)
    m_bs_connector->connection_manager()->broadcast(mb);

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

MyDistLoadDispatcher * MyDistLoadModule::dispatcher() const
{
  return m_dispatcher;
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


/////////////////////////////////////
//middle to BS
/////////////////////////////////////

//MyMiddleToBSProcessor//

MyMiddleToBSProcessor::MyMiddleToBSProcessor(MyBaseHandler * handler): super(handler)
{

}

const char * MyMiddleToBSProcessor::name() const
{
  return "MyMiddleToBSProcessor";
}

MyBaseProcessor::EVENT_RESULT MyMiddleToBSProcessor::on_recv_packet_i(ACE_Message_Block * mb)
{
  if (mb)
    mb->release();
  ((MyMiddleToBSHandler*)m_handler)->checker_update();
  return ER_OK;
}

PREPARE_MEMORY_POOL(MyMiddleToBSProcessor);


//MyMiddleToBSHandler//

MyMiddleToBSHandler::MyMiddleToBSHandler(MyBaseConnectionManager * xptr): MyBaseHandler(xptr)
{
  m_processor = new MyMiddleToBSProcessor(this);
}

MyDistLoadModule * MyMiddleToBSHandler::module_x() const
{
  return (MyDistLoadModule *)connector()->module_x();
}

void MyMiddleToBSHandler::checker_update()
{
  m_checker.update();
}

int MyMiddleToBSHandler::handle_timeout(const ACE_Time_Value &, const void *)
{
  if (m_checker.expired())
  {
    MY_ERROR("no data received from bs @MyMiddleToBSHandler ...\n");
    return -1;
  }
  ACE_Message_Block * mb = my_get_hb_mb();
  if (mb)
  {
    if (send_data(mb) < 0)
      return -1;
  }
  return 0;
}

int MyMiddleToBSHandler::on_open()
{
  ACE_Time_Value interval(30);
  if (reactor()->schedule_timer(this, (void*)0, interval, interval) < 0)
  {
    MY_ERROR(ACE_TEXT("MyMiddleToBSHandler setup timer failed, %s"), (const char*)MyErrno());
    return -1;
  }

  if (!g_test_mode)
    MY_INFO("MyMiddleToBSHandler setup timer: OK\n");

  ACE_Message_Block * mb = my_get_hb_mb();
  if (mb)
  {
    if (send_data(mb) < 0)
      return -1;
  }
  m_checker.update();

  return 0;
}


void MyMiddleToBSHandler::on_close()
{

}

PREPARE_MEMORY_POOL(MyMiddleToBSHandler);


//MyMiddleToBSConnector//

MyMiddleToBSConnector::MyMiddleToBSConnector(MyBaseDispatcher * _dispatcher, MyBaseConnectionManager * _manager):
    MyBaseConnector(_dispatcher, _manager)
{
  m_tcp_port = MyConfigX::instance()->bs_server_port;
  m_reconnect_interval = RECONNECT_INTERVAL;
  m_tcp_addr = MyConfigX::instance()->bs_server_addr;
}

const char * MyMiddleToBSConnector::name() const
{
  return "MyMiddleToBSConnector";
}

int MyMiddleToBSConnector::make_svc_handler(MyBaseHandler *& sh)
{
  sh = new MyMiddleToBSHandler(m_connection_manager);
  if (!sh)
  {
    MY_ERROR("can not alloc MyMiddleToBSHandler from %s\n", name());
    return -1;
  }
  sh->parent((void*)this);
  sh->reactor(reactor());
  return 0;
}
