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

MyBaseProcessor::EVENT_RESULT MyLocationProcessor::on_recv_header()
{
  if (MyBaseServerProcessor::on_recv_header() == ER_ERROR)
    return ER_ERROR;

  if (m_packet_header.command == MyDataPacketHeader::CMD_CLIENT_VERSION_CHECK_REQ)
  {
    MyClientVersionCheckRequestProc proc;
    proc.attach((const char*)&m_packet_header);
    if (!proc.validate_header())
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

int MyHttpProcessor::packet_length()
{
  return m_packet_header;
}

MyBaseProcessor::EVENT_RESULT MyHttpProcessor::on_recv_header()
{
  int len = packet_length();
  if (len > 1024 * 1024 * 10 || len <= 4)
  {
    MY_ERROR("got an invalid http packet with size = %d\n", len);
    return ER_ERROR;
  }
  return ER_OK;
}

MyBaseProcessor::EVENT_RESULT MyHttpProcessor::on_recv_packet_i(ACE_Message_Block * mb)
{
  ACE_UNUSED_ARG(mb);
  m_wait_for_close = true;
  bool ok = do_process_input_data();
  ACE_Message_Block * reply_mb = MyMemPoolFactoryX::instance()->get_message_block(4);
  if (!reply_mb)
  {
    MY_ERROR(ACE_TEXT("failed to allocate 4 bytes sized memory block @MyHttpProcessor::handle_input().\n"));
    return ER_ERROR;
  }
  const char ok_reply_str[] = "1";
  const char bad_reply_str[] = "0";
  const int reply_len = sizeof(ok_reply_str) / sizeof(char);
  ACE_OS::strsncpy(reply_mb->base(), (ok? ok_reply_str:bad_reply_str), reply_len);
  reply_mb->wr_ptr(reply_len);
  return (m_handler->send_data(reply_mb) <= 0 ? ER_ERROR:ER_OK);
}

bool MyHttpProcessor::do_process_input_data()
{
  ACE_Time_Value tv(ACE_Time_Value::zero);
  if (MyServerAppX::instance()->http_module()->http_service()->putq(m_current_block, &tv) != -1)
  {
    m_current_block = NULL;
    return true;
  } else
  {
    m_current_block->release();
    m_current_block = NULL;
    return false;
  }
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

bool MyHttpService::handle_packet(ACE_Message_Block * mb)
{
  const char const_header[] = "http://127.0.0.1:10092/file?";
  const int const_header_len = sizeof(const_header) / sizeof(char) - 1;
  if (unlikely((int)(mb->length()) <= const_header_len))
    return false;

  char * packet = mb->base();
  if (ACE_OS::memcmp(packet, const_header, const_header_len) != 0)
  {
    MY_ERROR("bad http packet, no match header found\n");
    return false;
  }

  packet += const_header_len;
  const char const_separator = '&';

  const char * const_acode = "acode=";
  char * acode;
  if (!mycomutil_find_tag_value(packet, const_acode, acode, const_separator))
  {
    MY_ERROR("can not find tag %s at http packet\n", const_acode);
    return false;
  }

  const char * const_ftype = "ftype=";
  char * ftype;
  if (!mycomutil_find_tag_value(packet, const_ftype, ftype, const_separator))
  {
    MY_ERROR("can not find tag %s at http packet\n", const_ftype);
    return false;
  }

  const char * const_fdir = "fdir=";
  char * fdir;
  if (!mycomutil_find_tag_value(packet, const_fdir, fdir, const_separator))
  {
    MY_ERROR("can not find tag %s at http packet\n", const_fdir);
    return false;
  }

  const char * const_findex = "findex=";
  char * findex;
  if (!mycomutil_find_tag_value(packet, const_findex, findex, const_separator))
  {
    MY_ERROR("can not find tag %s at http packet\n", const_findex);
    return false;
  }

  const char * const_adir = "adir=";
  char * adir;
  if (!mycomutil_find_tag_value(packet, const_adir, adir, const_separator))
  {
    MY_ERROR("can not find tag %s at http packet\n", const_adir);
    return false;
  }

  const char * const_aindex = "aindex=";
  char * aindex;
  if (!mycomutil_find_tag_value(packet, const_aindex, aindex, const_separator))
  {
    MY_ERROR("can not find tag %s at http packet\n", const_aindex);
    return false;
  }

  const char * const_ver = "ver=";
  char * ver;
  if (!mycomutil_find_tag_value(packet, const_ver, ver, const_separator))
  {
    MY_ERROR("can not find tag %s at http packet\n", const_ver);
    return false;
  }

  const char * const_type = "type=";
  char * type;
  if (!mycomutil_find_tag_value(packet, const_type, type, const_separator))
  {
    MY_ERROR("can not find tag %s at http packet\n", const_type);
    return false;
  }

  if (!*ftype || !*acode || !*fdir || !*ver || !*type)
  {
    MY_ERROR("can not find all non-null data at http packet\n");
    return false;
  }

  char password[12];
  mycomutil_generate_random_password(password, 12);

  if (!MyServerAppX::instance()->db().save_dist(ftype, fdir, findex, adir, aindex, ver, type, password))
  {
    MY_ERROR("can not save_dist to db\n");
    return false;
  }

  if (!MyServerAppX::instance()->db().save_dist_clients(acode, ver))
  {
    MY_ERROR("can not save_dist_clients to db\n");
    return false;
  }


  //todo: add logic here
  return true;
}

const char * MyHttpService::composite_path()
{
  return "_x_cmp_x_";
}

bool MyHttpService::generate_compressed_files(const char * src_path, const char * dist_id, const char * password)
{
  MyPooledMemGuard destdir;
  destdir.init_from_string(MyConfigX::instance()->compressed_store_path.c_str(), "/", dist_id);
  if (mkdir(destdir.data(), S_IRWXU) == -1 && ACE_OS::last_error() != EEXIST)
  {
    MY_ERROR("can not create directory %s, %s\n", destdir.data(), (const char *)MyErrno());
    return false;
  }
  MyPooledMemGuard composite_dir;
  composite_dir.init_from_string(destdir.data(), "/", composite_path());
  if (mkdir(composite_dir.data(), S_IRWXU) == -1 && ACE_OS::last_error() != EEXIST)
  {
    MY_ERROR("can not create directory %s, %s\n", composite_dir.data(), (const char *)MyErrno());
    return false;
  }

  MyPooledMemGuard all_in_one;
  all_in_one.init_from_string(composite_dir.data(), "/all_in_one.mbz");
  if (!m_compositor.open(all_in_one.data()))
    return false;
  bool result = do_generate_compressed_files(src_path, destdir.data(), ACE_OS::strlen(src_path), password);
  if (!result)
    MY_ERROR("can not generate compressed files for %s from %s\n", dist_id, src_path);
  m_compositor.close();
  return result;
}

bool MyHttpService::do_generate_compressed_files(const char * src_path, const char * dest_path,
     int prefix_len, const char * password)
{
  if (unlikely(!src_path || !*src_path || !dest_path || !*dest_path))
    return false;

  if (mkdir(dest_path, S_IRWXU) == -1 && ACE_OS::last_error() != EEXIST)
  {
    MY_ERROR("can not create directory %s, %s\n", dest_path, (const char *)MyErrno());
    return false;
  }

  DIR * dir = opendir(src_path);
  if (!dir)
  {
    MY_ERROR("can not open directory: %s, %s\n", src_path, (const char*)MyErrno());
    return false;
  }

  int len1 = ACE_OS::strlen(src_path);
  int len2 = ACE_OS::strlen(dest_path);

  struct dirent *entry;
  while ((entry = readdir(dir)) != NULL)
  {
    if (!entry->d_name)
      continue;
    if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
      continue;

    MyPooledMemGuard msrc, mdest;
    int len = ACE_OS::strlen(entry->d_name);
    MyMemPoolFactoryX::instance()->get_mem(len1 + len + 2, &msrc);
    ACE_OS::sprintf(msrc.data(), "%s/%s", src_path, entry->d_name);
    MyMemPoolFactoryX::instance()->get_mem(len2 + len + 8, &mdest);


    if (entry->d_type == DT_REG)
    {
      ACE_OS::sprintf(mdest.data(), "%s/%s.mbz", dest_path, entry->d_name);
      if (!m_compressor.compress(msrc.data(), prefix_len, mdest.data(), password))
      {
        MY_ERROR("compress(%s, %s) failed\n", msrc.data(), mdest.data());
        closedir(dir);
        return false;
      }
      if (!m_compositor.add(mdest.data()))
      {
        closedir(dir);
        return false;
      }
    }
    else if(entry->d_type == DT_DIR)
    {
      ACE_OS::sprintf(mdest.data(), "%s/%s", dest_path, entry->d_name);
      if (!do_generate_compressed_files(msrc.data(), mdest.data(), prefix_len, password))
      {
        closedir(dir);
        return false;
      }
    } else
      MY_WARNING("unknown file type (= %d) for file @MyHttpService::generate_compressed_files file = %s/%s\n",
           entry->d_type, src_path, entry->d_name);
  };

  closedir(dir);
  return true;
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
}

MyDistLoadProcessor::~MyDistLoadProcessor()
{

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
    MyClientVersionCheckRequestProc proc;
    proc.attach((const char*)&m_packet_header);
    bool result = proc.validate_data();
    if (!result)
    {
      MY_ERROR("bad client version check req packet received from %s\n", info_string().c_str());
      return ER_ERROR;
    }
    return ER_OK;
  }

  if (m_packet_header.command == MyDataPacketHeader::CMD_LOAD_BALANCE_REQ)
  {
    MyLoadBalanceRequestProc proc;
    proc.attach((const char*)&m_packet_header);
    bool result = proc.validate_header();
    if (!result)
    {
      MY_ERROR("bad load_balance packet received from %s\n", info_string().c_str());
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
    MY_ERROR("bad load_balance version check (bad key) received from %s\n", info_string().c_str());
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


/////////////////////////////////////
//middle to BS
/////////////////////////////////////

//MyMiddleToBSProcessor//

MyMiddleToBSProcessor::MyMiddleToBSProcessor(MyBaseHandler * handler): super(handler)
{

}


//MyMiddleToBSHandler//

MyMiddleToBSHandler::MyMiddleToBSHandler(MyBaseConnectionManager * xptr): MyBaseHandler(xptr)
{
  m_processor = new MyMiddleToBSProcessor(this);
}

MyDistLoadModule * MyMiddleToBSHandler::module_x() const
{
  return (MyDistLoadModule *)connector()->module_x();
}

int MyMiddleToBSHandler::on_open()
{
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
