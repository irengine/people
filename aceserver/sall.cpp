#include "sall.h"
#include "app.h"
#include "sapp.h"

//MyHttpDistInfo//

MyHttpDistInfo::MyHttpDistInfo(CONST text * dist_id)
{
  exist = false;
  md5_len = 0;
  ver_len = 0;
  findex_len = 0;
  password_len = 0;
  aindex_len = 0;

  ftype[0] = ftype[1] = 0;
  type[0] = type[1] = 0;
  ver.from_string(dist_id);
  ver_len = strlen(dist_id);

  md5_opt_len = 0;
}

truefalse MyHttpDistInfo::need_md5() CONST
{
  return (type_is_multi(type[0]));
}

truefalse MyHttpDistInfo::need_mbz_md5() CONST
{
  return !need_md5();
}

DVOID MyHttpDistInfo::calc_md5_opt_len()
{
  if (need_md5() && md5_len > 0 && md5_opt_len == 0)
  {
    CMemGuard md5_2;
    md5_2.from_string(md5.data());
    CFileMD5s md5s;
    if (md5s.from_buffer(md5_2.data(), NULL))
      md5_opt_len = md5s.total_size(false) - 1;
  }
}


//MyHttpDistRequest//

MyHttpDistRequest::MyHttpDistRequest()
{
  acode = NULL;
  ftype = NULL;
  fdir = NULL;
  findex = NULL;
  adir = NULL;
  aindex = NULL;
  ver = NULL;
  type = NULL;
  password = NULL;
}

MyHttpDistRequest::MyHttpDistRequest(CONST MyHttpDistInfo & info)
{
  acode = NULL;
  ftype = (char*)info.ftype;
  fdir = info.fdir.data();
  findex = info.findex.data();
  adir = NULL;
  aindex = info.aindex.data();
  ver = info.ver.data();
  type = (char*)info.type;
  password = info.password.data();
}

truefalse MyHttpDistRequest::check_value(CONST text * value, CONST text * value_name) CONST
{
  if (!value || !*value)
  {
    C_ERROR("bad http dist request, no %s value\n", value_name);
    return false;
  }

  return true;
}

truefalse MyHttpDistRequest::check_valid(CONST truefalse check_acode) CONST
{
  if (check_acode && !check_value(acode, "acode"))
    return false;

  if (!check_value(ftype, "ftype"))
    return false;

  if (unlikely(ftype[1] != 0 || !ftype_is_valid(ftype[0])))
  {
    C_ERROR("bad http dist request, ftype = %s\n", ftype);
    return false;
  }

  if (!check_value(findex, "findex"))
    return false;

  if (!check_value(fdir, "fdir"))
    return false;

  if (!check_value(ver, "ver"))
    return false;

  if (!check_value(type, "type"))
    return false;

  if (unlikely(type[1] != 0 || !type_is_valid(type[0])))
  {
    C_ERROR("bad http dist request, type = %s\n", type);
    return false;
  }

  return true;
}

truefalse MyHttpDistRequest::need_md5() CONST
{
  return (type && type_is_multi(*type));
}

truefalse MyHttpDistRequest::need_mbz_md5() CONST
{
  return !need_md5();
}


//MyHttpDistInfos//

MyHttpDistInfos::MyHttpDistInfos()
{
  last_load_time.from_string("");
}

MyHttpDistInfos::~MyHttpDistInfos()
{
  clear();
}

ni MyHttpDistInfos::count() CONST
{
  return m_info_map.size();
}

DVOID MyHttpDistInfos::clear()
{
  std::for_each(dist_infos.begin(), dist_infos.end(), CPoolObjectDeletor());
  dist_infos.clear();
  MyHttpDistInfoList x;
  x.swap(dist_infos);
  m_info_map.clear();
}

MyHttpDistInfo * MyHttpDistInfos::create_http_dist_info(CONST text * dist_id)
{
  DVOID * p = CMemPoolX::instance()->alloc_mem_x(sizeof(MyHttpDistInfo));
  MyHttpDistInfo * result = new (p) MyHttpDistInfo(dist_id);
  dist_infos.push_back(result);
  m_info_map.insert(std::pair<const text *, MyHttpDistInfo *>(result->ver.data(), result));
  return result;
}

truefalse MyHttpDistInfos::need_reload()
{
  return (!MyServerAppX::instance()->db().dist_info_is_update(*this));
}

DVOID MyHttpDistInfos::prepare_update(CONST ni capacity)
{
  clear();
  dist_infos.reserve(capacity);
}

MyHttpDistInfo * MyHttpDistInfos::find(CONST text * dist_id)
{
  if (unlikely(!dist_id || !*dist_id))
    return NULL;

  MyHttpDistInfoMap::iterator it = m_info_map.find(dist_id);
  return it == m_info_map.end()? NULL: it->second;
}


//MyDistCompressor//

CONST text * MyDistCompressor::composite_path()
{
  return "_x_cmp_x_";
}

CONST text * MyDistCompressor::all_in_one_mbz()
{
  return "_x_cmp_x_/all_in_one.mbz";
}

DVOID MyDistCompressor::get_all_in_one_mbz_file_name(CONST text * dist_id, CMemGuard & filename)
{
  CMemGuard tmp;
  tmp.from_string(CCfgX::instance()->bz_files_path.c_str(), "/", dist_id);
  filename.from_string(tmp.data(), "/", all_in_one_mbz());
}

truefalse MyDistCompressor::compress(MyHttpDistRequest & http_dist_request)
{
  truefalse result = false;
  truefalse bm = false;
  ni prefix_len = strlen(http_dist_request.fdir) - 1;
  CMemGuard destdir;
  CMemGuard composite_dir;
  CMemGuard all_in_one;
  CMemGuard mfile;
  CMemGuard mdestfile;
//  MyPooledMemGuard destdir_mfile;
  destdir.from_string(CCfgX::instance()->bz_files_path.c_str(), "/", http_dist_request.ver);
  if (!CSysFS::make_path(destdir.data(), false))
  {
    C_ERROR("can not create directory %s, %s\n", destdir.data(), (CONST text *)CErrno());
    goto __exit__;
  }

  composite_dir.from_string(destdir.data(), "/", composite_path());
  if (!CSysFS::make_path(composite_dir.data(), false))
  {
    C_ERROR("can not create directory %s, %s\n", composite_dir.data(), (CONST text *)CErrno());
    goto __exit__;
  }
  all_in_one.from_string(composite_dir.data(), "/all_in_one.mbz");
  if (!type_is_single(*http_dist_request.type))
    if (!m_compositor.open(all_in_one.data()))
      goto __exit__;

  CSysFS::cat_path(http_dist_request.fdir, http_dist_request.findex, mfile);
  mdestfile.from_string(destdir.data(), "/", (http_dist_request.findex? http_dist_request.findex: http_dist_request.aindex), ".mbz");
  bm = m_compressor.compress(mfile.data(), prefix_len, mdestfile.data(), http_dist_request.password);
  if (!bm && !type_is_multi(*http_dist_request.type))
  {
    C_ERROR("compress(%s) to (%s) failed\n", mfile.data(), mdestfile.data());
    m_compositor.close();
    return false;
  }
  if (!type_is_single(*http_dist_request.type) && bm && !m_compositor.add(mdestfile.data()))
  {
    m_compositor.close();
    return false;
  }

  if (type_is_single(*http_dist_request.type))
  {
    result = CSysFS::rename(mdestfile.data(), all_in_one.data(), false);
    goto __exit__;
  }

  if (unlikely(!CSysFS::get_correlate_path(mfile, prefix_len)))
  {
    C_ERROR("can not calculate related path for %s\n", mfile.data());
    m_compositor.close();
    goto __exit__;
  }

//  destdir_mfile.init_from_string(destdir.data(), mfile.data() + prefix_len);
  result = do_generate_compressed_files(mfile.data(), destdir.data(), prefix_len, http_dist_request.password);
  m_compositor.close();

__exit__:
  if (!result)
    C_ERROR("can not generate compressed files for %s\n", http_dist_request.ver);
  else
    C_INFO("generation of compressed files for %s is done\n", http_dist_request.ver);

  if (type_is_all(*http_dist_request.type))
  {
    CSysFS::remove(mdestfile.data());
    ni len = strlen(mdestfile.data());
    if (likely(len > 4))
    {
      mdestfile.data()[len - 4] = 0;
      if (likely(CSysFS::get_correlate_path(mdestfile, 1)))
        CSysFS::remove_path(mdestfile.data(), true);
    }
  }
  return result;
}

truefalse MyDistCompressor::do_generate_compressed_files(CONST text * src_path, CONST text * dest_path,
     ni prefix_len, CONST text * password)
{
  if (unlikely(!src_path || !*src_path || !dest_path || !*dest_path))
    return false;

  if (!CSysFS::make_path(dest_path, false))
  {
    C_ERROR("can not create directory %s, %s\n", dest_path, (CONST text *)CErrno());
    return false;
  }

  DIR * dir = opendir(src_path);
  if (!dir)
  {
    C_ERROR("can not open directory: %s, %s\n", src_path, (CONST char*)CErrno());
    return false;
  }

  ni len1 = strlen(src_path);
  ni len2 = strlen(dest_path);

  struct dirent *entry;
  ni dest_middle_leading_path_len = len1 - prefix_len;
  if (dest_middle_leading_path_len > 0)
  {
    if (!CSysFS::make_path(dest_path, src_path + prefix_len + 1, false, false))
    {
      C_ERROR("failed to create dir %s%s %s\n", dest_path, src_path + prefix_len, (CONST char*)CErrno());
      return false;
    }
  }

  while ((entry = readdir(dir)) != NULL)
  {
    if (unlikely(!entry->d_name))
      continue;
    if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
      continue;

    CMemGuard msrc, mdest;
    ni len = strlen(entry->d_name);
    CMemPoolX::instance()->alloc_mem(len1 + len + 2, &msrc);
    sprintf(msrc.data(), "%s/%s", src_path, entry->d_name);
    CMemPoolX::instance()->alloc_mem(len2 + len + 10 + dest_middle_leading_path_len, &mdest);

    if (entry->d_type == DT_REG)
    {
      if (dest_middle_leading_path_len > 0)
        sprintf(mdest.data(), "%s%s/%s.mbz", dest_path, src_path + prefix_len, entry->d_name);
      else
        sprintf(mdest.data(), "%s/%s.mbz", dest_path, entry->d_name);
      if (!m_compressor.compress(msrc.data(), prefix_len, mdest.data(), password))
      {
        C_ERROR("compress(%s) to (%s) failed\n", msrc.data(), mdest.data());
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
      if (dest_middle_leading_path_len > 0)
        sprintf(mdest.data(), "%s%s/%s", dest_path, src_path + prefix_len, entry->d_name);
      else
        sprintf(mdest.data(), "%s/%s", dest_path, entry->d_name);

      if (!do_generate_compressed_files(msrc.data(), dest_path, prefix_len, password))
      {
        closedir(dir);
        return false;
      }
    } else
      C_WARNING("unknown file type (= %d) for file @MyHttpService::generate_compressed_files file = %s/%s\n",
           entry->d_type, src_path, entry->d_name);
  };

  closedir(dir);
  return true;
}


//MyDistMd5Calculator//

truefalse MyDistMd5Calculator::calculate(MyHttpDistRequest & http_dist_request, CMemGuard &md5_result, ni & md5_len)
{
  if (!http_dist_request.need_md5())
  {
    C_INFO("skipping file md5 generation for %s, not needed\n", http_dist_request.ver);
    return true;
  }

  CFileMD5s md5s_server;
  if (unlikely(!md5s_server.calculate(http_dist_request.fdir, http_dist_request.findex, type_is_single(*http_dist_request.type))))
  {
    C_ERROR("failed to calculate md5 file list for dist %s\n", http_dist_request.ver);
    return false;
  }
  md5s_server.sort();
  md5_len = md5s_server.total_size(true);

  CMemPoolX::instance()->alloc_mem(md5_len, &md5_result);
  if (unlikely(!md5s_server.to_buffer(md5_result.data(), md5_len, true)))
  {
    C_ERROR("can not get md5 file list result for dist %s\n", http_dist_request.ver);
    return false;
  }

//  truefalse result = MyServerAppX::instance()->db().save_dist_md5(http_dist_request.ver, md5_result.data(), md5_len);
//  if (likely(result))
//    C_INFO("file md5 list for %s generated and stored into database\n", http_dist_request.ver);
//  else
//    C_ERROR("can not save file md5 list for %s into database\n", http_dist_request.ver);
  return true;
}


truefalse MyDistMd5Calculator::calculate_all_in_one_ftp_md5(CONST text * dist_id, CMemGuard & md5_result)
{
  CMemGuard filename;
  MyDistCompressor::get_all_in_one_mbz_file_name(dist_id, filename);
  return c_util_calculate_file_md5(filename.data(), md5_result);
}


CMB * my_get_hb_mb()
{
  CMB * mb = CMemPoolX::instance()->get_mb_bs(1, "99");
  if (!mb)
    return NULL;
  text * dest = mb->base() + MyBSBasePacket::DATA_OFFSET;
  *dest = '1';
  *(dest + 1) = MyBSBasePacket::BS_PACKET_END_MARK;
  return mb;
}


//MyFindDistLoad//

class MyFindDistLoad
{
public:
  MyFindDistLoad(CONST text * addr)
  {
    m_addr = addr;
  }

  truefalse operator()(MyDistLoad& load) CONST
  {
    if (!m_addr)
      return false;
    return (strcmp(m_addr, load.m_ip_addr) == 0);
  }

private:
  CONST text * m_addr;
};


//MyDistLoads//

MyDistLoads::MyDistLoads()
{
  m_loads.reserve(6);
  m_server_list_length = 0;
  m_server_list[0] = 0;
}

DVOID MyDistLoads::update(CONST MyDistLoad & load)
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
    it->m_last_access = g_clock_counter;
  }

  calc_server_list();
}

DVOID MyDistLoads::remove(CONST text * addr)
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

MyDistLoads::MyDistLoadVecIt MyDistLoads::find_i(CONST text * addr)
{
  return find_if(m_loads.begin(), m_loads.end(), MyFindDistLoad(addr));
}

DVOID MyDistLoads::calc_server_list()
{
  m_server_list[0] = 0;
  sort(m_loads.begin(), m_loads.end());
  MyDistLoadVecIt it;
  ni remain_len = SERVER_LIST_LENGTH - 2;
  text * ptr = m_server_list;
  for (it = m_loads.begin(); it != m_loads.end(); ++it)
  {
    ni len = strlen(it->m_ip_addr);
    if (len == 0)
      continue;
    if (unlikely(len > remain_len))
    {
      C_ERROR("dist server addr list is too long @MyDistLoads::calc_server_list()\n");
      break;
    }
    memcpy(ptr, it->m_ip_addr, len + 1);
    ptr += len;
    remain_len -= (len + 1);
    *ptr = MyDataPacketHeader::ITEM_SEPARATOR;
    ++ptr;
  }
  *ptr = 0;

  ni ftp_list_len = CCfgX::instance()->ftp_addr_list.length();
  if (unlikely(ftp_list_len + 3 > remain_len))
    C_ERROR("ftp server addr list is too long @MyDistLoads::calc_server_list()\n");
  else
  {
    *ptr++ = MyDataPacketHeader::FINISH_SEPARATOR;
    ACE_OS::strsncpy(ptr, CCfgX::instance()->ftp_addr_list.c_str(), remain_len + 1);
  }

  m_server_list_length = strlen(m_server_list);
  ++m_server_list_length;
}

ni MyDistLoads::get_server_list(text * buffer, ni buffer_len)
{
  ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, m_mutex, 0);
  if (!buffer || buffer_len < m_server_list_length)
    return 0;
  ACE_OS::strsncpy(buffer, m_server_list, buffer_len);
  return m_server_list_length;
}

DVOID MyDistLoads::scan_for_dead()
{
  ACE_MT(ACE_GUARD(ACE_Thread_Mutex, ace_mon, m_mutex));
  MyDistLoadVecIt it;
  for (it = m_loads.begin(); it != m_loads.end(); )
  {
    if (it->m_last_access + ni(DEAD_TIME * 60 / CApp::CLOCK_INTERVAL) < g_clock_counter)
      it = m_loads.erase(it);
    else
      ++it;
  };

  calc_server_list();
}


//MyUnusedPathRemover//

MyUnusedPathRemover::~MyUnusedPathRemover()
{
  std::for_each(m_path_list.begin(), m_path_list.end(), CObjDeletor());
}

DVOID MyUnusedPathRemover::add_dist_id(CONST text * dist_id)
{
  CMemGuard * guard = new CMemGuard;
  guard->from_string(dist_id);
  m_path_list.push_back(guard);
  m_path_set.insert(guard->data());
}

truefalse MyUnusedPathRemover::path_ok(CONST text * _path)
{
  return m_path_set.find(_path) != m_path_set.end();
}

DVOID MyUnusedPathRemover::check_path(CONST text * path)
{
  DIR * dir = opendir(path);
  if (!dir)
  {
    C_ERROR("can not open directory: %s %s\n", path, (CONST char*)CErrno());
    return;
  }

  ni count = 0, ok_count = 0;
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
        CMemGuard mpath;
        mpath.from_string(path, "/", entry->d_name);
        if (CSysFS::remove_path(mpath.data(), true))
          ++ ok_count;
      }
    }
  };

  closedir(dir);
  C_INFO("removed %d/%d unused path(s) from compress_store\n", ok_count, count);
}


//MyLocationProcessor//

MyDistLoads * MyLocationProcessor::m_dist_loads = NULL;

MyLocationProcessor::MyLocationProcessor(CHandlerBase * handler): CServerProcBase(handler)
{

}

CONST text * MyLocationProcessor::name() CONST
{
  return "MyLocationProcessor";
}

CProcBase::EVENT_RESULT MyLocationProcessor::on_recv_header()
{
  if (CServerProcBase::on_recv_header() == ER_ERROR)
    return ER_ERROR;

  if (m_packet_header.command == MyDataPacketHeader::CMD_CLIENT_VERSION_CHECK_REQ)
  {
    if (!my_dph_validate_client_version_check_req(&m_packet_header))
    {
      C_ERROR("failed to validate header for client version check req\n");
      return ER_ERROR;
    }
    return ER_OK;
  }

  return ER_ERROR;
}

CProcBase::EVENT_RESULT MyLocationProcessor::on_recv_packet_i(CMB * mb)
{
  CServerProcBase::on_recv_packet_i(mb);

  MyDataPacketHeader * header = (MyDataPacketHeader *)mb->base();
  if (header->command == MyDataPacketHeader::CMD_CLIENT_VERSION_CHECK_REQ)
    return do_version_check(mb);

  CMBGuard guard(mb);
  C_ERROR("unsupported command received, command = %d\n", header->command);
  return ER_ERROR;
}


CProcBase::EVENT_RESULT MyLocationProcessor::do_version_check(CMB * mb)
{
  CMBGuard guard(mb);

//  MyClientIDTable & client_id_table = MyServerAppX::instance()->client_id_table();
//
//  MyBaseProcessor::EVENT_RESULT ret = do_version_check_common(mb, client_id_table);
//  if (ret != ER_CONTINUE)
//    return ret;
  m_client_id = "dummy";

  text server_list[MyDistLoads::SERVER_LIST_LENGTH];
  ni len = m_dist_loads->get_server_list(server_list, MyDistLoads::SERVER_LIST_LENGTH); //double copy
  CMB * reply_mb = make_version_check_reply_mb(MyClientVersionCheckReply::VER_SERVER_LIST, len);

  MyClientVersionCheckReply *reply = (MyClientVersionCheckReply *)reply_mb->base();
  if (likely(len > 0))
    memcpy(reply->data, server_list, len);

  if (m_handler->send_data(reply_mb) <= 0)
    return ER_ERROR; //no unsent data, force a close
  else
    return ER_OK;
}

PREPARE_MEMORY_POOL(MyLocationProcessor);


//MyLocationHandler//

MyLocationHandler::MyLocationHandler(CConnectionManagerBase * xptr): CHandlerBase(xptr)
{
  m_processor = new MyLocationProcessor(this);
}

PREPARE_MEMORY_POOL(MyLocationHandler);

//MyLocationService//

MyLocationService::MyLocationService(CMod * module, ni numThreads):
    CTaskBase(module, numThreads)
{

}

ni MyLocationService::svc()
{
  C_INFO("running %s::svc()\n", name());

  for (CMB * mb; getq(mb) != -1;)
  {

    mb->release ();
  }

  C_INFO("exiting %s::svc()\n", name());
  return 0;
}


//MyLocationAcceptor//

MyLocationAcceptor::MyLocationAcceptor(CDispatchBase * _dispatcher, CConnectionManagerBase * _manager):
    CAcceptorBase(_dispatcher, _manager)
{
  m_tcp_port = CCfgX::instance()->middle_server_client_port;
  m_idle_time_as_dead = IDLE_TIME_AS_DEAD;
}

ni MyLocationAcceptor::make_svc_handler(CHandlerBase *& sh)
{
  sh = new MyLocationHandler(m_connection_manager);
  if (!sh)
  {
    C_ERROR("can not alloc MyLocationHandler from %s\n", name());
    return -1;
  }
  sh->parent((void*)this);
  sh->reactor(reactor());
  return 0;
}

CONST text * MyLocationAcceptor::name() CONST
{
  return "MyLocationAcceptor";
}


//MyLocationDispatcher//

MyLocationDispatcher::MyLocationDispatcher(CMod * _module, ni numThreads):
    CDispatchBase(_module, numThreads)
{
  m_acceptor = NULL;
  msg_queue()->high_water_mark(MSG_QUEUE_MAX_SIZE);
}

truefalse MyLocationDispatcher::on_start()
{
  if (!m_acceptor)
    m_acceptor = new MyLocationAcceptor(this, new CConnectionManagerBase());
  add_acceptor(m_acceptor);
  return true;
}

DVOID MyLocationDispatcher::on_stop()
{
  m_acceptor = NULL;
}

CONST text * MyLocationDispatcher::name() CONST
{
  return "MyLocationDispatcher";
}

//MyLocationModule//

MyLocationModule::MyLocationModule(CApp * app): CMod(app)
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

truefalse MyLocationModule::on_start()
{
  add_task(m_service = new MyLocationService(this, 1));
  add_dispatch(m_dispatcher = new MyLocationDispatcher(this));
  return true;
}

DVOID MyLocationModule::on_stop()
{
  m_service = NULL;
  m_dispatcher = NULL;
}

CONST text * MyLocationModule::name() CONST
{
  return "MyLocationModule";
}

//============================//
//http module stuff begins here
//============================//

//MyHttpProcessor//

MyHttpProcessor::MyHttpProcessor(CHandlerBase * handler): super(handler)
{

}

MyHttpProcessor::~MyHttpProcessor()
{

}

CONST text * MyHttpProcessor::name() CONST
{
  return "MyHttpProcessor";
}

ni MyHttpProcessor::packet_length()
{
  return m_packet_header;
}

CProcBase::EVENT_RESULT MyHttpProcessor::on_recv_header()
{
  ni len = packet_length();
  if (len > 1024 * 1024 || len <= 32)
  {
    C_ERROR("got an invalid http packet with size = %d\n", len);
    return ER_ERROR;
  }
  C_INFO("http processor got packet len = %d\n", len);
  return ER_OK;
}

CProcBase::EVENT_RESULT MyHttpProcessor::on_recv_packet_i(CMB * mb)
{
  ACE_UNUSED_ARG(mb);
  C_INFO("http processor got complete packet, len = %d\n", mb->length());
  m_wait_for_close = true;
  truefalse ok = do_process_input_data();
  CMB * reply_mb = CMemPoolX::instance()->get_mb(1);
  if (!reply_mb)
  {
    C_ERROR(ACE_TEXT("failed to allocate 1 bytes sized memory block @MyHttpProcessor::handle_input().\n"));
    return ER_ERROR;
  }
  *(reply_mb->base()) = (ok? '1':'0');
  reply_mb->wr_ptr(1);
  return (m_handler->send_data(reply_mb) <= 0 ? ER_ERROR:ER_OK);
}

truefalse MyHttpProcessor::do_process_input_data()
{
  truefalse result = true;
  CONST text * CONST_dist_cmd = "http://127.0.0.1:10092/file?";
  CONST text * CONST_task_cmd = "http://127.0.0.1:10092/task?";
  CONST text * CONST_prio_cmd = "http://127.0.0.1:10092/prio?";
  ni ntype = -1;
  if (likely(ACE_OS::strncmp(CONST_dist_cmd, m_current_block->base() + 4, strlen(CONST_dist_cmd)) == 0))
    ntype = 1;
  else if (ACE_OS::strncmp(CONST_task_cmd, m_current_block->base() + 4, strlen(CONST_task_cmd)) == 0)
  {
    ntype = 3;
    m_current_block->set_self_flags(0x2000);
  }
  else if (ACE_OS::strncmp(CONST_prio_cmd, m_current_block->base() + 4, strlen(CONST_prio_cmd)) == 0)
  {
    truefalse ret = do_prio(m_current_block);
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
    result = (c_util_mb_putq(MyServerAppX::instance()->http_module()->http_service(), m_current_block,
              "http request into target queue @MyHttpProcessor::do_process_input_data()"));
  m_current_block = NULL;
  return result;
}

truefalse MyHttpProcessor::do_prio(CMB * mb)
{
  CONST text CONST_header[] = "http://127.0.0.1:10092/prio?";
  CONST ni CONST_header_len = sizeof(CONST_header) / sizeof(text) - 1;
  ni mb_len = mb->length();
  memmove(mb->base(), mb->base() + 4, mb_len - 4);
  mb->base()[mb_len - 4] = 0;
  if (unlikely((ni)(mb->length()) <= CONST_header_len + 10))
  {
    C_ERROR("bad http request, packet too short\n", CONST_header);
    return false;
  }

  text * packet = mb->base();
  if (memcmp(packet, CONST_header, CONST_header_len) != 0)
  {
    C_ERROR("bad http packet, no match header of (%s) found\n", CONST_header);
    return false;
  }

  packet += CONST_header_len;
  CONST text CONST_separator = '&';

  CONST text * CONST_ver = "ver=";
  text * ver = 0;
  if (!c_util_find_tag_value(packet, CONST_ver, ver, CONST_separator))
  {
    C_ERROR("can not find tag %s at http packet\n", CONST_ver);
    return false;
  }


  CONST text * CONST_plist = "plist=";
  text * plist = 0;
  if (!c_util_find_tag_value(packet, CONST_plist, plist, CONST_separator))
  {
    C_ERROR("can not find tag %s at http packet\n", CONST_plist);
    return false;
  }


  MyDB & db = MyServerAppX::instance()->db();
  if (!db.ping_db_server())
  {
    C_ERROR("no connection to db, aborting processing\n");
    return false;
  }

  C_INFO("prio list = %s\n", plist? plist:"NULL");
  return db.save_prio(plist);
}

PREPARE_MEMORY_POOL(MyHttpProcessor);


//MyHttpHandler//

MyHttpHandler::MyHttpHandler(CConnectionManagerBase * xptr): CHandlerBase(xptr)
{
  m_processor = new MyHttpProcessor(this);
}

PREPARE_MEMORY_POOL(MyHttpHandler);


//MyHttpAcceptor//

MyHttpAcceptor::MyHttpAcceptor(CDispatchBase * _dispatcher, CConnectionManagerBase * _manager):
    CAcceptorBase(_dispatcher, _manager)
{
  m_tcp_port = CCfgX::instance()->http_port;
  m_idle_time_as_dead = IDLE_TIME_AS_DEAD;
}

ni MyHttpAcceptor::make_svc_handler(CHandlerBase *& sh)
{
  sh = new MyHttpHandler(m_connection_manager);
  if (!sh)
  {
    C_ERROR("not enough memory to create MyHttpHandler object\n");
    return -1;
  }
  sh->parent((void*)this);
  sh->reactor(reactor());
  return 0;
}

CONST text * MyHttpAcceptor::name() CONST
{
  return "MyHttpAcceptor";
}


//MyHttpService//

MyHttpService::MyHttpService(CMod * module, ni numThreads)
  : CTaskBase(module, numThreads)
{
  msg_queue()->high_water_mark(MSG_QUEUE_MAX_SIZE);
}

ni MyHttpService::svc()
{
  C_INFO("running %s::svc()\n", name());

  for (CMB * mb; getq(mb) != -1; )
  {
    handle_packet(mb);
    mb->release();
  }

  C_INFO("exiting %s::svc()\n", name());
  return 0;
};

CONST text * MyHttpService::name() CONST
{
  return "MyHttpService";
}

truefalse MyHttpService::parse_request(CMB * mb, MyHttpDistRequest &http_dist_request)
{
  CONST text CONST_header[] = "http://127.0.0.1:10092/file?";
  CONST ni CONST_header_len = sizeof(CONST_header) / sizeof(text) - 1;
  ni mb_len = mb->length();
  memmove(mb->base(), mb->base() + 4, mb_len - 4);
  mb->base()[mb_len - 4] = 0;
  if (unlikely((ni)(mb->length()) <= CONST_header_len + 10))
  {
    C_ERROR("bad http request, packet too short\n", CONST_header);
    return false;
  }

  text * packet = mb->base();
  if (memcmp(packet, CONST_header, CONST_header_len) != 0)
  {
    C_ERROR("bad http packet, no match header of (%s) found\n", CONST_header);
    return false;
  }

  packet += CONST_header_len;
  CONST text CONST_separator = '&';

  CONST text * CONST_acode = "acode=";
  if (!c_util_find_tag_value(packet, CONST_acode, http_dist_request.acode, CONST_separator))
  {
    C_ERROR("can not find tag %s at http packet\n", CONST_acode);
    return false;
  }

  CONST text * CONST_ftype = "ftype=";
  if (!c_util_find_tag_value(packet, CONST_ftype, http_dist_request.ftype, CONST_separator))
  {
    C_ERROR("can not find tag %s at http packet\n", CONST_ftype);
    return false;
  }

  CONST text * CONST_fdir = "fdir=";
  if (!c_util_find_tag_value(packet, CONST_fdir, http_dist_request.fdir, CONST_separator))
  {
    C_ERROR("can not find tag %s at http packet\n", CONST_fdir);
    return false;
  }

  CONST text * CONST_findex = "findex=";
  if (!c_util_find_tag_value(packet, CONST_findex, http_dist_request.findex, CONST_separator))
  {
    C_ERROR("can not find tag %s at http packet\n", CONST_findex);
    return false;
  }

  CONST text * CONST_adir = "adir=";
  if (!c_util_find_tag_value(packet, CONST_adir, http_dist_request.adir, CONST_separator))
  {
    C_ERROR("can not find tag %s at http packet\n", CONST_adir);
    return false;
  }

  CONST text * CONST_aindex = "aindex=";
  if (!c_util_find_tag_value(packet, CONST_aindex, http_dist_request.aindex, CONST_separator))
  {
    C_ERROR("can not find tag %s at http packet\n", CONST_aindex);
    return false;
  }

  CONST text * CONST_ver = "ver=";
  if (!c_util_find_tag_value(packet, CONST_ver, http_dist_request.ver, CONST_separator))
  {
    C_ERROR("can not find tag %s at http packet\n", CONST_ver);
    return false;
  }

  CONST text * CONST_type = "type=";
  if (!c_util_find_tag_value(packet, CONST_type, http_dist_request.type, CONST_separator))
  {
    C_ERROR("can not find tag %s at http packet\n", CONST_type);
    return false;
  }

  return true;
}

truefalse MyHttpService::handle_packet(CMB * _mb)
{
  if ((_mb->self_flags() & 0x2000) == 0)
  {
    MyHttpDistRequest http_dist_request;
    truefalse result = do_handle_packet(_mb, http_dist_request);
    if (unlikely(!result && !http_dist_request.check_valid(true)))
      return false;
    ni total_len;
    text buff[32];
    c_util_generate_time_string(buff, 32, true);
    total_len = strlen(buff) + strlen(http_dist_request.ver) + 8;
    CMB * mb = CMemPoolX::instance()->get_mb_bs(total_len, MY_BS_DIST_FEEDBACK_CMD);
    text * dest = mb->base() + MyBSBasePacket::DATA_OFFSET;
    sprintf(dest, "%s#%c##1#%c#%s", http_dist_request.ver, *http_dist_request.ftype,
        result? '1':'0', buff);
    dest[total_len] = MyBSBasePacket::BS_PACKET_END_MARK;
    MyServerAppX::instance()->dist_load_module()->dispatcher()->send_to_bs(mb);

    return result;
  } else
  {
    return do_handle_packet2(_mb);
  }
}

truefalse MyHttpService::do_handle_packet(CMB * mb, MyHttpDistRequest & http_dist_request)
{
  if (!parse_request(mb, http_dist_request))
    return false;

  if (!http_dist_request.check_valid(true))
    return false;

  text password[12];
  c_util_gen_random_password(password, 12);
  http_dist_request.password = password;
  MyDB & db = MyServerAppX::instance()->db();

  if (unlikely(!module_x()->running_with_app()))
    return false;

  if (!do_compress(http_dist_request))
    return false;

  if (unlikely(!module_x()->running_with_app()))
    return false;

  CMemGuard md5_result;
  {
    MyDistMd5Calculator calc;
    ni md5_len;
    if (!calc.calculate(http_dist_request, md5_result, md5_len))
      return false;
  }

  if (unlikely(!module_x()->running_with_app()))
    return false;

  CMemGuard mbz_md5_result;
//  if (http_dist_request.need_mbz_md5()) //generate all in one.mbz md5 anyway
  {
    if (!MyDistMd5Calculator::calculate_all_in_one_ftp_md5(http_dist_request.ver, mbz_md5_result))
      return false;
  }

  if (!db.ping_db_server())
  {
    C_ERROR("no connection to db, aborting processing of dist %s\n", http_dist_request.ver);
    return false;
  }

  if (!db.save_dist(http_dist_request, md5_result.data(), mbz_md5_result.data()))
  {
    C_ERROR("can not save_dist to db\n");
    return false;
  }

  if (!db.save_dist_clients(http_dist_request.acode, http_dist_request.adir, http_dist_request.ver))
  {
    C_ERROR("can not save_dist_clients to db\n");
    return false;
  }

  if (unlikely(!module_x()->running_with_app()))
    return false;

  if (!db.dist_info_update_status())
  {
    C_ERROR("call to dist_info_update_status() failed\n");
    return false;
  }

  db.remove_orphan_dist_info();

  notify_dist_servers();

  MyUnusedPathRemover path_remover;
  if (db.get_dist_ids(path_remover))
    path_remover.check_path(CCfgX::instance()->bz_files_path.c_str());

  return true;
}

truefalse MyHttpService::do_handle_packet2(CMB * mb)
{
  CONST text CONST_header[] = "http://127.0.0.1:10092/task?";
  CONST ni CONST_header_len = sizeof(CONST_header) / sizeof(text) - 1;
  ni mb_len = mb->length();
  memmove(mb->base(), mb->base() + 4, mb_len - 4);
  mb->base()[mb_len - 4] = 0;
  if (unlikely((ni)(mb->length()) <= CONST_header_len + 10))
  {
    C_ERROR("bad http request, packet too short\n", CONST_header);
    return false;
  }

  text * packet = mb->base();
  if (memcmp(packet, CONST_header, CONST_header_len) != 0)
  {
    C_ERROR("bad http packet, no match header of (%s) found\n", CONST_header);
    return false;
  }

  packet += CONST_header_len;
  CONST text CONST_separator = '&';

  CONST text * CONST_ver = "ver=";
  text * ver = 0;
  if (!c_util_find_tag_value(packet, CONST_ver, ver, CONST_separator))
  {
    C_ERROR("can not find tag %s at http packet\n", CONST_ver);
    return false;
  }


  CONST text * CONST_cmd = "cmd=";
  text * cmd = 0;
  if (!c_util_find_tag_value(packet, CONST_cmd, cmd, CONST_separator))
  {
    C_ERROR("can not find tag %s at http packet\n", CONST_cmd);
    return false;
  }

  CONST text * CONST_backid = "backid=";
  text * backid = 0;
  if (!c_util_find_tag_value(packet, CONST_backid, backid, CONST_separator))
  {
    C_ERROR("can not find tag %s at http packet\n", CONST_backid);
    return false;
  }

  CONST text * CONST_acode = "acode=";
  text * acode = 0;
  if (!c_util_find_tag_value(packet, CONST_acode, acode, CONST_separator))
  {
    C_ERROR("can not find tag %s at http packet\n", CONST_acode);
    return false;
  }

  MyDB & db = MyServerAppX::instance()->db();
  if (!db.ping_db_server())
  {
    C_ERROR("no connection to db, aborting processing\n");
    return false;
  }

  db.save_sr(backid, cmd, acode);
  if (!db.dist_info_update_status())
  {
    C_ERROR("call to dist_info_update_status() failed\n");
    return false;
  }

  notify_dist_servers();
  return true;
}

truefalse MyHttpService::do_compress(MyHttpDistRequest & http_dist_request)
{
  MyDistCompressor compressor;
  return compressor.compress(http_dist_request);
}

truefalse MyHttpService::do_calc_md5(MyHttpDistRequest & http_dist_request)
{
  MyDistMd5Calculator calc;
  CMemGuard md5_result;
  ni md5_len;
  return calc.calculate(http_dist_request, md5_result, md5_len);
}

truefalse MyHttpService::notify_dist_servers()
{
  CMB * mb = CMemPoolX::instance()->get_mb_cmd(0, MyDataPacketHeader::CMD_HAVE_DIST_TASK);
  return c_util_mb_putq(MyServerAppX::instance()->dist_load_module()->dispatcher(), mb, "dist task notification to target queue");
}

//MyHttpDispatcher//

MyHttpDispatcher::MyHttpDispatcher(CMod * pModule, ni numThreads):
    CDispatchBase(pModule, numThreads)
{
  m_acceptor = NULL;
}

CONST text * MyHttpDispatcher::name() CONST
{
  return "MyHttpDispatcher";
}

DVOID MyHttpDispatcher::on_stop()
{
  m_acceptor = NULL;
}

truefalse MyHttpDispatcher::on_start()
{
  if (!m_acceptor)
    m_acceptor = new MyHttpAcceptor(this, new CConnectionManagerBase());
  add_acceptor(m_acceptor);
  return true;
}


//MyHttpModule//

MyHttpModule::MyHttpModule(CApp * app): CMod(app)
{
  m_dispatcher = NULL;
  m_service = NULL;
}

MyHttpModule::~MyHttpModule()
{

}

CONST text * MyHttpModule::name() CONST
{
  return "MyHttpModule";
}

MyHttpService * MyHttpModule::http_service()
{
  return m_service;
}

truefalse MyHttpModule::on_start()
{
  add_task(m_service = new MyHttpService(this, 1));
  add_dispatch(m_dispatcher = new MyHttpDispatcher(this));
  return true;
}

DVOID MyHttpModule::on_stop()
{
  m_dispatcher = NULL;
  m_service = NULL;
}


//============================//
//DistLoad module stuff begins here
//============================//

//MyDistLoadProcessor//

MyDistLoadProcessor::MyDistLoadProcessor(CHandlerBase * handler): CServerProcBase(handler)
{
  m_client_id_verified = false;
  m_dist_loads = NULL;
  m_handler->msg_queue()->high_water_mark(MSG_QUEUE_MAX_SIZE);
}

MyDistLoadProcessor::~MyDistLoadProcessor()
{

}

CONST text * MyDistLoadProcessor::name() CONST
{
  return "MyDistLoadProcessor";
}

DVOID MyDistLoadProcessor::dist_loads(MyDistLoads * dist_loads)
{
  m_dist_loads = dist_loads;
}

CProcBase::EVENT_RESULT MyDistLoadProcessor::on_recv_header()
{
  if (super::on_recv_header() == ER_ERROR)
    return ER_ERROR;

  if (m_packet_header.command == MyDataPacketHeader::CMD_CLIENT_VERSION_CHECK_REQ)
  {
    if (!my_dph_validate_client_version_check_req(&m_packet_header))
    {
      CMemGuard info;
      info_string(info);
      C_ERROR("bad client version check req packet received from %s\n", info.data());
      return ER_ERROR;
    }
    return ER_OK;
  }

  if (m_packet_header.command == MyDataPacketHeader::CMD_LOAD_BALANCE_REQ)
  {
    if (!my_dph_validate_load_balance_req(&m_packet_header))
    {
      CMemGuard info;
      info_string(info);
      C_ERROR("bad load_balance packet received from %s\n", info.data());
      return ER_ERROR;
    }
    return ER_OK;
  }

  C_ERROR(ACE_TEXT("unexpected packet header received @MyDistLoadProcessor.on_recv_header, cmd = %d\n"),
      m_packet_header.command);
  return ER_ERROR;
}

CProcBase::EVENT_RESULT MyDistLoadProcessor::on_recv_packet_i(CMB * mb)
{
  CServerProcBase::on_recv_packet_i(mb);
  CMBGuard guard(mb);

  MyDataPacketHeader * header = (MyDataPacketHeader *)mb->base();
  if (header->command == MyDataPacketHeader::CMD_CLIENT_VERSION_CHECK_REQ)
    return do_version_check(mb);

  if (header->command == MyDataPacketHeader::CMD_LOAD_BALANCE_REQ)
    return do_load_balance(mb);

  C_ERROR("unsupported command received @MyDistLoadProcessor::on_recv_packet_i, command = %d\n",
      header->command);
  return ER_ERROR;
}

CProcBase::EVENT_RESULT MyDistLoadProcessor::do_version_check(CMB * mb)
{
  MyClientVersionCheckRequest * p = (MyClientVersionCheckRequest *) mb->base();
  m_client_id = "DistServer";
  truefalse result = (p->client_id == CCfgX::instance()->skey.c_str());
  if (!result)
  {
    CMemGuard info;
    info_string(info);
    C_ERROR("bad load_balance version check (bad key) received from %s\n", info.data());
    return ER_ERROR;
  }
  m_client_id_verified = true;

  CMB * reply_mb = make_version_check_reply_mb(MyClientVersionCheckReply::VER_OK);
  return (m_handler->send_data(reply_mb) < 0 ? ER_ERROR: ER_OK);
}

truefalse MyDistLoadProcessor::client_id_verified() CONST
{
  return m_client_id_verified;
}

CProcBase::EVENT_RESULT MyDistLoadProcessor::do_load_balance(CMB * mb)
{
  MyLoadBalanceRequest * br = (MyLoadBalanceRequest *)mb->base();
  MyDistLoad dl;
  dl.clients_connected(br->clients_connected);
  dl.ip_addr(br->ip_addr);
  m_dist_loads->update(dl);
  return ER_OK;
}


//MyDistLoadHandler//

MyDistLoadHandler::MyDistLoadHandler(CConnectionManagerBase * xptr): CHandlerBase(xptr)
{
  m_processor = new MyDistLoadProcessor(this);
}

DVOID MyDistLoadHandler::dist_loads(MyDistLoads * dist_loads)
{
  ((MyDistLoadProcessor*)m_processor)->dist_loads(dist_loads);
}

PREPARE_MEMORY_POOL(MyDistLoadHandler);

//MyDistLoadAcceptor//

MyDistLoadAcceptor::MyDistLoadAcceptor(CDispatchBase * _dispatcher, CConnectionManagerBase * _manager):
    CAcceptorBase(_dispatcher, _manager)
{
  m_tcp_port = CCfgX::instance()->middle_server_dist_port;
  m_idle_time_as_dead = IDLE_TIME_AS_DEAD;
}

ni MyDistLoadAcceptor::make_svc_handler(CHandlerBase *& sh)
{
  sh = new MyDistLoadHandler(m_connection_manager);
  if (!sh)
  {
    C_ERROR("not enough memory to create MyDistLoadHandler object\n");
    return -1;
  }
  sh->parent((void*)this);
  sh->reactor(reactor());
  ((MyDistLoadHandler*)sh)->dist_loads(MyServerAppX::instance()->location_module()->dist_loads());
  return 0;
}

CONST text * MyDistLoadAcceptor::name() CONST
{
  return "MyDistLoadAcceptor";
}


//MyDistLoadDispatcher//

MyDistLoadDispatcher::MyDistLoadDispatcher(CMod * pModule, ni numThreads):
    CDispatchBase(pModule, numThreads)
{
  m_acceptor = NULL;
  m_bs_connector = NULL;
  msg_queue()->high_water_mark(MSG_QUEUE_MAX_SIZE);
}

MyDistLoadDispatcher::~MyDistLoadDispatcher()
{
  ACE_Time_Value tv(ACE_Time_Value::zero);
  ni i = 0;
  for (CMB * mb; m_to_bs_queue.dequeue(mb, &tv) != -1; )
  {
    ++i;
    mb->release();
  }
  if (i > 0)
    C_INFO("releasing %d mb on %s::termination\n", i, name());
}

CONST text * MyDistLoadDispatcher::name() CONST
{
  return "MyDistLoadDispatcher";
}

DVOID MyDistLoadDispatcher::send_to_bs(CMB * mb)
{
  ACE_Time_Value tv(ACE_Time_Value::zero);
  if (m_to_bs_queue.enqueue(mb, &tv) < 0)
  {
    C_ERROR("MyDistLoadDispatcher::send_to_bs() failed, %s\n", (CONST char*)CErrno());
    mb->release();
  }
}

ni MyDistLoadDispatcher::handle_timeout(CONST ACE_Time_Value &, CONST DVOID *)
{
  MyServerAppX::instance()->location_module()->dist_loads()->scan_for_dead();
  return 0;
}

DVOID MyDistLoadDispatcher::on_stop()
{
  m_acceptor = NULL;
  m_bs_connector = NULL;
  reactor()->cancel_timer(this);
}

truefalse MyDistLoadDispatcher::on_start()
{
  if (!m_acceptor)
    m_acceptor = new MyDistLoadAcceptor(this, new CConnectionManagerBase());
  add_acceptor(m_acceptor);
  if (!m_bs_connector)
    m_bs_connector = new MyMiddleToBSConnector(this, new CConnectionManagerBase());
  add_connector(m_bs_connector);

  ACE_Time_Value interval(ni(MyDistLoads::DEAD_TIME * 60 / CApp::CLOCK_INTERVAL / 2));
  if (reactor()->schedule_timer(this, 0, interval, interval) == -1)
  {
    C_ERROR("can not setup dist load server scan timer\n");
    return false;
  }
  return true;
}

truefalse MyDistLoadDispatcher::on_event_loop()
{
  ACE_Time_Value tv(ACE_Time_Value::zero);
  CMB * mb;
  CONST ni CONST_max_count = 10;
  ni i = 0;
  while (++i < CONST_max_count && this->getq(mb, &tv) != -1)
    m_acceptor->connection_manager()->broadcast(mb);

  i = 0;
  while (++i < CONST_max_count && m_to_bs_queue.dequeue(mb, &tv) != -1)
    m_bs_connector->connection_manager()->broadcast(mb);

  return true;
}


//MyDistLoadModule//

MyDistLoadModule::MyDistLoadModule(CApp * app): CMod(app)
{
  m_dispatcher = NULL;
}

MyDistLoadModule::~MyDistLoadModule()
{

}

CONST text * MyDistLoadModule::name() CONST
{
  return "MyDistLoadModule";
}

MyDistLoadDispatcher * MyDistLoadModule::dispatcher() CONST
{
  return m_dispatcher;
}

truefalse MyDistLoadModule::on_start()
{
  add_dispatch(m_dispatcher = new MyDistLoadDispatcher(this));
  return true;
}

DVOID MyDistLoadModule::on_stop()
{
  m_dispatcher = NULL;
}


/////////////////////////////////////
//middle to BS
/////////////////////////////////////

//MyMiddleToBSProcessor//

MyMiddleToBSProcessor::MyMiddleToBSProcessor(CHandlerBase * handler): super(handler)
{

}

CONST text * MyMiddleToBSProcessor::name() CONST
{
  return "MyMiddleToBSProcessor";
}

CProcBase::EVENT_RESULT MyMiddleToBSProcessor::on_recv_packet_i(CMB * mb)
{
  if (mb)
    mb->release();
  ((MyMiddleToBSHandler*)m_handler)->checker_update();
  return ER_OK;
}

PREPARE_MEMORY_POOL(MyMiddleToBSProcessor);


//MyMiddleToBSHandler//

MyMiddleToBSHandler::MyMiddleToBSHandler(CConnectionManagerBase * xptr): CHandlerBase(xptr)
{
  m_processor = new MyMiddleToBSProcessor(this);
}

MyDistLoadModule * MyMiddleToBSHandler::module_x() CONST
{
  return (MyDistLoadModule *)connector()->module_x();
}

DVOID MyMiddleToBSHandler::checker_update()
{
  m_checker.update();
}

ni MyMiddleToBSHandler::handle_timeout(CONST ACE_Time_Value &, CONST DVOID *)
{
  if (m_checker.expired())
  {
    C_ERROR("no data received from bs @MyMiddleToBSHandler ...\n");
    return -1;
  }
  CMB * mb = my_get_hb_mb();
  if (mb)
  {
    if (send_data(mb) < 0)
      return -1;
  }
  return 0;
}

ni MyMiddleToBSHandler::on_open()
{
  ACE_Time_Value interval(30);
  if (reactor()->schedule_timer(this, (void*)0, interval, interval) < 0)
  {
    C_ERROR(ACE_TEXT("MyMiddleToBSHandler setup timer failed, %s"), (CONST char*)CErrno());
    return -1;
  }

  if (!g_is_test)
    C_INFO("MyMiddleToBSHandler setup timer: OK\n");

  CMB * mb = my_get_hb_mb();
  if (mb)
  {
    if (send_data(mb) < 0)
      return -1;
  }
  m_checker.update();

  return 0;
}


DVOID MyMiddleToBSHandler::on_close()
{

}

PREPARE_MEMORY_POOL(MyMiddleToBSHandler);


//MyMiddleToBSConnector//

MyMiddleToBSConnector::MyMiddleToBSConnector(CDispatchBase * _dispatcher, CConnectionManagerBase * _manager):
    CConnectorBase(_dispatcher, _manager)
{
  m_tcp_port = CCfgX::instance()->bs_port;
  m_reconnect_interval = RECONNECT_INTERVAL;
  m_tcp_addr = CCfgX::instance()->bs_addr;
}

CONST text * MyMiddleToBSConnector::name() CONST
{
  return "MyMiddleToBSConnector";
}

ni MyMiddleToBSConnector::make_svc_handler(CHandlerBase *& sh)
{
  sh = new MyMiddleToBSHandler(m_connection_manager);
  if (!sh)
  {
    C_ERROR("can not alloc MyMiddleToBSHandler from %s\n", name());
    return -1;
  }
  sh->parent((void*)this);
  sh->reactor(reactor());
  return 0;
}

//!//dist component

//MyDistClient//

MyDistClient::MyDistClient(MyHttpDistInfo * _dist_info, MyDistClientOne * _dist_one)
{
  dist_info = _dist_info;
  status = -1;
  last_update = 0;
  dist_one = _dist_one;
}

truefalse MyDistClient::check_valid() CONST
{
  return ((dist_info != NULL) && (status >= 0 && status <= 4));
}

truefalse MyDistClient::active()
{
  return dist_one->active();
}

CONST text * MyDistClient::client_id() CONST
{
  return dist_one->client_id();
}

ni MyDistClient::client_id_index() CONST
{
  return dist_one->client_id_index();
}

DVOID MyDistClient::update_status(ni _status)
{
  if (_status > status)
    status = _status;
}

DVOID MyDistClient::delete_self()
{
  dist_one->delete_dist_client(this);
}

DVOID MyDistClient::update_md5_list(CONST text * _md5)
{
  if (unlikely(!dist_info->need_md5()))
  {
    C_WARNING("got unexpected md5 reply packet on client_id(%s) dist_id(%s)\n",
        client_id(), dist_info->ver.data());
    return;
  }

  if (unlikely(md5.data() && md5.data()[0]))
    return;

  md5.from_string(_md5);
  update_status(2);
}

DVOID MyDistClient::send_fb_detail(truefalse ok)
{
  CMB * mb = make_ftp_fb_detail_mb(ok);
  MyServerAppX::instance()->dist_to_middle_module()->send_to_bs(mb);
}

DVOID MyDistClient::psp(CONST text /*c*/)
{
  delete_self();
/*  if (c == '0')
    update_status(6);
  else
    update_status(8);
*/
}

DVOID MyDistClient::dist_ftp_md5_reply(CONST text * md5list)
{
  if (unlikely(*md5list == 0))
  {
    text buff[50];
    c_util_generate_time_string(buff, 50, true);
    MyServerAppX::instance()->heart_beat_module()->ftp_feedback_submitter().add(
        dist_info->ver.data(),
        dist_info->ftype[0],
        client_id(),
        '2', '1', buff);

    MyServerAppX::instance()->heart_beat_module()->ftp_feedback_submitter().add(
        dist_info->ver.data(),
        dist_info->ftype[0],
        client_id(),
        '3', '1', buff);

    MyServerAppX::instance()->heart_beat_module()->ftp_feedback_submitter().add(
        dist_info->ver.data(),
        dist_info->ftype[0],
        client_id(),
        '4', '1', buff);

    send_fb_detail(true);

    dist_one->delete_dist_client(this);
//    MyServerAppX::instance()->db().set_dist_client_status(*this, 5);
//    update_status(5);
    return;
  }

  if (!md5.data() || !md5.data()[0])
  {
    update_md5_list(md5list);
    MyServerAppX::instance()->db().set_dist_client_md5(client_id(), dist_info->ver.data(), md5list, 2);
  }

  do_stage_2();
}

truefalse MyDistClient::dist_file()
{
  if (!active())
    return true;

  switch (status)
  {
  case 0:
    return do_stage_0();

  case 1:
    return do_stage_1();

  case 2:
    return do_stage_2();

  case 3:
    return do_stage_3();

  case 4:
    return do_stage_4();

  case 5:
    return do_stage_5();

  case 6:
    return do_stage_6();

  case 7:
    return do_stage_7();

  case 8:
    return do_stage_8();

  default:
    C_ERROR("unexpected status value = %d @MyDistClient::dist_file\n", status);
    return false;
  }
}

truefalse MyDistClient::do_stage_0()
{
  if (dist_info->need_md5())
  {
    if(send_md5())
    {
      MyServerAppX::instance()->db().set_dist_client_status(*this, 1);
      update_status(1);
    }
    return true;
  }

  if (send_ftp())
  {
    MyServerAppX::instance()->db().set_dist_client_status(*this, 3);
    update_status(3);
  }
  return true;
}

truefalse MyDistClient::do_stage_1()
{
  time_t now = time(NULL);
  if (now > last_update + MD5_REPLY_TIME_OUT * 60)
    send_md5();

  return true;
}

truefalse MyDistClient::do_stage_2()
{
  if (!mbz_file.data() || !mbz_file.data()[0])
  {
    if ((dist_info->md5_opt_len > 0 && (ni)strlen(md5.data()) >= dist_info->md5_opt_len) || !generate_diff_mbz())
    {
      mbz_file.from_string(MyDistCompressor::all_in_one_mbz());
      mbz_md5.from_string(dist_info->mbz_md5.data());
    }
    MyServerAppX::instance()->db().set_dist_client_mbz(client_id(), dist_info->ver.data(), mbz_file.data(), mbz_md5.data());
  }

  if (send_ftp())
  {
    MyServerAppX::instance()->db().set_dist_client_status(*this, 3);
    update_status(3);
  }
  return true;
}

truefalse MyDistClient::do_stage_3()
{
  time_t now = time(NULL);
  if (now > last_update + FTP_REPLY_TIME_OUT * 60)
    send_ftp();

  return true;
}

truefalse MyDistClient::do_stage_4()
{
  return false;
}

truefalse MyDistClient::do_stage_5()
{
//  time_t now = time(NULL);
//  if (now > last_update + 5 * 60)
    send_psp('0');
  return true;
}

truefalse MyDistClient::do_stage_6()
{
  return false;
}

truefalse MyDistClient::do_stage_7()
{
//  time_t now = time(NULL);
//  if (now > last_update + 5 * 60)
    send_psp('1');
  return true;
}

truefalse MyDistClient::do_stage_8()
{
  return false;
}


ni MyDistClient::dist_out_leading_length()
{
  ni adir_len = adir.data() ? strlen(adir.data()) : (ni)MyDataPacketHeader::NULL_ITEM_LENGTH;
  ni aindex_len = dist_info->aindex_len > 0 ? dist_info->aindex_len : (ni)MyDataPacketHeader::NULL_ITEM_LENGTH;
  return dist_info->ver_len + dist_info->findex_len + aindex_len + adir_len + 4 + 2 + 2;
}

DVOID MyDistClient::dist_out_leading_data(text * data)
{
  sprintf(data, "%s%c%s%c%s%c%s%c%c%c%c%c",
      dist_info->ver.data(), MyDataPacketHeader::ITEM_SEPARATOR,
      dist_info->findex.data(), MyDataPacketHeader::ITEM_SEPARATOR,
      adir.data()? adir.data(): Null_Item, MyDataPacketHeader::ITEM_SEPARATOR,
      dist_info->aindex.data()? dist_info->aindex.data(): Null_Item, MyDataPacketHeader::ITEM_SEPARATOR,
      dist_info->ftype[0], MyDataPacketHeader::ITEM_SEPARATOR,
      dist_info->type[0], MyDataPacketHeader::FINISH_SEPARATOR);
}

CMB * MyDistClient::make_ftp_fb_detail_mb(truefalse bok)
{
  CMemGuard md5_new;
  text buff[32];
  c_util_generate_time_string(buff, 32, true);
  CONST text * detail_files;
  if (type_is_multi(dist_info->type[0]))
  {
    if (!md5.data())
      detail_files = "";
    else
    {
      md5_new.from_string(md5.data());
      c_util_string_replace_text(md5_new.data(), MyDataPacketHeader::ITEM_SEPARATOR, ':');
      ni len = strlen(md5_new.data());
      if (md5_new.data()[len - 1] == ':')
        md5_new.data()[len - 1] = 0;
      detail_files = md5_new.data();
    }
  }
  else
    detail_files = dist_info->findex.data();

  ni total_len = strlen(dist_one->client_id()) + strlen(dist_info->ver.data()) +
      strlen(buff) + strlen(dist_info->findex.data()) + strlen(detail_files) +
      10;
  //batNO, fileKindCode, agentCode, indexName, fileName, type,flag, date
  CMB * mb = CMemPoolX::instance()->get_mb_bs(total_len, MY_BS_DIST_FBDETAIL_CMD);
  text * dest = mb->base() + MyBSBasePacket::DATA_OFFSET;
  sprintf(dest, "%s#%c#%s#%s#%s#%c#%c#%s",
      dist_info->ver.data(),
      dist_info->ftype[0],
      dist_one->client_id(),
      dist_info->findex.data(),
      detail_files,
      dist_info->type[0],
      bok? '1': '0',
      buff);
  dest[total_len] = MyBSBasePacket::BS_PACKET_END_MARK;
  return mb;
}

truefalse MyDistClient::send_md5()
{
  if (!dist_info->md5.data() || !dist_info->md5.data()[0] || dist_info->md5_len <= 0)
    return false;

  ni md5_len = dist_info->md5_len + 1;
  ni data_len = dist_out_leading_length() + md5_len;
  CMB * mb = CMemPoolX::instance()->get_mb_cmd(data_len, MyDataPacketHeader::CMD_SERVER_FILE_MD5_LIST);
  MyDataPacketExt * md5_packet = (MyDataPacketExt *)mb->base();
  md5_packet->magic = client_id_index();
  dist_out_leading_data(md5_packet->data);
  memcpy(md5_packet->data + data_len - md5_len, dist_info->md5.data(), md5_len);

  last_update = time(NULL);

  return c_util_mb_putq(MyServerAppX::instance()->heart_beat_module()->dispatcher(), mb, "file md5 list to dispatcher's queue");
}

truefalse MyDistClient::generate_diff_mbz()
{
  CMemGuard destdir;
  CMemGuard composite_dir;
  CMemGuard mdestfile;
  destdir.from_string(CCfgX::instance()->bz_files_path.c_str(), "/", dist_info->ver.data());
  composite_dir.from_string(destdir.data(), "/", MyDistCompressor::composite_path());
  mdestfile.from_string(composite_dir.data(), "/", client_id(), ".mbz");
  CCompCombiner compositor;
  if (!compositor.open(mdestfile.data()))
    return false;
  CMemGuard md5_copy;
  md5_copy.from_string(md5.data());
  text separators[2] = { MyDataPacketHeader::ITEM_SEPARATOR, 0 };
  CStringTokenizer tokenizer(md5_copy.data(), separators);
  text * token;
  CMemGuard filename;
  while ((token =tokenizer.get()) != NULL)
  {
    filename.from_string(destdir.data(), "/", token, ".mbz");
    if (!compositor.add(filename.data()))
    {
      CSysFS::remove(mdestfile.data());
      return false;
    }
  }

  CMemGuard md5_result;
  if (!c_util_calculate_file_md5(mdestfile.data(), md5_result))
  {
    C_ERROR("failed to calculate md5 for file %s\n", mdestfile.data());
    CSysFS::remove(mdestfile.data());
    return false;
  }

  mbz_file.from_string(mdestfile.data() + strlen(destdir.data()) + 1);
  mbz_md5.from_string(md5_result.data());
  return true;
}

truefalse MyDistClient::send_psp(CONST text c)
{
  ni data_len = dist_info->ver_len + 2;
  CMB * mb = CMemPoolX::instance()->get_mb_cmd(data_len, MyDataPacketHeader::CMD_PSP);
  MyDataPacketExt * dpe = (MyDataPacketExt *)mb->base();
  dpe->magic = client_id_index();
  dpe->data[0] = c;
  memcpy(dpe->data + 1, dist_info->ver.data(), data_len - 1);
  last_update = time(NULL);
  return c_util_mb_putq(MyServerAppX::instance()->heart_beat_module()->dispatcher(), mb, "psp to dispatcher's queue");
}

truefalse MyDistClient::send_ftp()
{
  CONST text * ftp_file_name;
  CONST text * _mbz_md5;

  if (!dist_info->need_md5())
  {
    ftp_file_name = MyDistCompressor::all_in_one_mbz();
    _mbz_md5 = dist_info->mbz_md5.data();
  } else
  {
    ftp_file_name = mbz_file.data();
    _mbz_md5 = mbz_md5.data();
  }

  ni _mbz_md5_len = strlen(_mbz_md5) + 1;
  ni leading_length = dist_out_leading_length();
  ni ftp_file_name_len = strlen(ftp_file_name) + 1;
  ni data_len = leading_length + ftp_file_name_len + dist_info->password_len + 1 + _mbz_md5_len;
  CMB * mb = CMemPoolX::instance()->get_mb_cmd(data_len, MyDataPacketHeader::CMD_FTP_FILE);
  MyDataPacketExt * packet = (MyDataPacketExt *)mb->base();
  packet->magic = client_id_index();
  dist_out_leading_data(packet->data);
  text * ptr = packet->data + leading_length;
  memcpy(ptr, ftp_file_name, ftp_file_name_len);
  ptr += ftp_file_name_len;
  *(ptr - 1) = MyDataPacketHeader::ITEM_SEPARATOR;
  memcpy(ptr, _mbz_md5, _mbz_md5_len);
  ptr += _mbz_md5_len;
  *(ptr - 1) = MyDataPacketHeader::FINISH_SEPARATOR;
  memcpy(ptr, dist_info->password.data(), dist_info->password_len + 1);

  last_update = time(NULL);

  return c_util_mb_putq(MyServerAppX::instance()->heart_beat_module()->dispatcher(), mb, "file md5 list to dispatcher's queue");
}


//MyDistClientOne//

MyDistClientOne::MyDistClientOne(MyDistClients * dist_clients, CONST text * client_id): m_client_id(client_id)
{
  m_dist_clients = dist_clients;
  m_client_id_index = -1;
}

MyDistClientOne::~MyDistClientOne()
{
  clear();
}

CONST text * MyDistClientOne::client_id() CONST
{
  return m_client_id.as_string();
}

ni MyDistClientOne::client_id_index() CONST
{
  return m_client_id_index;
}

truefalse MyDistClientOne::active()
{
  truefalse switched;
  return g_client_ids->active(m_client_id, m_client_id_index, switched);
}

truefalse MyDistClientOne::is_client_id(CONST text * _client_id) CONST
{
  return strcmp(m_client_id.as_string(), _client_id) == 0;
}

MyDistClient * MyDistClientOne::create_dist_client(MyHttpDistInfo * _dist_info)
{
  DVOID * p = CMemPoolX::instance()->alloc_mem_x(sizeof(MyDistClient));
  MyDistClient * result = new (p) MyDistClient(_dist_info, this);
  m_client_ones.push_back(result);
  m_dist_clients->on_create_dist_client(result);
  return result;
}

DVOID MyDistClientOne::delete_dist_client(MyDistClient * dc)
{
  m_dist_clients->on_remove_dist_client(dc, false);
  m_client_ones.remove(dc);
  MyServerAppX::instance()->db().delete_dist_client(m_client_id.as_string(), dc->dist_info->ver.data());
  CPoolObjectDeletor dlt;
  dlt(dc);
//  if (m_client_ones.empty())
//    m_dist_clients->delete_client_one(this);
}

DVOID MyDistClientOne::clear()
{
  std::for_each(m_client_ones.begin(), m_client_ones.end(), CPoolObjectDeletor());
  m_client_ones.clear();
}

truefalse MyDistClientOne::dist_files()
{
  truefalse switched;
  if (!g_client_ids->active(m_client_id, m_client_id_index, switched))
    return !m_client_ones.empty();

  MyDistClientOneList::iterator it;

  if (unlikely(switched))
  {
    g_client_ids->switched(m_client_id_index, false);
    for (it = m_client_ones.begin(); it != m_client_ones.end(); ++it)
      m_dist_clients->on_remove_dist_client(*it, false);
    clear();
    MyServerAppX::instance()->db().load_dist_clients(m_dist_clients, this);
    C_DEBUG("reloading client one db for client id (%s)\n", m_client_id.as_string());
  }

  for (it = m_client_ones.begin(); it != m_client_ones.end(); )
  {
    if (!(*it)->dist_file())
    {
      m_dist_clients->on_remove_dist_client(*it, true);
      CPoolObjectDeletor dlt;
      dlt(*it);
      it = m_client_ones.erase(it);
    } else
      ++it;
  }
  return !m_client_ones.empty();
}


//MyClientMapKey//

MyClientMapKey::MyClientMapKey(CONST text * _dist_id, CONST text * _client_id)
{
  dist_id = _dist_id;
  client_id = _client_id;
}

truefalse MyClientMapKey::operator == (CONST MyClientMapKey & rhs) CONST
{
  return strcmp(dist_id, rhs.dist_id) == 0 &&
      strcmp(client_id, rhs.client_id) == 0;
}


//MyDistClients//

MyDistClients::MyDistClients(MyHttpDistInfos * dist_infos)
{
  m_dist_infos = dist_infos;
  db_time = 0;
  m_dist_client_finished = 0;
}

MyDistClients::~MyDistClients()
{
  clear();
}

DVOID MyDistClients::clear()
{
  std::for_each(dist_clients.begin(), dist_clients.end(), CPoolObjectDeletor());
  dist_clients.clear();
  m_dist_clients_map.clear();
  m_dist_client_ones_map.clear();
  db_time = 0;
}

DVOID MyDistClients::on_create_dist_client(MyDistClient * dc)
{
  m_dist_clients_map.insert(std::pair<const MyClientMapKey, MyDistClient *>
     (MyClientMapKey(dc->dist_info->ver.data(), dc->client_id()), dc));
}

DVOID MyDistClients::on_remove_dist_client(MyDistClient * dc, truefalse finished)
{
  if (finished)
    ++m_dist_client_finished;
  m_dist_clients_map.erase(MyClientMapKey(dc->dist_info->ver.data(), dc->client_id()));
}

MyHttpDistInfo * MyDistClients::find_dist_info(CONST text * dist_id)
{
  C_ASSERT_RETURN(m_dist_infos, "", NULL);
  return m_dist_infos->find(dist_id);
}

MyDistClient * MyDistClients::find_dist_client(CONST text * client_id, CONST text * dist_id)
{
  MyDistClientMap::iterator it;
  it = m_dist_clients_map.find(MyClientMapKey(dist_id, client_id));
  if (it == m_dist_clients_map.end())
    return NULL;
  else
    return it->second;
}

MyDistClientOne * MyDistClients::find_client_one(CONST text * client_id)
{
  MyDistClientOneMap::iterator it;
  it = m_dist_client_ones_map.find(client_id);
  if (it == m_dist_client_ones_map.end())
    return NULL;
  else
    return it->second;
}

MyDistClientOne * MyDistClients::create_client_one(CONST text * client_id)
{
  DVOID * p = CMemPoolX::instance()->alloc_mem_x(sizeof(MyDistClientOne));
  MyDistClientOne * result = new (p) MyDistClientOne(this, client_id);
  dist_clients.push_back(result);
  m_dist_client_ones_map.insert(std::pair<const text *, MyDistClientOne *>(result->client_id(), result));
  return result;
}

DVOID MyDistClients::delete_client_one(MyDistClientOne * dco)
{
  m_dist_client_ones_map.erase(dco->client_id());
  CPoolObjectDeletor dlt;
  dlt(dco);
}

DVOID MyDistClients::dist_files()
{
  m_dist_client_finished = 0;
  MyDistClientOneList::iterator it;
  for (it = dist_clients.begin(); it != dist_clients.end(); )
  {
    if (!(*it)->dist_files())
    {
      m_dist_client_ones_map.erase((*it)->client_id());
      CPoolObjectDeletor dlt;
      dlt(*it);
      it = dist_clients.erase(it);
    } else
      ++it;
  }
  if (m_dist_client_finished > 0)
    C_INFO("number of dist client(s) finished in this round = %d\n", m_dist_client_finished);
  C_INFO("after dist_files(), dist info = %d, client one = %d, dist client = %d\n",
     m_dist_infos->count(),  m_dist_client_ones_map.size(), m_dist_clients_map.size());
}


//MyClientFileDistributor//

MyClientFileDistributor::MyClientFileDistributor(): m_dist_clients(&m_dist_infos)
{
  m_last_begin = 0;
  m_last_end = 0;
}

truefalse MyClientFileDistributor::distribute(truefalse check_reload)
{
  time_t now = time(NULL);
  truefalse reload = false;
  if (check_reload)
    reload = m_dist_infos.need_reload();
  else if (now - m_last_end < IDLE_TIME * 60)
    return false;
  else
    reload = m_dist_infos.need_reload();

  if (MyServerAppX::instance()->heart_beat_module())
    MyServerAppX::instance()->heart_beat_module()->pl();

  if (unlikely(reload))
    C_INFO("loading dist entries from db...\n");

  m_last_begin = now;
  check_dist_info(reload);
  check_dist_clients(reload);
  m_last_end = time(NULL);
  return true;
}

truefalse MyClientFileDistributor::check_dist_info(truefalse reload)
{
  if (reload)
  {
    m_dist_infos.prepare_update(0);
    return (MyServerAppX::instance()->db().load_dist_infos(m_dist_infos) < 0)? false:true;
  }

  return true;
}

truefalse MyClientFileDistributor::check_dist_clients(truefalse reload)
{
  if (reload)
  {
    m_dist_clients.clear();
    if (!MyServerAppX::instance()->db().load_dist_clients(&m_dist_clients, NULL))
      return false;
  }

  m_dist_clients.dist_files();
  return true;
}

DVOID MyClientFileDistributor::dist_ftp_file_reply(CONST text * client_id, CONST text * dist_id, ni _status, truefalse ok)
{
  MyDistClient * dc = m_dist_clients.find_dist_client(client_id, dist_id);
  if (unlikely(dc == NULL))
    return;

  if (_status <= 3)
  {
    dc->update_status(_status);
    MyServerAppX::instance()->db().set_dist_client_status(client_id, dist_id, _status);
  }
  else
  {
    dc->send_fb_detail(ok);
    dc->delete_self();
  }
}

DVOID MyClientFileDistributor::dist_ftp_md5_reply(CONST text * client_id, CONST text * dist_id, CONST text * md5list)
{
  MyDistClient * dc = m_dist_clients.find_dist_client(client_id, dist_id);
  if (likely(dc != NULL))
    dc->dist_ftp_md5_reply(md5list);
}

DVOID MyClientFileDistributor::psp(CONST text * client_id, CONST text * dist_id, text c)
{
  MyDistClient * dc = m_dist_clients.find_dist_client(client_id, dist_id);
  if (likely(dc != NULL))
    dc->psp(c);
}


//MyHeartBeatProcessor//

MyPingSubmitter * MyHeartBeatProcessor::m_heart_beat_submitter = NULL;
MyIPVerSubmitter * MyHeartBeatProcessor::m_ip_ver_submitter = NULL;
MyFtpFeedbackSubmitter * MyHeartBeatProcessor::m_ftp_feedback_submitter = NULL;
MyAdvClickSubmitter * MyHeartBeatProcessor::m_adv_click_submitter = NULL;
MyPcOnOffSubmitter * MyHeartBeatProcessor::m_pc_on_off_submitter = NULL;
MyHWAlarmSubmitter * MyHeartBeatProcessor::m_hardware_alarm_submitter = NULL;
MyVLCSubmitter * MyHeartBeatProcessor::m_vlc_submitter = NULL;
MyVLCEmptySubmitter * MyHeartBeatProcessor::m_vlc_empty_submitter = NULL;

MyHeartBeatProcessor::MyHeartBeatProcessor(CHandlerBase * handler): CServerProcBase(handler)
{
  m_handler->msg_queue()->high_water_mark(MSG_QUEUE_MAX_SIZE);
  m_hw_ver[0] = 0;
}

CONST text * MyHeartBeatProcessor::name() CONST
{
  return "MyHeartBeatProcessor";
}

CProcBase::EVENT_RESULT MyHeartBeatProcessor::on_recv_header()
{
//  {
//    MyPooledMemGuard info;
//    info_string(info);
//    if (m_packet_header.command != MyDataPacketHeader::CMD_HEARTBEAT_PING)
//      C_DEBUG("get client packet header: command = %d, len = %d from %s\n",
//          m_packet_header.command, m_packet_header.length, info.data());
//  }

  if (super::on_recv_header() == ER_ERROR)
    return ER_ERROR;

  if (m_packet_header.command == MyDataPacketHeader::CMD_HEARTBEAT_PING)
  {
    if (!my_dph_validate_heart_beat(&m_packet_header))
    {
      CMemGuard info;
      info_string(info);
      C_ERROR("bad heart beat packet received from %s\n", info.data());
      return ER_ERROR;
    }

    //the thread context switching and synchronization cost outbeat the benefit of using another thread
    do_ping();
    return ER_OK_FINISHED;
  }

  if (m_packet_header.command == MyDataPacketHeader::CMD_CLIENT_VERSION_CHECK_REQ)
  {
    if (!my_dph_validate_client_version_check_req(&m_packet_header, 30))
    {
      CMemGuard info;
      info_string(info);
      C_ERROR("bad client version check req packet received from %s\n", info.data());
      return ER_ERROR;
    }
    return ER_OK;
  }

  if (m_packet_header.command == MyDataPacketHeader::CMD_VLC_EMPTY)
  {
    if (!my_dph_validate_vlc_empty(&m_packet_header))
    {
      CMemGuard info;
      info_string(info);
      C_ERROR("bad client vlc empty req packet received from %s\n", info.data());
      return ER_ERROR;
    }
    return ER_OK;
  }


  if (m_packet_header.command == MyDataPacketHeader::CMD_HARDWARE_ALARM)
  {
    if (!my_dph_validate_plc_alarm(&m_packet_header))
    {
      CMemGuard info;
      info_string(info);
      C_ERROR("bad hardware alarm request packet received from %s\n", info.data());
      return ER_ERROR;
    }
    C_DEBUG("get hardware alarm packet from %s\n", m_client_id.as_string());
    return ER_OK;
  }

  if (m_packet_header.command == MyDataPacketHeader::CMD_SERVER_FILE_MD5_LIST)
  {
    if (!my_dph_validate_file_md5_list(&m_packet_header))
    {
      CMemGuard info;
      info_string(info);
      C_ERROR("bad md5 file list packet received from %s\n", info.data());
      return ER_ERROR;
    } else
    {
      CMemGuard info;
      info_string(info);
      C_INFO("get md5 file list packet received from %s, len = %d\n", info.data(), m_packet_header.length);
    }
    return ER_OK;
  }

  if (m_packet_header.command == MyDataPacketHeader::CMD_FTP_FILE)
  {
    if (!my_dph_validate_ftp_file(&m_packet_header))
    {
      CMemGuard info;
      info_string(info);
      C_ERROR("bad file ftp packet received from %s\n", info.data());
      return ER_ERROR;
    }
    return ER_OK;
  }

  if (m_packet_header.command == MyDataPacketHeader::CMD_IP_VER_REQ)
  {
    if (m_packet_header.length != sizeof(MyIpVerRequest) || m_packet_header.magic != MyDataPacketHeader::DATAPACKET_MAGIC)
    {
      CMemGuard info;
      info_string(info);
      C_ERROR("bad ip ver request packet received from %s\n", info.data());
      return ER_ERROR;
    }
    return ER_OK;
  }

  if (m_packet_header.command == MyDataPacketHeader::CMD_UI_CLICK)
  {
    if (m_packet_header.length <= (ni)sizeof(MyDataPacketHeader)
        || m_packet_header.length >= 1 * 1024 * 1024
        || m_packet_header.magic != MyDataPacketHeader::DATAPACKET_MAGIC)
    {
      CMemGuard info;
      info_string(info);
      C_ERROR("bad adv click request packet received from %s\n", info.data());
      return ER_ERROR;
    }
    return ER_OK;
  }

  if (m_packet_header.command == MyDataPacketHeader::CMD_VLC)
  {
    if (m_packet_header.length <= (ni)sizeof(MyDataPacketHeader)
        || m_packet_header.length >= 1 * 1024 * 1024
        || m_packet_header.magic != MyDataPacketHeader::DATAPACKET_MAGIC)
    {
      CMemGuard info;
      info_string(info);
      C_ERROR("bad vlc request packet received from %s\n", info.data());
      return ER_ERROR;
    }

    return ER_OK;
  }


  if (m_packet_header.command == MyDataPacketHeader::CMD_PC_ON_OFF)
  {
    if (m_packet_header.length < (ni)sizeof(MyDataPacketHeader) + 15 + 1 + 1
        || m_packet_header.length > (ni)sizeof(MyDataPacketHeader) + 30
        || m_packet_header.magic != MyDataPacketHeader::DATAPACKET_MAGIC)
    {
      CMemGuard info;
      info_string(info);
      C_ERROR("bad pc on off request packet received from %s\n", info.data());
      return ER_ERROR;
    }
    C_DEBUG("get pc on off packet from %s\n", m_client_id.as_string());
    return ER_OK;
  }

  if (m_packet_header.command == MyDataPacketHeader::CMD_TEST)
  {
    if (m_packet_header.magic != MyDataPacketHeader::DATAPACKET_MAGIC)
    {
      CMemGuard info;
      info_string(info);
      C_ERROR("bad test packet received from %s\n", info.data());
      return ER_ERROR;
    }
    return ER_OK;
  }

  if (m_packet_header.command == MyDataPacketHeader::CMD_PSP)
  {
    if (m_packet_header.length < (ni)sizeof(MyDataPacketHeader) + 10
        || m_packet_header.length > (ni)sizeof(MyDataPacketHeader) + 60
        || m_packet_header.magic != MyDataPacketHeader::DATAPACKET_MAGIC)
    {
      CMemGuard info;
      info_string(info);
      C_ERROR("bad psp packet received from %s\n", info.data());
      return ER_ERROR;
    }
    return ER_OK;
  }


  C_ERROR(ACE_TEXT("unexpected packet header received @MyHeartBeatProcessor.on_recv_header, cmd = %d\n"),
      m_packet_header.command);

  return ER_ERROR;
}

CProcBase::EVENT_RESULT MyHeartBeatProcessor::on_recv_packet_i(CMB * mb)
{
  CServerProcBase::on_recv_packet_i(mb);

  {
    CMemGuard info;
    info_string(info);
    C_DEBUG("get complete client packet: command = %d, len = %d from %s\n",
        m_packet_header.command, m_packet_header.length, info.data());
  }

  MyDataPacketHeader * header = (MyDataPacketHeader *)mb->base();
  if (header->command == MyDataPacketHeader::CMD_CLIENT_VERSION_CHECK_REQ)
    return do_version_check(mb);

  if (header->command == MyDataPacketHeader::CMD_VLC_EMPTY)
    return do_vlc_empty_req(mb);

  if (header->command == MyDataPacketHeader::CMD_HARDWARE_ALARM)
    return do_hardware_alarm_req(mb);

  if (header->command == MyDataPacketHeader::CMD_SERVER_FILE_MD5_LIST)
    return do_md5_file_list(mb);

  if (header->command == MyDataPacketHeader::CMD_FTP_FILE)
    return do_ftp_reply(mb);

  if (header->command == MyDataPacketHeader::CMD_IP_VER_REQ)
    return do_ip_ver_req(mb);

  if (header->command == MyDataPacketHeader::CMD_UI_CLICK)
    return do_adv_click_req(mb);

  if (header->command == MyDataPacketHeader::CMD_VLC)
    return do_vlc_req(mb);

  if (header->command == MyDataPacketHeader::CMD_PC_ON_OFF)
    return do_pc_on_off_req(mb);

  if (header->command == MyDataPacketHeader::CMD_TEST)
    return do_test(mb);

  if (header->command == MyDataPacketHeader::CMD_PSP)
    return do_psp(mb);

  CMBGuard guard(mb);
  C_ERROR("unsupported command received @MyHeartBeatProcessor::on_recv_packet_i, command = %d\n",
      header->command);
  return ER_ERROR;
}

DVOID MyHeartBeatProcessor::do_ping()
{
//  C_DEBUG(ACE_TEXT("got a heart beat from %s\n"), info_string().c_str());
  m_heart_beat_submitter->add_ping(m_client_id.as_string(), m_client_id_length);
}

CProcBase::EVENT_RESULT MyHeartBeatProcessor::do_version_check(CMB * mb)
{
  CMBGuard guard(mb);
  CClientIDS & client_id_table = MyServerAppX::instance()->client_id_table();
  MyDataPacketExt * dpe = (MyDataPacketExt *) mb->base();
  if (!dpe->guard())
  {
    CMemGuard info;
    info_string(info);
    C_ERROR(ACE_TEXT("bad client version check packet, dpe->guard() failed: %s\n"), info.data());
    return ER_ERROR;
  }

  {
    MyClientVersionCheckRequest * vc = (MyClientVersionCheckRequest *)mb->base();
    if (vc->uuid[0] != 0)
      memcpy(m_peer_addr, vc->uuid, 16);
  }

  ACE_OS::strsncpy(m_hw_ver, ((MyClientVersionCheckRequest*)mb->base())->hw_ver, 12);
  if (m_hw_ver[0] == 0)
  {
    ACE_OS::strcpy(m_hw_ver, "NULL");
    CMemGuard info;
    info_string(info);
    C_WARNING(ACE_TEXT("client version check packet led/lcd driver version empty: %s\n"), info.data());
  }
  CProcBase::EVENT_RESULT ret = do_version_check_common(mb, client_id_table);

  m_ip_ver_submitter->add_data(m_client_id.as_string(), m_client_id_length, m_peer_addr, m_client_version.to_string(), m_hw_ver);

  if (ret != ER_CONTINUE)
    return ret;

  CClientInfo client_info;
  client_id_table.value_all(m_client_id_index, client_info);

  CMB * reply_mb;
  if (m_client_version < CCfgX::instance()->client_ver_min)
  {
    reply_mb = make_version_check_reply_mb(MyClientVersionCheckReply::VER_MISMATCH, client_info.password_len + 2);
    m_wait_for_close = true;
  }
  else if (m_client_version < CCfgX::instance()->client_ver_now)
    reply_mb = make_version_check_reply_mb(MyClientVersionCheckReply::VER_OK_CAN_UPGRADE, client_info.password_len + 2);
  else
    reply_mb = make_version_check_reply_mb(MyClientVersionCheckReply::VER_OK, client_info.password_len + 2);

  if (!m_wait_for_close)
  {
    MyClientVersionCheckRequest * vc = (MyClientVersionCheckRequest *)mb->base();
    if (vc->server_id != CCfgX::instance()->dist_server_id)
      client_id_table.switched(m_client_id_index, true);

    CMemGuard info;
    info_string(info);
    C_INFO(ACE_TEXT("client version check ok: %s\n"), info.data());
  }

  MyClientVersionCheckReply * vcr = (MyClientVersionCheckReply *) reply_mb->base();
  *((u_int8_t*)vcr->data) = CCfgX::instance()->dist_server_id;
  memcpy(vcr->data + 1, client_info.ftp_password, client_info.password_len + 1);
  if (m_handler->send_data(reply_mb) < 0)
    return ER_ERROR;
  return do_send_pq();
}

CProcBase::EVENT_RESULT MyHeartBeatProcessor::do_send_pq()
{
  CMemGuard value;
  if (!MyServerAppX::instance()->heart_beat_module()->get_pl(value))
    return ER_OK;
  ni m = strlen(value.data()) + 1;
  CMB * mb = CMemPoolX::instance()->get_mb_cmd(m, MyDataPacketHeader::CMD_TQ);
  MyDataPacketExt * dpe = (MyDataPacketExt*) mb->base();
  memcpy(dpe->data, value.data(), m);
  if (m_handler->send_data(mb) < 0)
    return ER_ERROR;
  else
    return ER_OK;
}

CProcBase::EVENT_RESULT MyHeartBeatProcessor::do_md5_file_list(CMB * mb)
{
  MyDataPacketExt * md5filelist = (MyDataPacketExt *)mb->base();
  if (unlikely(!md5filelist->guard()))
  {
    CMemGuard info;
    info_string(info);
    C_ERROR("bad md5 file list packet from %s\n", info.data());
    return ER_ERROR;
  }

  {
    CMemGuard info;
    info_string(info);
    C_DEBUG("complete md5 list from client %s, length = %d\n", info.data(), mb->length());
  }

  MyServerAppX::instance()->heart_beat_module()->service()->add_request_slow(mb);
  return ER_OK;
}

CProcBase::EVENT_RESULT MyHeartBeatProcessor::do_ftp_reply(CMB * mb)
{
  MyDataPacketExt * md5filelist = (MyDataPacketExt *)mb->base();
  if (unlikely(!md5filelist->guard()))
  {
    CMemGuard info;
    info_string(info);
    C_ERROR("bad ftp reply packet from %s\n", info.data());
    return ER_ERROR;
  }
  CMB * mb_reply = CMemPoolX::instance()->get_mb_ack(mb);
//  C_DEBUG("got one ftp reply packet, size = %d\n", mb->capacity());
  MyServerAppX::instance()->heart_beat_module()->service()->add_request(mb, true);

//  MyServerAppX::instance()->dist_put_to_service(mb);
  if (mb_reply != NULL)
    if (m_handler->send_data(mb_reply) < 0)
      return ER_ERROR;
  return ER_OK;
}

CProcBase::EVENT_RESULT MyHeartBeatProcessor::do_ip_ver_req(CMB * mb)
{
  CMBGuard guard(mb);
  m_ip_ver_submitter->add_data(m_client_id.as_string(), m_client_id_length, m_peer_addr, m_client_version.to_string(), m_hw_ver);
  return ER_OK;
}

CProcBase::EVENT_RESULT MyHeartBeatProcessor::do_adv_click_req(CMB * mb)
{
  CMBGuard guard(mb);
  MyDataPacketExt * dpe = (MyDataPacketExt *)mb->base();
  if (unlikely(!dpe->guard()))
  {
    CMemGuard info;
    info_string(info);
    C_ERROR("bad adv click packet from %s\n", info.data());
    return ER_ERROR;
  }

  CONST text record_separator[] = {MyDataPacketHeader::FINISH_SEPARATOR, 0};
  CStringTokenizer tknz(dpe->data, record_separator);
  text * record;
  while ((record = tknz.get()) != NULL)
  {
    CONST text separator[] = {MyDataPacketHeader::ITEM_SEPARATOR, 0};
    CStringTokenizer tknz_x(record, separator);
    CONST text * chn = tknz_x.get();
    CONST text * pcode = tknz_x.get();
    CONST text * number;
    if (unlikely(!pcode))
      continue;
    number = tknz_x.get();
    if (unlikely(!number))
      continue;
    if (strlen(number) >= 12)
      continue;
    m_adv_click_submitter->add_data(m_client_id.as_string(), m_client_id_length, chn, pcode, number);
  }

  return ER_OK;
}

CProcBase::EVENT_RESULT MyHeartBeatProcessor::do_hardware_alarm_req(CMB * mb)
{
  CMBGuard guard(mb);
  MyPLCAlarm * alarm = (MyPLCAlarm *) mb->base();
  if (unlikely((alarm->x != '1' && alarm->x != '2' && alarm->x != '5' && alarm->x != '6') ||
      (alarm->y < '0' || alarm->y > '3')))
  {
    CMemGuard info;
    info_string(info);
    C_ERROR("bad hardware alarm packet from %s, x = %c, y = %c\n", info.data(), alarm->x, alarm->y);
    return ER_ERROR;
  }

  text datetime[32];
  c_util_generate_time_string(datetime, 20, true);
  m_hardware_alarm_submitter->add_data(m_client_id.as_string(), m_client_id_length, alarm->x, alarm->y, datetime);
  return ER_OK;
}

CProcBase::EVENT_RESULT MyHeartBeatProcessor::do_vlc_req(CMB * mb)
{
  CMBGuard guard(mb);
  MyDataPacketExt * dpe = (MyDataPacketExt *)mb->base();
  if (unlikely(!dpe->guard()))
  {
    CMemGuard info;
    info_string(info);
    C_ERROR("bad vlc packet from %s\n", info.data());
    return ER_ERROR;
  }

  text separator[2] = {MyDataPacketHeader::ITEM_SEPARATOR, 0};
  CStringTokenizer tknizer(dpe->data, separator);
  text * token;
  while ((token = tknizer.get()) != NULL)
  {
    text * ptr = strchr(token, MyDataPacketHeader::MIDDLE_SEPARATOR);
    if (!ptr)
      continue;
    *ptr ++ = 0;
    m_vlc_submitter->add_data(m_client_id.as_string(), m_client_id_length, token, ptr);
  }
  return ER_OK;
}

CProcBase::EVENT_RESULT MyHeartBeatProcessor::do_vlc_empty_req(CMB * mb)
{
  CMBGuard guard(mb);
  MyDataPacketExt * dpe = (MyDataPacketExt *)mb->base();
  text c = dpe->data[0];
  if (c != '1' && c != '0')
  {
    CMemGuard info;
    info_string(info);
    C_ERROR("bad vlc empty packet from %s, data = %c\n", info.data(), c);
  } else
    m_vlc_empty_submitter->add_data(m_client_id.as_string(), m_client_id_length, c);
  return ER_OK;
}

CProcBase::EVENT_RESULT MyHeartBeatProcessor::do_psp(CMB * mb)
{
  MyServerAppX::instance()->heart_beat_module()->service()->add_request(mb, true);
  return ER_OK;
}

CProcBase::EVENT_RESULT MyHeartBeatProcessor::do_pc_on_off_req(CMB * mb)
{
  CMBGuard guard(mb);
  MyDataPacketExt * dpe = (MyDataPacketExt *)mb->base();
  if (unlikely(!dpe->guard()))
  {
    CMemGuard info;
    info_string(info);
    C_ERROR("bad pc on/off packet from %s\n", info.data());
    return ER_ERROR;
  }

  if (unlikely(dpe->data[0] != '1' && dpe->data[0] != '2' && dpe->data[0] != '3'))
  {
    C_ERROR("invalid pc on/off flag (%c)\n", dpe->data[0]);
    return ER_ERROR;
  }

  m_pc_on_off_submitter->add_data(m_client_id.as_string(), m_client_id_length, dpe->data[0], dpe->data + 1);
  return ER_OK;
}

CProcBase::EVENT_RESULT MyHeartBeatProcessor::do_test(CMB * mb)
{
//  MyMessageBlockGuard guard(mb);
  C_DEBUG("playback test packet of %d bytes...\n", mb->length());
  MyDataPacketHeader * dph = (MyDataPacketHeader *) mb->base();
  dph->magic = MyDataPacketHeader::DATAPACKET_MAGIC;
//  mb->rd_ptr(mb->base());
//  mb->wr_ptr(mb->capacity());
  m_handler->send_data(mb);
  return ER_OK;
}

PREPARE_MEMORY_POOL(MyHeartBeatProcessor);


//MyAccumulatorBlock//

MyAccumulatorBlock::MyAccumulatorBlock(ni block_size, ni max_item_length, MyBaseSubmitter * submitter, truefalse auto_submit)
{
  m_block_size = block_size;
  m_max_item_length = max_item_length + 1;
  m_submitter = submitter;
  m_auto_submit = auto_submit;
  m_current_block = CMemPoolX::instance()->get_mb(m_block_size);
  submitter->add_block(this);
  reset();
}

MyAccumulatorBlock::~MyAccumulatorBlock()
{
  if (m_current_block)
    m_current_block->release();
}

DVOID MyAccumulatorBlock::reset()
{
  m_current_ptr = m_current_block->base();
}

truefalse MyAccumulatorBlock::add(CONST text * item, ni len)
{
  if (len == 0)
    len = strlen(item);
  ++len;
  ni remain_len = m_block_size - (m_current_ptr - m_current_block->base());
  if (unlikely(len > remain_len))
  {
    if (m_auto_submit)
    {
      m_submitter->submit();
      remain_len = m_block_size;
    } else
    {
      C_FATAL("expected long item @MyAccumulatorBlock::add(), remain_len=%d, item=%s\n", remain_len, item);
      return false;
    }
  }
  memcpy(m_current_ptr, item, len - 1);
  m_current_ptr += len;
  *(m_current_ptr - 1) = ITEM_SEPARATOR;
  return (remain_len - len > m_max_item_length);
}

truefalse MyAccumulatorBlock::add(text c)
{
  text buff[2];
  buff[0] = c;
  buff[1] = 0;
  return add(buff, 1);
}

CONST text * MyAccumulatorBlock::data()
{
  return m_current_block->base();
}

ni MyAccumulatorBlock::data_len() CONST
{
  ni result = (m_current_ptr - m_current_block->base());
  return std::max(result - 1, 0);
}


//MyBaseSubmitter//

MyBaseSubmitter::~MyBaseSubmitter()
{

}

DVOID MyBaseSubmitter::submit()
{
  do_submit(get_command());
  reset();
}

DVOID MyBaseSubmitter::check_time_out()
{
  if ((*m_blocks.begin())->data_len() == 0)
    return;

  submit();
}

DVOID MyBaseSubmitter::add_block(MyAccumulatorBlock * block)
{
  m_blocks.push_back(block);
}

DVOID MyBaseSubmitter::do_submit(CONST text * cmd)
{
  if (unlikely((*m_blocks.begin())->data_len() == 0))
    return;
  MyBlockList::iterator it;

  ni total_len = 0;
  for (it = m_blocks.begin(); it != m_blocks.end(); ++it)
    total_len += (*it)->data_len() + 1;
  --total_len;

  CMB * mb = CMemPoolX::instance()->get_mb_bs(total_len, cmd);
  text * dest = mb->base() + MyBSBasePacket::DATA_OFFSET;
  for (it = m_blocks.begin(); ; )
  {
    ni len = (*it)->data_len();
    memcpy(dest, (*it)->data(), len);
    if (++it != m_blocks.end())
    {
      dest[len] = MyBSBasePacket::BS_PARAMETER_SEPARATOR;
      dest += (len + 1);
    } else
      break;
  }
  MyServerAppX::instance()->dist_to_middle_module()->send_to_bs(mb);
}

DVOID MyBaseSubmitter::reset()
{
  std::for_each(m_blocks.begin(), m_blocks.end(), std::mem_fun(&MyAccumulatorBlock::reset));
};


//MyFtpFeedbackSubmitter//

MyFtpFeedbackSubmitter::MyFtpFeedbackSubmitter():
  m_dist_id_block(BLOCK_SIZE, 32, this), m_ftype_block(BLOCK_SIZE, 1, this), m_client_id_block(BLOCK_SIZE, sizeof(MyClientID), this),
  m_step_block(BLOCK_SIZE, 1, this), m_ok_flag_block(BLOCK_SIZE, 1, this), m_date_block(BLOCK_SIZE, 15, this)
{

}

MyFtpFeedbackSubmitter::~MyFtpFeedbackSubmitter()
{

}

CONST text * MyFtpFeedbackSubmitter::get_command() CONST
{
  return MY_BS_DIST_FEEDBACK_CMD;
}

DVOID MyFtpFeedbackSubmitter::add(CONST text *dist_id, text ftype, CONST text *client_id, text step, text ok_flag, CONST text * date)
{
  truefalse ret = true;

  if (!m_dist_id_block.add(dist_id))
    ret = false;
  if (!m_client_id_block.add(client_id))
    ret = false;
  if (!m_ftype_block.add(ftype))
    ret = false;
  if (!m_step_block.add(step))
    ret = false;
  if (!m_ok_flag_block.add(ok_flag))
    ret = false;
  if (!m_date_block.add(date))
    ret = false;

  if (!ret)
    submit();
}


//MyPingSubmitter//

MyPingSubmitter::MyPingSubmitter(): m_block(BLOCK_SIZE, sizeof(MyClientID), this, true)
{

}

MyPingSubmitter::~MyPingSubmitter()
{

}

DVOID MyPingSubmitter::add_ping(CONST text * client_id, CONST ni len)
{
  if (unlikely(!client_id || !*client_id || len <= 0))
    return;
  if (!m_block.add(client_id, len))
    submit();
}

CONST text * MyPingSubmitter::get_command() CONST
{
  return MY_BS_HEART_BEAT_CMD;
}


//MyIPVerSubmitter//

MyIPVerSubmitter::MyIPVerSubmitter():
    m_id_block(BLOCK_SIZE, sizeof(MyClientID), this),
    m_ip_block(BLOCK_SIZE, INET_ADDRSTRLEN, this),
    m_ver_block(BLOCK_SIZE * 3 / sizeof(MyClientID) + 1, 7, this)//,
//    m_hw_ver1_block(BLOCK_SIZE, 12, this),
//    m_hw_ver2_block(BLOCK_SIZE, 12, this)
{

}

DVOID MyIPVerSubmitter::add_data(CONST text * client_id, ni id_len, CONST text * ip, CONST text * ver, CONST text * hwver)
{
  ACE_UNUSED_ARG(hwver);
  truefalse ret = true;
  if (!m_id_block.add(client_id, id_len))
    ret = false;
  if (!m_ip_block.add(ip, 0))
    ret = false;
  if (!m_ver_block.add(ver, 0))
    ret = false;
//  if (!m_hw_ver1_block.add(hwver, 0))
//    ret = false;
//  if (!m_hw_ver2_block.add(hwver, 0))
//    ret = false;

  if (!ret)
    submit();
}

CONST text * MyIPVerSubmitter::get_command() CONST
{
  return MY_BS_IP_VER_CMD;
}


//MyPcOnOffSubmitter//

MyPcOnOffSubmitter::MyPcOnOffSubmitter():
    m_id_block(BLOCK_SIZE, sizeof(MyClientID), this),
    m_on_off_block(BLOCK_SIZE / 10, 1, this),
    m_datetime_block(BLOCK_SIZE, 25, this)
{

}

DVOID MyPcOnOffSubmitter::add_data(CONST text * client_id, ni id_len, CONST text c_on, CONST text * datetime)
{
  truefalse ret = true;
  if (!m_id_block.add(client_id, id_len))
    ret = false;
  if (!m_on_off_block.add(c_on))
    ret = false;
  if (!m_datetime_block.add(datetime, 0))
    ret = false;

  if (!ret)
    submit();
}

CONST text * MyPcOnOffSubmitter::get_command() CONST
{
  return MY_BS_POWERON_LINK_CMD;
}


//MyAdvClickSubmitter//

MyAdvClickSubmitter::MyAdvClickSubmitter() : m_id_block(BLOCK_SIZE, sizeof(MyClientID), this),
    m_chn_block(BLOCK_SIZE, 50, this), m_pcode_block(BLOCK_SIZE, 50, this), m_number_block(BLOCK_SIZE, 24, this)
{

}

DVOID MyAdvClickSubmitter::add_data(CONST text * client_id, ni id_len, CONST text * chn, CONST text * pcode, CONST text * number)
{
  truefalse ret = true;
  if (!m_id_block.add(client_id, id_len))
    ret = false;
  if (!m_chn_block.add(chn, 0))
    ret = false;
  if (!m_pcode_block.add(pcode, 0))
    ret = false;
  if (!m_number_block.add(number, 0))
    ret = false;

  if (!ret)
    submit();
}

CONST text * MyAdvClickSubmitter::get_command() CONST
{
  return MY_BS_ADV_CLICK_CMD;
}


//MyHWAlarmSubmitter//

MyHWAlarmSubmitter::MyHWAlarmSubmitter():
      m_id_block(BLOCK_SIZE, sizeof(MyClientID), this),
      m_type_block(BLOCK_SIZE, 1, this),
      m_value_block(BLOCK_SIZE, 5, this),
      m_datetime_block(BLOCK_SIZE, 25, this)
{

}

DVOID MyHWAlarmSubmitter::add_data(CONST text * client_id, ni id_len, CONST text x, CONST text y, CONST text * datetime)
{
  truefalse ret = true;
  if (!m_id_block.add(client_id, id_len))
    ret = false;

  if (!m_type_block.add(x))
    ret = false;

  if (x != '6')
  {
    if (!m_value_block.add(y))
      ret = false;
  } else
  {
    CONST text * _y = "00";
    if (y == '1')
      _y = "01";
    else if (y == '2')
      _y = "10";
    else if (y == '3')
      _y = "11";
    if (!m_value_block.add(_y))
      ret = false;
  }

  if (!m_datetime_block.add(datetime))
    ret = false;

  if (!ret)
    submit();
}

CONST text * MyHWAlarmSubmitter::get_command() CONST
{
  return MY_BS_HARD_MON_CMD;
}


//MyVLCSubmitter//

MyVLCSubmitter::MyVLCSubmitter():
    m_id_block(BLOCK_SIZE, sizeof(MyClientID), this),
    m_fn_block(BLOCK_SIZE, 200, this),
    m_number_block(BLOCK_SIZE, 8, this)
{

}

DVOID MyVLCSubmitter::add_data(CONST text * client_id, ni id_len, CONST text * fn, CONST text * number)
{
  ni fn_len = strlen(fn);
  if (fn_len >= 200)
    return;
  truefalse ret = true;
  if (!m_id_block.add(client_id, id_len))
    ret = false;
  if (!m_fn_block.add(fn, fn_len))
    ret = false;
  if (!m_number_block.add(number, 0))
    ret = false;

  if (!ret)
    submit();
}

CONST text * MyVLCSubmitter::get_command() CONST
{
  return MY_BS_VLC_CMD;
}


//MyVLCEmptySubmitter//

MyVLCEmptySubmitter::MyVLCEmptySubmitter():
    m_id_block(BLOCK_SIZE, sizeof(MyClientID), this),
    m_state_block(BLOCK_SIZE, 400, this),
    m_datetime_block(BLOCK_SIZE, 25, this)
{

}

DVOID MyVLCEmptySubmitter::add_data(CONST text * client_id, ni id_len, CONST text state)
{
  truefalse ret = true;
  if (!m_id_block.add(client_id, id_len))
    ret = false;
  if (!m_state_block.add(state))
    ret = false;

  text datetime[32];
  c_util_generate_time_string(datetime, 20, true);
  if (!m_datetime_block.add(datetime))
    ret = false;

  if (!ret)
    submit();
}

CONST text * MyVLCEmptySubmitter::get_command() CONST
{
  return MY_BS_VLC_EMPTY_CMD;
}


//MyHeartBeatHandler//

MyHeartBeatHandler::MyHeartBeatHandler(CConnectionManagerBase * xptr): CHandlerBase(xptr)
{
  m_processor = new MyHeartBeatProcessor(this);
}

CClientIDS * MyHeartBeatHandler::client_id_table() CONST
{
  return g_client_ids;
}

PREPARE_MEMORY_POOL(MyHeartBeatHandler);


//MyHeartBeatService//

MyHeartBeatService::MyHeartBeatService(CMod * module, ni numThreads):
    CTaskBase(module, numThreads)
{
  msg_queue()->high_water_mark(MSG_QUEUE_MAX_SIZE);
  m_queue2.high_water_mark(MSG_QUEUE_MAX_SIZE * 5);
}

truefalse MyHeartBeatService::add_request(CMB * mb, truefalse btail)
{
  ACE_Time_Value tv(ACE_Time_Value::zero);
  ni ret;
  if (btail)
    ret = this->msg_queue()->enqueue_tail(mb, &tv);
  else
    ret = this->msg_queue()->enqueue_head(mb, &tv);
  if (unlikely(ret < 0))
  {
    C_ERROR("can not put message @MyHeartBeatService::add_request %s\n", (CONST text *)CErrno());
    mb->release();
    return false;
  }

  return true;
}

truefalse MyHeartBeatService::add_request_slow(CMB * mb)
{
  ACE_Time_Value tv(ACE_Time_Value::zero);
  if (unlikely(m_queue2.enqueue_tail(mb, &tv) < 0))
  {
    C_ERROR("can not put message to MyHeartBeatService.m_queue2 %s\n", (CONST text *)CErrno());
    mb->release();
    return false;
  }

  return true;
}

ni MyHeartBeatService::svc()
{
  C_INFO("running %s::svc()\n", name());
  CMB * mb;
  ACE_Time_Value tv(ACE_Time_Value::zero);
  while (MyServerAppX::instance()->running())
  {
    truefalse idle = true;
    for (; this->msg_queue()->dequeue(mb, &tv) != -1; )
    {
      idle = false;
      CMBGuard guard(mb);
      if (mb->capacity() == sizeof(ni))
      {
        ni cmd = *(ni*)mb->base();
        if (cmd == TIMED_DIST_TASK)
        {
          m_distributor.distribute(false);
        } else
          C_ERROR("unknown command recieved(%d)\n", cmd);
      } else
      {
        MyDataPacketHeader * dph = (MyDataPacketHeader *) mb->base();
        if (dph->command == MyDataPacketHeader::CMD_HAVE_DIST_TASK)
        {
          do_have_dist_task();
        } else if ((dph->command == MyDataPacketHeader::CMD_FTP_FILE))
        {
//          C_DEBUG("service: got one ftp reply packet, size = %d\n", mb->capacity());
          do_ftp_file_reply(mb);
        } else if ((dph->command == MyDataPacketHeader::CMD_PSP))
        {
          do_psp(mb);
        } else
          C_ERROR("unknown packet recieved @%s, cmd = %d\n", name(), dph->command);
      }
    }

    if (m_queue2.dequeue_head(mb, &tv) != -1)
    {
      idle = false;
      CMBGuard guard(mb);
      MyDataPacketHeader * dph = (MyDataPacketHeader *) mb->base();
      if ((dph->command == MyDataPacketHeader::CMD_SERVER_FILE_MD5_LIST))
      {
        do_file_md5_reply(mb);
      } else
        C_ERROR("unknown packet received @%s.queue2, cmd = %d\n", name(), dph->command);
    }

    if (idle)
      ACE_OS::sleep(1);
  }
  C_INFO("exiting %s::svc()\n", name());
  return 0;
}

DVOID MyHeartBeatService::do_have_dist_task()
{
  m_distributor.distribute(true);
}

DVOID MyHeartBeatService::do_ftp_file_reply(CMB * mb)
{
  MyDataPacketExt * dpe = (MyDataPacketExt*) mb->base();
  MyClientID client_id;
  if (unlikely(!MyServerAppX::instance()->client_id_table().value(dpe->magic, &client_id)))
  {
    C_FATAL("can not find client id @MyHeartBeatService::do_ftp_file_reply()\n");
    return;
  } //todo: optimize: pass client_id directly from processor

  ni len = dpe->length - sizeof(MyDataPacketHeader);
  if (unlikely(dpe->data[len - 5] != MyDataPacketHeader::ITEM_SEPARATOR))
  {
    C_ERROR("bad ftp file reply packet @%s::do_ftp_file_reply()\n", name());
    return;
  }
  dpe->data[len - 5] = 0;
  if (unlikely(!dpe->data[0]))
  {
    C_ERROR("bad ftp file reply packet @%s::do_ftp_file_reply(), no dist_id\n", name());
    return;
  }

  CONST text * dist_id = dpe->data;
  text ok = dpe->data[len - 4];
  text recv_status = dpe->data[len - 3];
  text ftype = dpe->data[len - 2];
  text step = 0;
  ni status;

  if (unlikely(ok != '0' && ok != '1'))
  {
    C_ERROR("bad ok flag(%c) on client ftp reply @%s\n", ok, name());
    return;
  }
  if (unlikely(!ftype_is_valid(ftype) && ftype != 'x'))
  {
    C_ERROR("bad ftype(%c) on client ftp reply @%s\n", ftype, name());
    return;
  }

  if (recv_status == '2')
  {
    C_DEBUG("ftp command received client_id(%s) dist_id(%s)\n", client_id.as_string(), dist_id);
    status = 4;
  } else if (recv_status == '3')
  {
    status = 5;
    step = '3';
    C_DEBUG("ftp download completed client_id(%s) dist_id(%s)\n", client_id.as_string(), dist_id);
  } else if (recv_status == '4')
  {
    status = 5;
    C_DEBUG("dist extract completed client_id(%s) dist_id(%s)\n", client_id.as_string(), dist_id);
  } else if (recv_status == '5')
  {
    status = 5;
    C_DEBUG("dist extract failed client_id(%s) dist_id(%s)\n", client_id.as_string(), dist_id);
  } else if (recv_status == '9')
  {
    C_DEBUG("dist download started client_id(%s) dist_id(%s)\n", client_id.as_string(), dist_id);
    step = '2';
  } else if (recv_status == '7')
  {
    C_DEBUG("dist download failed client_id(%s) dist_id(%s)\n", client_id.as_string(), dist_id);
    step = '3';
    status = 5;
  }
  else
  {
    C_ERROR("unknown ftp reply status code: %c\n", recv_status);
    return;
  }

  if ((ftype != 'x') && step != 0)
  {
    text buff[32];
    c_util_generate_time_string(buff, 32, true);
    ((MyHeartBeatModule *)module_x())->ftp_feedback_submitter().add(dist_id, ftype, client_id.as_string(), step, ok, buff);
    if (step == '3' && ok == '1')
      ((MyHeartBeatModule *)module_x())->ftp_feedback_submitter().add(dist_id, ftype, client_id.as_string(), '4', ok, buff);
  }
  if (recv_status == '9')
    return;

  m_distributor.dist_ftp_file_reply(client_id.as_string(), dist_id, status, ok == '1');
}

DVOID MyHeartBeatService::do_psp(CMB * mb)
{
  MyDataPacketExt * dpe = (MyDataPacketExt*) mb->base();
  MyClientID client_id;
  if (unlikely(!MyServerAppX::instance()->client_id_table().value(dpe->magic, &client_id)))
  {
    C_FATAL("can not find client id @MyHeartBeatService::do_file_md5_reply()\n");
    return;
  } //todo: optimize: pass client_id directly from processor

  m_distributor.psp(client_id.as_string(), dpe->data + 1, dpe->data[0]);
}

DVOID MyHeartBeatService::do_file_md5_reply(CMB * mb)
{
  MyDataPacketExt * dpe = (MyDataPacketExt*) mb->base();
  MyClientID client_id;
  if (unlikely(!MyServerAppX::instance()->client_id_table().value(dpe->magic, &client_id)))
  {
    C_FATAL("can not find client id @MyHeartBeatService::do_file_md5_reply()\n");
    return;
  } //todo: optimize: pass client_id directly from processor

  if (unlikely(!dpe->data[0]))
  {
    C_ERROR("bad file md5 list reply packet @%s::do_file_md5_reply(), no dist_id\n", name());
    return;
  }
  text * md5list = strchr(dpe->data, MyDataPacketHeader::ITEM_SEPARATOR);
  if (unlikely(!md5list))
  {
    C_ERROR("bad file md5 list reply packet @%s::do_file_md5_reply(), no dist_id mark\n", name());
    return;
  }
  *md5list ++ = 0;
  CONST text * dist_id = dpe->data;
//  C_DEBUG("file md5 list from client_id(%s) dist_id(%s): %s\n", client_id.as_string(),
//      dist_id, (*md5list? md5list: "(empty)"));
  C_DEBUG("file md5 list from client_id(%s) dist_id(%s): len = %d\n", client_id.as_string(), dist_id, strlen(md5list));

  m_distributor.dist_ftp_md5_reply(client_id.as_string(), dist_id, md5list);
}


//MyHeartBeatAcceptor//

MyHeartBeatAcceptor::MyHeartBeatAcceptor(CDispatchBase * _dispatcher, CConnectionManagerBase * _manager):
    CAcceptorBase(_dispatcher, _manager)
{
  m_tcp_port = CCfgX::instance()->ping_port;
  m_idle_time_as_dead = IDLE_TIME_AS_DEAD;
}

ni MyHeartBeatAcceptor::make_svc_handler(CHandlerBase *& sh)
{
  sh = new MyHeartBeatHandler(m_connection_manager);
  if (!sh)
  {
    C_ERROR("can not alloc MyHeartBeatHandler from %s\n", name());
    return -1;
  }
  sh->parent((void*)this);
  sh->reactor(reactor());
  return 0;
}

CONST text * MyHeartBeatAcceptor::name() CONST
{
  return "MyHeartBeatAcceptor";
}


//MyHeartBeatDispatcher//

MyHeartBeatDispatcher::MyHeartBeatDispatcher(CMod * pModule, ni numThreads):
    CDispatchBase(pModule, numThreads)
{
  m_acceptor = NULL;
  m_clock_interval = CLOCK_INTERVAL;
  msg_queue()->high_water_mark(MSG_QUEUE_MAX_SIZE);
}

CONST text * MyHeartBeatDispatcher::name() CONST
{
  return "MyHeartBeatDispatcher";
}

MyHeartBeatAcceptor * MyHeartBeatDispatcher::acceptor() CONST
{
  return m_acceptor;
}

ni MyHeartBeatDispatcher::handle_timeout(CONST ACE_Time_Value &tv, CONST DVOID *act)
{
  ACE_UNUSED_ARG(tv);
  ACE_UNUSED_ARG(act);
  if ((long)act == CDispatchBase::TIMER_ID_BASE)
  {
    CMB *mb;
    ACE_Time_Value nowait(ACE_Time_Value::zero);
    while (-1 != this->getq(mb, &nowait))
    {
      if (unlikely(mb->size() < sizeof(MyDataPacketHeader)))
      {
        C_ERROR("invalid message block size @ %s::handle_timeout\n", name());
        mb->release();
        continue;
      }
      ni index = ((MyDataPacketHeader*)mb->base())->magic;
      CHandlerBase * handler = m_acceptor->connection_manager()->find_handler_by_index(index);
      if (!handler)
      {
//        C_WARNING("can not send data to client since connection is lost @ %s::handle_timeout\n", name());
        mb->release();
        continue;
      }

      if (unlikely(MyDataPacketHeader::CMD_DISCONNECT_INTERNAL == ((MyDataPacketHeader*)mb->base())->command))
      {
        //handler->processor()->prepare_to_close();
        handler->handle_close(ACE_INVALID_HANDLE, 0);
        mb->release();
        continue;
      }

      ((MyDataPacketHeader*)mb->base())->magic = MyDataPacketHeader::DATAPACKET_MAGIC;

      if (handler->send_data(mb) < 0)
        handler->handle_close(ACE_INVALID_HANDLE, 0);
    }
  } else if ((long)act == TIMER_ID_HEART_BEAT)
  {
    MyHeartBeatProcessor::m_heart_beat_submitter->check_time_out();
  } else if ((long)act == TIMER_ID_IP_VER)
  {
    MyHeartBeatProcessor::m_ip_ver_submitter->check_time_out();
  } else if ((long)act == TIMER_ID_FTP_FEEDBACK)
  {
    MyHeartBeatProcessor::m_ftp_feedback_submitter->check_time_out();
  }
  else if ((long)act == TIMER_ID_DIST_SERVICE)
  {
    CMB * mb = CMemPoolX::instance()->get_mb(sizeof(ni));
    *(ni*)mb->base() = MyHeartBeatService::TIMED_DIST_TASK;
    MyServerAppX::instance()->heart_beat_module()->service()->add_request(mb, false);
  } else if ((long)act == TIMER_ID_ADV_CLICK)
  {
    MyHeartBeatProcessor::m_adv_click_submitter->check_time_out();
    MyHeartBeatProcessor::m_pc_on_off_submitter->check_time_out();
    MyHeartBeatProcessor::m_hardware_alarm_submitter->check_time_out();
    MyHeartBeatProcessor::m_vlc_submitter->check_time_out();
    MyHeartBeatProcessor::m_vlc_empty_submitter->check_time_out();
  }
  return 0;
}

DVOID MyHeartBeatDispatcher::on_stop()
{
  m_acceptor = NULL;
}

DVOID MyHeartBeatDispatcher::on_stop_stage_1()
{

}

truefalse MyHeartBeatDispatcher::on_start()
{
  if (!m_acceptor)
    m_acceptor = new MyHeartBeatAcceptor(this, new CConnectionManagerBase());
  add_acceptor(m_acceptor);

  {
    ACE_Time_Value interval(CLOCK_TICK_HEART_BEAT);
    if (reactor()->schedule_timer(this, (CONST void*)TIMER_ID_HEART_BEAT, interval, interval) < 0)
    {
      C_ERROR("setup heart beat timer failed %s %s\n", name(), (CONST char*)CErrno());
      return false;
    }
  }

  {
    ACE_Time_Value interval(CLOCK_TICK_IP_VER);
    if (reactor()->schedule_timer(this, (CONST void*)TIMER_ID_IP_VER, interval, interval) < 0)
    {
      C_ERROR("setup heart beat timer failed %s %s\n", name(), (CONST char*)CErrno());
      return false;
    }
  }

  {
    ACE_Time_Value interval(CLOCK_TICK_FTP_FEEDBACK);
    if (reactor()->schedule_timer(this, (CONST void*)TIMER_ID_FTP_FEEDBACK, interval, interval) < 0)
    {
      C_ERROR("setup ftp feedback timer failed %s %s\n", name(), (CONST char*)CErrno());
      return false;
    }
  }

  {
    ACE_Time_Value interval(CLOCK_TICK_DIST_SERVICE * 60);
    if (reactor()->schedule_timer(this, (CONST void*)TIMER_ID_DIST_SERVICE, interval, interval) < 0)
    {
      C_ERROR("setup heart beat timer failed %s %s\n", name(), (CONST char*)CErrno());
      return false;
    }
  }

  {
    ACE_Time_Value interval(CLOCK_TICK_ADV_CLICK * 60);
    if (reactor()->schedule_timer(this, (CONST void*)TIMER_ID_ADV_CLICK, interval, interval) < 0)
    {
      C_ERROR("setup adv click timer failed %s %s\n", name(), (CONST char*)CErrno());
      return false;
    }
  }

  return true;
}


//MyHeartBeatModule//

MyHeartBeatModule::MyHeartBeatModule(CApp * app): CMod(app)
{
  m_service = NULL;
  m_dispatcher = NULL;
  MyHeartBeatProcessor::m_heart_beat_submitter = &m_ping_sumbitter;
  MyHeartBeatProcessor::m_ip_ver_submitter = &m_ip_ver_submitter;
  MyHeartBeatProcessor::m_ftp_feedback_submitter = &m_ftp_feedback_submitter;
  MyHeartBeatProcessor::m_adv_click_submitter = &m_adv_click_submitter;
  MyHeartBeatProcessor::m_pc_on_off_submitter = &m_pc_on_off_submitter;
  MyHeartBeatProcessor::m_hardware_alarm_submitter = &m_hardware_alarm_submitter;
  MyHeartBeatProcessor::m_vlc_submitter = &m_vlc_submitter;
  MyHeartBeatProcessor::m_vlc_empty_submitter = &m_vlc_empty_submitter;
}

MyHeartBeatModule::~MyHeartBeatModule()
{

}

MyHeartBeatDispatcher * MyHeartBeatModule::dispatcher() CONST
{
  return m_dispatcher;
}

MyHeartBeatService * MyHeartBeatModule::service() CONST
{
  return m_service;
}

ni MyHeartBeatModule::num_active_clients() CONST
{
  if (unlikely(!m_dispatcher || !m_dispatcher->acceptor() || !m_dispatcher->acceptor()->connection_manager()))
    return 0xFFFFFF;
  return m_dispatcher->acceptor()->connection_manager()->active_count();
}

MyFtpFeedbackSubmitter & MyHeartBeatModule::ftp_feedback_submitter()
{
  return m_ftp_feedback_submitter;
}

DVOID MyHeartBeatModule::pl()
{
  CMemGuard value;
  if (!MyServerAppX::instance()->db().load_pl(value))
    return;
  ACE_GUARD(ACE_Thread_Mutex, ace_mon, this->m_mutex);
  m_pl.from_string(value.data());
}

truefalse MyHeartBeatModule::get_pl(CMemGuard & value)
{
  ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, false);
  if (!m_pl.data() || !*m_pl.data())
    return false;
  value.from_string(m_pl.data());
  return true;
}

CONST text * MyHeartBeatModule::name() CONST
{
  return "MyHeartBeatModule";
}

truefalse MyHeartBeatModule::on_start()
{
  add_task(m_service = new MyHeartBeatService(this, 1));
  add_dispatch(m_dispatcher = new MyHeartBeatDispatcher(this));
  return true;
}

DVOID MyHeartBeatModule::on_stop()
{
  m_service = NULL;
  m_dispatcher = NULL;
}


/////////////////////////////////////
//dist to BS
/////////////////////////////////////

//MyDistToBSProcessor//

MyDistToBSProcessor::MyDistToBSProcessor(CHandlerBase * handler): super(handler)
{
  m_handler->msg_queue()->high_water_mark(MSG_QUEUE_MAX_SIZE);
}

CONST text * MyDistToBSProcessor::name() CONST
{
  return "MyDistToBSProcessor";
}

CProcBase::EVENT_RESULT MyDistToBSProcessor::on_recv_packet_i(CMB * mb)
{
  CMBGuard guard(mb);

  if (super::on_recv_packet_i(mb) != ER_OK)
    return ER_ERROR;
  MyBSBasePacket * bspacket = (MyBSBasePacket *) mb->base();
  if (memcmp(bspacket->cmd, MY_BS_IP_VER_CMD, sizeof(bspacket->cmd)) == 0)
    process_ip_ver_reply(bspacket);
//  C_INFO("got a bs reply packet:%s\n", mb->base());

  ((MyDistToBSHandler*)m_handler)->checker_update();

  return ER_OK;
}

DVOID MyDistToBSProcessor::process_ip_ver_reply(MyBSBasePacket * bspacket)
{
  text separator[2] = {';', 0};
  CStringTokenizer tknizer(bspacket->data, separator);
  text * token;
  while ((token = tknizer.get()) != NULL)
    process_ip_ver_reply_one(token);
}

DVOID MyDistToBSProcessor::process_ip_ver_reply_one(text * item)
{
  text * id, * data;
  id = item;
  data = strchr(item, ':');
  if (unlikely(!data || data == item || *(data + 1) == 0))
    return;
  *data++ = 0;
  truefalse client_valid = !(data[0] == '*' && data[1] == 0);
  CClientIDS & id_table = MyServerAppX::instance()->client_id_table();
  MyClientID client_id(id);
  ni index;
  if (unlikely(!id_table.mark_valid(client_id, client_valid, index)))
    MyServerAppX::instance()->db().mark_client_valid(id, client_valid);

  if (likely(client_valid))
  {
    ni len = strlen(data) + 1;
    CMB * mb = CMemPoolX::instance()->get_mb_cmd(len, MyDataPacketHeader::CMD_IP_VER_REQ);
    MyDataPacketExt * dpe = (MyDataPacketExt *) mb->base();
    memcpy(dpe->data, data, len);
    dpe->magic = index;
    c_util_mb_putq(MyServerAppX::instance()->heart_beat_module()->dispatcher(), mb, "ip ver reply to dispatcher's queue");
  } else
  {
    if (index >= 0)
    {
      CMB * mb = CMemPoolX::instance()->get_mb_cmd(0, MyDataPacketHeader::CMD_DISCONNECT_INTERNAL);
      MyDataPacketExt * dpe = (MyDataPacketExt *) mb->base();
      dpe->magic = index;
      c_util_mb_putq(MyServerAppX::instance()->heart_beat_module()->dispatcher(), mb, "disconnect internal to dispatcher's queue");
    }
  }
}


//MyDistToBSHandler//

MyDistToBSHandler::MyDistToBSHandler(CConnectionManagerBase * xptr): CHandlerBase(xptr)
{
  m_processor = new MyDistToBSProcessor(this);
}

MyDistToMiddleModule * MyDistToBSHandler::module_x() CONST
{
  return (MyDistToMiddleModule *)connector()->module_x();
}

DVOID MyDistToBSHandler::checker_update()
{
  m_checker.update();
}

ni MyDistToBSHandler::handle_timeout(CONST ACE_Time_Value &, CONST DVOID *)
{
  if (m_checker.expired())
  {
    C_ERROR("no data received from bs @MyDistToBSHandler ...\n");
    return -1;
  }
  CMB * mb = my_get_hb_mb();
  if (mb)
  {
    if (send_data(mb) < 0)
      return -1;
  }
  return 0;
}

ni MyDistToBSHandler::on_open()
{
  ACE_Time_Value interval(30);
  if (reactor()->schedule_timer(this, (void*)0, interval, interval) < 0)
  {
    C_ERROR(ACE_TEXT("MyDistToBSHandler setup timer failed, %s"), (CONST char*)CErrno());
    return -1;
  }

  if (!g_is_test)
    C_INFO("MyDistToBSHandler setup timer: OK\n");

  CMB * mb = my_get_hb_mb();
  if (mb)
  {
    if (send_data(mb) < 0)
      return -1;
  }
  m_checker.update();

  return 0;
}


DVOID MyDistToBSHandler::on_close()
{

}

PREPARE_MEMORY_POOL(MyDistToBSHandler);


//MyDistToBSConnector//

MyDistToBSConnector::MyDistToBSConnector(CDispatchBase * _dispatcher, CConnectionManagerBase * _manager):
    CConnectorBase(_dispatcher, _manager)
{
  m_tcp_port = CCfgX::instance()->bs_port;
  m_reconnect_interval = RECONNECT_INTERVAL;
  m_tcp_addr = CCfgX::instance()->bs_addr;
}

CONST text * MyDistToBSConnector::name() CONST
{
  return "MyDistToBSConnector";
}

ni MyDistToBSConnector::make_svc_handler(CHandlerBase *& sh)
{
  sh = new MyDistToBSHandler(m_connection_manager);
  if (!sh)
  {
    C_ERROR("can not alloc MyDistToBSHandler from %s\n", name());
    return -1;
  }
  sh->parent((void*)this);
  sh->reactor(reactor());
  return 0;
}


/////////////////////////////////////
//dist to middle module
/////////////////////////////////////

//MyDistToMiddleProcessor//


MyDistToMiddleProcessor::MyDistToMiddleProcessor(CHandlerBase * handler): CClientProcBase(handler)
{
  m_version_check_reply_done = false;
  m_local_addr[0] = 0;
  m_handler->msg_queue()->high_water_mark(MSG_QUEUE_MAX_SIZE);
}

ni MyDistToMiddleProcessor::on_open()
{
  if (super::on_open() < 0)
    return -1;

  ACE_INET_Addr local_addr;
  if (m_handler->peer().get_local_addr(local_addr) == 0)
    local_addr.get_host_addr((char*)m_local_addr, IP_ADDR_LENGTH);

  return send_version_check_req();
}

CProcBase::EVENT_RESULT MyDistToMiddleProcessor::on_recv_header()
{
  CProcBase::EVENT_RESULT result = super::on_recv_header();
  if (result != ER_CONTINUE)
    return ER_ERROR;

  truefalse bVersionCheckReply = m_packet_header.command == MyDataPacketHeader::CMD_CLIENT_VERSION_CHECK_REPLY; //m_version_check_reply_done
  if (bVersionCheckReply == m_version_check_reply_done)
  {
    C_ERROR(ACE_TEXT("unexpected packet header from dist server, version_check_reply_done = %d, "
                      "packet is version_check_reply = %d.\n"), m_version_check_reply_done, bVersionCheckReply);
    return ER_ERROR;
  }

  if (bVersionCheckReply)
  {
    if (!my_dph_validate_client_version_check_reply(&m_packet_header))
    {
      C_ERROR("failed to validate header for version check reply packet\n");
      return ER_ERROR;
    }
    return ER_OK;
  }

  if (m_packet_header.command == MyDataPacketHeader::CMD_HAVE_DIST_TASK)
  {
    if (!my_dph_validate_have_dist_task(&m_packet_header))
    {
      C_ERROR("failed to validate header for dist task notify packet\n");
      return ER_ERROR;
    }
    return ER_OK;
  }

  if (m_packet_header.command == MyDataPacketHeader::CMD_REMOTE_CMD)
  {
    if (!my_dph_validate_file_md5_list(&m_packet_header))
    {
      C_ERROR("failed to validate header for remote cmd notify packet\n");
      return ER_ERROR;
    }
    return ER_OK;
  }

  C_ERROR("unexpected packet header from dist server, header.command = %d\n", m_packet_header.command);
  return ER_ERROR;
}

CProcBase::EVENT_RESULT MyDistToMiddleProcessor::on_recv_packet_i(CMB * mb)
{
  CFormatProcBase::on_recv_packet_i(mb);

  MyDataPacketHeader * header = (MyDataPacketHeader *)mb->base();

  if (header->command == MyDataPacketHeader::CMD_CLIENT_VERSION_CHECK_REPLY)
  {
    CProcBase::EVENT_RESULT result = do_version_check_reply(mb);
    C_INFO("handshake response from middle server: %s\n", (result == ER_OK? "OK":"Failed"));
    if (result == ER_OK)
    {
      ((MyDistToMiddleHandler*)m_handler)->setup_timer();
      client_verified(true);
    }
    return result;
  }

  if (header->command == MyDataPacketHeader::CMD_HAVE_DIST_TASK)
  {
    CProcBase::EVENT_RESULT result = do_have_dist_task(mb);
    C_INFO("got notification from middle server on new dist task\n");
    return result;
  }

  if (m_packet_header.command == MyDataPacketHeader::CMD_REMOTE_CMD)
  {
    C_INFO("got notification from middle server on remote cmd\n");
    CProcBase::EVENT_RESULT result = do_remote_cmd_task(mb);
    return result;
  }

  CMBGuard guard(mb);
  C_ERROR("unsupported command received @MyDistToMiddleProcessor::on_recv_packet_i(), command = %d\n",
      header->command);
  return ER_ERROR;
}

ni MyDistToMiddleProcessor::send_server_load()
{
  if (!m_version_check_reply_done)
    return 0;

  CMB * mb = CMemPoolX::instance()->get_mb_cmd_direct(sizeof(MyLoadBalanceRequest), MyDataPacketHeader::CMD_LOAD_BALANCE_REQ);
  MyLoadBalanceRequest * req = (MyLoadBalanceRequest *) mb->base();
  req->set_ip_addr(m_local_addr);
  req->clients_connected = MyServerAppX::instance()->heart_beat_module()->num_active_clients();
  C_INFO("sending dist server load number [%d] to middle server...\n", req->clients_connected);
  return (m_handler->send_data(mb) < 0 ? -1: 0);
}

CProcBase::EVENT_RESULT MyDistToMiddleProcessor::do_version_check_reply(CMB * mb)
{
  CMBGuard guard(mb);
  m_version_check_reply_done = true;

  CONST text * prefix_msg = "dist server version check reply:";
  MyClientVersionCheckReply * vcr = (MyClientVersionCheckReply *) mb->base();
  switch (vcr->reply_code)
  {
  case MyClientVersionCheckReply::VER_OK:
    return CProcBase::ER_OK;

  case MyClientVersionCheckReply::VER_OK_CAN_UPGRADE:
    C_INFO("%s get version can upgrade response\n", prefix_msg);
    return CProcBase::ER_OK;

  case MyClientVersionCheckReply::VER_MISMATCH:
    C_ERROR("%s get version mismatch response\n", prefix_msg);
    return CProcBase::ER_ERROR;

  case MyClientVersionCheckReply::VER_ACCESS_DENIED:
    C_ERROR("%s get access denied response\n", prefix_msg);
    return CProcBase::ER_ERROR;

  case MyClientVersionCheckReply::VER_SERVER_BUSY:
    C_ERROR("%s get server busy response\n", prefix_msg);
    return CProcBase::ER_ERROR;

  default: //server_list
    C_ERROR("%s get unknown reply code = %d\n", prefix_msg, vcr->reply_code);
    return CProcBase::ER_ERROR;
  }

}

CProcBase::EVENT_RESULT MyDistToMiddleProcessor::do_have_dist_task(CMB * mb)
{
  MyServerAppX::instance()->heart_beat_module()->service()->add_request(mb, false);
  return ER_OK;
}

CProcBase::EVENT_RESULT MyDistToMiddleProcessor::do_remote_cmd_task(CMB * mb)
{
  CMBGuard guard(mb);
  return ER_OK;
}

ni MyDistToMiddleProcessor::send_version_check_req()
{
  CMB * mb = make_version_check_request_mb();
  MyClientVersionCheckRequest * proc = (MyClientVersionCheckRequest *)mb->base();
  proc->client_version_major = 1;
  proc->client_version_minor = 0;
  proc->client_id = CCfgX::instance()->skey.c_str();
  proc->server_id = CCfgX::instance()->dist_server_id;
  C_INFO("sending handshake request to middle server...\n");
  return (m_handler->send_data(mb) < 0? -1: 0);
}


//MyDistToMiddleHandler//

MyDistToMiddleHandler::MyDistToMiddleHandler(CConnectionManagerBase * xptr): CHandlerBase(xptr)
{
  m_processor = new MyDistToMiddleProcessor(this);
  m_load_balance_req_timer_id = -1;
}

DVOID MyDistToMiddleHandler::setup_timer()
{
  ACE_Time_Value tv_start(ACE_Time_Value::zero);
  ACE_Time_Value interval(LOAD_BALANCE_REQ_INTERVAL * 60);
  m_load_balance_req_timer_id = reactor()->schedule_timer(this, (void*)LOAD_BALANCE_REQ_TIMER, tv_start, interval);
  if (m_load_balance_req_timer_id < 0)
    C_ERROR(ACE_TEXT("MyDistToMiddleHandler setup load balance req timer failed, %s"), (CONST char*)CErrno());
}

MyDistToMiddleModule * MyDistToMiddleHandler::module_x() CONST
{
  return (MyDistToMiddleModule *)connector()->module_x();
}

ni MyDistToMiddleHandler::on_open()
{
  return 0;
}

ni MyDistToMiddleHandler::handle_timeout(CONST ACE_Time_Value &current_time, CONST DVOID *act)
{
  ACE_UNUSED_ARG(current_time);
  if (long(act) == LOAD_BALANCE_REQ_TIMER)
    return ((MyDistToMiddleProcessor*)m_processor)->send_server_load();
  else if (long(act) == 0)
    return -1;
  else
  {
    C_ERROR("unexpected timer call @MyDistToMiddleHandler::handle_timeout, timer id = %d\n", long(act));
    return 0;
  }
}

DVOID MyDistToMiddleHandler::on_close()
{
  if (m_load_balance_req_timer_id >= 0)
    reactor()->cancel_timer(m_load_balance_req_timer_id);
}

PREPARE_MEMORY_POOL(MyDistToMiddleHandler);



//MyDistToMiddleConnector//

MyDistToMiddleConnector::MyDistToMiddleConnector(CDispatchBase * _dispatcher, CConnectionManagerBase * _manager):
    CConnectorBase(_dispatcher, _manager)
{
  m_tcp_port = CCfgX::instance()->middle_server_dist_port;
  m_reconnect_interval = RECONNECT_INTERVAL;
  m_tcp_addr = CCfgX::instance()->middle_addr;
}

CONST text * MyDistToMiddleConnector::name() CONST
{
  return "MyDistToMiddleConnector";
}

ni MyDistToMiddleConnector::make_svc_handler(CHandlerBase *& sh)
{
  sh = new MyDistToMiddleHandler(m_connection_manager);
  if (!sh)
  {
    C_ERROR("can not alloc MyDistToMiddleHandler from %s\n", name());
    return -1;
  }
//  C_DEBUG("MyDistToMiddleConnector::make_svc_handler(%X)...\n", long(sh));
  sh->parent((void*)this);
  sh->reactor(reactor());
  return 0;
}


//MyDistToMiddleDispatcher//

MyDistToMiddleDispatcher::MyDistToMiddleDispatcher(CMod * pModule, ni numThreads):
    CDispatchBase(pModule, numThreads)
{
  m_connector = NULL;
  m_bs_connector = NULL;
  msg_queue()->high_water_mark(MSG_QUEUE_MAX_SIZE);
  m_to_bs_queue.high_water_mark(MSG_QUEUE_MAX_SIZE);
}

MyDistToMiddleDispatcher::~MyDistToMiddleDispatcher()
{

}

DVOID MyDistToMiddleDispatcher::on_stop_stage_1()
{
  ACE_Time_Value tv(ACE_Time_Value::zero);
  CMB * mb;
  while (m_to_bs_queue.dequeue(mb, &tv) != -1)
    mb->release();
  while (this->msg_queue()->dequeue(mb, &tv) != -1)
    mb->release();
}

truefalse MyDistToMiddleDispatcher::on_start()
{
  if (!m_connector)
    m_connector = new MyDistToMiddleConnector(this, new CConnectionManagerBase());
  add_connector(m_connector);
  if (!m_bs_connector)
    m_bs_connector = new MyDistToBSConnector(this, new CConnectionManagerBase());
  add_connector(m_bs_connector);
  return true;
}

truefalse MyDistToMiddleDispatcher::on_event_loop()
{
  ACE_Time_Value tv(ACE_Time_Value::zero);
  CMB * mb;
  CONST ni CONST_max_count = 10;
  ni i = 0;
  while (++i < CONST_max_count && this->getq(mb, &tv) != -1)
    m_connector->connection_manager()->broadcast(mb);

  tv = ACE_Time_Value::zero;
  i = 0;
  while (++i < CONST_max_count && m_to_bs_queue.dequeue(mb, &tv) != -1)
    m_bs_connector->connection_manager()->broadcast(mb);

  return true;
}

CONST text * MyDistToMiddleDispatcher::name() CONST
{
  return "MyDistToMiddleDispatcher";
}

DVOID MyDistToMiddleDispatcher::send_to_bs(CMB * mb)
{
  ACE_Time_Value tv(ACE_Time_Value::zero);
  if (m_to_bs_queue.enqueue(mb, &tv) < 0)
    mb->release();
}

DVOID MyDistToMiddleDispatcher::send_to_middle(CMB * mb)
{
  c_util_mb_putq(this, mb, "@ MyDistToMiddleDispatcher::send_to_middle");
}

DVOID MyDistToMiddleDispatcher::on_stop()
{
  m_connector = NULL;
  m_bs_connector = NULL;
}


//MyDistToMiddleModule//

MyDistToMiddleModule::MyDistToMiddleModule(CApp * app): CMod(app)
{
  m_dispatcher = NULL;
}

MyDistToMiddleModule::~MyDistToMiddleModule()
{

}

CONST text * MyDistToMiddleModule::name() CONST
{
  return "MyDistToMiddleModule";
}

DVOID MyDistToMiddleModule::send_to_bs(CMB * mb)
{
  m_dispatcher->send_to_bs(mb);
}

DVOID MyDistToMiddleModule::send_to_middle(CMB * mb)
{
  m_dispatcher->send_to_middle(mb);
}

truefalse MyDistToMiddleModule::on_start()
{
  add_dispatch(m_dispatcher = new MyDistToMiddleDispatcher(this));
  return true;
}

DVOID MyDistToMiddleModule::on_stop()
{
  m_dispatcher = NULL;
}


//!//database

CONST text * CONST_db_name = "acedb";

//this class is internal for implementation only. invisible outside of dbmodule
class MyPGResultGuard
{
public:
  MyPGResultGuard(PGresult * res): m_result(res)
  {}
  ~MyPGResultGuard()
  {
    PQclear(m_result);
  }

private:
  MyPGResultGuard(CONST MyPGResultGuard &);
  MyPGResultGuard & operator = (CONST MyPGResultGuard &);

  PGresult * m_result;
};

//MyDB//

MyDB::MyDB()
{
  m_connection = NULL;
  m_server_port = 0;
}

MyDB::~MyDB()
{
  disconnect();
}

time_t MyDB::get_time_from_string(CONST text * s)
{
  SF time_t _current = time(NULL);
  CONST time_t CONST_longevity = CONST_one_year * 10;

  if (unlikely(!s || !*s))
    return 0;
  struct tm _tm;
  ni ret = sscanf(s, "%04d-%02d-%02d %02d:%02d:%02d", &_tm.tm_year, &_tm.tm_mon, &_tm.tm_mday,
      &_tm.tm_hour, &_tm.tm_min, &_tm.tm_sec);
  _tm.tm_year -= 1900;
  _tm.tm_mon -= 1;
  _tm.tm_isdst = -1;
  if (ret != 6 || _tm.tm_year <= 0)
    return 0;

  time_t result = mktime(&_tm);
  if (result + CONST_longevity < _current || _current + CONST_longevity < result)
    return 0;

  return result;
}

truefalse MyDB::connect()
{
  ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, false);
  if (connected())
    return true;
  CCfg * cfg = CCfgX::instance();
  CONST text * connect_str_template = "hostaddr=%s port=%d user='%s' password='%s' dbname=acedb";
  CONST ni STRING_LEN = 1024;
  text connect_str[STRING_LEN];
  snprintf(connect_str, STRING_LEN - 1, connect_str_template,
      cfg->db_addr.c_str(), cfg->db_port, cfg->db_name.c_str(), cfg->db_password.c_str());
  m_connection = PQconnectdb(connect_str);
  C_INFO("start connecting to database\n");
  truefalse result = (PQstatus(m_connection) == CONNECTION_OK);
  if (!result)
  {
    C_ERROR("connect to database failed, msg = %s\n", PQerrorMessage(m_connection));
    PQfinish(m_connection);
    m_connection = NULL;
  }
  else
    C_INFO("connect to database OK\n");
  return result;
}

truefalse MyDB::ping_db_server()
{
  ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, false);
  CONST text * select_sql = "select ('now'::text)::timestamp(0) without time zone";
  exec_command(select_sql);
  return check_db_connection();
}

truefalse MyDB::check_db_connection()
{
  if (unlikely(!connected()))
    return false;
  ConnStatusType cst = PQstatus(m_connection);
  if (cst == CONNECTION_BAD)
  {
    C_ERROR("connection to db lost, trying to re-connect...\n");
    PQreset(m_connection);
    cst = PQstatus(m_connection);
    if (cst == CONNECTION_BAD)
    {
      C_ERROR("reconnect to db failed: %s\n", PQerrorMessage(m_connection));
      return false;
    } else
      C_INFO("reconnect to db OK!\n");
  }
  return true;
}

DVOID MyDB::disconnect()
{
  if (connected())
  {
    PQfinish(m_connection);
    m_connection = NULL;
  }
}

truefalse MyDB::connected() CONST
{
  return m_connection != NULL;
}

truefalse MyDB::begin_transaction()
{
  return exec_command("BEGIN");
}

truefalse MyDB::commit()
{
  return exec_command("COMMIT");
}

truefalse MyDB::rollback()
{
  return exec_command("ROLLBACK");
}

DVOID MyDB::wrap_str(CONST text * s, CMemGuard & wrapped) CONST
{
  if (!s || !*s)
    wrapped.from_string("null");
  else
    wrapped.from_string("'", s, "'");
}

time_t MyDB::get_db_time_i()
{
  CONST text * CONST_select_sql = "select ('now'::text)::timestamp(0) without time zone";
  PGresult * pres = PQexec(m_connection, CONST_select_sql);
  MyPGResultGuard guard(pres);
  if (!pres || PQresultStatus(pres) != PGRES_TUPLES_OK)
  {
    C_ERROR("MyDB::sql (%s) failed: %s\n", CONST_select_sql, PQerrorMessage(m_connection));
    return 0;
  }
  if (unlikely(PQntuples(pres) <= 0))
    return 0;
  return get_time_from_string(PQgetvalue(pres, 0, 0));
}

truefalse MyDB::exec_command(CONST text * sql_command, ni * affected)
{
  if (unlikely(!sql_command || !*sql_command))
    return false;
  PGresult * pres = PQexec(m_connection, sql_command);
  MyPGResultGuard guard(pres);
  if (!pres || (PQresultStatus(pres) != PGRES_COMMAND_OK && PQresultStatus(pres) != PGRES_TUPLES_OK))
  {
    C_ERROR("MyDB::exec_command(%s) failed: %s\n", sql_command, PQerrorMessage(m_connection));
    return false;
  } else
  {
    if (affected)
    {
      CONST text * s = PQcmdTuples(pres);
      if (!s || !*s)
        *affected = 0;
      else
        *affected = atoi(PQcmdTuples(pres));
    }
    return true;
  }
}

truefalse MyDB::get_client_ids(CClientIDS * id_table)
{
  C_ASSERT_RETURN(id_table != NULL, "null id_table @MyDB::get_client_ids\n", false);

  CONST text * CONST_select_sql_template = "select client_id, client_password, client_expired, auto_seq "
                                           "from tb_clients where auto_seq > %d order by auto_seq";
  text select_sql[1024];
  snprintf(select_sql, 1024 - 1, CONST_select_sql_template, id_table->last_sequence());

  ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, false);
  PGresult * pres = PQexec(m_connection, select_sql);
  MyPGResultGuard guard(pres);
  if (!pres || PQresultStatus(pres) != PGRES_TUPLES_OK)
  {
    C_ERROR("MyDB::sql (%s) failed: %s\n", select_sql, PQerrorMessage(m_connection));
    return false;
  }
  ni count = PQntuples(pres);
  if (count > 0)
  {
    id_table->prepare_space(count);
    truefalse expired;
    CONST text * p;
    for (ni i = 0; i < count; ++i)
    {
      p = PQgetvalue(pres, i, 2);
      expired = p && (*p == 't' || *p == 'T');
      id_table->add(PQgetvalue(pres, i, 0), PQgetvalue(pres, i, 1), expired);
    }
    ni last_seq = atoi(PQgetvalue(pres, count - 1, 1));
    id_table->last_sequence(last_seq);
  }

  C_INFO("MyDB::get %d client_IDs from database\n", count);
  return true;
}

truefalse MyDB::save_client_id(CONST text * s)
{
  MyClientID id = s;
  id.trim_tail_space();
  if (id.as_string()[0] == 0)
    return false;

  CONST text * insert_sql_template = "insert into tb_clients(client_id) values('%s')";
  text insert_sql[1024];
  snprintf(insert_sql, 1024, insert_sql_template, id.as_string());

  ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, false);
  return exec_command(insert_sql);
}

truefalse MyDB::save_dist(MyHttpDistRequest & http_dist_request, CONST text * md5, CONST text * mbz_md5)
{
  CONST text * insert_sql_template = "insert into tb_dist_info("
               "dist_id, dist_type, dist_aindex, dist_findex, dist_fdir,"
               "dist_ftype, dist_password, dist_md5, dist_mbz_md5) "
               "values('%s', '%s', %s, '%s', '%s', '%s', '%s', '%s', '%s')";
  CONST text * _md5 = md5 ? md5 : "";
  CONST text * _mbz_md5 = mbz_md5 ? mbz_md5 : "";
  ni len = strlen(insert_sql_template) + strlen(_md5) + strlen(_mbz_md5) + 2000;
  CMemGuard sql;
  CMemPoolX::instance()->alloc_mem(len, &sql);
  CMemGuard aindex;
  wrap_str(http_dist_request.aindex, aindex);
  snprintf(sql.data(), len - 1, insert_sql_template,
      http_dist_request.ver, http_dist_request.type, aindex.data(),
      http_dist_request.findex, http_dist_request.fdir,
      http_dist_request.ftype, http_dist_request.password, _md5, _mbz_md5);

  ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, false);
  return exec_command(sql.data());
}

truefalse MyDB::save_sr(text * dids, CONST text * cmd, text * idlist)
{
  CONST text * sql_tpl = "update tb_dist_clients set dc_status = %d where dc_dist_id = '%s' and dc_client_id = '%s'";
  ni status = *cmd == '1'? 5: 7;

  text sql[1024];

  ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, false);

  text separator[2] = {';', 0};
  CONST ni BATCH_COUNT = 20;
  ni i = 0, total = 0, ok = 0;
  CStringTokenizer client_ids(idlist, separator);
  CStringTokenizer dist_ids(dids, separator);
  std::list<char *> l_client_ids, l_dist_ids;
  text * client_id, *dist_id;
  while ((client_id = client_ids.get()) != NULL)
    l_client_ids.push_back(client_id);
  while((dist_id = dist_ids.get()) != NULL)
    l_dist_ids.push_back(dist_id);
  std::list<char *>::iterator it1, it2;
  for (it1 = l_dist_ids.begin(); it1 != l_dist_ids.end(); ++ it1)
  {
    dist_id = *it1;
    for (it2 = l_client_ids.begin(); it2 != l_client_ids.end(); ++ it2)
    {
      total ++;
      client_id = *it2;
      if (i == 0)
      {
        if (!begin_transaction())
        {
          C_ERROR("failed to begin transaction @MyDB::save_sr\n");
          return false;
        }
      }
      snprintf(sql, 1024, sql_tpl, status, dist_id, client_id);
      exec_command(sql);
      ++i;
      if (i == BATCH_COUNT)
      {
        if (!commit())
        {
          C_ERROR("failed to commit transaction @MyDB::save_sr\n");
          rollback();
        } else
          ok += i;
        i = 0;
      }
    }
  }

  if (i != 0)
  {
    if (!commit())
    {
      C_ERROR("failed to commit transaction @MyDB::save_sr\n");
      rollback();
    } else
      ok += i;
  }

  C_INFO("MyDB::save_sr success/total = %d/%d\n", ok, total);
  return true;
}

truefalse MyDB::save_prio(CONST text * prio)
{
  if (!prio || !*prio)
    return false;
  text sql[2048];
  CONST text * sql_template = "update tb_config set cfg_value = '%s' where cfg_id = 2";
  snprintf(sql, 2048, sql_template, prio);
  ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, false);
  return exec_command(sql);
}

truefalse MyDB::save_dist_clients(text * idlist, text * adirlist, CONST text * dist_id)
{
  CONST text * insert_sql_template1 = "insert into tb_dist_clients(dc_dist_id, dc_client_id, dc_adir) values('%s', '%s', '%s')";
  CONST text * insert_sql_template2 = "insert into tb_dist_clients(dc_dist_id, dc_client_id) values('%s', '%s')";
  text insert_sql[2048];

  ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, false);

  text separator[2] = {';', 0};
  CONST ni BATCH_COUNT = 20;
  ni i = 0, total = 0, ok = 0;
  CStringTokenizer client_ids(idlist, separator);
  CStringTokenizer adirs(adirlist, separator);
  text * client_id, * adir;
  while ((client_id = client_ids.get()) != NULL)
  {
    adir = adirs.get();
    total ++;
    if (i == 0)
    {
      if (!begin_transaction())
      {
        C_ERROR("failed to begin transaction @MyDB::save_dist_clients\n");
        return false;
      }
    }
    if (adir)
      snprintf(insert_sql, 2048, insert_sql_template1, dist_id, client_id, adir);
    else
      snprintf(insert_sql, 2048, insert_sql_template2, dist_id, client_id);
    exec_command(insert_sql);
    ++i;
    if (i == BATCH_COUNT)
    {
      if (!commit())
      {
        C_ERROR("failed to commit transaction @MyDB::save_dist_clients\n");
        rollback();
      } else
        ok += i;

      i = 0;
    }
  }

  if (i != 0)
  {
    if (!commit())
    {
      C_ERROR("failed to commit transaction @MyDB::save_dist_clients\n");
      rollback();
    } else
      ok += i;
  }

  C_INFO("MyDB::save_dist_clients success/total = %d/%d\n", ok, total);
  return true;
}

truefalse MyDB::save_dist_cmp_done(CONST text *dist_id)
{
  if (unlikely(!dist_id || !*dist_id))
    return false;

  CONST text * update_sql_template = "update tb_dist_info set dist_cmp_done = 1 where dist_id='%s'";
  text insert_sql[1024];
  snprintf(insert_sql, 1024, update_sql_template, dist_id);

  ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, false);
  return exec_command(insert_sql);
}

ni MyDB::load_dist_infos(MyHttpDistInfos & infos)
{
  CONST text * CONST_select_sql = "select dist_id, dist_type, dist_aindex, dist_findex, dist_fdir,"
                                  " dist_ftype, dist_time, dist_password, dist_mbz_md5, dist_md5"
                                   " from tb_dist_info order by dist_time";
//      "select *, ((('now'::text)::timestamp(0) without time zone - dist_cmp_time > interval '00:10:10') "
//      ") and dist_cmp_done = '0' as cmp_needed, "
//      "((('now'::text)::timestamp(0) without time zone - dist_md5_time > interval '00:10:10') "
//      ") and (dist_md5 is null) and (dist_type = '1') as md5_needed "
//      "from tb_dist_info order by dist_time";

  ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, false);

  PGresult * pres = PQexec(m_connection, CONST_select_sql);
  MyPGResultGuard guard(pres);
  if (!pres || PQresultStatus(pres) != PGRES_TUPLES_OK)
  {
    C_ERROR("MyDB::sql (%s) failed: %s\n", CONST_select_sql, PQerrorMessage(m_connection));
    return -1;
  }

  ni count = PQntuples(pres);
  ni field_count = PQnfields(pres);
  if (unlikely(field_count != 10))
  {
    C_ERROR("incorrect column count(%d) @MyDB::load_dist_infos\n", field_count);
    return -1;
  }

  infos.prepare_update(count);
  for (ni i = 0; i < count; ++ i)
  {
    MyHttpDistInfo * info = infos.create_http_dist_info(PQgetvalue(pres, i, 0));

    for (ni j = 0; j < field_count; ++j)
    {
      CONST text * fvalue = PQgetvalue(pres, i, j);
      if (!fvalue || !*fvalue)
        continue;

      if (j == 5)
        info->ftype[0] = *fvalue;
      else if (j == 4)
        info->fdir.from_string(fvalue);
      else if (j == 3)
      {
        info->findex.from_string(fvalue);
        info->findex_len = strlen(fvalue);
      }
      else if (j == 9)
      {
        info->md5.from_string(fvalue);
        info->md5_len = strlen(fvalue);
      }
      else if (j == 1)
        info->type[0] = *fvalue;
      else if (j == 7)
      {
        info->password.from_string(fvalue);
        info->password_len = strlen(fvalue);
      }
      else if (j == 6)
      {
        info->dist_time.from_string(fvalue);
      }
      else if (j == 2)
      {
        info->aindex.from_string(fvalue);
        info->aindex_len = strlen(fvalue);
      }
      else if (j == 8)
        info->mbz_md5.from_string(fvalue);
    }

    info->calc_md5_opt_len();
  }

  C_INFO("MyDB::get %d dist infos from database\n", count);
  return count;
}

//truefalse MyDB::dist_take_cmp_ownership(MyHttpDistInfo * info)
//{
//  if (unlikely(!info))
//    return false;
//
//  text where[128];
//  snprintf(where, 128, "where dist_id = '%s'", info->ver.data());
//  return take_owner_ship("tb_dist_info", "dist_cmp_time", info->cmp_time, where);
//}
//
//truefalse MyDB::dist_take_md5_ownership(MyHttpDistInfo * info)
//{
//  if (unlikely(!info))
//    return false;
//
//  text where[128];
//  snprintf(where, 128, "where dist_id = '%s'", info->ver.data());
//  return take_owner_ship("tb_dist_info", "dist_md5_time", info->md5_time, where);
//}

truefalse MyDB::take_owner_ship(CONST text * table, CONST text * field, CMemGuard & old_time, CONST text * where_clause)
{
  CONST text * update_sql_template = "update %s set "
                                     "%s = ('now'::text)::timestamp(0) without time zone "
                                     "%s and %s %s %s";
  text sql[1024];
  if (old_time.data() && old_time.data()[0])
  {
    CMemGuard wrapped_time;
    wrap_str(old_time.data(), wrapped_time);
    snprintf(sql, 1024, update_sql_template, table, field, where_clause, field, "=", wrapped_time.data());
  }
  else
    snprintf(sql, 1024, update_sql_template, table, field, where_clause, field, "is", "null");

  ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, false);
  ni m = 0;
  if (!exec_command(sql, &m))
    return false;

  truefalse result = (m == 1);

  CONST text * select_sql_template = "select %s from %s %s";
  snprintf(sql, 1024, select_sql_template, field, table, where_clause);
  PGresult * pres = PQexec(m_connection, sql);
  MyPGResultGuard guard(pres);
  if (!pres || PQresultStatus(pres) != PGRES_TUPLES_OK)
  {
    C_ERROR("MyDB::sql (%s) failed: %s\n", sql, PQerrorMessage(m_connection));
    return result;
  }
  ni count = PQntuples(pres);
  if (count > 0)
    old_time.from_string(PQgetvalue(pres, 0, 0));
  return result;
}

truefalse MyDB::dist_mark_cmp_done(CONST text * dist_id)
{
  if (unlikely(!dist_id || !*dist_id))
    return false;

  CONST text * update_sql_template = "update tb_dist_info set dist_cmp_done = 1 "
                                     "where dist_id = '%s'";
  text sql[1024];
  snprintf(sql, 1024, update_sql_template, dist_id);

  ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, false);
  return exec_command(sql);
}

truefalse MyDB::dist_mark_md5_done(CONST text * dist_id)
{
  if (unlikely(!dist_id || !*dist_id))
    return false;

  CONST text * update_sql_template = "update tb_dist_info set dist_md5_done = 1 "
                                     "where dist_id = '%s'";
  text sql[1024];
  snprintf(sql, 1024, update_sql_template, dist_id);

  ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, false);
  return exec_command(sql);
}

truefalse MyDB::save_dist_md5(CONST text * dist_id, CONST text * md5, ni md5_len)
{
  if (unlikely(!dist_id || !*dist_id || !md5))
    return false;

  CONST text * update_sql_template = "update tb_dist_info set dist_md5 = '%s' "
                                     "where dist_id = '%s'";
  ni len = md5_len + strlen(update_sql_template) + strlen(dist_id) + 20;
  CMemGuard sql;
  CMemPoolX::instance()->alloc_mem(len, &sql);
  snprintf(sql.data(), len, update_sql_template, md5, dist_id);

  ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, false);
  return exec_command(sql.data());
}

truefalse MyDB::save_dist_ftp_md5(CONST text * dist_id, CONST text * md5)
{
  if (unlikely(!dist_id || !*dist_id || !md5 || !*md5))
    return false;

  CONST text * update_sql_template = "update tb_dist_info set dist_mbz_md5 = '%s' "
                                     "where dist_id = '%s'";
  text sql[1024];
  snprintf(sql, 1024, update_sql_template, md5, dist_id);

  ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, false);
  return exec_command(sql);
}

truefalse MyDB::load_dist_clients(MyDistClients * dist_clients, MyDistClientOne * _dc_one)
{
  C_ASSERT_RETURN(dist_clients != NULL, "null dist_clients @MyDB::load_dist_clients\n", false);

  CONST text * CONST_select_sql_1 = "select dc_dist_id, dc_client_id, dc_status, dc_adir, dc_last_update,"
      " dc_mbz_file, dc_mbz_md5, dc_md5"
      " from tb_dist_clients order by dc_client_id";
  CONST text * CONST_select_sql_2 = "select dc_dist_id, dc_client_id, dc_status, dc_adir, dc_last_update,"
      " dc_mbz_file, dc_mbz_md5, dc_md5"
      " from tb_dist_clients where dc_client_id = '%s'";
  CONST text * CONST_select_sql;

  text sql[512];
  if (!_dc_one)
    CONST_select_sql = CONST_select_sql_1;
  else
  {
    snprintf(sql, 512, CONST_select_sql_2, _dc_one->client_id());
    CONST_select_sql = sql;
  }

  ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, false);

//  dist_clients->db_time = get_db_time_i();
//  if (unlikely(dist_clients->db_time == 0))
//  {
//    C_ERROR("can not get db server time\n");
//    return false;
//  }

  PGresult * pres = PQexec(m_connection, CONST_select_sql);
  MyPGResultGuard guard(pres);
  if (!pres || PQresultStatus(pres) != PGRES_TUPLES_OK)
  {
    C_ERROR("MyDB::sql (%s) failed: %s\n", CONST_select_sql, PQerrorMessage(m_connection));
    return -1;
  }
  ni count = PQntuples(pres);
  ni field_count = PQnfields(pres);
  ni count_added = 0;
  MyDistClientOne * dc_one;

  if (count == 0)
    goto __exit__;
  if (unlikely(field_count != 8))
  {
    C_ERROR("wrong column number(%d) @MyDB::load_dist_clients()\n", field_count);
    return false;
  }

  MyHttpDistInfo * info;
  if (!_dc_one)
    dc_one = dist_clients->create_client_one(PQgetvalue(pres, 0, 1));
  else
    dc_one = _dc_one;
  for (ni i = 0; i < count; ++ i)
  {
    info = dist_clients->find_dist_info(PQgetvalue(pres, i, 0));
    if (unlikely(!info))
      continue;

    if (!_dc_one)
    {
      CONST text * client_id = PQgetvalue(pres, i, 1);
      if (unlikely(!dc_one->is_client_id(client_id)))
        dc_one = dist_clients->create_client_one(client_id);
    }

    MyDistClient * dc = dc_one->create_dist_client(info);

    CONST text * md5 = NULL;
    for (ni j = 0; j < field_count; ++j)
    {
      CONST text * fvalue = PQgetvalue(pres, i, j);
      if (!fvalue || !*fvalue)
        continue;

      if (j == 2)
        dc->status = atoi(fvalue);
      else if (j == 3)
        dc->adir.from_string(fvalue);
      else if (j == 7)
        md5 = fvalue;
      else if (j == 5)
        dc->mbz_file.from_string(fvalue);
      else if (j == 4)
        dc->last_update = get_time_from_string(fvalue);
      else if (j == 6)
        dc->mbz_md5.from_string(fvalue);
    }

    if (dc->status < 3 && md5 != NULL)
      dc->md5.from_string(md5);

    ++ count_added;
  }

__exit__:
  if (!_dc_one)
    C_INFO("MyDB::get %d/%d dist client infos from database\n", count_added, count);
  return count;
}

truefalse MyDB::set_dist_client_status(MyDistClient & dist_client, ni new_status)
{
  return set_dist_client_status(dist_client.client_id(), dist_client.dist_info->ver.data(), new_status);
}

truefalse MyDB::set_dist_client_status(CONST text * client_id, CONST text * dist_id, ni new_status)
{
  CONST text * update_sql_template = "update tb_dist_clients set dc_status = %d "
                                     "where dc_dist_id = '%s' and dc_client_id='%s' and dc_status < %d";
  text sql[1024];
  snprintf(sql, 1024, update_sql_template, new_status, dist_id, client_id, new_status);

  ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, false);
  return exec_command(sql);
}

truefalse MyDB::set_dist_client_md5(CONST text * client_id, CONST text * dist_id, CONST text * md5, ni new_status)
{
  CONST text * update_sql_template = "update tb_dist_clients set dc_status = %d, dc_md5 = '%s' "
                                     "where dc_dist_id = '%s' and dc_client_id='%s' and dc_status < %d";
  ni len = strlen(update_sql_template) + strlen(md5) + strlen(client_id)
    + strlen(dist_id) + 40;
  CMemGuard sql;
  CMemPoolX::instance()->alloc_mem(len, &sql);
  snprintf(sql.data(), len, update_sql_template, new_status, md5, dist_id, client_id, new_status);

  ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, false);
  ni num = 0;
  return exec_command(sql.data(), &num) && num == 1;
}

truefalse MyDB::set_dist_client_mbz(CONST text * client_id, CONST text * dist_id, CONST text * mbz, CONST text * mbz_md5)
{
  CONST text * update_sql_template = "update tb_dist_clients set dc_mbz_file = '%s', dc_mbz_md5 = '%s' "
                                     "where dc_dist_id = '%s' and dc_client_id='%s' and dc_status < 3";
  ni len = strlen(update_sql_template) + strlen(mbz) + strlen(client_id)
          + strlen(dist_id) + 40 + strlen(mbz_md5);
  CMemGuard sql;
  CMemPoolX::instance()->alloc_mem(len, &sql);
  snprintf(sql.data(), len, update_sql_template, mbz, mbz_md5, dist_id, client_id);

  ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, false);
  ni num = 0;
  return exec_command(sql.data(), &num) && num == 1;
}

truefalse MyDB::delete_dist_client(CONST text * client_id, CONST text * dist_id)
{
  CONST text * delete_sql_template = "delete from tb_dist_clients where dc_dist_id = '%s' and dc_client_id='%s'";
  text sql[1024];
  snprintf(sql, 1024, delete_sql_template, dist_id, client_id);

  ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, false);
  return exec_command(sql);
}

truefalse MyDB::dist_info_is_update(MyHttpDistInfos & infos)
{
  {
    ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, false);
    if (!check_db_connection())
      return true;
  }
  CMemGuard value;
  if (!load_cfg_value(1, value))
    return true;
  truefalse result = strcmp(infos.last_load_time.data(), value.data()) == 0;
  if (!result)
    infos.last_load_time.from_string(value.data());
  return result;
}

truefalse MyDB::load_pl(CMemGuard & value)
{
  return load_cfg_value(2, value);
}

truefalse MyDB::dist_info_update_status()
{
  ni now = (ni)time(NULL);
  ni x = random() % 0xFFFFFF;
  text buff[64];
  snprintf(buff, 64, "%d-%d", now, x);
  return set_cfg_value(1, buff);
}

truefalse MyDB::remove_orphan_dist_info()
{
  CONST text * sql = "select post_process()";

  ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, false);
  return exec_command(sql);
}

truefalse MyDB::get_dist_ids(MyUnusedPathRemover & path_remover)
{
  CONST text * sql = "select dist_id from tb_dist_info";

  ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, false);
  PGresult * pres = PQexec(m_connection, sql);
  MyPGResultGuard guard(pres);
  if (!pres || PQresultStatus(pres) != PGRES_TUPLES_OK)
  {
    C_ERROR("MyDB::sql (%s) failed: %s\n", sql, PQerrorMessage(m_connection));
    return false;
  }
  ni count = PQntuples(pres);
  if (count > 0)
  {
    for (ni i = 0; i < count; ++i)
      path_remover.add_dist_id(PQgetvalue(pres, i, 0));
  }
  return true;
}

truefalse MyDB::mark_client_valid(CONST text * client_id, truefalse valid)
{
  text sql[1024];
  if (!valid)
  {
    CONST text * sql_template = "delete from tb_clients where client_id = '%s'";
    snprintf(sql, 1024, sql_template, client_id);
  } else
  {
    CONST text * sql_template = "insert into tb_clients(client_id, client_password) values('%s', '%s')";
    snprintf(sql, 1024, sql_template, client_id, client_id);
  }

  ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, false);
  return exec_command(sql);
}

truefalse MyDB::set_cfg_value(CONST ni id, CONST text * value)
{
  CONST text * sql_template = "update tb_config set cfg_value = '%s' where cfg_id = %d";
  text sql[1024];
  snprintf(sql, 1024, sql_template, value, id);

  ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, false);
  return exec_command(sql);
}

truefalse MyDB::load_cfg_value(CONST ni id, CMemGuard & value)
{
  ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, false);
  return load_cfg_value_i(id, value);
}

truefalse MyDB::load_cfg_value_i(CONST ni id, CMemGuard & value)
{
  CONST text * CONST_select_sql_template = "select cfg_value from tb_config where cfg_id = %d";
  text select_sql[1024];
  snprintf(select_sql, 1024, CONST_select_sql_template, id);

  PGresult * pres = PQexec(m_connection, select_sql);
  MyPGResultGuard guard(pres);
  if (!pres || PQresultStatus(pres) != PGRES_TUPLES_OK)
  {
    C_ERROR("MyDB::sql (%s) failed: %s\n", select_sql, PQerrorMessage(m_connection));
    return false;
  }
  ni count = PQntuples(pres);
  if (count > 0)
  {
    value.from_string(PQgetvalue(pres, 0, 0));
    return true;
  } else
    return false;
}


truefalse MyDB::load_db_server_time_i(time_t &t)
{
  CONST text * select_sql = "select ('now'::text)::timestamp(0) without time zone";
  PGresult * pres = PQexec(m_connection, select_sql);
  MyPGResultGuard guard(pres);
  if (!pres || PQresultStatus(pres) != PGRES_TUPLES_OK)
  {
    C_ERROR("MyDB::sql (%s) failed: %s\n", select_sql, PQerrorMessage(m_connection));
    return false;
  }
  if (PQntuples(pres) <= 0)
    return false;
  t = get_time_from_string(PQgetvalue(pres, 0, 0));
  return true;
}
