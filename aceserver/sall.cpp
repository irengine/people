#include "sall.h"
#include "app.h"
#include "sapp.h"

CBsDistData::CBsDistData(CONST text * dist_id)
{
  ftype[0] = ftype[1] = 0;
  type[0] = type[1] = 0;
  ver.init(dist_id);
  ver_len = strlen(dist_id);
  md5_opt_len = 0;
  exist = false;
  md5_len = 0;
  ver_len = 0;
  findex_len = 0;
  password_len = 0;
  aindex_len = 0;
}

truefalse CBsDistData::have_checksum() CONST
{
  return (c_tell_type_multi(type[0]));
}

truefalse CBsDistData::have_checksum_compress() CONST
{
  return !have_checksum();
}

DVOID CBsDistData::calc_md5_opt_len()
{
  if (have_checksum() && md5_len > 0 && md5_opt_len == 0)
  {
    CMemProt md5_2;
    md5_2.init(md5.get_ptr());
    CCheckSums md5s;
    if (md5s.load_text(md5_2.get_ptr(), NULL))
      md5_opt_len = md5s.text_len(false) - 1;
  }
}


CBsDistReq::CBsDistReq()
{
  aindex = NULL;
  ver = NULL;
  type = NULL;
  password = NULL;
  acode = NULL;
  ftype = NULL;
  fdir = NULL;
  findex = NULL;
  adir = NULL;
}

CBsDistReq::CBsDistReq(CONST CBsDistData & data)
{
  acode = NULL;
  ftype = (char*)data.ftype;
  fdir = data.fdir.get_ptr();
  findex = data.findex.get_ptr();
  adir = NULL;
  aindex = data.aindex.get_ptr();
  ver = data.ver.get_ptr();
  type = (char*)data.type;
  password = data.password.get_ptr();
}

truefalse CBsDistReq::do_validate(CONST text * v_x, CONST text * v_y) CONST
{
  if (!v_x || !*v_x)
  {
    C_ERROR("invalid bs dist command, no %s\n", v_y);
    return false;
  }

  return true;
}

truefalse CBsDistReq::is_ok(CONST truefalse v_acode_also) CONST
{
  if (v_acode_also && !do_validate(acode, "acode"))
    return false;

  if (!do_validate(ftype, "ftype"))
    return false;

  if (unlikely(ftype[1] != 0 || !c_tell_ftype_valid(ftype[0])))
  {
    C_ERROR("invalid bs dist command, ftype = %s\n", ftype);
    return false;
  }

  if (!do_validate(findex, "findex"))
    return false;

  if (!do_validate(fdir, "fdir"))
    return false;

  if (!do_validate(ver, "ver"))
    return false;

  if (!do_validate(type, "type"))
    return false;

  if (unlikely(type[1] != 0 || !c_tell_type_valid(type[0])))
  {
    C_ERROR("invalid bs dist command, type = %s\n", type);
    return false;
  }

  return true;
}

truefalse CBsDistReq::have_checksum() CONST
{
  return (type && c_tell_type_multi(*type));
}

truefalse CBsDistReq::have_checksum_compress() CONST
{
  return !have_checksum();
}


CBsDistDatas::CBsDistDatas()
{
  prev_query_ts.init("");
}

CBsDistDatas::~CBsDistDatas()
{
  reset();
}

ni CBsDistDatas::size() CONST
{
  return m_data_map.size();
}

DVOID CBsDistDatas::reset()
{
  std::for_each(m_datas.begin(), m_datas.end(), CPoolObjectDeletor());
  m_datas.clear();
  CBsDistDataVec x;
  x.swap(m_datas);
  m_data_map.clear();
}

CBsDistData * CBsDistDatas::alloc_data(CONST text * did)
{
  DVOID * p = CCacheX::instance()->get_raw(sizeof(CBsDistData));
  CBsDistData * l_x = new (p) CBsDistData(did);
  m_datas.push_back(l_x);
  m_data_map.insert(std::pair<const text *, CBsDistData *>(l_x->ver.get_ptr(), l_x));
  return l_x;
}

truefalse CBsDistDatas::need_reload()
{
  return (!CRunnerX::instance()->db().dist_info_is_update(*this));
}

DVOID CBsDistDatas::alloc_spaces(CONST ni m)
{
  reset();
  m_datas.reserve(m);
}

CBsDistData * CBsDistDatas::search(CONST text * did)
{
  if (unlikely(!did || !*did))
    return NULL;

  CBsDistDataMap::iterator it = m_data_map.find(did);
  return it == m_data_map.end()? NULL: it->second;
}



CONST text * CCompFactory::dir_of_composite()
{
  return "_x_cmp_x_";
}

CONST text * CCompFactory::single_fn()
{
  return "_x_cmp_x_/all_in_one.mbz";
}

DVOID CCompFactory::query_single_fn(CONST text * did, CMemProt & fn)
{
  CMemProt tmp;
  tmp.init(CCfgX::instance()->bz_files_path.c_str(), "/", did);
  fn.init(tmp.get_ptr(), "/", single_fn());
}

truefalse CCompFactory::do_comp(CBsDistReq & v_req)
{
  truefalse l_x = false;
  truefalse bm = false;
  ni l_skip_n = strlen(v_req.fdir) - 1;
  CMemProt l_to_path;
  CMemProt l_cmp_path;
  CMemProt single;
  CMemProt mfile;
  CMemProt l_to_fn;
  l_to_path.init(CCfgX::instance()->bz_files_path.c_str(), "/", v_req.ver);
  if (!CSysFS::create_dir(l_to_path.get_ptr(), false))
  {
    C_ERROR("create_dir %s, %s\n", l_to_path.get_ptr(), (CONST text *)CSysError());
    goto label_out;
  }

  l_cmp_path.init(l_to_path.get_ptr(), "/", dir_of_composite());
  if (!CSysFS::create_dir(l_cmp_path.get_ptr(), false))
  {
    C_ERROR("create_dir %s, %s\n", l_cmp_path.get_ptr(), (CONST text *)CSysError());
    goto label_out;
  }
  single.init(l_cmp_path.get_ptr(), "/all_in_one.mbz");
  if (!c_tell_type_single(*v_req.type))
    if (!m_comp_uniter.begin(single.get_ptr()))
      goto label_out;

  CSysFS::dir_add(v_req.fdir, v_req.findex, mfile);
  l_to_fn.init(l_to_path.get_ptr(), "/", (v_req.findex? v_req.findex: v_req.aindex), ".mbz");
  bm =   m_data_comp.reduce(mfile.get_ptr(), l_skip_n, l_to_fn.get_ptr(), v_req.password);
  if (!bm && !c_tell_type_multi(*v_req.type))
  {
    C_ERROR("comp(%s) to (%s)\n", mfile.get_ptr(), l_to_fn.get_ptr());
    m_comp_uniter.finish();
    return false;
  }
  if (!c_tell_type_single(*v_req.type) && bm && !m_comp_uniter.append(l_to_fn.get_ptr()))
  {
    m_comp_uniter.finish();
    return false;
  }

  if (c_tell_type_single(*v_req.type))
  {
    l_x = CSysFS::rename(l_to_fn.get_ptr(), single.get_ptr(), false);
    goto label_out;
  }

  if (unlikely(!CSysFS::dir_from_mfile(mfile, l_skip_n)))
  {
    C_ERROR("dir_from_mfile %s\n", mfile.get_ptr());
    m_comp_uniter.finish();
    goto label_out;
  }

  l_x = i_work(mfile.get_ptr(), l_to_path.get_ptr(), l_skip_n, v_req.password);
  m_comp_uniter.finish();

label_out:
  if (!l_x)
    C_ERROR("fail to create comp files%s\n", v_req.ver);
  else
    C_INFO("creation comp files %s finished\n", v_req.ver);

  if (c_tell_type_all(*v_req.type))
  {
    CSysFS::remove(l_to_fn.get_ptr());
    ni m = strlen(l_to_fn.get_ptr());
    if (likely(m > 4))
    {
      l_to_fn.get_ptr()[m - 4] = 0;
      if (likely(CSysFS::dir_from_mfile(l_to_fn, 1)))
        CSysFS::delete_dir(l_to_fn.get_ptr(), true);
    }
  }
  return l_x;
}

truefalse CCompFactory::i_work(CONST text * from_dir, CONST text * to_dir, ni skip_n, CONST text * key)
{
  if (unlikely(!from_dir || !*from_dir || !to_dir || !*to_dir))
    return false;

  if (!CSysFS::create_dir(to_dir, false))
  {
    C_ERROR("fail create path %s, %s\n", to_dir, (CONST text *)CSysError());
    return false;
  }

  DIR * dir = opendir(from_dir);
  if (!dir)
  {
    C_ERROR("opendir: %s, %s\n", from_dir, (CONST char*)CSysError());
    return false;
  }

  ni len1 = strlen(from_dir);
  ni len2 = strlen(to_dir);

  struct dirent * l_x;
  ni l_y = len1 - skip_n;
  if (l_y > 0)
  {
    if (!CSysFS::create_dir(to_dir, from_dir + skip_n + 1, false, false))
    {
      C_ERROR("create_dir %s%s %s\n", to_dir, from_dir + skip_n, (CONST char*)CSysError());
      return false;
    }
  }

  while ((l_x = readdir(dir)) != NULL)
  {
    if (unlikely(!l_x->d_name))
      continue;
    if (!strcmp(l_x->d_name, ".") || !strcmp(l_x->d_name, ".."))
      continue;

    CMemProt l_from, l_to;
    ni l_m = strlen(l_x->d_name);
    CCacheX::instance()->get(len1 + l_m + 2, &l_from);
    sprintf(l_from.get_ptr(), "%s/%s", from_dir, l_x->d_name);
    CCacheX::instance()->get(len2 + l_m + 10 + l_y, &l_to);

    if (l_x->d_type == DT_REG)
    {
      if (l_y > 0)
        sprintf(l_to.get_ptr(), "%s%s/%s.mbz", to_dir, from_dir + skip_n, l_x->d_name);
      else
        sprintf(l_to.get_ptr(), "%s/%s.mbz", to_dir, l_x->d_name);
      if (!m_data_comp.reduce(l_from.get_ptr(), skip_n, l_to.get_ptr(), key))
      {
        C_ERROR("comp(%s) to (%s) failed\n", l_from.get_ptr(), l_to.get_ptr());
        closedir(dir);
        return false;
      }
      if (!m_comp_uniter.append(l_to.get_ptr()))
      {
        closedir(dir);
        return false;
      }
    }
    else if(l_x->d_type == DT_DIR)
    {
      if (l_y > 0)
        sprintf(l_to.get_ptr(), "%s%s/%s", to_dir, from_dir + skip_n, l_x->d_name);
      else
        sprintf(l_to.get_ptr(), "%s/%s", to_dir, l_x->d_name);

      if (!i_work(l_from.get_ptr(), to_dir, skip_n, key))
      {
        closedir(dir);
        return false;
      }
    } else
      C_WARNING("unexpected file type (= %d) file = %s/%s\n", l_x->d_type, from_dir, l_x->d_name);
  };

  closedir(dir);
  return true;
}




truefalse CChecksumComputer::compute(CBsDistReq & v_req, CMemProt & v_checksum, ni & v_cs_size)
{
  if (!v_req.have_checksum())
  {
    C_INFO("skipping file md5 generation for %s, not needed\n", v_req.ver);
    return true;
  }

  CCheckSums l_cs;
  if (unlikely(!l_cs.compute(v_req.fdir, v_req.findex, c_tell_type_single(*v_req.type))))
  {
    C_ERROR("failed to calculate md5 file list for dist %s\n", v_req.ver);
    return false;
  }
  l_cs.make_ordered();
  v_cs_size = l_cs.text_len(true);

  CCacheX::instance()->get(v_cs_size, &v_checksum);
  if (unlikely(!l_cs.save_text(v_checksum.get_ptr(), v_cs_size, true)))
  {
    C_ERROR("can not get md5 file list result for dist %s\n", v_req.ver);
    return false;
  }
  return true;
}


truefalse CChecksumComputer::compute_single_cs(CONST text * did, CMemProt & v_cs)
{
  CMemProt l_fn;
  CCompFactory::query_single_fn(did, l_fn);
  return c_tools_tally_md5(l_fn.get_ptr(), v_cs);
}


CMB * c_create_hb_mb()
{
  CMB * mb = CCacheX::instance()->get_mb_bs(1, "99");
  if (!mb)
    return NULL;
  text * dest = mb->base() + CBSData::DATA_OFFSET;
  *dest = '1';
  *(dest + 1) = CBSData::END_MARK;
  return mb;
}


class CBalanceSearcher
{
public:
  CBalanceSearcher(CONST text * p)
  {
    m_ip = p;
  }

  truefalse operator()(CBalanceData& x) CONST
  {
    if (!m_ip)
      return false;
    return (strcmp(m_ip, x.m_ip) == 0);
  }

private:
  CONST text * m_ip;
};



CBalanceDatas::CBalanceDatas()
{
  m_loads.reserve(6);
  m_ip_size = 0;
  m_ips[0] = 0;
}

DVOID CBalanceDatas::refresh(CONST CBalanceData & load)
{
  if (load.m_ip[0] == 0)
    return;
  ACE_MT(ACE_GUARD(ACE_Thread_Mutex, ace_mon, m_mutex));
  CBalanceDataVecIt it = do_search(load.m_ip);
  if (it == m_loads.end())
    m_loads.push_back(load);
  else
  {
    it->set_load(load.m_load);
    it->m_prev_access_ts = g_clock_counter;
  }

  do_compute_ips();
}

DVOID CBalanceDatas::del(CONST text * ip)
{
  if (!ip || !*ip)
    return;
  ACE_MT(ACE_GUARD(ACE_Thread_Mutex, ace_mon, m_mutex));
  CBalanceDataVecIt it = do_search(ip);
  if (it == m_loads.end())
    return;
  m_loads.erase(it);

  do_compute_ips();
}

CBalanceDatas::CBalanceDataVecIt CBalanceDatas::do_search(CONST text * ip)
{
  return find_if(m_loads.begin(), m_loads.end(), CBalanceSearcher(ip));
}

DVOID CBalanceDatas::do_compute_ips()
{
  m_ips[0] = 0;
  sort(m_loads.begin(), m_loads.end());
  CBalanceDataVecIt it;
  ni l_x = IP_SIZE - 2;
  text * l_p = m_ips;
  for (it = m_loads.begin(); it != m_loads.end(); ++it)
  {
    ni len = strlen(it->m_ip);
    if (len == 0)
      continue;
    if (unlikely(len > l_x))
    {
      C_ERROR("ips too long\n");
      break;
    }
    memcpy(l_p, it->m_ip, len + 1);
    l_p += len;
    l_x -= (len + 1);
    *l_p = CCmdHeader::ITEM_SEPARATOR;
    ++l_p;
  }
  *l_p = 0;

  ni l_m = CCfgX::instance()->ftp_servers.length();
  if (unlikely(l_m + 3 > l_x))
    C_ERROR("ips too long\n");
  else
  {
    *l_p++ = CCmdHeader::FINISH_SEPARATOR;
    ACE_OS::strsncpy(l_p, CCfgX::instance()->ftp_servers.c_str(), l_x + 1);
  }

  m_ip_size = strlen(m_ips);
  ++m_ip_size;
}

ni CBalanceDatas::query_servers(text * v_result, ni v_result_size)
{
  ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, m_mutex, 0);
  if (!v_result || v_result_size < m_ip_size)
    return 0;
  ACE_OS::strsncpy(v_result, m_ips, v_result_size);
  return m_ip_size;
}

DVOID CBalanceDatas::check_broken()
{
  ACE_MT(ACE_GUARD(ACE_Thread_Mutex, ace_mon, m_mutex));
  CBalanceDataVecIt it;
  for (it = m_loads.begin(); it != m_loads.end(); )
  {
    if (it->m_prev_access_ts + ni(BROKEN_INTERVAL * 60 / CApp::CLOCK_TIME) < g_clock_counter)
      it = m_loads.erase(it);
    else
      ++it;
  };

  do_compute_ips();
}


CObsoleteDirDeleter::~CObsoleteDirDeleter()
{
  std::for_each(m_dirlist.begin(), m_dirlist.end(), CObjDeletor());
}

DVOID CObsoleteDirDeleter::append_did(CONST text * did)
{
  CMemProt * l_x = new CMemProt;
  l_x->init(did);
  m_dirlist.push_back(l_x);
  m_dirs.insert(l_x->get_ptr());
}

truefalse CObsoleteDirDeleter::dir_valid(CONST text * dir)
{
  return m_dirs.find(dir) != m_dirs.end();
}

DVOID CObsoleteDirDeleter::work(CONST text * v_dir)
{
  DIR * l_x = opendir(v_dir);
  if (!l_x)
  {
    C_ERROR("opendir(%s) %s\n", v_dir, (CONST char*)CSysError());
    return;
  }

  ni l_total = 0, l_good_num = 0;
  struct dirent * l_y;
  while ((l_y = readdir(l_x)) != NULL)
  {
    if (!l_y->d_name)
      continue;
    if (!strcmp(l_y->d_name, ".") || !strcmp(l_y->d_name, ".."))
      continue;

    if(l_y->d_type == DT_DIR)
    {
      if(!dir_valid(l_y->d_name))
      {
        ++l_total;
        CMemProt l_z;
        l_z.init(v_dir, "/", l_y->d_name);
        if (CSysFS::delete_dir(l_z.get_ptr(), true))
          ++ l_good_num;
      }
    }
  };

  closedir(l_x);
  C_INFO("deleted %d/%d obsolete dir @CObsoleteDirDeleter\n", l_good_num, l_total);
}




CBalanceDatas * CPositionProc::m_balance_datas = NULL;

CPositionProc::CPositionProc(CParentHandler * p): CParentServerProc(p)
{

}

CONST text * CPositionProc::name() CONST
{
  return "CPositionProc";
}

CProc::OUTPUT CPositionProc::at_head_arrival()
{
  if (CParentServerProc::at_head_arrival() == OP_FAIL)
    return OP_FAIL;

  if (m_data_head.cmd == CCmdHeader::PT_VER_REQ)
  {
    if (!c_packet_check_term_ver_req(&m_data_head))
    {
      C_ERROR("bad term packet header\n");
      return OP_FAIL;
    }
    return OP_OK;
  }

  return OP_FAIL;
}

CProc::OUTPUT CPositionProc::do_read_data(CMB * mb)
{
  CParentServerProc::do_read_data(mb);

  CCmdHeader * l_p = (CCmdHeader *)mb->base();
  if (l_p->cmd == CCmdHeader::PT_VER_REQ)
    return do_version_check(mb);

  CMBProt guard(mb);
  C_ERROR("get bad cmd = %d\n", l_p->cmd);
  return OP_FAIL;
}


CProc::OUTPUT CPositionProc::do_version_check(CMB * mb)
{
  CMBProt prot(mb);
  m_term_sn = "foobar";
  text ips[CBalanceDatas::IP_SIZE];
  ni m = m_balance_datas->query_servers(ips, CBalanceDatas::IP_SIZE);
  CMB * mb2 = i_create_mb_ver_reply(CTermVerReply::SC_SERVER_LIST, m);

  CTermVerReply * l_x = (CTermVerReply *)mb2->base();
  if (likely(m > 0))
    memcpy(l_x->data, ips, m);

  if (m_handler->post_packet(mb2) <= 0)
    return OP_FAIL;
  else
    return OP_OK;
}

PREPARE_MEMORY_POOL(CPositionProc);




CPositionHandler::CPositionHandler(CHandlerDirector * p): CParentHandler(p)
{
  m_proc = new CPositionProc(this);
}

PREPARE_MEMORY_POOL(CPositionHandler);



CPositionTask::CPositionTask(CContainer * p, ni v_thrds):
    CTaskBase(p, v_thrds)
{

}

ni CPositionTask::svc()
{
  C_INFO("Start %s::svc()\n", name());
  for (CMB * mb; getq(mb) != -1;)
    mb->release ();
  C_INFO("exiting %s::svc()\n", name());
  return 0;
}




CPositionAcc::CPositionAcc(CParentScheduler * p1, CHandlerDirector * p2): CParentAcc(p1, p2)
{
  m_tcp_port = CCfgX::instance()->pre_client_port;
  m_reap_interval = BROKEN_DELAY;
}

ni CPositionAcc::make_svc_handler(CParentHandler *& sh)
{
  sh = new CPositionHandler(m_director);
  if (!sh)
  {
    C_ERROR("oom @%s\n", name());
    return -1;
  }
  sh->container((void*)this);
  sh->reactor(reactor());
  return 0;
}

CONST text * CPositionAcc::name() CONST
{
  return "CPositionAcc";
}


CPositionScheduler::CPositionScheduler(CContainer * p, ni m): CParentScheduler(p, m)
{
  m_acc = NULL;
  msg_queue()->high_water_mark(MQ_MAX);
}

truefalse CPositionScheduler::before_begin()
{
  if (!m_acc)
    m_acc = new CPositionAcc(this, new CHandlerDirector());
  acc_add(m_acc);
  return true;
}

DVOID CPositionScheduler::before_finish()
{
  m_acc = NULL;
}

CONST text * CPositionScheduler::name() CONST
{
  return "CPositionScheduler";
}



CPositionContainer::CPositionContainer(CApp * p): CContainer(p)
{
  m_task = NULL;
  m_scheduler = NULL;
  CPositionProc::m_balance_datas = &m_balance_datas;
}

CPositionContainer::~CPositionContainer()
{

}

CBalanceDatas * CPositionContainer::balance_datas()
{
  return &m_balance_datas;
}

truefalse CPositionContainer::before_begin()
{
  add_task(m_task = new CPositionTask(this, 1));
  add_scheduler(m_scheduler = new CPositionScheduler(this));
  return true;
}

DVOID CPositionContainer::before_finish()
{
  m_task = NULL;
  m_scheduler = NULL;
}

CONST text * CPositionContainer::name() CONST
{
  return "CPositionContainer";
}

CBsReqProc::CBsReqProc(CParentHandler * p): baseclass(p)
{

}

CBsReqProc::~CBsReqProc()
{

}

CONST text * CBsReqProc::name() CONST
{
  return "CBsReqProc";
}

ni CBsReqProc::data_len()
{
  return m_data_head;
}

CProc::OUTPUT CBsReqProc::at_head_arrival()
{
  ni l_x = data_len();
  if (l_x > 1024 * 1024 || l_x <= 32)
  {
    C_ERROR("bad bs req size = %d\n", l_x);
    return OP_FAIL;
  }
  C_INFO("recv bs req len = %d\n", l_x);
  return OP_OK;
}

CProc::OUTPUT CBsReqProc::do_read_data(CMB * v_mb)
{
  C_INFO("BS req full len = %d\n", v_mb->length());
  m_mark_down = true;
  truefalse ok = handle_req();
  CMB * mb = CCacheX::instance()->get_mb(1);
  if (!mb)
  {
    C_ERROR(ACE_TEXT("oom\n"));
    return OP_FAIL;
  }
  *(mb->base()) = (ok? '1':'0');
  mb->wr_ptr(1);
  return (m_handler->post_packet(mb) <= 0 ? OP_FAIL:OP_OK);
}

truefalse CBsReqProc::handle_req()
{
  truefalse l_ret = true;
  CONST text * CONST_task = "http://127.0.0.1:10092/task?";
  CONST text * CONST_prio = "http://127.0.0.1:10092/prio?";
  CONST text * CONST_dist = "http://127.0.0.1:10092/file?";
  ni l_m = -1;
  if (likely(ACE_OS::strncmp(CONST_dist, m_mb->base() + 4, strlen(CONST_dist)) == 0))
    l_m = 1;
  else if (ACE_OS::strncmp(CONST_task, m_mb->base() + 4, strlen(CONST_task)) == 0)
  {
    l_m = 3;
    m_mb->set_self_flags(0x2000);
  }
  else if (ACE_OS::strncmp(CONST_prio, m_mb->base() + 4, strlen(CONST_prio)) == 0)
  {
    truefalse ret = handle_prio(m_mb);
    m_mb->release();
    m_mb = NULL;
    return ret;
  }

  if (l_m == -1)
  {
    m_mb->release();
    m_mb = NULL;
    return false;
  }
  if (likely(l_m == 1 || l_m == 3))
    l_ret = (c_tools_mb_putq(CRunnerX::instance()->http_module()->bs_req_task(), m_mb,
              "CBsReqProc::handle_req"));
  m_mb = NULL;
  return l_ret;
}

truefalse CBsReqProc::handle_prio(CMB * mb)
{
  CONST text CONST_leading[] = "http://127.0.0.1:10092/prio?";
  CONST ni CONST_leading_size = sizeof(CONST_leading) / sizeof(text) - 1;
  ni mb_len = mb->length();
  memmove(mb->base(), mb->base() + 4, mb_len - 4);
  mb->base()[mb_len - 4] = 0;
  if (unlikely((ni)(mb->length()) <= CONST_leading_size + 10))
  {
    C_ERROR("invalid bs req too short\n");
    return false;
  }

  text * l_ptr = mb->base();
  if (memcmp(l_ptr, CONST_leading, CONST_leading_size) != 0)
  {
    C_ERROR("invalid bs req, no %s\n", CONST_leading);
    return false;
  }

  l_ptr += CONST_leading_size;
  CONST text CONST_separator = '&';

  CONST text * CONST_ver = "ver=";
  text * ver = 0;
  if (!c_tools_locate_key_result(l_ptr, CONST_ver, ver, CONST_separator))
  {
    C_ERROR("bad bs req, no %s\n", CONST_ver);
    return false;
  }


  CONST text * CONST_plist = "plist=";
  text * plist = 0;
  if (!c_tools_locate_key_result(l_ptr, CONST_plist, plist, CONST_separator))
  {
    C_ERROR("bad bs req, no %s\n", CONST_plist);
    return false;
  }


  MyDB & db = CRunnerX::instance()->db();
  if (!db.ping_db_server())
  {
    C_ERROR("no connection to db, quitting\n");
    return false;
  }

  C_INFO("prio = %s\n", plist? plist:"NULL");
  return db.save_prio(plist);
}

PREPARE_MEMORY_POOL(CBsReqProc);


CBsReqHandler::CBsReqHandler(CHandlerDirector * p): CParentHandler(p)
{
  m_proc = new CBsReqProc(this);
}

PREPARE_MEMORY_POOL(CBsReqHandler);


CBsReqAcc::CBsReqAcc(CParentScheduler * p1, CHandlerDirector * p2): CParentAcc(p1, p2)
{
  m_tcp_port = CCfgX::instance()->http_port;
  m_reap_interval = BROKEN_DELAY;
}

ni CBsReqAcc::make_svc_handler(CParentHandler *& sh)
{
  sh = new CBsReqHandler(m_director);
  if (!sh)
  {
    C_ERROR("oom\n");
    return -1;
  }
  sh->container((void*)this);
  sh->reactor(reactor());
  return 0;
}

CONST text * CBsReqAcc::name() CONST
{
  return "CBsReqAcc";
}


CBsReqTask::CBsReqTask(CContainer * p, ni m): CTaskBase(p, m)
{
  msg_queue()->high_water_mark(MQ_MAX);
}

ni CBsReqTask::svc()
{
  C_INFO("Start %s::svc()\n", name());
  for (CMB * mb; getq(mb) != -1; )
  {
    process_mb(mb);
    mb->release();
  }
  C_INFO("exiting %s::svc()\n", name());
  return 0;
};

CONST text * CBsReqTask::name() CONST
{
  return "CBsReqTask";
}

truefalse CBsReqTask::analyze_cmd(CMB * mb, CBsDistReq & v_bs_req)
{
  CONST text CONST_header[] = "http://127.0.0.1:10092/file?";
  CONST ni CONST_header_len = sizeof(CONST_header) / sizeof(text) - 1;
  ni l_x = mb->length();
  memmove(mb->base(), mb->base() + 4, l_x - 4);
  mb->base()[l_x - 4] = 0;
  if (unlikely((ni)(mb->length()) <= CONST_header_len + 10))
  {
    C_ERROR("invalid bs req: too short\n");
    return false;
  }

  text * l_ptr = mb->base();
  if (memcmp(l_ptr, CONST_header, CONST_header_len) != 0)
  {
    C_ERROR("invalid bs req: no %s\n", CONST_header);
    return false;
  }

  l_ptr += CONST_header_len;
  CONST text CONST_separator = '&';

  CONST text * CONST_acode = "acode=";
  if (!c_tools_locate_key_result(l_ptr, CONST_acode, v_bs_req.acode, CONST_separator))
  {
    C_ERROR("invalid bs req: no %s\n", CONST_acode);
    return false;
  }

  CONST text * CONST_ftype = "ftype=";
  if (!c_tools_locate_key_result(l_ptr, CONST_ftype, v_bs_req.ftype, CONST_separator))
  {
    C_ERROR("invalid bs req: no %s\n", CONST_ftype);
    return false;
  }

  CONST text * CONST_fdir = "fdir=";
  if (!c_tools_locate_key_result(l_ptr, CONST_fdir, v_bs_req.fdir, CONST_separator))
  {
    C_ERROR("invalid bs req: no %s\n", CONST_fdir);
    return false;
  }

  CONST text * CONST_findex = "findex=";
  if (!c_tools_locate_key_result(l_ptr, CONST_findex, v_bs_req.findex, CONST_separator))
  {
    C_ERROR("invalid bs req: no %s\n", CONST_findex);
    return false;
  }

  CONST text * CONST_adir = "adir=";
  if (!c_tools_locate_key_result(l_ptr, CONST_adir, v_bs_req.adir, CONST_separator))
  {
    C_ERROR("invalid bs req: no %s\n", CONST_adir);
    return false;
  }

  CONST text * CONST_aindex = "aindex=";
  if (!c_tools_locate_key_result(l_ptr, CONST_aindex, v_bs_req.aindex, CONST_separator))
  {
    C_ERROR("invalid bs req: no %s\n", CONST_aindex);
    return false;
  }

  CONST text * CONST_ver = "ver=";
  if (!c_tools_locate_key_result(l_ptr, CONST_ver, v_bs_req.ver, CONST_separator))
  {
    C_ERROR("invalid bs req: no %s\n", CONST_ver);
    return false;
  }

  CONST text * CONST_type = "type=";
  if (!c_tools_locate_key_result(l_ptr, CONST_type, v_bs_req.type, CONST_separator))
  {
    C_ERROR("invalid bs req: no %s\n", CONST_type);
    return false;
  }

  return true;
}

truefalse CBsReqTask::process_mb(CMB * v_mb)
{
  if ((v_mb->self_flags() & 0x2000) == 0)
  {
    CBsDistReq l_bs_req;
    truefalse l_ret = process_mb_i(v_mb, l_bs_req);
    if (unlikely(!l_ret && !l_bs_req.is_ok(true)))
      return false;
    ni l_all;
    text tmp[32];
    c_tools_convert_time_to_text(tmp, 32, true);
    l_all = strlen(tmp) + strlen(l_bs_req.ver) + 8;
    CMB * mb = CCacheX::instance()->get_mb_bs(l_all, CONST_BS_DIST_FEEDBACK_CMD);
    text * l_ptr = mb->base() + CBSData::DATA_OFFSET;
    sprintf(l_ptr, "%s#%c##1#%c#%s", l_bs_req.ver, *l_bs_req.ftype,
        l_ret? '1':'0', tmp);
    l_ptr[l_all] = CBSData::END_MARK;
    CRunnerX::instance()->dist_load_module()->scheduler()->post_bs(mb);

    return l_ret;
  } else
  {
    return process_mb_i2(v_mb);
  }
}

truefalse CBsReqTask::process_mb_i(CMB * mb, CBsDistReq & v_bs_req)
{
  if (!analyze_cmd(mb, v_bs_req))
    return false;

  if (!v_bs_req.is_ok(true))
    return false;

  text key[12];
  c_tools_create_rnd_text(key, 12);
  v_bs_req.password = key;
  MyDB & l_database = CRunnerX::instance()->db();

  if (unlikely(!container()->working_app()))
    return false;

  if (!process_comp(v_bs_req))
    return false;

  if (unlikely(!container()->working_app()))
    return false;

  CMemProt l_cs;
  {
    CChecksumComputer l_cs_computer;
    ni md5_len;
    if (!l_cs_computer.compute(v_bs_req, l_cs, md5_len))
      return false;
  }

  if (unlikely(!container()->working_app()))
    return false;

  CMemProt l_single_cs;
  {
    if (!CChecksumComputer::compute_single_cs(v_bs_req.ver, l_single_cs))
      return false;
  }

  if (!l_database.ping_db_server())
  {
    C_ERROR("lost db con, no more proc of dist %s\n", v_bs_req.ver);
    return false;
  }

  if (!l_database.save_dist(v_bs_req, l_cs.get_ptr(), l_single_cs.get_ptr()))
  {
    C_ERROR("can not save_dist to db\n");
    return false;
  }

  if (!l_database.save_dist_clients(v_bs_req.acode, v_bs_req.adir, v_bs_req.ver))
  {
    C_ERROR("can not save_dist_clients to db\n");
    return false;
  }

  if (unlikely(!container()->working_app()))
    return false;

  if (!l_database.dist_info_update_status())
  {
    C_ERROR("call to dist_info_update_status() failed\n");
    return false;
  }

  l_database.remove_orphan_dist_info();

  tell_dists();

  CObsoleteDirDeleter x;
  if (l_database.get_dist_ids(x))
    x.work(CCfgX::instance()->bz_files_path.c_str());

  return true;
}

truefalse CBsReqTask::process_mb_i2(CMB * mb)
{
  CONST text CONST_header[] = "http://127.0.0.1:10092/task?";
  CONST ni CONST_header_len = sizeof(CONST_header) / sizeof(text) - 1;
  ni l_m = mb->length();
  memmove(mb->base(), mb->base() + 4, l_m - 4);
  mb->base()[l_m - 4] = 0;
  if (unlikely((ni)(mb->length()) <= CONST_header_len + 10))
  {
    C_ERROR("invalid bs req too short\n");
    return false;
  }

  text * l_ptr = mb->base();
  if (memcmp(l_ptr, CONST_header, CONST_header_len) != 0)
  {
    C_ERROR("invalid bs req: no (%s)\n", CONST_header);
    return false;
  }

  l_ptr += CONST_header_len;
  CONST text CONST_separator = '&';

  CONST text * CONST_ver = "ver=";
  text * ver = 0;
  if (!c_tools_locate_key_result(l_ptr, CONST_ver, ver, CONST_separator))
  {
    C_ERROR("invalid bs req: no %s\n", CONST_ver);
    return false;
  }


  CONST text * CONST_cmd = "cmd=";
  text * cmd = 0;
  if (!c_tools_locate_key_result(l_ptr, CONST_cmd, cmd, CONST_separator))
  {
    C_ERROR("invalid bs req: no %s\n", CONST_cmd);
    return false;
  }

  CONST text * CONST_backid = "backid=";
  text * backid = 0;
  if (!c_tools_locate_key_result(l_ptr, CONST_backid, backid, CONST_separator))
  {
    C_ERROR("invalid bs req: no %s\n", CONST_backid);
    return false;
  }

  CONST text * CONST_acode = "acode=";
  text * acode = 0;
  if (!c_tools_locate_key_result(l_ptr, CONST_acode, acode, CONST_separator))
  {
    C_ERROR("invalid bs req: no %s\n", CONST_acode);
    return false;
  }

  MyDB & l_database = CRunnerX::instance()->db();
  if (!l_database.ping_db_server())
  {
    C_ERROR("lost db con\n");
    return false;
  }

  l_database.save_sr(backid, cmd, acode);
  if (!l_database.dist_info_update_status())
  {
    C_ERROR("call to dist_info_update_status() failed\n");
    return false;
  }

  tell_dists();
  return true;
}

truefalse CBsReqTask::process_comp(CBsDistReq & v_x)
{
  CCompFactory l_x;
  return l_x.do_comp(v_x);
}

truefalse CBsReqTask::compute_checksum(CBsDistReq & v_x)
{
  CChecksumComputer obj;
  CMemProt prot;
  ni l_x;
  return obj.compute(v_x, prot, l_x);
}

truefalse CBsReqTask::tell_dists()
{
  CMB * mb = CCacheX::instance()->get_mb_cmd(0, CCmdHeader::PT_HAVE_DIST_TASK);
  return c_tools_mb_putq(CRunnerX::instance()->dist_load_module()->scheduler(), mb, "dist work");
}



CBsReqScheduler::CBsReqScheduler(CContainer * p, ni m): CParentScheduler(p, m)
{
  m_acc = NULL;
}

CONST text * CBsReqScheduler::name() CONST
{
  return "CBsReqScheduler";
}

DVOID CBsReqScheduler::before_finish()
{
  m_acc = NULL;
}

truefalse CBsReqScheduler::before_begin()
{
  if (!m_acc)
    m_acc = new CBsReqAcc(this, new CHandlerDirector());
  acc_add(m_acc);
  return true;
}


CBsReqContainer::CBsReqContainer(CApp * ptr): CContainer(ptr)
{
  m_scheduler = NULL;
  m_bs_req_task = NULL;
}

CBsReqContainer::~CBsReqContainer()
{

}

CONST text * CBsReqContainer::name() CONST
{
  return "CBsReqContainer";
}

CBsReqTask * CBsReqContainer::bs_req_task()
{
  return m_bs_req_task;
}

truefalse CBsReqContainer::before_begin()
{
  add_task(m_bs_req_task = new CBsReqTask(this, 1));
  add_scheduler(m_scheduler = new CBsReqScheduler(this));
  return true;
}

DVOID CBsReqContainer::before_finish()
{
  m_scheduler = NULL;
  m_bs_req_task = NULL;
}


CBalanceProc::CBalanceProc(CParentHandler * p): CParentServerProc(p)
{
  m_term_sn_check_done = false;
  m_balance_datas = NULL;
  m_handler->msg_queue()->high_water_mark(MQ_MAX);
}

CBalanceProc::~CBalanceProc()
{

}

CONST text * CBalanceProc::name() CONST
{
  return "CBalanceProc";
}

DVOID CBalanceProc::balance_datas(CBalanceDatas * ptr)
{
  m_balance_datas = ptr;
}

CProc::OUTPUT CBalanceProc::at_head_arrival()
{
  if (baseclass::at_head_arrival() == OP_FAIL)
    return OP_FAIL;

  if (m_data_head.cmd == CCmdHeader::PT_VER_REQ)
  {
    if (!c_packet_check_term_ver_req(&m_data_head))
    {
      CMemProt l_x;
      get_sinfo(l_x);
      C_ERROR("bad client version check req packet received from %s\n", l_x.get_ptr());
      return OP_FAIL;
    }
    return OP_OK;
  }

  if (m_data_head.cmd == CCmdHeader::PT_LOAD_BALANCE_REQ)
  {
    if (!c_packet_check_load_balance_req(&m_data_head))
    {
      CMemProt l_x;
      get_sinfo(l_x);
      C_ERROR("bad load_balance packet received from %s\n", l_x.get_ptr());
      return OP_FAIL;
    }
    return OP_OK;
  }

  C_ERROR("get unknown header @CBalanceProc.at_head_arrival, cmd = %d\n", m_data_head.cmd);
  return OP_FAIL;
}

CProc::OUTPUT CBalanceProc::do_read_data(CMB * mb)
{
  CParentServerProc::do_read_data(mb);
  CMBProt prot(mb);

  CCmdHeader * l_ptr = (CCmdHeader *)mb->base();
  if (l_ptr->cmd == CCmdHeader::PT_VER_REQ)
    return term_ver_validate(mb);

  if (l_ptr->cmd == CCmdHeader::PT_LOAD_BALANCE_REQ)
    return handle_balance(mb);

  C_ERROR("get unknown cmd @CBalanceProc::do_read_data, command = %d\n",
      l_ptr->cmd);
  return OP_FAIL;
}

CProc::OUTPUT CBalanceProc::term_ver_validate(CMB * mb)
{
  CTerminalVerReq * p = (CTerminalVerReq *) mb->base();
  m_term_sn = "DistServer";
  truefalse l_x = (p->term_sn == CCfgX::instance()->skey.c_str());
  if (!l_x)
  {
    CMemProt x;
    get_sinfo(x);
    C_ERROR("bad load_balance version check (bad key) received from %s\n", x.get_ptr());
    return OP_FAIL;
  }
  m_term_sn_check_done = true;

  CMB * mb2 = i_create_mb_ver_reply(CTermVerReply::SC_OK);
  return (m_handler->post_packet(mb2) < 0 ? OP_FAIL: OP_OK);
}

truefalse CBalanceProc::term_sn_check_done() CONST
{
  return m_term_sn_check_done;
}

CProc::OUTPUT CBalanceProc::handle_balance(CMB * mb)
{
  CLoadBalanceReq * l_x = (CLoadBalanceReq *)mb->base();
  CBalanceData dl;
  dl.set_load(l_x->load);
  dl.set_ip(l_x->ip);
  m_balance_datas->refresh(dl);
  return OP_OK;
}



CBalanceHandler::CBalanceHandler(CHandlerDirector * p): CParentHandler(p)
{
  m_proc = new CBalanceProc(this);
}

DVOID CBalanceHandler::balance_datas(CBalanceDatas * p)
{
  ((CBalanceProc*)m_proc)->balance_datas(p);
}

PREPARE_MEMORY_POOL(CBalanceHandler);



CBalanceAcc::CBalanceAcc(CParentScheduler * p1, CHandlerDirector * p2): CParentAcc(p1, p2)
{
  m_tcp_port = CCfgX::instance()->server_port;
  m_reap_interval = REAP_DELAY;
}

ni CBalanceAcc::make_svc_handler(CParentHandler *& sh)
{
  sh = new CBalanceHandler(m_director);
  if (!sh)
  {
    C_ERROR("oom\n");
    return -1;
  }
  sh->container((void*)this);
  sh->reactor(reactor());
  ((CBalanceHandler*)sh)->balance_datas(CRunnerX::instance()->location_module()->balance_datas());
  return 0;
}

CONST text * CBalanceAcc::name() CONST
{
  return "CBalanceAcc";
}


CBalanceScheduler::CBalanceScheduler(CContainer * p, ni m): CParentScheduler(p, m)
{
  m_acc = NULL;
  m_bs_conn = NULL;
  msg_queue()->high_water_mark(MQ_MAX);
}

CBalanceScheduler::~CBalanceScheduler()
{
  ACE_Time_Value l_x(ACE_Time_Value::zero);
  ni l_m = 0;
  for (CMB * mb; m_bs_mq.dequeue(mb, &l_x) != -1; )
  {
    ++l_m;
    mb->release();
  }
}

CONST text * CBalanceScheduler::name() CONST
{
  return "CBalanceScheduler";
}

DVOID CBalanceScheduler::post_bs(CMB * mb)
{
  ACE_Time_Value l_x(ACE_Time_Value::zero);
  if (m_bs_mq.enqueue(mb, &l_x) < 0)
  {
    C_ERROR("post to bs failed, %s\n", (CONST char*)CSysError());
    mb->release();
  }
}

ni CBalanceScheduler::handle_timeout(CONST ACE_Time_Value &, CONST DVOID *)
{
  CRunnerX::instance()->location_module()->balance_datas()->check_broken();
  return 0;
}

DVOID CBalanceScheduler::before_finish()
{
  m_acc = NULL;
  m_bs_conn = NULL;
  reactor()->cancel_timer(this);
}

truefalse CBalanceScheduler::before_begin()
{
  if (!m_acc)
    m_acc = new CBalanceAcc(this, new CHandlerDirector());
  acc_add(m_acc);
  if (!m_bs_conn)
    m_bs_conn = new MyMiddleToBSConnector(this, new CHandlerDirector());
  conn_add(m_bs_conn);

  ACE_Time_Value l_x(ni(CBalanceDatas::BROKEN_INTERVAL * 60 / CApp::CLOCK_TIME / 2));
  if (reactor()->schedule_timer(this, 0, l_x, l_x) == -1)
  {
    C_ERROR("fail to setup timer: balance check\n");
    return false;
  }
  return true;
}

truefalse CBalanceScheduler::do_schedule_work()
{
  ACE_Time_Value tv(ACE_Time_Value::zero);
  CMB * mb;
  CONST ni CONST_peak_num = 10;
  ni i = 0;
  while (++i < CONST_peak_num && this->getq(mb, &tv) != -1)
    m_acc->director()->post_all(mb);

  i = 0;
  while (++i < CONST_peak_num && m_bs_mq.dequeue(mb, &tv) != -1)
    m_bs_conn->director()->post_all(mb);

  return true;
}


CBalanceContainer::CBalanceContainer(CApp * ptr): CContainer(ptr)
{
  m_scheduler = NULL;
}

CBalanceContainer::~CBalanceContainer()
{

}

CONST text * CBalanceContainer::name() CONST
{
  return "CBalanceContainer";
}

CBalanceScheduler * CBalanceContainer::scheduler() CONST
{
  return m_scheduler;
}

truefalse CBalanceContainer::before_begin()
{
  add_scheduler(m_scheduler = new CBalanceScheduler(this));
  return true;
}

DVOID CBalanceContainer::before_finish()
{
  m_scheduler = NULL;
}


//m->bs

MyMiddleToBSProcessor::MyMiddleToBSProcessor(CParentHandler * handler): baseclass(handler)
{

}

CONST text * MyMiddleToBSProcessor::name() CONST
{
  return "MyMiddleToBSProcessor";
}

CProc::OUTPUT MyMiddleToBSProcessor::do_read_data(CMB * mb)
{
  if (mb)
    mb->release();
  ((MyMiddleToBSHandler*)m_handler)->checker_update();
  return OP_OK;
}

PREPARE_MEMORY_POOL(MyMiddleToBSProcessor);


//MyMiddleToBSHandler//

MyMiddleToBSHandler::MyMiddleToBSHandler(CHandlerDirector * xptr): CParentHandler(xptr)
{
  m_proc = new MyMiddleToBSProcessor(this);
}

CBalanceContainer * MyMiddleToBSHandler::module_x() CONST
{
  return (CBalanceContainer *)connector()->container();
}

DVOID MyMiddleToBSHandler::checker_update()
{
  m_checker.refresh();
}

ni MyMiddleToBSHandler::handle_timeout(CONST ACE_Time_Value &, CONST DVOID *)
{
  if (m_checker.overdue())
  {
    C_ERROR("no data received from bs @MyMiddleToBSHandler ...\n");
    return -1;
  }
  CMB * mb = c_create_hb_mb();
  if (mb)
  {
    if (post_packet(mb) < 0)
      return -1;
  }
  return 0;
}

ni MyMiddleToBSHandler::at_start()
{
  ACE_Time_Value interval(30);
  if (reactor()->schedule_timer(this, (void*)0, interval, interval) < 0)
  {
    C_ERROR(ACE_TEXT("MyMiddleToBSHandler setup timer failed, %s"), (CONST char*)CSysError());
    return -1;
  }

  if (!g_is_test)
    C_INFO("MyMiddleToBSHandler setup timer: OK\n");

  CMB * mb = c_create_hb_mb();
  if (mb)
  {
    if (post_packet(mb) < 0)
      return -1;
  }
  m_checker.refresh();

  return 0;
}


DVOID MyMiddleToBSHandler::at_finish()
{

}

PREPARE_MEMORY_POOL(MyMiddleToBSHandler);


//MyMiddleToBSConnector//

MyMiddleToBSConnector::MyMiddleToBSConnector(CParentScheduler * _dispatcher, CHandlerDirector * _manager):
    CParentConn(_dispatcher, _manager)
{
  m_port_of_ip = CCfgX::instance()->bs_port;
  m_retry_delay = RECONNECT_INTERVAL;
  m_remote_ip = CCfgX::instance()->bs_addr;
}

CONST text * MyMiddleToBSConnector::name() CONST
{
  return "MyMiddleToBSConnector";
}

ni MyMiddleToBSConnector::make_svc_handler(CParentHandler *& sh)
{
  sh = new MyMiddleToBSHandler(m_director);
  if (!sh)
  {
    C_ERROR("can not alloc MyMiddleToBSHandler from %s\n", name());
    return -1;
  }
  sh->container((void*)this);
  sh->reactor(reactor());
  return 0;
}

//!//dist component

//MyDistClient//

MyDistClient::MyDistClient(CBsDistData * _dist_info, MyDistClientOne * _dist_one)
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
  if (unlikely(!dist_info->have_checksum()))
  {
    C_WARNING("got unexpected md5 reply packet on client_id(%s) dist_id(%s)\n",
        client_id(), dist_info->ver.get_ptr());
    return;
  }

  if (unlikely(md5.get_ptr() && md5.get_ptr()[0]))
    return;

  md5.init(_md5);
  update_status(2);
}

DVOID MyDistClient::send_fb_detail(truefalse ok)
{
  CMB * mb = make_ftp_fb_detail_mb(ok);
  CRunnerX::instance()->dist_to_middle_module()->send_to_bs(mb);
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
    c_tools_convert_time_to_text(buff, 50, true);
    CRunnerX::instance()->ping_component()->ftp_feedback_submitter().add(
        dist_info->ver.get_ptr(),
        dist_info->ftype[0],
        client_id(),
        '2', '1', buff);

    CRunnerX::instance()->ping_component()->ftp_feedback_submitter().add(
        dist_info->ver.get_ptr(),
        dist_info->ftype[0],
        client_id(),
        '3', '1', buff);

    CRunnerX::instance()->ping_component()->ftp_feedback_submitter().add(
        dist_info->ver.get_ptr(),
        dist_info->ftype[0],
        client_id(),
        '4', '1', buff);

    send_fb_detail(true);

    dist_one->delete_dist_client(this);
//    MyServerAppX::instance()->db().set_dist_client_status(*this, 5);
//    update_status(5);
    return;
  }

  if (!md5.get_ptr() || !md5.get_ptr()[0])
  {
    update_md5_list(md5list);
    CRunnerX::instance()->db().set_dist_client_md5(client_id(), dist_info->ver.get_ptr(), md5list, 2);
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
  if (dist_info->have_checksum())
  {
    if(send_md5())
    {
      CRunnerX::instance()->db().set_dist_client_status(*this, 1);
      update_status(1);
    }
    return true;
  }

  if (send_ftp())
  {
    CRunnerX::instance()->db().set_dist_client_status(*this, 3);
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
  if (!mbz_file.get_ptr() || !mbz_file.get_ptr()[0])
  {
    if ((dist_info->md5_opt_len > 0 && (ni)strlen(md5.get_ptr()) >= dist_info->md5_opt_len) || !generate_diff_mbz())
    {
      mbz_file.init(CCompFactory::single_fn());
      mbz_md5.init(dist_info->mbz_md5.get_ptr());
    }
    CRunnerX::instance()->db().set_dist_client_mbz(client_id(), dist_info->ver.get_ptr(), mbz_file.get_ptr(), mbz_md5.get_ptr());
  }

  if (send_ftp())
  {
    CRunnerX::instance()->db().set_dist_client_status(*this, 3);
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
  ni adir_len = adir.get_ptr() ? strlen(adir.get_ptr()) : (ni)CCmdHeader::ITEM_NULL_SIZE;
  ni aindex_len = dist_info->aindex_len > 0 ? dist_info->aindex_len : (ni)CCmdHeader::ITEM_NULL_SIZE;
  return dist_info->ver_len + dist_info->findex_len + aindex_len + adir_len + 4 + 2 + 2;
}

DVOID MyDistClient::dist_out_leading_data(text * data)
{
  sprintf(data, "%s%c%s%c%s%c%s%c%c%c%c%c",
      dist_info->ver.get_ptr(), CCmdHeader::ITEM_SEPARATOR,
      dist_info->findex.get_ptr(), CCmdHeader::ITEM_SEPARATOR,
      adir.get_ptr()? adir.get_ptr(): Item_NULL, CCmdHeader::ITEM_SEPARATOR,
      dist_info->aindex.get_ptr()? dist_info->aindex.get_ptr(): Item_NULL, CCmdHeader::ITEM_SEPARATOR,
      dist_info->ftype[0], CCmdHeader::ITEM_SEPARATOR,
      dist_info->type[0], CCmdHeader::FINISH_SEPARATOR);
}

CMB * MyDistClient::make_ftp_fb_detail_mb(truefalse bok)
{
  CMemProt md5_new;
  text buff[32];
  c_tools_convert_time_to_text(buff, 32, true);
  CONST text * detail_files;
  if (c_tell_type_multi(dist_info->type[0]))
  {
    if (!md5.get_ptr())
      detail_files = "";
    else
    {
      md5_new.init(md5.get_ptr());
      c_tools_text_replace(md5_new.get_ptr(), CCmdHeader::ITEM_SEPARATOR, ':');
      ni len = strlen(md5_new.get_ptr());
      if (md5_new.get_ptr()[len - 1] == ':')
        md5_new.get_ptr()[len - 1] = 0;
      detail_files = md5_new.get_ptr();
    }
  }
  else
    detail_files = dist_info->findex.get_ptr();

  ni total_len = strlen(dist_one->client_id()) + strlen(dist_info->ver.get_ptr()) +
      strlen(buff) + strlen(dist_info->findex.get_ptr()) + strlen(detail_files) +
      10;
  //batNO, fileKindCode, agentCode, indexName, fileName, type,flag, date
  CMB * mb = CCacheX::instance()->get_mb_bs(total_len, CONST_BS_DIST_FBDETAIL_CMD);
  text * dest = mb->base() + CBSData::DATA_OFFSET;
  sprintf(dest, "%s#%c#%s#%s#%s#%c#%c#%s",
      dist_info->ver.get_ptr(),
      dist_info->ftype[0],
      dist_one->client_id(),
      dist_info->findex.get_ptr(),
      detail_files,
      dist_info->type[0],
      bok? '1': '0',
      buff);
  dest[total_len] = CBSData::END_MARK;
  return mb;
}

truefalse MyDistClient::send_md5()
{
  if (!dist_info->md5.get_ptr() || !dist_info->md5.get_ptr()[0] || dist_info->md5_len <= 0)
    return false;

  ni md5_len = dist_info->md5_len + 1;
  ni data_len = dist_out_leading_length() + md5_len;
  CMB * mb = CCacheX::instance()->get_mb_cmd(data_len, CCmdHeader::PT_FILE_MD5_LIST);
  CCmdExt * md5_packet = (CCmdExt *)mb->base();
  md5_packet->signature = client_id_index();
  dist_out_leading_data(md5_packet->data);
  memcpy(md5_packet->data + data_len - md5_len, dist_info->md5.get_ptr(), md5_len);

  last_update = time(NULL);

  return c_tools_mb_putq(CRunnerX::instance()->ping_component()->dispatcher(), mb, "file md5 list to dispatcher's queue");
}

truefalse MyDistClient::generate_diff_mbz()
{
  CMemProt destdir;
  CMemProt composite_dir;
  CMemProt mdestfile;
  destdir.init(CCfgX::instance()->bz_files_path.c_str(), "/", dist_info->ver.get_ptr());
  composite_dir.init(destdir.get_ptr(), "/", CCompFactory::dir_of_composite());
  mdestfile.init(composite_dir.get_ptr(), "/", client_id(), ".mbz");
  CCompUniter compositor;
  if (!compositor.begin(mdestfile.get_ptr()))
    return false;
  CMemProt md5_copy;
  md5_copy.init(md5.get_ptr());
  text separators[2] = { CCmdHeader::ITEM_SEPARATOR, 0 };
  CTextDelimiter tokenizer(md5_copy.get_ptr(), separators);
  text * token;
  CMemProt filename;
  while ((token =tokenizer.get()) != NULL)
  {
    filename.init(destdir.get_ptr(), "/", token, ".mbz");
    if (!compositor.append(filename.get_ptr()))
    {
      CSysFS::remove(mdestfile.get_ptr());
      return false;
    }
  }

  CMemProt md5_result;
  if (!c_tools_tally_md5(mdestfile.get_ptr(), md5_result))
  {
    C_ERROR("failed to calculate md5 for file %s\n", mdestfile.get_ptr());
    CSysFS::remove(mdestfile.get_ptr());
    return false;
  }

  mbz_file.init(mdestfile.get_ptr() + strlen(destdir.get_ptr()) + 1);
  mbz_md5.init(md5_result.get_ptr());
  return true;
}

truefalse MyDistClient::send_psp(CONST text c)
{
  ni data_len = dist_info->ver_len + 2;
  CMB * mb = CCacheX::instance()->get_mb_cmd(data_len, CCmdHeader::PT_PSP);
  CCmdExt * dpe = (CCmdExt *)mb->base();
  dpe->signature = client_id_index();
  dpe->data[0] = c;
  memcpy(dpe->data + 1, dist_info->ver.get_ptr(), data_len - 1);
  last_update = time(NULL);
  return c_tools_mb_putq(CRunnerX::instance()->ping_component()->dispatcher(), mb, "psp to dispatcher's queue");
}

truefalse MyDistClient::send_ftp()
{
  CONST text * ftp_file_name;
  CONST text * _mbz_md5;

  if (!dist_info->have_checksum())
  {
    ftp_file_name = CCompFactory::single_fn();
    _mbz_md5 = dist_info->mbz_md5.get_ptr();
  } else
  {
    ftp_file_name = mbz_file.get_ptr();
    _mbz_md5 = mbz_md5.get_ptr();
  }

  ni _mbz_md5_len = strlen(_mbz_md5) + 1;
  ni leading_length = dist_out_leading_length();
  ni ftp_file_name_len = strlen(ftp_file_name) + 1;
  ni data_len = leading_length + ftp_file_name_len + dist_info->password_len + 1 + _mbz_md5_len;
  CMB * mb = CCacheX::instance()->get_mb_cmd(data_len, CCmdHeader::PT_FTP_FILE);
  CCmdExt * packet = (CCmdExt *)mb->base();
  packet->signature = client_id_index();
  dist_out_leading_data(packet->data);
  text * ptr = packet->data + leading_length;
  memcpy(ptr, ftp_file_name, ftp_file_name_len);
  ptr += ftp_file_name_len;
  *(ptr - 1) = CCmdHeader::ITEM_SEPARATOR;
  memcpy(ptr, _mbz_md5, _mbz_md5_len);
  ptr += _mbz_md5_len;
  *(ptr - 1) = CCmdHeader::FINISH_SEPARATOR;
  memcpy(ptr, dist_info->password.get_ptr(), dist_info->password_len + 1);

  last_update = time(NULL);

  return c_tools_mb_putq(CRunnerX::instance()->ping_component()->dispatcher(), mb, "file md5 list to dispatcher's queue");
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
  return m_client_id.to_str();
}

ni MyDistClientOne::client_id_index() CONST
{
  return m_client_id_index;
}

truefalse MyDistClientOne::active()
{
  truefalse switched;
  return g_term_sns->connected(m_client_id, m_client_id_index, switched);
}

truefalse MyDistClientOne::is_client_id(CONST text * _client_id) CONST
{
  return strcmp(m_client_id.to_str(), _client_id) == 0;
}

MyDistClient * MyDistClientOne::create_dist_client(CBsDistData * _dist_info)
{
  DVOID * p = CCacheX::instance()->get_raw(sizeof(MyDistClient));
  MyDistClient * result = new (p) MyDistClient(_dist_info, this);
  m_client_ones.push_back(result);
  m_dist_clients->on_create_dist_client(result);
  return result;
}

DVOID MyDistClientOne::delete_dist_client(MyDistClient * dc)
{
  m_dist_clients->on_remove_dist_client(dc, false);
  m_client_ones.remove(dc);
  CRunnerX::instance()->db().delete_dist_client(m_client_id.to_str(), dc->dist_info->ver.get_ptr());
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
  if (!g_term_sns->connected(m_client_id, m_client_id_index, switched))
    return !m_client_ones.empty();

  MyDistClientOneList::iterator it;

  if (unlikely(switched))
  {
    g_term_sns->server_changed(m_client_id_index, false);
    for (it = m_client_ones.begin(); it != m_client_ones.end(); ++it)
      m_dist_clients->on_remove_dist_client(*it, false);
    clear();
    CRunnerX::instance()->db().load_dist_clients(m_dist_clients, this);
    C_DEBUG("reloading client one db for client id (%s)\n", m_client_id.to_str());
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

MyDistClients::MyDistClients(CBsDistDatas * dist_infos)
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
     (MyClientMapKey(dc->dist_info->ver.get_ptr(), dc->client_id()), dc));
}

DVOID MyDistClients::on_remove_dist_client(MyDistClient * dc, truefalse finished)
{
  if (finished)
    ++m_dist_client_finished;
  m_dist_clients_map.erase(MyClientMapKey(dc->dist_info->ver.get_ptr(), dc->client_id()));
}

CBsDistData * MyDistClients::find_dist_info(CONST text * dist_id)
{
  C_ASSERT_RETURN(m_dist_infos, "", NULL);
  return m_dist_infos->search(dist_id);
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
  DVOID * p = CCacheX::instance()->get_raw(sizeof(MyDistClientOne));
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
     m_dist_infos->size(),  m_dist_client_ones_map.size(), m_dist_clients_map.size());
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

  if (CRunnerX::instance()->ping_component())
    CRunnerX::instance()->ping_component()->pl();

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
    m_dist_infos.alloc_spaces(0);
    return (CRunnerX::instance()->db().load_dist_infos(m_dist_infos) < 0)? false:true;
  }

  return true;
}

truefalse MyClientFileDistributor::check_dist_clients(truefalse reload)
{
  if (reload)
  {
    m_dist_clients.clear();
    if (!CRunnerX::instance()->db().load_dist_clients(&m_dist_clients, NULL))
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
    CRunnerX::instance()->db().set_dist_client_status(client_id, dist_id, _status);
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

MyHeartBeatProcessor::MyHeartBeatProcessor(CParentHandler * handler): CParentServerProc(handler)
{
  m_handler->msg_queue()->high_water_mark(MSG_QUEUE_MAX_SIZE);
  m_hw_ver[0] = 0;
}

CONST text * MyHeartBeatProcessor::name() CONST
{
  return "MyHeartBeatProcessor";
}

CProc::OUTPUT MyHeartBeatProcessor::at_head_arrival()
{
//  {
//    MyPooledMemProt info;
//    get_sinfo(info);
//    if (m_data_head.command != MyDataPacketHeader::CMD_HEARTBEAT_PING)
//      C_DEBUG("get client packet header: command = %d, len = %d from %s\n",
//          m_data_head.command, m_data_head.length, info.data());
//  }

  if (baseclass::at_head_arrival() == OP_FAIL)
    return OP_FAIL;

  if (m_data_head.cmd == CCmdHeader::PT_PING)
  {
    if (!c_packet_check_ping(&m_data_head))
    {
      CMemProt info;
      get_sinfo(info);
      C_ERROR("bad heart beat packet received from %s\n", info.get_ptr());
      return OP_FAIL;
    }

    //the thread context switching and synchronization cost outbeat the benefit of using another thread
    do_ping();
    return OP_DONE;
  }

  if (m_data_head.cmd == CCmdHeader::PT_VER_REQ)
  {
    if (!c_packet_check_term_ver_req(&m_data_head, 30))
    {
      CMemProt info;
      get_sinfo(info);
      C_ERROR("bad client version check req packet received from %s\n", info.get_ptr());
      return OP_FAIL;
    }
    return OP_OK;
  }

  if (m_data_head.cmd == CCmdHeader::PT_VLC_EMPTY)
  {
    if (!c_packet_check_vlc_empty(&m_data_head))
    {
      CMemProt info;
      get_sinfo(info);
      C_ERROR("bad client vlc empty req packet received from %s\n", info.get_ptr());
      return OP_FAIL;
    }
    return OP_OK;
  }


  if (m_data_head.cmd == CCmdHeader::PT_HARDWARE_ALARM)
  {
    if (!c_packet_check_plc_alarm(&m_data_head))
    {
      CMemProt info;
      get_sinfo(info);
      C_ERROR("bad hardware alarm request packet received from %s\n", info.get_ptr());
      return OP_FAIL;
    }
    C_DEBUG("get hardware alarm packet from %s\n", m_term_sn.to_str());
    return OP_OK;
  }

  if (m_data_head.cmd == CCmdHeader::PT_FILE_MD5_LIST)
  {
    if (!c_packet_check_file_md5_list(&m_data_head))
    {
      CMemProt info;
      get_sinfo(info);
      C_ERROR("bad md5 file list packet received from %s\n", info.get_ptr());
      return OP_FAIL;
    } else
    {
      CMemProt info;
      get_sinfo(info);
      C_INFO("get md5 file list packet received from %s, len = %d\n", info.get_ptr(), m_data_head.size);
    }
    return OP_OK;
  }

  if (m_data_head.cmd == CCmdHeader::PT_FTP_FILE)
  {
    if (!c_packet_check_ftp_file(&m_data_head))
    {
      CMemProt info;
      get_sinfo(info);
      C_ERROR("bad file ftp packet received from %s\n", info.get_ptr());
      return OP_FAIL;
    }
    return OP_OK;
  }

  if (m_data_head.cmd == CCmdHeader::PT_IP_VER_REQ)
  {
    if (m_data_head.size != sizeof(CIpVerReq) || m_data_head.signature != CCmdHeader::SIGNATURE)
    {
      CMemProt info;
      get_sinfo(info);
      C_ERROR("bad ip ver request packet received from %s\n", info.get_ptr());
      return OP_FAIL;
    }
    return OP_OK;
  }

  if (m_data_head.cmd == CCmdHeader::PT_ADV_CLICK)
  {
    if (m_data_head.size <= (ni)sizeof(CCmdHeader)
        || m_data_head.size >= 1 * 1024 * 1024
        || m_data_head.signature != CCmdHeader::SIGNATURE)
    {
      CMemProt info;
      get_sinfo(info);
      C_ERROR("bad adv click request packet received from %s\n", info.get_ptr());
      return OP_FAIL;
    }
    return OP_OK;
  }

  if (m_data_head.cmd == CCmdHeader::PT_VLC)
  {
    if (m_data_head.size <= (ni)sizeof(CCmdHeader)
        || m_data_head.size >= 1 * 1024 * 1024
        || m_data_head.signature != CCmdHeader::SIGNATURE)
    {
      CMemProt info;
      get_sinfo(info);
      C_ERROR("bad vlc request packet received from %s\n", info.get_ptr());
      return OP_FAIL;
    }

    return OP_OK;
  }


  if (m_data_head.cmd == CCmdHeader::PT_PC_ON_OFF)
  {
    if (m_data_head.size < (ni)sizeof(CCmdHeader) + 15 + 1 + 1
        || m_data_head.size > (ni)sizeof(CCmdHeader) + 30
        || m_data_head.signature != CCmdHeader::SIGNATURE)
    {
      CMemProt info;
      get_sinfo(info);
      C_ERROR("bad pc on off request packet received from %s\n", info.get_ptr());
      return OP_FAIL;
    }
    C_DEBUG("get pc on off packet from %s\n", m_term_sn.to_str());
    return OP_OK;
  }

  if (m_data_head.cmd == CCmdHeader::PT_TEST)
  {
    if (m_data_head.signature != CCmdHeader::SIGNATURE)
    {
      CMemProt info;
      get_sinfo(info);
      C_ERROR("bad test packet received from %s\n", info.get_ptr());
      return OP_FAIL;
    }
    return OP_OK;
  }

  if (m_data_head.cmd == CCmdHeader::PT_PSP)
  {
    if (m_data_head.size < (ni)sizeof(CCmdHeader) + 10
        || m_data_head.size > (ni)sizeof(CCmdHeader) + 60
        || m_data_head.signature != CCmdHeader::SIGNATURE)
    {
      CMemProt info;
      get_sinfo(info);
      C_ERROR("bad psp packet received from %s\n", info.get_ptr());
      return OP_FAIL;
    }
    return OP_OK;
  }


  C_ERROR(ACE_TEXT("unexpected packet header received @MyHeartBeatProcessor.at_head_arrival, cmd = %d\n"),
      m_data_head.cmd);

  return OP_FAIL;
}

CProc::OUTPUT MyHeartBeatProcessor::do_read_data(CMB * mb)
{
  CParentServerProc::do_read_data(mb);

  {
    CMemProt info;
    get_sinfo(info);
    C_DEBUG("get complete client packet: command = %d, len = %d from %s\n",
        m_data_head.cmd, m_data_head.size, info.get_ptr());
  }

  CCmdHeader * header = (CCmdHeader *)mb->base();
  if (header->cmd == CCmdHeader::PT_VER_REQ)
    return do_version_check(mb);

  if (header->cmd == CCmdHeader::PT_VLC_EMPTY)
    return do_vlc_empty_req(mb);

  if (header->cmd == CCmdHeader::PT_HARDWARE_ALARM)
    return do_hardware_alarm_req(mb);

  if (header->cmd == CCmdHeader::PT_FILE_MD5_LIST)
    return do_md5_file_list(mb);

  if (header->cmd == CCmdHeader::PT_FTP_FILE)
    return do_ftp_reply(mb);

  if (header->cmd == CCmdHeader::PT_IP_VER_REQ)
    return do_ip_ver_req(mb);

  if (header->cmd == CCmdHeader::PT_ADV_CLICK)
    return do_adv_click_req(mb);

  if (header->cmd == CCmdHeader::PT_VLC)
    return do_vlc_req(mb);

  if (header->cmd == CCmdHeader::PT_PC_ON_OFF)
    return do_pc_on_off_req(mb);

  if (header->cmd == CCmdHeader::PT_TEST)
    return do_test(mb);

  if (header->cmd == CCmdHeader::PT_PSP)
    return do_psp(mb);

  CMBProt guard(mb);
  C_ERROR("unsupported command received @MyHeartBeatProcessor::do_read_data, command = %d\n",
      header->cmd);
  return OP_FAIL;
}

DVOID MyHeartBeatProcessor::do_ping()
{
//  C_DEBUG(ACE_TEXT("got a heart beat from %s\n"), get_sinfo().c_str());
  m_heart_beat_submitter->add_ping(m_term_sn.to_str(), m_term_sn_len);
}

CProc::OUTPUT MyHeartBeatProcessor::do_version_check(CMB * mb)
{
  CMBProt guard(mb);
  CTermSNs & term_SNs = CRunnerX::instance()->termSNs();
  CCmdExt * dpe = (CCmdExt *) mb->base();
  if (!dpe->validate())
  {
    CMemProt info;
    get_sinfo(info);
    C_ERROR(ACE_TEXT("bad client version check packet, dpe->guard() failed: %s\n"), info.get_ptr());
    return OP_FAIL;
  }

  {
    CTerminalVerReq * vc = (CTerminalVerReq *)mb->base();
    if (vc->uuid[0] != 0)
      memcpy(m_remote_ip, vc->uuid, 16);
  }

  ACE_OS::strsncpy(m_hw_ver, ((CTerminalVerReq*)mb->base())->hw_ver, 12);
  if (m_hw_ver[0] == 0)
  {
    ACE_OS::strcpy(m_hw_ver, "NULL");
    CMemProt info;
    get_sinfo(info);
    C_WARNING(ACE_TEXT("client version check packet led/lcd driver version empty: %s\n"), info.get_ptr());
  }
  CProc::OUTPUT ret = i_is_ver_ok(mb, term_SNs);

  m_ip_ver_submitter->add_data(m_term_sn.to_str(), m_term_sn_len, m_remote_ip, m_term_ver.to_text(), m_hw_ver);

  if (ret != OP_GO_ON)
    return ret;

  CTermData client_info;
  term_SNs.get_termData(m_term_loc, client_info);

  CMB * reply_mb;
  if (m_term_ver < CCfgX::instance()->client_ver_min)
  {
    reply_mb = i_create_mb_ver_reply(CTermVerReply::SC_NOT_MATCH, client_info.download_auth_len + 2);
    m_mark_down = true;
  }
  else if (m_term_ver < CCfgX::instance()->client_ver_now)
    reply_mb = i_create_mb_ver_reply(CTermVerReply::SC_OK_UP, client_info.download_auth_len + 2);
  else
    reply_mb = i_create_mb_ver_reply(CTermVerReply::SC_OK, client_info.download_auth_len + 2);

  if (!m_mark_down)
  {
    CTerminalVerReq * vc = (CTerminalVerReq *)mb->base();
    if (vc->server_id != CCfgX::instance()->server_id)
      term_SNs.server_changed(m_term_loc, true);

    CMemProt info;
    get_sinfo(info);
    C_INFO(ACE_TEXT("client version check ok: %s\n"), info.get_ptr());
  }

  CTermVerReply * vcr = (CTermVerReply *) reply_mb->base();
  *((u_int8_t*)vcr->data) = CCfgX::instance()->server_id;
  memcpy(vcr->data + 1, client_info.download_auth, client_info.download_auth_len + 1);
  if (m_handler->post_packet(reply_mb) < 0)
    return OP_FAIL;
  return do_send_pq();
}

CProc::OUTPUT MyHeartBeatProcessor::do_send_pq()
{
  CMemProt value;
  if (!CRunnerX::instance()->ping_component()->get_pl(value))
    return OP_OK;
  ni m = strlen(value.get_ptr()) + 1;
  CMB * mb = CCacheX::instance()->get_mb_cmd(m, CCmdHeader::PT_TQ);
  CCmdExt * dpe = (CCmdExt*) mb->base();
  memcpy(dpe->data, value.get_ptr(), m);
  if (m_handler->post_packet(mb) < 0)
    return OP_FAIL;
  else
    return OP_OK;
}

CProc::OUTPUT MyHeartBeatProcessor::do_md5_file_list(CMB * mb)
{
  CCmdExt * md5filelist = (CCmdExt *)mb->base();
  if (unlikely(!md5filelist->validate()))
  {
    CMemProt info;
    get_sinfo(info);
    C_ERROR("bad md5 file list packet from %s\n", info.get_ptr());
    return OP_FAIL;
  }

  {
    CMemProt info;
    get_sinfo(info);
    C_DEBUG("complete md5 list from client %s, length = %d\n", info.get_ptr(), mb->length());
  }

  CRunnerX::instance()->ping_component()->service()->add_request_slow(mb);
  return OP_OK;
}

CProc::OUTPUT MyHeartBeatProcessor::do_ftp_reply(CMB * mb)
{
  CCmdExt * md5filelist = (CCmdExt *)mb->base();
  if (unlikely(!md5filelist->validate()))
  {
    CMemProt info;
    get_sinfo(info);
    C_ERROR("bad ftp reply packet from %s\n", info.get_ptr());
    return OP_FAIL;
  }
  CMB * mb_reply = CCacheX::instance()->get_mb_ack(mb);
//  C_DEBUG("got one ftp reply packet, size = %d\n", mb->capacity());
  CRunnerX::instance()->ping_component()->service()->add_request(mb, true);

//  MyServerAppX::instance()->dist_put_to_service(mb);
  if (mb_reply != NULL)
    if (m_handler->post_packet(mb_reply) < 0)
      return OP_FAIL;
  return OP_OK;
}

CProc::OUTPUT MyHeartBeatProcessor::do_ip_ver_req(CMB * mb)
{
  CMBProt guard(mb);
  m_ip_ver_submitter->add_data(m_term_sn.to_str(), m_term_sn_len, m_remote_ip, m_term_ver.to_text(), m_hw_ver);
  return OP_OK;
}

CProc::OUTPUT MyHeartBeatProcessor::do_adv_click_req(CMB * mb)
{
  CMBProt guard(mb);
  CCmdExt * dpe = (CCmdExt *)mb->base();
  if (unlikely(!dpe->validate()))
  {
    CMemProt info;
    get_sinfo(info);
    C_ERROR("bad adv click packet from %s\n", info.get_ptr());
    return OP_FAIL;
  }

  CONST text record_separator[] = {CCmdHeader::FINISH_SEPARATOR, 0};
  CTextDelimiter tknz(dpe->data, record_separator);
  text * record;
  while ((record = tknz.get()) != NULL)
  {
    CONST text separator[] = {CCmdHeader::ITEM_SEPARATOR, 0};
    CTextDelimiter tknz_x(record, separator);
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
    m_adv_click_submitter->add_data(m_term_sn.to_str(), m_term_sn_len, chn, pcode, number);
  }

  return OP_OK;
}

CProc::OUTPUT MyHeartBeatProcessor::do_hardware_alarm_req(CMB * mb)
{
  CMBProt guard(mb);
  CPLCWarning * alarm = (CPLCWarning *) mb->base();
  if (unlikely((alarm->x != '1' && alarm->x != '2' && alarm->x != '5' && alarm->x != '6') ||
      (alarm->y < '0' || alarm->y > '3')))
  {
    CMemProt info;
    get_sinfo(info);
    C_ERROR("bad hardware alarm packet from %s, x = %c, y = %c\n", info.get_ptr(), alarm->x, alarm->y);
    return OP_FAIL;
  }

  text datetime[32];
  c_tools_convert_time_to_text(datetime, 20, true);
  m_hardware_alarm_submitter->add_data(m_term_sn.to_str(), m_term_sn_len, alarm->x, alarm->y, datetime);
  return OP_OK;
}

CProc::OUTPUT MyHeartBeatProcessor::do_vlc_req(CMB * mb)
{
  CMBProt guard(mb);
  CCmdExt * dpe = (CCmdExt *)mb->base();
  if (unlikely(!dpe->validate()))
  {
    CMemProt info;
    get_sinfo(info);
    C_ERROR("bad vlc packet from %s\n", info.get_ptr());
    return OP_FAIL;
  }

  text separator[2] = {CCmdHeader::ITEM_SEPARATOR, 0};
  CTextDelimiter tknizer(dpe->data, separator);
  text * token;
  while ((token = tknizer.get()) != NULL)
  {
    text * ptr = strchr(token, CCmdHeader::MIDDLE_SEPARATOR);
    if (!ptr)
      continue;
    *ptr ++ = 0;
    m_vlc_submitter->add_data(m_term_sn.to_str(), m_term_sn_len, token, ptr);
  }
  return OP_OK;
}

CProc::OUTPUT MyHeartBeatProcessor::do_vlc_empty_req(CMB * mb)
{
  CMBProt guard(mb);
  CCmdExt * dpe = (CCmdExt *)mb->base();
  text c = dpe->data[0];
  if (c != '1' && c != '0')
  {
    CMemProt info;
    get_sinfo(info);
    C_ERROR("bad vlc empty packet from %s, data = %c\n", info.get_ptr(), c);
  } else
    m_vlc_empty_submitter->add_data(m_term_sn.to_str(), m_term_sn_len, c);
  return OP_OK;
}

CProc::OUTPUT MyHeartBeatProcessor::do_psp(CMB * mb)
{
  CRunnerX::instance()->ping_component()->service()->add_request(mb, true);
  return OP_OK;
}

CProc::OUTPUT MyHeartBeatProcessor::do_pc_on_off_req(CMB * mb)
{
  CMBProt guard(mb);
  CCmdExt * dpe = (CCmdExt *)mb->base();
  if (unlikely(!dpe->validate()))
  {
    CMemProt info;
    get_sinfo(info);
    C_ERROR("bad pc on/off packet from %s\n", info.get_ptr());
    return OP_FAIL;
  }

  if (unlikely(dpe->data[0] != '1' && dpe->data[0] != '2' && dpe->data[0] != '3'))
  {
    C_ERROR("invalid pc on/off flag (%c)\n", dpe->data[0]);
    return OP_FAIL;
  }

  m_pc_on_off_submitter->add_data(m_term_sn.to_str(), m_term_sn_len, dpe->data[0], dpe->data + 1);
  return OP_OK;
}

CProc::OUTPUT MyHeartBeatProcessor::do_test(CMB * mb)
{
//  MyMessageBlockProt guard(mb);
  C_DEBUG("playback test packet of %d bytes...\n", mb->length());
  CCmdHeader * dph = (CCmdHeader *) mb->base();
  dph->signature = CCmdHeader::SIGNATURE;
//  mb->rd_ptr(mb->base());
//  mb->wr_ptr(mb->capacity());
  m_handler->post_packet(mb);
  return OP_OK;
}

PREPARE_MEMORY_POOL(MyHeartBeatProcessor);


//MyAccumulatorBlock//

MyAccumulatorBlock::MyAccumulatorBlock(ni block_size, ni max_item_length, MyBaseSubmitter * submitter, truefalse auto_submit)
{
  m_block_size = block_size;
  m_max_item_length = max_item_length + 1;
  m_submitter = submitter;
  m_auto_submit = auto_submit;
  m_mb = CCacheX::instance()->get_mb(m_block_size);
  submitter->add_block(this);
  reset();
}

MyAccumulatorBlock::~MyAccumulatorBlock()
{
  if (m_mb)
    m_mb->release();
}

DVOID MyAccumulatorBlock::reset()
{
  m_current_ptr = m_mb->base();
}

truefalse MyAccumulatorBlock::add(CONST text * item, ni len)
{
  if (len == 0)
    len = strlen(item);
  ++len;
  ni remain_len = m_block_size - (m_current_ptr - m_mb->base());
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
  return m_mb->base();
}

ni MyAccumulatorBlock::data_len() CONST
{
  ni result = (m_current_ptr - m_mb->base());
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

  CMB * mb = CCacheX::instance()->get_mb_bs(total_len, cmd);
  text * dest = mb->base() + CBSData::DATA_OFFSET;
  for (it = m_blocks.begin(); ; )
  {
    ni len = (*it)->data_len();
    memcpy(dest, (*it)->data(), len);
    if (++it != m_blocks.end())
    {
      dest[len] = CBSData::PARAM_SEPARATOR;
      dest += (len + 1);
    } else
      break;
  }
  CRunnerX::instance()->dist_to_middle_module()->send_to_bs(mb);
}

DVOID MyBaseSubmitter::reset()
{
  std::for_each(m_blocks.begin(), m_blocks.end(), std::mem_fun(&MyAccumulatorBlock::reset));
};


//MyFtpFeedbackSubmitter//

MyFtpFeedbackSubmitter::MyFtpFeedbackSubmitter():
  m_dist_id_block(BLOCK_SIZE, 32, this), m_ftype_block(BLOCK_SIZE, 1, this), m_client_id_block(BLOCK_SIZE, sizeof(CNumber), this),
  m_step_block(BLOCK_SIZE, 1, this), m_ok_flag_block(BLOCK_SIZE, 1, this), m_date_block(BLOCK_SIZE, 15, this)
{

}

MyFtpFeedbackSubmitter::~MyFtpFeedbackSubmitter()
{

}

CONST text * MyFtpFeedbackSubmitter::get_command() CONST
{
  return CONST_BS_DIST_FEEDBACK_CMD;
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

MyPingSubmitter::MyPingSubmitter(): m_block(BLOCK_SIZE, sizeof(CNumber), this, true)
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
  return CONST_BS_PING_CMD;
}


//MyIPVerSubmitter//

MyIPVerSubmitter::MyIPVerSubmitter():
    m_id_block(BLOCK_SIZE, sizeof(CNumber), this),
    m_ip_block(BLOCK_SIZE, INET_ADDRSTRLEN, this),
    m_ver_block(BLOCK_SIZE * 3 / sizeof(CNumber) + 1, 7, this)//,
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
  return CONST_BS_IP_VER_CMD;
}


//MyPcOnOffSubmitter//

MyPcOnOffSubmitter::MyPcOnOffSubmitter():
    m_id_block(BLOCK_SIZE, sizeof(CNumber), this),
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
  return CONST_BS_POWERON_LINK_CMD;
}


//MyAdvClickSubmitter//

MyAdvClickSubmitter::MyAdvClickSubmitter() : m_id_block(BLOCK_SIZE, sizeof(CNumber), this),
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
  return CONST_BS_ADV_CLICK_CMD;
}


//MyHWAlarmSubmitter//

MyHWAlarmSubmitter::MyHWAlarmSubmitter():
      m_id_block(BLOCK_SIZE, sizeof(CNumber), this),
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
  return CONST_BS_HARD_MON_CMD;
}


//MyVLCSubmitter//

MyVLCSubmitter::MyVLCSubmitter():
    m_id_block(BLOCK_SIZE, sizeof(CNumber), this),
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
  return CONST_BS_VLC_CMD;
}


//MyVLCEmptySubmitter//

MyVLCEmptySubmitter::MyVLCEmptySubmitter():
    m_id_block(BLOCK_SIZE, sizeof(CNumber), this),
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
  c_tools_convert_time_to_text(datetime, 20, true);
  if (!m_datetime_block.add(datetime))
    ret = false;

  if (!ret)
    submit();
}

CONST text * MyVLCEmptySubmitter::get_command() CONST
{
  return CONST_BS_VLC_EMPTY_CMD;
}


//MyHeartBeatHandler//

MyHeartBeatHandler::MyHeartBeatHandler(CHandlerDirector * xptr): CParentHandler(xptr)
{
  m_proc = new MyHeartBeatProcessor(this);
}

CTermSNs * MyHeartBeatHandler::term_SNs() CONST
{
  return g_term_sns;
}

PREPARE_MEMORY_POOL(MyHeartBeatHandler);


//MyHeartBeatService//

MyHeartBeatService::MyHeartBeatService(CContainer * module, ni numThreads):
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
    C_ERROR("can not put message @MyHeartBeatService::add_request %s\n", (CONST text *)CSysError());
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
    C_ERROR("can not put message to MyHeartBeatService.m_queue2 %s\n", (CONST text *)CSysError());
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
  while (CRunnerX::instance()->running())
  {
    truefalse idle = true;
    for (; this->msg_queue()->dequeue(mb, &tv) != -1; )
    {
      idle = false;
      CMBProt guard(mb);
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
        CCmdHeader * dph = (CCmdHeader *) mb->base();
        if (dph->cmd == CCmdHeader::PT_HAVE_DIST_TASK)
        {
          do_have_dist_task();
        } else if ((dph->cmd == CCmdHeader::PT_FTP_FILE))
        {
//          C_DEBUG("service: got one ftp reply packet, size = %d\n", mb->capacity());
          do_ftp_file_reply(mb);
        } else if ((dph->cmd == CCmdHeader::PT_PSP))
        {
          do_psp(mb);
        } else
          C_ERROR("unknown packet recieved @%s, cmd = %d\n", name(), dph->cmd);
      }
    }

    if (m_queue2.dequeue_head(mb, &tv) != -1)
    {
      idle = false;
      CMBProt guard(mb);
      CCmdHeader * dph = (CCmdHeader *) mb->base();
      if ((dph->cmd == CCmdHeader::PT_FILE_MD5_LIST))
      {
        do_file_md5_reply(mb);
      } else
        C_ERROR("unknown packet received @%s.queue2, cmd = %d\n", name(), dph->cmd);
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
  CCmdExt * dpe = (CCmdExt*) mb->base();
  CNumber client_id;
  if (unlikely(!CRunnerX::instance()->termSNs().get_sn(dpe->signature, &client_id)))
  {
    C_FATAL("can not find client id @MyHeartBeatService::do_ftp_file_reply()\n");
    return;
  } //todo: optimize: pass client_id directly from processor

  ni len = dpe->size - sizeof(CCmdHeader);
  if (unlikely(dpe->data[len - 5] != CCmdHeader::ITEM_SEPARATOR))
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
  if (unlikely(!c_tell_ftype_valid(ftype) && ftype != 'x'))
  {
    C_ERROR("bad ftype(%c) on client ftp reply @%s\n", ftype, name());
    return;
  }

  if (recv_status == '2')
  {
    C_DEBUG("ftp command received client_id(%s) dist_id(%s)\n", client_id.to_str(), dist_id);
    status = 4;
  } else if (recv_status == '3')
  {
    status = 5;
    step = '3';
    C_DEBUG("ftp download completed client_id(%s) dist_id(%s)\n", client_id.to_str(), dist_id);
  } else if (recv_status == '4')
  {
    status = 5;
    C_DEBUG("dist extract completed client_id(%s) dist_id(%s)\n", client_id.to_str(), dist_id);
  } else if (recv_status == '5')
  {
    status = 5;
    C_DEBUG("dist extract failed client_id(%s) dist_id(%s)\n", client_id.to_str(), dist_id);
  } else if (recv_status == '9')
  {
    C_DEBUG("dist download started client_id(%s) dist_id(%s)\n", client_id.to_str(), dist_id);
    step = '2';
  } else if (recv_status == '7')
  {
    C_DEBUG("dist download failed client_id(%s) dist_id(%s)\n", client_id.to_str(), dist_id);
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
    c_tools_convert_time_to_text(buff, 32, true);
    ((MyHeartBeatModule *)container())->ftp_feedback_submitter().add(dist_id, ftype, client_id.to_str(), step, ok, buff);
    if (step == '3' && ok == '1')
      ((MyHeartBeatModule *)container())->ftp_feedback_submitter().add(dist_id, ftype, client_id.to_str(), '4', ok, buff);
  }
  if (recv_status == '9')
    return;

  m_distributor.dist_ftp_file_reply(client_id.to_str(), dist_id, status, ok == '1');
}

DVOID MyHeartBeatService::do_psp(CMB * mb)
{
  CCmdExt * dpe = (CCmdExt*) mb->base();
  CNumber client_id;
  if (unlikely(!CRunnerX::instance()->termSNs().get_sn(dpe->signature, &client_id)))
  {
    C_FATAL("can not find client id @MyHeartBeatService::do_file_md5_reply()\n");
    return;
  } //todo: optimize: pass client_id directly from processor

  m_distributor.psp(client_id.to_str(), dpe->data + 1, dpe->data[0]);
}

DVOID MyHeartBeatService::do_file_md5_reply(CMB * mb)
{
  CCmdExt * dpe = (CCmdExt*) mb->base();
  CNumber client_id;
  if (unlikely(!CRunnerX::instance()->termSNs().get_sn(dpe->signature, &client_id)))
  {
    C_FATAL("can not find client id @MyHeartBeatService::do_file_md5_reply()\n");
    return;
  } //todo: optimize: pass client_id directly from processor

  if (unlikely(!dpe->data[0]))
  {
    C_ERROR("bad file md5 list reply packet @%s::do_file_md5_reply(), no dist_id\n", name());
    return;
  }
  text * md5list = strchr(dpe->data, CCmdHeader::ITEM_SEPARATOR);
  if (unlikely(!md5list))
  {
    C_ERROR("bad file md5 list reply packet @%s::do_file_md5_reply(), no dist_id mark\n", name());
    return;
  }
  *md5list ++ = 0;
  CONST text * dist_id = dpe->data;
//  C_DEBUG("file md5 list from client_id(%s) dist_id(%s): %s\n", client_id.as_string(),
//      dist_id, (*md5list? md5list: "(empty)"));
  C_DEBUG("file md5 list from client_id(%s) dist_id(%s): len = %d\n", client_id.to_str(), dist_id, strlen(md5list));

  m_distributor.dist_ftp_md5_reply(client_id.to_str(), dist_id, md5list);
}


//MyHeartBeatAcceptor//

MyHeartBeatAcceptor::MyHeartBeatAcceptor(CParentScheduler * _dispatcher, CHandlerDirector * _manager):
    CParentAcc(_dispatcher, _manager)
{
  m_tcp_port = CCfgX::instance()->ping_port;
  m_reap_interval = IDLE_TIME_AS_DEAD;
}

ni MyHeartBeatAcceptor::make_svc_handler(CParentHandler *& sh)
{
  sh = new MyHeartBeatHandler(m_director);
  if (!sh)
  {
    C_ERROR("can not alloc MyHeartBeatHandler from %s\n", name());
    return -1;
  }
  sh->container((void*)this);
  sh->reactor(reactor());
  return 0;
}

CONST text * MyHeartBeatAcceptor::name() CONST
{
  return "MyHeartBeatAcceptor";
}


//MyHeartBeatDispatcher//

MyHeartBeatDispatcher::MyHeartBeatDispatcher(CContainer * pModule, ni numThreads):
    CParentScheduler(pModule, numThreads)
{
  m_acceptor = NULL;
  m_delay_clock = CLOCK_INTERVAL;
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
  if ((long)act == CParentScheduler::TID)
  {
    CMB *mb;
    ACE_Time_Value nowait(ACE_Time_Value::zero);
    while (-1 != this->getq(mb, &nowait))
    {
      if (unlikely(mb->size() < sizeof(CCmdHeader)))
      {
        C_ERROR("invalid message block size @ %s::handle_timeout\n", name());
        mb->release();
        continue;
      }
      ni index = ((CCmdHeader*)mb->base())->signature;
      CParentHandler * handler = m_acceptor->director()->locate(index);
      if (!handler)
      {
//        C_WARNING("can not send data to client since connection is lost @ %s::handle_timeout\n", name());
        mb->release();
        continue;
      }

      if (unlikely(CCmdHeader::PT_DISCONNECT_INTERNAL == ((CCmdHeader*)mb->base())->cmd))
      {
        //handler->processor()->prepare_to_close();
        handler->handle_close(ACE_INVALID_HANDLE, 0);
        mb->release();
        continue;
      }

      ((CCmdHeader*)mb->base())->signature = CCmdHeader::SIGNATURE;

      if (handler->post_packet(mb) < 0)
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
    CMB * mb = CCacheX::instance()->get_mb(sizeof(ni));
    *(ni*)mb->base() = MyHeartBeatService::TIMED_DIST_TASK;
    CRunnerX::instance()->ping_component()->service()->add_request(mb, false);
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

DVOID MyHeartBeatDispatcher::before_finish()
{
  m_acceptor = NULL;
}

DVOID MyHeartBeatDispatcher::before_finish_stage_1()
{

}

truefalse MyHeartBeatDispatcher::before_begin()
{
  if (!m_acceptor)
    m_acceptor = new MyHeartBeatAcceptor(this, new CHandlerDirector());
  acc_add(m_acceptor);

  {
    ACE_Time_Value interval(CLOCK_TICK_HEART_BEAT);
    if (reactor()->schedule_timer(this, (CONST void*)TIMER_ID_HEART_BEAT, interval, interval) < 0)
    {
      C_ERROR("setup heart beat timer failed %s %s\n", name(), (CONST char*)CSysError());
      return false;
    }
  }

  {
    ACE_Time_Value interval(CLOCK_TICK_IP_VER);
    if (reactor()->schedule_timer(this, (CONST void*)TIMER_ID_IP_VER, interval, interval) < 0)
    {
      C_ERROR("setup heart beat timer failed %s %s\n", name(), (CONST char*)CSysError());
      return false;
    }
  }

  {
    ACE_Time_Value interval(CLOCK_TICK_FTP_FEEDBACK);
    if (reactor()->schedule_timer(this, (CONST void*)TIMER_ID_FTP_FEEDBACK, interval, interval) < 0)
    {
      C_ERROR("setup ftp feedback timer failed %s %s\n", name(), (CONST char*)CSysError());
      return false;
    }
  }

  {
    ACE_Time_Value interval(CLOCK_TICK_DIST_SERVICE * 60);
    if (reactor()->schedule_timer(this, (CONST void*)TIMER_ID_DIST_SERVICE, interval, interval) < 0)
    {
      C_ERROR("setup heart beat timer failed %s %s\n", name(), (CONST char*)CSysError());
      return false;
    }
  }

  {
    ACE_Time_Value interval(CLOCK_TICK_ADV_CLICK * 60);
    if (reactor()->schedule_timer(this, (CONST void*)TIMER_ID_ADV_CLICK, interval, interval) < 0)
    {
      C_ERROR("setup adv click timer failed %s %s\n", name(), (CONST char*)CSysError());
      return false;
    }
  }

  return true;
}


//MyHeartBeatModule//

MyHeartBeatModule::MyHeartBeatModule(CApp * app): CContainer(app)
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
  if (unlikely(!m_dispatcher || !m_dispatcher->acceptor() || !m_dispatcher->acceptor()->director()))
    return 0xFFFFFF;
  return m_dispatcher->acceptor()->director()->active_count();
}

MyFtpFeedbackSubmitter & MyHeartBeatModule::ftp_feedback_submitter()
{
  return m_ftp_feedback_submitter;
}

DVOID MyHeartBeatModule::pl()
{
  CMemProt value;
  if (!CRunnerX::instance()->db().load_pl(value))
    return;
  ACE_GUARD(ACE_Thread_Mutex, ace_mon, this->m_mutex);
  m_pl.init(value.get_ptr());
}

truefalse MyHeartBeatModule::get_pl(CMemProt & value)
{
  ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, false);
  if (!m_pl.get_ptr() || !*m_pl.get_ptr())
    return false;
  value.init(m_pl.get_ptr());
  return true;
}

CONST text * MyHeartBeatModule::name() CONST
{
  return "MyHeartBeatModule";
}

truefalse MyHeartBeatModule::before_begin()
{
  add_task(m_service = new MyHeartBeatService(this, 1));
  add_scheduler(m_dispatcher = new MyHeartBeatDispatcher(this));
  return true;
}

DVOID MyHeartBeatModule::before_finish()
{
  m_service = NULL;
  m_dispatcher = NULL;
}


/////////////////////////////////////
//dist to BS
/////////////////////////////////////

//MyDistToBSProcessor//

MyDistToBSProcessor::MyDistToBSProcessor(CParentHandler * handler): baseclass(handler)
{
  m_handler->msg_queue()->high_water_mark(MSG_QUEUE_MAX_SIZE);
}

CONST text * MyDistToBSProcessor::name() CONST
{
  return "MyDistToBSProcessor";
}

CProc::OUTPUT MyDistToBSProcessor::do_read_data(CMB * mb)
{
  CMBProt guard(mb);

  if (baseclass::do_read_data(mb) != OP_OK)
    return OP_FAIL;
  CBSData * bspacket = (CBSData *) mb->base();
  if (memcmp(bspacket->command, CONST_BS_IP_VER_CMD, sizeof(bspacket->command)) == 0)
    process_ip_ver_reply(bspacket);
//  C_INFO("got a bs reply packet:%s\n", mb->base());

  ((MyDistToBSHandler*)m_handler)->checker_update();

  return OP_OK;
}

DVOID MyDistToBSProcessor::process_ip_ver_reply(CBSData * bspacket)
{
  text separator[2] = {';', 0};
  CTextDelimiter tknizer(bspacket->data, separator);
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
  CTermSNs & id_table = CRunnerX::instance()->termSNs();
  CNumber client_id(id);
  ni index;
  if (unlikely(!id_table.mark_valid(client_id, client_valid, index)))
    CRunnerX::instance()->db().mark_client_valid(id, client_valid);

  if (likely(client_valid))
  {
    ni len = strlen(data) + 1;
    CMB * mb = CCacheX::instance()->get_mb_cmd(len, CCmdHeader::PT_IP_VER_REQ);
    CCmdExt * dpe = (CCmdExt *) mb->base();
    memcpy(dpe->data, data, len);
    dpe->signature = index;
    c_tools_mb_putq(CRunnerX::instance()->ping_component()->dispatcher(), mb, "ip ver reply to dispatcher's queue");
  } else
  {
    if (index >= 0)
    {
      CMB * mb = CCacheX::instance()->get_mb_cmd(0, CCmdHeader::PT_DISCONNECT_INTERNAL);
      CCmdExt * dpe = (CCmdExt *) mb->base();
      dpe->signature = index;
      c_tools_mb_putq(CRunnerX::instance()->ping_component()->dispatcher(), mb, "disconnect internal to dispatcher's queue");
    }
  }
}


//MyDistToBSHandler//

MyDistToBSHandler::MyDistToBSHandler(CHandlerDirector * xptr): CParentHandler(xptr)
{
  m_proc = new MyDistToBSProcessor(this);
}

MyDistToMiddleModule * MyDistToBSHandler::module_x() CONST
{
  return (MyDistToMiddleModule *)connector()->container();
}

DVOID MyDistToBSHandler::checker_update()
{
  m_checker.refresh();
}

ni MyDistToBSHandler::handle_timeout(CONST ACE_Time_Value &, CONST DVOID *)
{
  if (m_checker.overdue())
  {
    C_ERROR("no data received from bs @MyDistToBSHandler ...\n");
    return -1;
  }
  CMB * mb = c_create_hb_mb();
  if (mb)
  {
    if (post_packet(mb) < 0)
      return -1;
  }
  return 0;
}

ni MyDistToBSHandler::at_start()
{
  ACE_Time_Value interval(30);
  if (reactor()->schedule_timer(this, (void*)0, interval, interval) < 0)
  {
    C_ERROR(ACE_TEXT("MyDistToBSHandler setup timer failed, %s"), (CONST char*)CSysError());
    return -1;
  }

  if (!g_is_test)
    C_INFO("MyDistToBSHandler setup timer: OK\n");

  CMB * mb = c_create_hb_mb();
  if (mb)
  {
    if (post_packet(mb) < 0)
      return -1;
  }
  m_checker.refresh();

  return 0;
}


DVOID MyDistToBSHandler::at_finish()
{

}

PREPARE_MEMORY_POOL(MyDistToBSHandler);


//MyDistToBSConnector//

MyDistToBSConnector::MyDistToBSConnector(CParentScheduler * _dispatcher, CHandlerDirector * _manager):
    CParentConn(_dispatcher, _manager)
{
  m_port_of_ip = CCfgX::instance()->bs_port;
  m_retry_delay = RECONNECT_INTERVAL;
  m_remote_ip = CCfgX::instance()->bs_addr;
}

CONST text * MyDistToBSConnector::name() CONST
{
  return "MyDistToBSConnector";
}

ni MyDistToBSConnector::make_svc_handler(CParentHandler *& sh)
{
  sh = new MyDistToBSHandler(m_director);
  if (!sh)
  {
    C_ERROR("can not alloc MyDistToBSHandler from %s\n", name());
    return -1;
  }
  sh->container((void*)this);
  sh->reactor(reactor());
  return 0;
}


/////////////////////////////////////
//dist to middle module
/////////////////////////////////////

//MyDistToMiddleProcessor//


MyDistToMiddleProcessor::MyDistToMiddleProcessor(CParentHandler * handler): CParentClientProc(handler)
{
  m_version_check_reply_done = false;
  m_local_addr[0] = 0;
  m_handler->msg_queue()->high_water_mark(MSG_QUEUE_MAX_SIZE);
}

ni MyDistToMiddleProcessor::at_start()
{
  if (baseclass::at_start() < 0)
    return -1;

  ACE_INET_Addr local_addr;
  if (m_handler->peer().get_local_addr(local_addr) == 0)
    local_addr.get_host_addr((char*)m_local_addr, IP_ADDR_LENGTH);

  return send_version_check_req();
}

CProc::OUTPUT MyDistToMiddleProcessor::at_head_arrival()
{
  CProc::OUTPUT result = baseclass::at_head_arrival();
  if (result != OP_GO_ON)
    return OP_FAIL;

  truefalse bVersionCheckReply = m_data_head.cmd == CCmdHeader::PT_VER_REPLY; //m_version_check_reply_done
  if (bVersionCheckReply == m_version_check_reply_done)
  {
    C_ERROR(ACE_TEXT("unexpected packet header from dist server, version_check_reply_done = %d, "
                      "packet is version_check_reply = %d.\n"), m_version_check_reply_done, bVersionCheckReply);
    return OP_FAIL;
  }

  if (bVersionCheckReply)
  {
    if (!c_packet_check_term_ver_reply(&m_data_head))
    {
      C_ERROR("failed to validate header for version check reply packet\n");
      return OP_FAIL;
    }
    return OP_OK;
  }

  if (m_data_head.cmd == CCmdHeader::PT_HAVE_DIST_TASK)
  {
    if (!c_packet_check_have_dist_task(&m_data_head))
    {
      C_ERROR("failed to validate header for dist task notify packet\n");
      return OP_FAIL;
    }
    return OP_OK;
  }

  if (m_data_head.cmd == CCmdHeader::PT_REMOTE_CMD)
  {
    if (!c_packet_check_file_md5_list(&m_data_head))
    {
      C_ERROR("failed to validate header for remote cmd notify packet\n");
      return OP_FAIL;
    }
    return OP_OK;
  }

  C_ERROR("unexpected packet header from dist server, header.command = %d\n", m_data_head.cmd);
  return OP_FAIL;
}

CProc::OUTPUT MyDistToMiddleProcessor::do_read_data(CMB * mb)
{
  CFormatProcBase::do_read_data(mb);

  CCmdHeader * header = (CCmdHeader *)mb->base();

  if (header->cmd == CCmdHeader::PT_VER_REPLY)
  {
    CProc::OUTPUT result = do_version_check_reply(mb);
    C_INFO("handshake response from middle server: %s\n", (result == OP_OK? "OK":"Failed"));
    if (result == OP_OK)
    {
      ((MyDistToMiddleHandler*)m_handler)->setup_timer();
      sn_check_ok(true);
    }
    return result;
  }

  if (header->cmd == CCmdHeader::PT_HAVE_DIST_TASK)
  {
    CProc::OUTPUT result = do_have_dist_task(mb);
    C_INFO("got notification from middle server on new dist task\n");
    return result;
  }

  if (m_data_head.cmd == CCmdHeader::PT_REMOTE_CMD)
  {
    C_INFO("got notification from middle server on remote cmd\n");
    CProc::OUTPUT result = do_remote_cmd_task(mb);
    return result;
  }

  CMBProt guard(mb);
  C_ERROR("unsupported command received @MyDistToMiddleProcessor::do_read_data(), command = %d\n",
      header->cmd);
  return OP_FAIL;
}

ni MyDistToMiddleProcessor::send_server_load()
{
  if (!m_version_check_reply_done)
    return 0;

  CMB * mb = CCacheX::instance()->get_mb_cmd_direct(sizeof(CLoadBalanceReq), CCmdHeader::PT_LOAD_BALANCE_REQ);
  CLoadBalanceReq * req = (CLoadBalanceReq *) mb->base();
  req->set_ip(m_local_addr);
  req->load = CRunnerX::instance()->ping_component()->num_active_clients();
  C_INFO("sending dist server load number [%d] to middle server...\n", req->load);
  return (m_handler->post_packet(mb) < 0 ? -1: 0);
}

CProc::OUTPUT MyDistToMiddleProcessor::do_version_check_reply(CMB * mb)
{
  CMBProt guard(mb);
  m_version_check_reply_done = true;

  CONST text * prefix_msg = "dist server version check reply:";
  CTermVerReply * vcr = (CTermVerReply *) mb->base();
  switch (vcr->ret_subcmd)
  {
  case CTermVerReply::SC_OK:
    return CProc::OP_OK;

  case CTermVerReply::SC_OK_UP:
    C_INFO("%s get version can upgrade response\n", prefix_msg);
    return CProc::OP_OK;

  case CTermVerReply::SC_NOT_MATCH:
    C_ERROR("%s get version mismatch response\n", prefix_msg);
    return CProc::OP_FAIL;

  case CTermVerReply::SC_ACCESS_DENIED:
    C_ERROR("%s get access denied response\n", prefix_msg);
    return CProc::OP_FAIL;

  case CTermVerReply::SC_SERVER_BUSY:
    C_ERROR("%s get server busy response\n", prefix_msg);
    return CProc::OP_FAIL;

  default: //server_list
    C_ERROR("%s get unknown reply code = %d\n", prefix_msg, vcr->ret_subcmd);
    return CProc::OP_FAIL;
  }

}

CProc::OUTPUT MyDistToMiddleProcessor::do_have_dist_task(CMB * mb)
{
  CRunnerX::instance()->ping_component()->service()->add_request(mb, false);
  return OP_OK;
}

CProc::OUTPUT MyDistToMiddleProcessor::do_remote_cmd_task(CMB * mb)
{
  CMBProt guard(mb);
  return OP_OK;
}

ni MyDistToMiddleProcessor::send_version_check_req()
{
  CMB * mb = create_login_mb();
  CTerminalVerReq * proc = (CTerminalVerReq *)mb->base();
  proc->term_ver_major = 1;
  proc->term_ver_minor = 0;
  proc->term_sn = CCfgX::instance()->skey.c_str();
  proc->server_id = CCfgX::instance()->server_id;
  C_INFO("sending handshake request to middle server...\n");
  return (m_handler->post_packet(mb) < 0? -1: 0);
}


//MyDistToMiddleHandler//

MyDistToMiddleHandler::MyDistToMiddleHandler(CHandlerDirector * xptr): CParentHandler(xptr)
{
  m_proc = new MyDistToMiddleProcessor(this);
  m_load_balance_req_timer_id = -1;
}

DVOID MyDistToMiddleHandler::setup_timer()
{
  ACE_Time_Value tv_start(ACE_Time_Value::zero);
  ACE_Time_Value interval(LOAD_BALANCE_REQ_INTERVAL * 60);
  m_load_balance_req_timer_id = reactor()->schedule_timer(this, (void*)LOAD_BALANCE_REQ_TIMER, tv_start, interval);
  if (m_load_balance_req_timer_id < 0)
    C_ERROR(ACE_TEXT("MyDistToMiddleHandler setup load balance req timer failed, %s"), (CONST char*)CSysError());
}

MyDistToMiddleModule * MyDistToMiddleHandler::module_x() CONST
{
  return (MyDistToMiddleModule *)connector()->container();
}

ni MyDistToMiddleHandler::at_start()
{
  return 0;
}

ni MyDistToMiddleHandler::handle_timeout(CONST ACE_Time_Value &current_time, CONST DVOID *act)
{
  ACE_UNUSED_ARG(current_time);
  if (long(act) == LOAD_BALANCE_REQ_TIMER)
    return ((MyDistToMiddleProcessor*)m_proc)->send_server_load();
  else if (long(act) == 0)
    return -1;
  else
  {
    C_ERROR("unexpected timer call @MyDistToMiddleHandler::handle_timeout, timer id = %d\n", long(act));
    return 0;
  }
}

DVOID MyDistToMiddleHandler::at_finish()
{
  if (m_load_balance_req_timer_id >= 0)
    reactor()->cancel_timer(m_load_balance_req_timer_id);
}

PREPARE_MEMORY_POOL(MyDistToMiddleHandler);



//MyDistToMiddleConnector//

MyDistToMiddleConnector::MyDistToMiddleConnector(CParentScheduler * _dispatcher, CHandlerDirector * _manager):
    CParentConn(_dispatcher, _manager)
{
  m_port_of_ip = CCfgX::instance()->server_port;
  m_retry_delay = RECONNECT_INTERVAL;
  m_remote_ip = CCfgX::instance()->middle_addr;
}

CONST text * MyDistToMiddleConnector::name() CONST
{
  return "MyDistToMiddleConnector";
}

ni MyDistToMiddleConnector::make_svc_handler(CParentHandler *& sh)
{
  sh = new MyDistToMiddleHandler(m_director);
  if (!sh)
  {
    C_ERROR("can not alloc MyDistToMiddleHandler from %s\n", name());
    return -1;
  }
//  C_DEBUG("MyDistToMiddleConnector::make_svc_handler(%X)...\n", long(sh));
  sh->container((void*)this);
  sh->reactor(reactor());
  return 0;
}


//MyDistToMiddleDispatcher//

MyDistToMiddleDispatcher::MyDistToMiddleDispatcher(CContainer * pModule, ni numThreads):
    CParentScheduler(pModule, numThreads)
{
  m_connector = NULL;
  m_bs_connector = NULL;
  msg_queue()->high_water_mark(MSG_QUEUE_MAX_SIZE);
  m_to_bs_queue.high_water_mark(MSG_QUEUE_MAX_SIZE);
}

MyDistToMiddleDispatcher::~MyDistToMiddleDispatcher()
{

}

DVOID MyDistToMiddleDispatcher::before_finish_stage_1()
{
  ACE_Time_Value tv(ACE_Time_Value::zero);
  CMB * mb;
  while (m_to_bs_queue.dequeue(mb, &tv) != -1)
    mb->release();
  while (this->msg_queue()->dequeue(mb, &tv) != -1)
    mb->release();
}

truefalse MyDistToMiddleDispatcher::before_begin()
{
  if (!m_connector)
    m_connector = new MyDistToMiddleConnector(this, new CHandlerDirector());
  conn_add(m_connector);
  if (!m_bs_connector)
    m_bs_connector = new MyDistToBSConnector(this, new CHandlerDirector());
  conn_add(m_bs_connector);
  return true;
}

truefalse MyDistToMiddleDispatcher::do_schedule_work()
{
  ACE_Time_Value tv(ACE_Time_Value::zero);
  CMB * mb;
  CONST ni CONST_max_count = 10;
  ni i = 0;
  while (++i < CONST_max_count && this->getq(mb, &tv) != -1)
    m_connector->director()->post_all(mb);

  tv = ACE_Time_Value::zero;
  i = 0;
  while (++i < CONST_max_count && m_to_bs_queue.dequeue(mb, &tv) != -1)
    m_bs_connector->director()->post_all(mb);

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
  c_tools_mb_putq(this, mb, "@ MyDistToMiddleDispatcher::send_to_middle");
}

DVOID MyDistToMiddleDispatcher::before_finish()
{
  m_connector = NULL;
  m_bs_connector = NULL;
}


//MyDistToMiddleModule//

MyDistToMiddleModule::MyDistToMiddleModule(CApp * app): CContainer(app)
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

truefalse MyDistToMiddleModule::before_begin()
{
  add_scheduler(m_dispatcher = new MyDistToMiddleDispatcher(this));
  return true;
}

DVOID MyDistToMiddleModule::before_finish()
{
  m_dispatcher = NULL;
}


//!//database

CONST text * CONST_db_name = "acedb";

//this class is internal for implementation only. invisible outside of dbmodule
class MyPGResultProt
{
public:
  MyPGResultProt(PGresult * res): m_result(res)
  {}
  ~MyPGResultProt()
  {
    PQclear(m_result);
  }

private:
  MyPGResultProt(CONST MyPGResultProt &);
  MyPGResultProt & operator = (CONST MyPGResultProt &);

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

time_t MyDB::get_time_init(CONST text * s)
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

DVOID MyDB::wrap_str(CONST text * s, CMemProt & wrapped) CONST
{
  if (!s || !*s)
    wrapped.init("null");
  else
    wrapped.init("'", s, "'");
}

time_t MyDB::get_db_time_i()
{
  CONST text * CONST_select_sql = "select ('now'::text)::timestamp(0) without time zone";
  PGresult * pres = PQexec(m_connection, CONST_select_sql);
  MyPGResultProt guard(pres);
  if (!pres || PQresultStatus(pres) != PGRES_TUPLES_OK)
  {
    C_ERROR("MyDB::sql (%s) failed: %s\n", CONST_select_sql, PQerrorMessage(m_connection));
    return 0;
  }
  if (unlikely(PQntuples(pres) <= 0))
    return 0;
  return get_time_init(PQgetvalue(pres, 0, 0));
}

truefalse MyDB::exec_command(CONST text * sql_command, ni * affected)
{
  if (unlikely(!sql_command || !*sql_command))
    return false;
  PGresult * pres = PQexec(m_connection, sql_command);
  MyPGResultProt guard(pres);
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

truefalse MyDB::get_client_ids(CTermSNs * id_table)
{
  C_ASSERT_RETURN(id_table != NULL, "null id_table @MyDB::get_client_ids\n", false);

  CONST text * CONST_select_sql_template = "select client_id, client_password, client_expired, auto_seq "
                                           "from tb_clients where auto_seq > %d order by auto_seq";
  text select_sql[1024];
  snprintf(select_sql, 1024 - 1, CONST_select_sql_template, id_table->prev_no());

  ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, false);
  PGresult * pres = PQexec(m_connection, select_sql);
  MyPGResultProt guard(pres);
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
      id_table->append(PQgetvalue(pres, i, 0), PQgetvalue(pres, i, 1), expired);
    }
    ni last_seq = atoi(PQgetvalue(pres, count - 1, 1));
    id_table->set_prev_no(last_seq);
  }

  C_INFO("MyDB::get %d client_IDs from database\n", count);
  return true;
}

truefalse MyDB::save_client_id(CONST text * s)
{
  CNumber id = s;
  id.rtrim();
  if (id.to_str()[0] == 0)
    return false;

  CONST text * insert_sql_template = "insert into tb_clients(client_id) values('%s')";
  text insert_sql[1024];
  snprintf(insert_sql, 1024, insert_sql_template, id.to_str());

  ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, false);
  return exec_command(insert_sql);
}

truefalse MyDB::save_dist(CBsDistReq & http_dist_request, CONST text * md5, CONST text * mbz_md5)
{
  CONST text * insert_sql_template = "insert into tb_dist_info("
               "dist_id, dist_type, dist_aindex, dist_findex, dist_fdir,"
               "dist_ftype, dist_password, dist_md5, dist_mbz_md5) "
               "values('%s', '%s', %s, '%s', '%s', '%s', '%s', '%s', '%s')";
  CONST text * _md5 = md5 ? md5 : "";
  CONST text * _mbz_md5 = mbz_md5 ? mbz_md5 : "";
  ni len = strlen(insert_sql_template) + strlen(_md5) + strlen(_mbz_md5) + 2000;
  CMemProt sql;
  CCacheX::instance()->get(len, &sql);
  CMemProt aindex;
  wrap_str(http_dist_request.aindex, aindex);
  snprintf(sql.get_ptr(), len - 1, insert_sql_template,
      http_dist_request.ver, http_dist_request.type, aindex.get_ptr(),
      http_dist_request.findex, http_dist_request.fdir,
      http_dist_request.ftype, http_dist_request.password, _md5, _mbz_md5);

  ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, false);
  return exec_command(sql.get_ptr());
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
  CTextDelimiter client_ids(idlist, separator);
  CTextDelimiter dist_ids(dids, separator);
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
  CTextDelimiter client_ids(idlist, separator);
  CTextDelimiter adirs(adirlist, separator);
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

ni MyDB::load_dist_infos(CBsDistDatas & infos)
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
  MyPGResultProt guard(pres);
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

  infos.alloc_spaces(count);
  for (ni i = 0; i < count; ++ i)
  {
    CBsDistData * info = infos.alloc_data(PQgetvalue(pres, i, 0));

    for (ni j = 0; j < field_count; ++j)
    {
      CONST text * fvalue = PQgetvalue(pres, i, j);
      if (!fvalue || !*fvalue)
        continue;

      if (j == 5)
        info->ftype[0] = *fvalue;
      else if (j == 4)
        info->fdir.init(fvalue);
      else if (j == 3)
      {
        info->findex.init(fvalue);
        info->findex_len = strlen(fvalue);
      }
      else if (j == 9)
      {
        info->md5.init(fvalue);
        info->md5_len = strlen(fvalue);
      }
      else if (j == 1)
        info->type[0] = *fvalue;
      else if (j == 7)
      {
        info->password.init(fvalue);
        info->password_len = strlen(fvalue);
      }
      else if (j == 6)
      {
        info->dist_time.init(fvalue);
      }
      else if (j == 2)
      {
        info->aindex.init(fvalue);
        info->aindex_len = strlen(fvalue);
      }
      else if (j == 8)
        info->mbz_md5.init(fvalue);
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

truefalse MyDB::take_owner_ship(CONST text * table, CONST text * field, CMemProt & old_time, CONST text * where_clause)
{
  CONST text * update_sql_template = "update %s set "
                                     "%s = ('now'::text)::timestamp(0) without time zone "
                                     "%s and %s %s %s";
  text sql[1024];
  if (old_time.get_ptr() && old_time.get_ptr()[0])
  {
    CMemProt wrapped_time;
    wrap_str(old_time.get_ptr(), wrapped_time);
    snprintf(sql, 1024, update_sql_template, table, field, where_clause, field, "=", wrapped_time.get_ptr());
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
  MyPGResultProt guard(pres);
  if (!pres || PQresultStatus(pres) != PGRES_TUPLES_OK)
  {
    C_ERROR("MyDB::sql (%s) failed: %s\n", sql, PQerrorMessage(m_connection));
    return result;
  }
  ni count = PQntuples(pres);
  if (count > 0)
    old_time.init(PQgetvalue(pres, 0, 0));
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
  CMemProt sql;
  CCacheX::instance()->get(len, &sql);
  snprintf(sql.get_ptr(), len, update_sql_template, md5, dist_id);

  ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, false);
  return exec_command(sql.get_ptr());
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
  MyPGResultProt guard(pres);
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

  CBsDistData * info;
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
        dc->adir.init(fvalue);
      else if (j == 7)
        md5 = fvalue;
      else if (j == 5)
        dc->mbz_file.init(fvalue);
      else if (j == 4)
        dc->last_update = get_time_init(fvalue);
      else if (j == 6)
        dc->mbz_md5.init(fvalue);
    }

    if (dc->status < 3 && md5 != NULL)
      dc->md5.init(md5);

    ++ count_added;
  }

__exit__:
  if (!_dc_one)
    C_INFO("MyDB::get %d/%d dist client infos from database\n", count_added, count);
  return count;
}

truefalse MyDB::set_dist_client_status(MyDistClient & dist_client, ni new_status)
{
  return set_dist_client_status(dist_client.client_id(), dist_client.dist_info->ver.get_ptr(), new_status);
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
  CMemProt sql;
  CCacheX::instance()->get(len, &sql);
  snprintf(sql.get_ptr(), len, update_sql_template, new_status, md5, dist_id, client_id, new_status);

  ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, false);
  ni num = 0;
  return exec_command(sql.get_ptr(), &num) && num == 1;
}

truefalse MyDB::set_dist_client_mbz(CONST text * client_id, CONST text * dist_id, CONST text * mbz, CONST text * mbz_md5)
{
  CONST text * update_sql_template = "update tb_dist_clients set dc_mbz_file = '%s', dc_mbz_md5 = '%s' "
                                     "where dc_dist_id = '%s' and dc_client_id='%s' and dc_status < 3";
  ni len = strlen(update_sql_template) + strlen(mbz) + strlen(client_id)
          + strlen(dist_id) + 40 + strlen(mbz_md5);
  CMemProt sql;
  CCacheX::instance()->get(len, &sql);
  snprintf(sql.get_ptr(), len, update_sql_template, mbz, mbz_md5, dist_id, client_id);

  ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, false);
  ni num = 0;
  return exec_command(sql.get_ptr(), &num) && num == 1;
}

truefalse MyDB::delete_dist_client(CONST text * client_id, CONST text * dist_id)
{
  CONST text * delete_sql_template = "delete from tb_dist_clients where dc_dist_id = '%s' and dc_client_id='%s'";
  text sql[1024];
  snprintf(sql, 1024, delete_sql_template, dist_id, client_id);

  ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, false);
  return exec_command(sql);
}

truefalse MyDB::dist_info_is_update(CBsDistDatas & infos)
{
  {
    ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, false);
    if (!check_db_connection())
      return true;
  }
  CMemProt value;
  if (!load_cfg_value(1, value))
    return true;
  truefalse result = strcmp(infos.prev_query_ts.get_ptr(), value.get_ptr()) == 0;
  if (!result)
    infos.prev_query_ts.init(value.get_ptr());
  return result;
}

truefalse MyDB::load_pl(CMemProt & value)
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

truefalse MyDB::get_dist_ids(CObsoleteDirDeleter & path_remover)
{
  CONST text * sql = "select dist_id from tb_dist_info";

  ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, false);
  PGresult * pres = PQexec(m_connection, sql);
  MyPGResultProt guard(pres);
  if (!pres || PQresultStatus(pres) != PGRES_TUPLES_OK)
  {
    C_ERROR("MyDB::sql (%s) failed: %s\n", sql, PQerrorMessage(m_connection));
    return false;
  }
  ni count = PQntuples(pres);
  if (count > 0)
  {
    for (ni i = 0; i < count; ++i)
      path_remover.append_did(PQgetvalue(pres, i, 0));
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

truefalse MyDB::load_cfg_value(CONST ni id, CMemProt & value)
{
  ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, false);
  return load_cfg_value_i(id, value);
}

truefalse MyDB::load_cfg_value_i(CONST ni id, CMemProt & value)
{
  CONST text * CONST_select_sql_template = "select cfg_value from tb_config where cfg_id = %d";
  text select_sql[1024];
  snprintf(select_sql, 1024, CONST_select_sql_template, id);

  PGresult * pres = PQexec(m_connection, select_sql);
  MyPGResultProt guard(pres);
  if (!pres || PQresultStatus(pres) != PGRES_TUPLES_OK)
  {
    C_ERROR("MyDB::sql (%s) failed: %s\n", select_sql, PQerrorMessage(m_connection));
    return false;
  }
  ni count = PQntuples(pres);
  if (count > 0)
  {
    value.init(PQgetvalue(pres, 0, 0));
    return true;
  } else
    return false;
}


truefalse MyDB::load_db_server_time_i(time_t &t)
{
  CONST text * select_sql = "select ('now'::text)::timestamp(0) without time zone";
  PGresult * pres = PQexec(m_connection, select_sql);
  MyPGResultProt guard(pres);
  if (!pres || PQresultStatus(pres) != PGRES_TUPLES_OK)
  {
    C_ERROR("MyDB::sql (%s) failed: %s\n", select_sql, PQerrorMessage(m_connection));
    return false;
  }
  if (PQntuples(pres) <= 0)
    return false;
  t = get_time_init(PQgetvalue(pres, 0, 0));
  return true;
}
