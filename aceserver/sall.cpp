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
  if (!db.check_online())
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

  if (!l_database.check_online())
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
  if (!l_database.check_online())
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
    m_bs_conn = new CM2BsConn(this, new CHandlerDirector());
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


//m2bs

CM2BsProc::CM2BsProc(CParentHandler * handler): baseclass(handler)
{

}

CONST text * CM2BsProc::name() CONST
{
  return "CM2BsProc";
}

CProc::OUTPUT CM2BsProc::do_read_data(CMB * mb)
{
  if (mb)
    mb->release();
  ((CM2BsHandler*)m_handler)->checker_update();
  return OP_OK;
}

PREPARE_MEMORY_POOL(CM2BsProc);


CM2BsHandler::CM2BsHandler(CHandlerDirector * xptr): CParentHandler(xptr)
{
  m_proc = new CM2BsProc(this);
}

CBalanceContainer * CM2BsHandler::container() CONST
{
  return (CBalanceContainer *)connector()->container();
}

DVOID CM2BsHandler::checker_update()
{
  m_validator.refresh();
}

ni CM2BsHandler::handle_timeout(CONST ACE_Time_Value &, CONST DVOID *)
{
  if (m_validator.overdue())
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

ni CM2BsHandler::at_start()
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
  m_validator.refresh();

  return 0;
}


DVOID CM2BsHandler::at_finish()
{

}

PREPARE_MEMORY_POOL(CM2BsHandler);


CM2BsConn::CM2BsConn(CParentScheduler * p1, CHandlerDirector * p2): CParentConn(p1, p2)
{
  m_port_of_ip = CCfgX::instance()->bs_port;
  m_retry_delay = RETRY_DELAY;
  m_remote_ip = CCfgX::instance()->bs_addr;
}

CONST text * CM2BsConn::name() CONST
{
  return "CM2BsConn";
}

ni CM2BsConn::make_svc_handler(CParentHandler *& sh)
{
  sh = new CM2BsHandler(m_director);
  if (!sh)
  {
    C_ERROR("oom %s\n", name());
    return -1;
  }
  sh->container((void*)this);
  sh->reactor(reactor());
  return 0;
}

//dst
CDistTermItem::CDistTermItem(CBsDistData * p1, CTermStation * p2)
{
  dist_data = p1;
  condition = -1;
  prev_access = 0;
  term_station = p2;
}

truefalse CDistTermItem::is_ok() CONST
{
  return ((dist_data != NULL) && (condition >= 0 && condition <= 4));
}

truefalse CDistTermItem::connected()
{
  return term_station->connected();
}

CONST text * CDistTermItem::term_sn() CONST
{
  return term_station->term_sn();
}

ni CDistTermItem::term_position() CONST
{
  return term_station->term_position();
}

DVOID CDistTermItem::set_condition(ni m)
{
  if (m > condition)
    condition = m;
}

DVOID CDistTermItem::destruct_me()
{
  term_station->destruct_term_item(this);
}

DVOID CDistTermItem::set_checksum(CONST text * v_cs)
{
  if (unlikely(!dist_data->have_checksum()))
  {
    C_WARNING("recv cs reply term_sn(%s) did(%s)\n", term_sn(), dist_data->ver.get_ptr());
    return;
  }

  if (unlikely(checksum.get_ptr() && checksum.get_ptr()[0]))
    return;

  checksum.init(v_cs);
  set_condition(2);
}

DVOID CDistTermItem::post_subs(truefalse ok)
{
  CMB * mb = create_mb_of_download_sub(ok);
  CRunnerX::instance()->dist_to_middle_module()->post_bs(mb);
}

DVOID CDistTermItem::control_pause_stop(CONST text )
{
  destruct_me();
}

DVOID CDistTermItem::download_checksum_feedback(CONST text * cs_s)
{
  if (unlikely(*cs_s == 0))
  {
    text tmp[50];
    c_tools_convert_time_to_text(tmp, 50, true);
    CRunnerX::instance()->ping_component()->download_reply_gatherer().append(
        dist_data->ver.get_ptr(), dist_data->ftype[0], term_sn(), '2', '1', tmp);

    CRunnerX::instance()->ping_component()->download_reply_gatherer().append(
        dist_data->ver.get_ptr(), dist_data->ftype[0], term_sn(), '3', '1', tmp);

    CRunnerX::instance()->ping_component()->download_reply_gatherer().append(
        dist_data->ver.get_ptr(), dist_data->ftype[0], term_sn(), '4', '1', tmp);

    post_subs(true);

    term_station->destruct_term_item(this);
    return;
  }

  if (!checksum.get_ptr() || !checksum.get_ptr()[0])
  {
    set_checksum(cs_s);
    CRunnerX::instance()->db().set_dist_client_md5(term_sn(), dist_data->ver.get_ptr(), cs_s, 2);
  }

  on_conditon2();
}

truefalse CDistTermItem::work()
{
  if (!connected())
    return true;

  switch (condition)
  {
  case 0:
    return on_conditon0();

  case 1:
    return on_conditon1();

  case 2:
    return on_conditon2();

  case 3:
    return on_conditon3();

  case 4:
    return on_conditon4();

  case 5:
    return on_conditon5();

  case 6:
    return on_conditon6();

  case 7:
    return on_conditon7();

  case 8:
    return on_conditon8();

  default:
    C_ERROR("bad condtion (=%d)\n", condition);
    return false;
  }
}

truefalse CDistTermItem::on_conditon0()
{
  if (dist_data->have_checksum())
  {
    if(post_cs())
    {
      CRunnerX::instance()->db().set_dist_client_status(*this, 1);
      set_condition(1);
    }
    return true;
  }

  if (post_download())
  {
    CRunnerX::instance()->db().set_dist_client_status(*this, 3);
    set_condition(3);
  }
  return true;
}

truefalse CDistTermItem::on_conditon1()
{
  time_t t = time(NULL);
  if (t > prev_access + CS_FEEDBACK_TV * 60)
    post_cs();

  return true;
}

truefalse CDistTermItem::on_conditon2()
{
  if (!cmp_fn.get_ptr() || !cmp_fn.get_ptr()[0])
  {
    if ((dist_data->md5_opt_len > 0 && (ni)strlen(checksum.get_ptr()) >= dist_data->md5_opt_len) || !create_cmp_file())
    {
      cmp_fn.init(CCompFactory::single_fn());
      cmp_checksum.init(dist_data->mbz_md5.get_ptr());
    }
    CRunnerX::instance()->db().set_dist_client_mbz(term_sn(), dist_data->ver.get_ptr(), cmp_fn.get_ptr(), cmp_checksum.get_ptr());
  }

  if (post_download())
  {
    CRunnerX::instance()->db().set_dist_client_status(*this, 3);
    set_condition(3);
  }
  return true;
}

truefalse CDistTermItem::on_conditon3()
{
  time_t t = time(NULL);
  if (t > prev_access + DOWNLOAD_FEEDBACK_TV * 60)
    post_download();

  return true;
}

truefalse CDistTermItem::on_conditon4()
{
  return false;
}

truefalse CDistTermItem::on_conditon5()
{
  post_pause_stop('0');
  return true;
}

truefalse CDistTermItem::on_conditon6()
{
  return false;
}

truefalse CDistTermItem::on_conditon7()
{
  post_pause_stop('1');
  return true;
}

truefalse CDistTermItem::on_conditon8()
{
  return false;
}


ni CDistTermItem::calc_common_header_len()
{
  ni l_x1 = adir.get_ptr() ? strlen(adir.get_ptr()) : (ni)CCmdHeader::ITEM_NULL_SIZE;
  ni l_x2 = dist_data->aindex_len > 0 ? dist_data->aindex_len : (ni)CCmdHeader::ITEM_NULL_SIZE;
  return dist_data->ver_len + dist_data->findex_len + l_x2 + l_x1 + 4 + 2 + 2;
}

DVOID CDistTermItem::format_common_header(text * v_ptr)
{
  sprintf(v_ptr, "%s%c%s%c%s%c%s%c%c%c%c%c",
      dist_data->ver.get_ptr(), CCmdHeader::ITEM_SEPARATOR,
      dist_data->findex.get_ptr(), CCmdHeader::ITEM_SEPARATOR,
      adir.get_ptr()? adir.get_ptr(): Item_NULL, CCmdHeader::ITEM_SEPARATOR,
      dist_data->aindex.get_ptr()? dist_data->aindex.get_ptr(): Item_NULL, CCmdHeader::ITEM_SEPARATOR,
      dist_data->ftype[0], CCmdHeader::ITEM_SEPARATOR,
      dist_data->type[0], CCmdHeader::FINISH_SEPARATOR);
}

CMB * CDistTermItem::create_mb_of_download_sub(truefalse fine)
{
  CMemProt l_cs;
  text tmp[32];
  c_tools_convert_time_to_text(tmp, 32, true);
  CONST text * l_x;
  if (c_tell_type_multi(dist_data->type[0]))
  {
    if (!checksum.get_ptr())
      l_x = "";
    else
    {
      l_cs.init(checksum.get_ptr());
      c_tools_text_replace(l_cs.get_ptr(), CCmdHeader::ITEM_SEPARATOR, ':');
      ni len = strlen(l_cs.get_ptr());
      if (l_cs.get_ptr()[len - 1] == ':')
        l_cs.get_ptr()[len - 1] = 0;
      l_x = l_cs.get_ptr();
    }
  }
  else
    l_x = dist_data->findex.get_ptr();

  ni l_m = strlen(term_station->term_sn()) + strlen(dist_data->ver.get_ptr()) +
      strlen(tmp) + strlen(dist_data->findex.get_ptr()) + strlen(l_x) + 10;
  CMB * mb = CCacheX::instance()->get_mb_bs(l_m, CONST_BS_DIST_FBDETAIL_CMD);
  text * l_ptr = mb->base() + CBSData::DATA_OFFSET;
  sprintf(l_ptr, "%s#%c#%s#%s#%s#%c#%c#%s", dist_data->ver.get_ptr(),
      dist_data->ftype[0], term_station->term_sn(), dist_data->findex.get_ptr(),
      l_x, dist_data->type[0], fine? '1': '0', tmp);
  l_ptr[l_m] = CBSData::END_MARK;
  return mb;
}

truefalse CDistTermItem::post_cs()
{
  if (!dist_data->md5.get_ptr() || !dist_data->md5.get_ptr()[0] || dist_data->md5_len <= 0)
    return false;

  ni l_cs_size = dist_data->md5_len + 1;
  ni l_m = calc_common_header_len() + l_cs_size;
  CMB * mb = CCacheX::instance()->get_mb_cmd(l_m, CCmdHeader::PT_FILE_MD5_LIST);
  CCmdExt * l_ptr = (CCmdExt *)mb->base();
  l_ptr->signature = term_position();
  format_common_header(l_ptr->data);
  memcpy(l_ptr->data + l_m - l_cs_size, dist_data->md5.get_ptr(), l_cs_size);

  prev_access = time(NULL);

  return c_tools_mb_putq(CRunnerX::instance()->ping_component()->scheduler(), mb, "checksum");
}

truefalse CDistTermItem::create_cmp_file()
{
  CMemProt l_to_dir;
  CMemProt l_cmp_path;
  CMemProt l_to_fn;
  l_to_dir.init(CCfgX::instance()->bz_files_path.c_str(), "/", dist_data->ver.get_ptr());
  l_cmp_path.init(l_to_dir.get_ptr(), "/", CCompFactory::dir_of_composite());
  l_to_fn.init(l_cmp_path.get_ptr(), "/", term_sn(), ".mbz");
  CCompUniter l_uniter;
  if (!l_uniter.begin(l_to_fn.get_ptr()))
    return false;
  CMemProt l_cs2;
  l_cs2.init(checksum.get_ptr());
  text separators[2] = { CCmdHeader::ITEM_SEPARATOR, 0 };
  CTextDelimiter l_delimiter(l_cs2.get_ptr(), separators);
  text * l_tag;
  CMemProt l_fn;
  while ((l_tag =l_delimiter.get()) != NULL)
  {
    l_fn.init(l_to_dir.get_ptr(), "/", l_tag, ".mbz");
    if (!l_uniter.append(l_fn.get_ptr()))
    {
      CSysFS::remove(l_to_fn.get_ptr());
      return false;
    }
  }

  CMemProt l_cs;
  if (!c_tools_tally_md5(l_to_fn.get_ptr(), l_cs))
  {
    C_ERROR("can not compute cs: %s\n", l_to_fn.get_ptr());
    CSysFS::remove(l_to_fn.get_ptr());
    return false;
  }

  cmp_fn.init(l_to_fn.get_ptr() + strlen(l_to_dir.get_ptr()) + 1);
  cmp_checksum.init(l_cs.get_ptr());
  return true;
}

truefalse CDistTermItem::post_pause_stop(CONST text c)
{
  ni l_m = dist_data->ver_len + 2;
  CMB * mb = CCacheX::instance()->get_mb_cmd(l_m, CCmdHeader::PT_PSP);
  CCmdExt * l_ptr = (CCmdExt *)mb->base();
  l_ptr->signature = term_position();
  l_ptr->data[0] = c;
  memcpy(l_ptr->data + 1, dist_data->ver.get_ptr(), l_m - 1);
  prev_access = time(NULL);
  return c_tools_mb_putq(CRunnerX::instance()->ping_component()->scheduler(), mb, "control pause stop");
}

truefalse CDistTermItem::post_download()
{
  CONST text * download_fn;
  CONST text * l_cmp_cs;

  if (!dist_data->have_checksum())
  {
    download_fn = CCompFactory::single_fn();
    l_cmp_cs = dist_data->mbz_md5.get_ptr();
  } else
  {
    download_fn = cmp_fn.get_ptr();
    l_cmp_cs = cmp_checksum.get_ptr();
  }

  ni l_m = strlen(l_cmp_cs) + 1;
  ni l_header_size = calc_common_header_len();
  ni l_download_fn_size = strlen(download_fn) + 1;
  ni l_n = l_header_size + l_download_fn_size + dist_data->password_len + 1 + l_m;
  CMB * mb = CCacheX::instance()->get_mb_cmd(l_n, CCmdHeader::PT_FTP_FILE);
  CCmdExt * l_ptr = (CCmdExt *)mb->base();
  l_ptr->signature = term_position();
  format_common_header(l_ptr->data);
  text * l_ptr2 = l_ptr->data + l_header_size;
  memcpy(l_ptr2, download_fn, l_download_fn_size);
  l_ptr2 += l_download_fn_size;
  *(l_ptr2 - 1) = CCmdHeader::ITEM_SEPARATOR;
  memcpy(l_ptr2, l_cmp_cs, l_m);
  l_ptr2 += l_m;
  *(l_ptr2 - 1) = CCmdHeader::FINISH_SEPARATOR;
  memcpy(l_ptr2, dist_data->password.get_ptr(), dist_data->password_len + 1);

  prev_access = time(NULL);

  return c_tools_mb_putq(CRunnerX::instance()->ping_component()->scheduler(), mb, "checksums");
}


CTermStation::CTermStation(CTermStations * p1, CONST text * p2): m_term_sn(p2)
{
  m_stations = p1;
  m_term_position = -1;
}

CTermStation::~CTermStation()
{
  reset();
}

CONST text * CTermStation::term_sn() CONST
{
  return m_term_sn.to_str();
}

ni CTermStation::term_position() CONST
{
  return m_term_position;
}

truefalse CTermStation::connected()
{
  truefalse change;
  return g_term_sns->connected(m_term_sn, m_term_position, change);
}

truefalse CTermStation::check_term_sn(CONST text * v_term_sn) CONST
{
  return strcmp(m_term_sn.to_str(), v_term_sn) == 0;
}

CDistTermItem * CTermStation::generate_term_item(CBsDistData * v_data)
{
  DVOID * p = CCacheX::instance()->get_raw(sizeof(CDistTermItem));
  CDistTermItem * l_ptr = new (p) CDistTermItem(v_data, this);
  m_items.push_back(l_ptr);
  m_stations->at_new_term_item(l_ptr);
  return l_ptr;
}

DVOID CTermStation::destruct_term_item(CDistTermItem * v_item)
{
  m_stations->at_del_term_item(v_item, false);
  m_items.remove(v_item);
  CRunnerX::instance()->db().delete_dist_client(m_term_sn.to_str(), v_item->dist_data->ver.get_ptr());
  CPoolObjectDeletor prot;
  prot(v_item);
}

DVOID CTermStation::reset()
{
  std::for_each(m_items.begin(), m_items.end(), CPoolObjectDeletor());
  m_items.clear();
}

truefalse CTermStation::work()
{
  truefalse change;
  if (!g_term_sns->connected(m_term_sn, m_term_position, change))
    return !m_items.empty();

  CDistTermItems::iterator l_x;

  if (unlikely(change))
  {
    g_term_sns->server_changed(m_term_position, false);
    for (l_x = m_items.begin(); l_x != m_items.end(); ++l_x)
      m_stations->at_del_term_item(*l_x, false);
    reset();
    CRunnerX::instance()->db().load_dist_clients(m_stations, this);
    C_DEBUG("fetching term(%s) from database\n", m_term_sn.to_str());
  }

  for (l_x = m_items.begin(); l_x != m_items.end(); )
  {
    if (!(*l_x)->work())
    {
      m_stations->at_del_term_item(*l_x, true);
      CPoolObjectDeletor prot;
      prot(*l_x);
      l_x = m_items.erase(l_x);
    } else
      ++l_x;
  }
  return !m_items.empty();
}


CTermQuickFinder::CTermQuickFinder(CONST text * p1, CONST text * p2)
{
  did = p1;
  term_sn = p2;
}

truefalse CTermQuickFinder::operator == (CONST CTermQuickFinder & v_obj) CONST
{
  return strcmp(did, v_obj.did) == 0 && strcmp(term_sn, v_obj.term_sn) == 0;
}


CTermStations::CTermStations(CBsDistDatas * p)
{
  m_datas = p;
  database_ts = 0;
  m_term_station_done = 0;
}

CTermStations::~CTermStations()
{
  reset();
}

DVOID CTermStations::reset()
{
  std::for_each(term_stations.begin(), term_stations.end(), CPoolObjectDeletor());
  term_stations.clear();
  m_term_items.clear();
  m_term_stations.clear();
  database_ts = 0;
}

DVOID CTermStations::at_new_term_item(CDistTermItem * p)
{
  m_term_items.insert(std::pair<const CTermQuickFinder, CDistTermItem *>
     (CTermQuickFinder(p->dist_data->ver.get_ptr(), p->term_sn()), p));
}

DVOID CTermStations::at_del_term_item(CDistTermItem * p, truefalse done)
{
  if (done)
    ++m_term_station_done;
  m_term_items.erase(CTermQuickFinder(p->dist_data->ver.get_ptr(), p->term_sn()));
}

CBsDistData * CTermStations::search_dist_data(CONST text * did)
{
  C_ASSERT_RETURN(m_datas, "", NULL);
  return m_datas->search(did);
}

CDistTermItem * CTermStations::search_term_item(CONST text * v_term_sn, CONST text * v_did)
{
  CDistTermItemMap::iterator it;
  it = m_term_items.find(CTermQuickFinder(v_did, v_term_sn));
  if (it == m_term_items.end())
    return NULL;
  else
    return it->second;
}

CTermStation * CTermStations::search_term_station(CONST text * v_term_sn)
{
  CTermStationMap::iterator it;
  it = m_term_stations.find(v_term_sn);
  if (it == m_term_stations.end())
    return NULL;
  else
    return it->second;
}

CTermStation * CTermStations::generate_term_station(CONST text * v_term_sn)
{
  DVOID * p = CCacheX::instance()->get_raw(sizeof(CTermStation));
  CTermStation * l_x = new (p) CTermStation(this, v_term_sn);
  term_stations.push_back(l_x);
  m_term_stations.insert(std::pair<const text *, CTermStation *>(l_x->term_sn(), l_x));
  return l_x;
}

DVOID CTermStations::destruct_term_station(CTermStation * v_ptr)
{
  m_term_stations.erase(v_ptr->term_sn());
  CPoolObjectDeletor prot;
  prot(v_ptr);
}

DVOID CTermStations::work()
{
  m_term_station_done = 0;
  CTermStationList::iterator l_x;
  for (l_x = term_stations.begin(); l_x != term_stations.end(); )
  {
    if (!(*l_x)->work())
    {
      m_term_stations.erase((*l_x)->term_sn());
      CPoolObjectDeletor prot;
      prot(*l_x);
      l_x = term_stations.erase(l_x);
    } else
      ++l_x;
  }
  if (m_term_station_done > 0)
    C_INFO("term station done = %d\n", m_term_station_done);
  C_INFO("Dist finished: jobs = %d, stations = %d, items = %d\n", m_datas->size(),  m_term_stations.size(), m_term_items.size());
}


CSpreader::CSpreader(): m_stations(&m_datas)
{
  m_prev_start = 0;
  m_prev_stop = 0;
}

truefalse CSpreader::work(truefalse v_query_db)
{
  time_t t = time(NULL);
  truefalse l_query_db = false;
  if (v_query_db)
    l_query_db = m_datas.need_reload();
  else if (t - m_prev_stop < Vacation_Delay * 60)
    return false;
  else
    l_query_db = m_datas.need_reload();

  if (CRunnerX::instance()->ping_component())
    CRunnerX::instance()->ping_component()->pl();

  if (unlikely(l_query_db))
    C_INFO("querying items from database...\n");

  m_prev_start = t;
  do_jobs(l_query_db);
  do_term_stations(l_query_db);
  m_prev_stop = time(NULL);
  return true;
}

truefalse CSpreader::do_jobs(truefalse v_query_db)
{
  if (v_query_db)
  {
    m_datas.alloc_spaces(0);
    return (CRunnerX::instance()->db().load_dist_infos(m_datas) < 0)? false:true;
  }

  return true;
}

truefalse CSpreader::do_term_stations(truefalse v_query_db)
{
  if (v_query_db)
  {
    m_stations.reset();
    if (!CRunnerX::instance()->db().load_dist_clients(&m_stations, NULL))
      return false;
  }

  m_stations.work();
  return true;
}

DVOID CSpreader::at_download_cmd_feedback(CONST text * v_term_sn, CONST text * v_did, ni v_condition, truefalse v_fine)
{
  CDistTermItem * l_item = m_stations.search_term_item(v_term_sn, v_did);
  if (unlikely(l_item == NULL))
    return;

  if (v_condition <= 3)
  {
    l_item->set_condition(v_condition);
    CRunnerX::instance()->db().set_dist_client_status(v_term_sn, v_did, v_condition);
  }
  else
  {
    l_item->post_subs(v_fine);
    l_item->destruct_me();
  }
}

DVOID CSpreader::at_download_checksum_feedback(CONST text * v_term_sn, CONST text * v_did, CONST text * v_cs_s)
{
  CDistTermItem * l_item = m_stations.search_term_item(v_term_sn, v_did);
  if (likely(l_item != NULL))
    l_item->download_checksum_feedback(v_cs_s);
}

DVOID CSpreader::control_pause_stop(CONST text * v_term_sn, CONST text * v_did, text v_x)
{
  CDistTermItem * l_item = m_stations.search_term_item(v_term_sn, v_did);
  if (likely(l_item != NULL))
    l_item->control_pause_stop(v_x);
}


CHeartBeatGatherer * CPingProc::m_heart_beat_submitter = NULL;
CIPVerGatherer * CPingProc::m_ip_ver_submitter = NULL;
CDownloadReplyGatherer * CPingProc::m_ftp_feedback_submitter = NULL;
CClickGatherer * CPingProc::m_adv_click_submitter = NULL;
CHwPowerTimeGatherer * CPingProc::m_pc_on_off_submitter = NULL;
CHardwareWarnGatherer * CPingProc::m_hardware_alarm_submitter = NULL;
CVideoGatherer * CPingProc::m_vlc_submitter = NULL;
CNoVideoWarnGatherer * CPingProc::m_vlc_empty_submitter = NULL;

CPingProc::CPingProc(CParentHandler * ptr): CParentServerProc(ptr)
{
  m_handler->msg_queue()->high_water_mark(MQ_PEAK);
  m_hw_ver[0] = 0;
}

CONST text * CPingProc::name() CONST
{
  return "CPingProc";
}

CProc::OUTPUT CPingProc::at_head_arrival()
{
  if (baseclass::at_head_arrival() == OP_FAIL)
    return OP_FAIL;

  if (m_data_head.cmd == CCmdHeader::PT_PING)
  {
    if (!c_packet_check_ping(&m_data_head))
    {
      CMemProt info;
      get_sinfo(info);
      C_ERROR("invalid ping from %s\n", info.get_ptr());
      return OP_FAIL;
    }

    handle_heart_beat();
    return OP_DONE;
  }

  if (m_data_head.cmd == CCmdHeader::PT_VER_REQ)
  {
    if (!c_packet_check_term_ver_req(&m_data_head, 30))
    {
      CMemProt l_x;
      get_sinfo(l_x);
      C_ERROR("invalid ver from %s\n", l_x.get_ptr());
      return OP_FAIL;
    }
    return OP_OK;
  }

  if (m_data_head.cmd == CCmdHeader::PT_VLC_EMPTY)
  {
    if (!c_packet_check_vlc_empty(&m_data_head))
    {
      CMemProt l_x;
      get_sinfo(l_x);
      C_ERROR("invalid video null from %s\n", l_x.get_ptr());
      return OP_FAIL;
    }
    return OP_OK;
  }


  if (m_data_head.cmd == CCmdHeader::PT_HARDWARE_ALARM)
  {
    if (!c_packet_check_plc_alarm(&m_data_head))
    {
      CMemProt l_x;
      get_sinfo(l_x);
      C_ERROR("invalid hw warn from %s\n", l_x.get_ptr());
      return OP_FAIL;
    }
    C_DEBUG("recv hw warn from %s\n", m_term_sn.to_str());
    return OP_OK;
  }

  if (m_data_head.cmd == CCmdHeader::PT_FILE_MD5_LIST)
  {
    if (!c_packet_check_file_md5_list(&m_data_head))
    {
      CMemProt l_x;
      get_sinfo(l_x);
      C_ERROR("invalid checksum from %s\n", l_x.get_ptr());
      return OP_FAIL;
    } else
    {
      CMemProt l_x;
      get_sinfo(l_x);
      C_INFO("recv checksum from %s, size = %d\n", l_x.get_ptr(), m_data_head.size);
    }
    return OP_OK;
  }

  if (m_data_head.cmd == CCmdHeader::PT_FTP_FILE)
  {
    if (!c_packet_check_ftp_file(&m_data_head))
    {
      CMemProt l_x;
      get_sinfo(l_x);
      C_ERROR("invalid download reply from %s\n", l_x.get_ptr());
      return OP_FAIL;
    }
    return OP_OK;
  }

  if (m_data_head.cmd == CCmdHeader::PT_IP_VER_REQ)
  {
    if (m_data_head.size != sizeof(CIpVerReq) || m_data_head.signature != CCmdHeader::SIGNATURE)
    {
      CMemProt l_x;
      get_sinfo(l_x);
      C_ERROR("invalid ipver from %s\n", l_x.get_ptr());
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
      CMemProt l_x;
      get_sinfo(l_x);
      C_ERROR("invalid clicks from %s\n", l_x.get_ptr());
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
      CMemProt l_x;
      get_sinfo(l_x);
      C_ERROR("invalid video req from %s\n", l_x.get_ptr());
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
      CMemProt l_x;
      get_sinfo(l_x);
      C_ERROR("invalid station power time from %s\n", l_x.get_ptr());
      return OP_FAIL;
    }
    C_DEBUG("recv station power time from %s\n", m_term_sn.to_str());
    return OP_OK;
  }

  if (m_data_head.cmd == CCmdHeader::PT_TEST)
  {
    if (m_data_head.signature != CCmdHeader::SIGNATURE)
    {
      CMemProt l_x;
      get_sinfo(l_x);
      C_ERROR("invalid test from %s\n", l_x.get_ptr());
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
      CMemProt l_x;
      get_sinfo(l_x);
      C_ERROR("invalid pause stop from %s\n", l_x.get_ptr());
      return OP_FAIL;
    }
    return OP_OK;
  }


  C_ERROR(ACE_TEXT("recv unknown data, command = %d\n"), m_data_head.cmd);

  return OP_FAIL;
}

CProc::OUTPUT CPingProc::do_read_data(CMB * mb)
{
  CParentServerProc::do_read_data(mb);

  {
    CMemProt info;
    get_sinfo(info);
    C_DEBUG("recv full data: cmd = %d, size = %d from %s\n", m_data_head.cmd, m_data_head.size, info.get_ptr());
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
  C_ERROR("get unknown cmd = %d\n",
      header->cmd);
  return OP_FAIL;
}

DVOID CPingProc::handle_heart_beat()
{
  m_heart_beat_submitter->append(m_term_sn.to_str(), m_term_sn_len);
}

CProc::OUTPUT CPingProc::do_version_check(CMB * mb)
{
  CMBProt prot(mb);
  CTermSNs & term_SNs = CRunnerX::instance()->termSNs();
  CCmdExt * l_ptr = (CCmdExt *) mb->base();
  if (!l_ptr->validate())
  {
    CMemProt l_x;
    get_sinfo(l_x);
    C_ERROR(ACE_TEXT("invalid term ver data: %s\n"), l_x.get_ptr());
    return OP_FAIL;
  }

  {
    CTerminalVerReq * l_x = (CTerminalVerReq *)mb->base();
    if (l_x->uuid[0] != 0)
      memcpy(m_remote_ip, l_x->uuid, 16);
  }

  ACE_OS::strsncpy(m_hw_ver, ((CTerminalVerReq*)mb->base())->hw_ver, 12);
  if (m_hw_ver[0] == 0)
  {
    ACE_OS::strcpy(m_hw_ver, "NULL");
    CMemProt l_x;
    get_sinfo(l_x);
    C_WARNING("term ver contains no hw ver: %s\n", l_x.get_ptr());
  }
  CProc::OUTPUT l_result = i_is_ver_ok(mb, term_SNs);

  m_ip_ver_submitter->append(m_term_sn.to_str(), m_term_sn_len, m_remote_ip, m_term_ver.to_text(), m_hw_ver);

  if (l_result != OP_GO_ON)
    return l_result;

  CTermData l_term_data;
  term_SNs.get_termData(m_term_loc, l_term_data);

  CMB * l_mbx;
  if (m_term_ver < CCfgX::instance()->client_ver_min)
  {
    l_mbx = i_create_mb_ver_reply(CTermVerReply::SC_NOT_MATCH, l_term_data.download_auth_len + 2);
    m_mark_down = true;
  }
  else if (m_term_ver < CCfgX::instance()->client_ver_now)
    l_mbx = i_create_mb_ver_reply(CTermVerReply::SC_OK_UP, l_term_data.download_auth_len + 2);
  else
    l_mbx = i_create_mb_ver_reply(CTermVerReply::SC_OK, l_term_data.download_auth_len + 2);

  if (!m_mark_down)
  {
    CTerminalVerReq * l_z = (CTerminalVerReq *)mb->base();
    if (l_z->server_id != CCfgX::instance()->server_id)
      term_SNs.server_changed(m_term_loc, true);

    CMemProt l_x;
    get_sinfo(l_x);
    C_INFO(ACE_TEXT("client version check ok: %s\n"), l_x.get_ptr());
  }

  CTermVerReply * l_vr = (CTermVerReply *) l_mbx->base();
  *((u_int8_t*)l_vr->data) = CCfgX::instance()->server_id;
  memcpy(l_vr->data + 1, l_term_data.download_auth, l_term_data.download_auth_len + 1);
  if (m_handler->post_packet(l_mbx) < 0)
    return OP_FAIL;
  return do_send_pq();
}

CProc::OUTPUT CPingProc::do_send_pq()
{
  CMemProt l_x;
  if (!CRunnerX::instance()->ping_component()->get_pl(l_x))
    return OP_OK;
  ni l_len = strlen(l_x.get_ptr()) + 1;
  CMB * mb = CCacheX::instance()->get_mb_cmd(l_len, CCmdHeader::PT_TQ);
  CCmdExt * l_ptr = (CCmdExt*) mb->base();
  memcpy(l_ptr->data, l_x.get_ptr(), l_len);
  if (m_handler->post_packet(mb) < 0)
    return OP_FAIL;
  else
    return OP_OK;
}

CProc::OUTPUT CPingProc::do_md5_file_list(CMB * mb)
{
  CCmdExt * l_checksums = (CCmdExt *)mb->base();
  if (unlikely(!l_checksums->validate()))
  {
    CMemProt l_x;
    get_sinfo(l_x);
    C_ERROR("invalid checksum from %s\n", l_x.get_ptr());
    return OP_FAIL;
  }

  {
    CMemProt l_x;
    get_sinfo(l_x);
    C_DEBUG("full checksum from %s, size = %d\n", l_x.get_ptr(), mb->length());
  }

  CRunnerX::instance()->ping_component()->service()->add_request_slow(mb);
  return OP_OK;
}

CProc::OUTPUT CPingProc::do_ftp_reply(CMB * mb)
{
  CCmdExt * l_checksums = (CCmdExt *)mb->base();
  if (unlikely(!l_checksums->validate()))
  {
    CMemProt l_x;
    get_sinfo(l_x);
    C_ERROR("invalid download feedback from %s\n", l_x.get_ptr());
    return OP_FAIL;
  }
  CMB * l_mbx = CCacheX::instance()->get_mb_ack(mb);
  CRunnerX::instance()->ping_component()->service()->add_request(mb, true);
  if (l_mbx != NULL)
    if (m_handler->post_packet(l_mbx) < 0)
      return OP_FAIL;
  return OP_OK;
}

CProc::OUTPUT CPingProc::do_ip_ver_req(CMB * mb)
{
  CMBProt prot(mb);
  m_ip_ver_submitter->append(m_term_sn.to_str(), m_term_sn_len, m_remote_ip, m_term_ver.to_text(), m_hw_ver);
  return OP_OK;
}

CProc::OUTPUT CPingProc::do_adv_click_req(CMB * mb)
{
  CMBProt prot(mb);
  CCmdExt * l_ptr = (CCmdExt *)mb->base();
  if (unlikely(!l_ptr->validate()))
  {
    CMemProt l_x;
    get_sinfo(l_x);
    C_ERROR("invalid click from %s\n", l_x.get_ptr());
    return OP_FAIL;
  }

  CONST text l_xxx[] = {CCmdHeader::FINISH_SEPARATOR, 0};
  CTextDelimiter l_delimiter(l_ptr->data, l_xxx);
  text * l_data;
  while ((l_data = l_delimiter.get()) != NULL)
  {
    CONST text l_yyy[] = {CCmdHeader::ITEM_SEPARATOR, 0};
    CTextDelimiter l_delimiter_2(l_data, l_yyy);
    CONST text * chn = l_delimiter_2.get();
    CONST text * pcode = l_delimiter_2.get();
    CONST text * l_x;
    if (unlikely(!pcode))
      continue;
    l_x = l_delimiter_2.get();
    if (unlikely(!l_x))
      continue;
    if (strlen(l_x) >= 12)
      continue;
    m_adv_click_submitter->append(m_term_sn.to_str(), m_term_sn_len, chn, pcode, l_x);
  }

  return OP_OK;
}

CProc::OUTPUT CPingProc::do_hardware_alarm_req(CMB * mb)
{
  CMBProt prot(mb);
  CPLCWarning * l_warn = (CPLCWarning *) mb->base();
  if (unlikely((l_warn->x != '1' && l_warn->x != '2' && l_warn->x != '5' && l_warn->x != '6') ||
      (l_warn->y < '0' || l_warn->y > '3')))
  {
    CMemProt l_x;
    get_sinfo(l_x);
    C_ERROR("invalid hw warn from %s, a = %c, b = %c\n", l_x.get_ptr(), l_warn->x, l_warn->y);
    return OP_FAIL;
  }

  text tmp[32];
  c_tools_convert_time_to_text(tmp, 20, true);
  m_hardware_alarm_submitter->append(m_term_sn.to_str(), m_term_sn_len, l_warn->x, l_warn->y, tmp);
  return OP_OK;
}

CProc::OUTPUT CPingProc::do_vlc_req(CMB * mb)
{
  CMBProt prot(mb);
  CCmdExt * l_ptr = (CCmdExt *)mb->base();
  if (unlikely(!l_ptr->validate()))
  {
    CMemProt l_x;
    get_sinfo(l_x);
    C_ERROR("invalid video from %s\n", l_x.get_ptr());
    return OP_FAIL;
  }

  text l_xxx[2] = {CCmdHeader::ITEM_SEPARATOR, 0};
  CTextDelimiter l_delimiter(l_ptr->data, l_xxx);
  text * l_tag;
  while ((l_tag = l_delimiter.get()) != NULL)
  {
    text * l_p = strchr(l_tag, CCmdHeader::MIDDLE_SEPARATOR);
    if (!l_p)
      continue;
    *l_p ++ = 0;
    m_vlc_submitter->append(m_term_sn.to_str(), m_term_sn_len, l_tag, l_p);
  }
  return OP_OK;
}

CProc::OUTPUT CPingProc::do_vlc_empty_req(CMB * mb)
{
  CMBProt prot(mb);
  CCmdExt * l_ptr = (CCmdExt *)mb->base();
  text l_z = l_ptr->data[0];
  if (l_z != '1' && l_z != '0')
  {
    CMemProt l_x;
    get_sinfo(l_x);
    C_ERROR("bad vlc empty packet from %s, data = %c\n", l_x.get_ptr(), l_z);
  } else
    m_vlc_empty_submitter->append(m_term_sn.to_str(), m_term_sn_len, l_z);
  return OP_OK;
}

CProc::OUTPUT CPingProc::do_psp(CMB * mb)
{
  CRunnerX::instance()->ping_component()->service()->add_request(mb, true);
  return OP_OK;
}

CProc::OUTPUT CPingProc::do_pc_on_off_req(CMB * mb)
{
  CMBProt prot(mb);
  CCmdExt * l_ptr = (CCmdExt *)mb->base();
  if (unlikely(!l_ptr->validate()))
  {
    CMemProt l_x;
    get_sinfo(l_x);
    C_ERROR("invalid hw power time from %s\n", l_x.get_ptr());
    return OP_FAIL;
  }

  if (unlikely(l_ptr->data[0] != '1' && l_ptr->data[0] != '2' && l_ptr->data[0] != '3'))
  {
    C_ERROR("bad hw power time flag (%c)\n", l_ptr->data[0]);
    return OP_FAIL;
  }

  m_pc_on_off_submitter->append(m_term_sn.to_str(), m_term_sn_len, l_ptr->data[0], l_ptr->data + 1);
  return OP_OK;
}

CProc::OUTPUT CPingProc::do_test(CMB * mb)
{
  C_DEBUG("handle test %d bytes...\n", mb->length());
  CCmdHeader * l_header = (CCmdHeader *) mb->base();
  l_header->signature = CCmdHeader::SIGNATURE;
  m_handler->post_packet(mb);
  return OP_OK;
}

PREPARE_MEMORY_POOL(CPingProc);


CGatheredData::CGatheredData(ni block_size, ni max_item_length, CParentGatherer * submitter, truefalse auto_submit)
{
  m_block_size = block_size;
  m_max_item_length = max_item_length + 1;
  m_gatherer = submitter;
  m_auto_submit = auto_submit;
  m_mb = CCacheX::instance()->get_mb(m_block_size);
  submitter->add_chunk(this);
  clear();
}

CGatheredData::~CGatheredData()
{
  if (m_mb)
    m_mb->release();
}

DVOID CGatheredData::clear()
{
  m_current_ptr = m_mb->base();
}

truefalse CGatheredData::append(CONST text * item, ni len)
{
  if (len == 0)
    len = strlen(item);
  ++len;
  ni remain_len = m_block_size - (m_current_ptr - m_mb->base());
  if (unlikely(len > remain_len))
  {
    if (m_auto_submit)
    {
      m_gatherer->post();
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

truefalse CGatheredData::append(text c)
{
  text buff[2];
  buff[0] = c;
  buff[1] = 0;
  return append(buff, 1);
}

CONST text * CGatheredData::data()
{
  return m_mb->base();
}

ni CGatheredData::data_len() CONST
{
  ni result = (m_current_ptr - m_mb->base());
  return std::max(result - 1, 0);
}


CParentGatherer::~CParentGatherer()
{

}

DVOID CParentGatherer::post()
{
  i_post(get_command());
  clear();
}

DVOID CParentGatherer::post_if_needed()
{
  if ((*m_chunks.begin())->data_len() == 0)
    return;

  post();
}

DVOID CParentGatherer::add_chunk(CGatheredData * ptr)
{
  m_chunks.push_back(ptr);
}

DVOID CParentGatherer::i_post(CONST text * ptr)
{
  if (unlikely((*m_chunks.begin())->data_len() == 0))
    return;
  CGatheredDatas::iterator it;

  ni l_m = 0;
  for (it = m_chunks.begin(); it != m_chunks.end(); ++it)
    l_m += (*it)->data_len() + 1;
  --l_m;

  CMB * mb = CCacheX::instance()->get_mb_bs(l_m, ptr);
  text * l_to = mb->base() + CBSData::DATA_OFFSET;
  for (it = m_chunks.begin(); ; )
  {
    ni l_n = (*it)->data_len();
    memcpy(l_to, (*it)->data(), l_n);
    if (++it != m_chunks.end())
    {
      l_to[l_n] = CBSData::PARAM_SEPARATOR;
      l_to += (l_n + 1);
    } else
      break;
  }
  CRunnerX::instance()->dist_to_middle_module()->post_bs(mb);
}

DVOID CParentGatherer::clear()
{
  std::for_each(m_chunks.begin(), m_chunks.end(), std::mem_fun(&CGatheredData::clear));
};




CDownloadReplyGatherer::CDownloadReplyGatherer():
  m_dist_id_block(BUFF_LEN, 32, this), m_ftype_block(BUFF_LEN, 1, this), m_client_id_block(BUFF_LEN, sizeof(CNumber), this),
  m_step_block(BUFF_LEN, 1, this), m_ok_flag_block(BUFF_LEN, 1, this), m_date_block(BUFF_LEN, 15, this)
{

}

CDownloadReplyGatherer::~CDownloadReplyGatherer()
{

}

CONST text * CDownloadReplyGatherer::get_command() CONST
{
  return CONST_BS_DIST_FEEDBACK_CMD;
}

DVOID CDownloadReplyGatherer::append(CONST text * v_did, text ftype, CONST text *term_sn, text step, text fine, CONST text * v_dt)
{
  truefalse ret = true;

  if (!m_dist_id_block.append(v_did))
    ret = false;
  if (!m_client_id_block.append(term_sn))
    ret = false;
  if (!m_ftype_block.append(ftype))
    ret = false;
  if (!m_step_block.append(step))
    ret = false;
  if (!m_ok_flag_block.append(fine))
    ret = false;
  if (!m_date_block.append(v_dt))
    ret = false;

  if (!ret)
    post();
}



CHeartBeatGatherer::CHeartBeatGatherer(): m_block(BUFF_LEN, sizeof(CNumber), this, true)
{

}

CHeartBeatGatherer::~CHeartBeatGatherer()
{

}

DVOID CHeartBeatGatherer::append(CONST text * term_sn, CONST ni m)
{
  if (unlikely(!term_sn || !*term_sn || m <= 0))
    return;
  if (!m_block.append(term_sn, m))
    post();
}

CONST text * CHeartBeatGatherer::get_command() CONST
{
  return CONST_BS_PING_CMD;
}


CIPVerGatherer::CIPVerGatherer():
    m_id_block(BUFF_LEN, sizeof(CNumber), this),
    m_ip_block(BUFF_LEN, INET_ADDRSTRLEN, this),
    m_ver_block(BUFF_LEN * 3 / sizeof(CNumber) + 1, 7, this)//,
{

}

DVOID CIPVerGatherer::append(CONST text * term_sn, ni sn_size, CONST text * ip, CONST text * ver, CONST text *)
{
  truefalse l_x = true;
  if (!m_id_block.append(term_sn, sn_size))
    l_x = false;
  if (!m_ip_block.append(ip, 0))
    l_x = false;
  if (!m_ver_block.append(ver, 0))
    l_x = false;

  if (!l_x)
    post();
}

CONST text * CIPVerGatherer::get_command() CONST
{
  return CONST_BS_IP_VER_CMD;
}



CHwPowerTimeGatherer::CHwPowerTimeGatherer(): m_id_block(BUFF_LEN, sizeof(CNumber), this),
    m_on_off_block(BUFF_LEN / 10, 1, this), m_datetime_block(BUFF_LEN, 25, this)
{

}

DVOID CHwPowerTimeGatherer::append(CONST text * term_sn, ni sn_size, CONST text isOn, CONST text * v_dt)
{
  truefalse l_x = true;
  if (!m_id_block.append(term_sn, sn_size))
    l_x = false;
  if (!m_on_off_block.append(isOn))
    l_x = false;
  if (!m_datetime_block.append(v_dt, 0))
    l_x = false;

  if (!l_x)
    post();
}

CONST text * CHwPowerTimeGatherer::get_command() CONST
{
  return CONST_BS_POWERON_LINK_CMD;
}


CClickGatherer::CClickGatherer() : m_id_block(BUFF_LEN, sizeof(CNumber), this),
    m_chn_block(BUFF_LEN, 50, this), m_pcode_block(BUFF_LEN, 50, this), m_number_block(BUFF_LEN, 24, this)
{

}

DVOID CClickGatherer::append(CONST text * term_sn, ni sn_size, CONST text * chn, CONST text * pcode, CONST text * v_count)
{
  truefalse l_x = true;
  if (!m_id_block.append(term_sn, sn_size))
    l_x = false;
  if (!m_chn_block.append(chn, 0))
    l_x = false;
  if (!m_pcode_block.append(pcode, 0))
    l_x = false;
  if (!m_number_block.append(v_count, 0))
    l_x = false;

  if (!l_x)
    post();
}

CONST text * CClickGatherer::get_command() CONST
{
  return CONST_BS_ADV_CLICK_CMD;
}




CHardwareWarnGatherer::CHardwareWarnGatherer():
      m_id_block(BUFF_LEN, sizeof(CNumber), this),
      m_type_block(BUFF_LEN, 1, this),
      m_value_block(BUFF_LEN, 5, this),
      m_datetime_block(BUFF_LEN, 25, this)
{

}

DVOID CHardwareWarnGatherer::append(CONST text * term_sn, ni sn_size, CONST text x, CONST text y, CONST text * v_dt)
{
  truefalse l_x = true;
  if (!m_id_block.append(term_sn, sn_size))
    l_x = false;

  if (!m_type_block.append(x))
    l_x = false;

  if (x != '6')
  {
    if (!m_value_block.append(y))
      l_x = false;
  } else
  {
    CONST text * l_y = "00";
    if (y == '1')
      l_y = "01";
    else if (y == '2')
      l_y = "10";
    else if (y == '3')
      l_y = "11";
    if (!m_value_block.append(l_y))
      l_x = false;
  }

  if (!m_datetime_block.append(v_dt))
    l_x = false;

  if (!l_x)
    post();
}

CONST text * CHardwareWarnGatherer::get_command() CONST
{
  return CONST_BS_HARD_MON_CMD;
}


CVideoGatherer::CVideoGatherer():
    m_id_block(BUFF_LEN, sizeof(CNumber), this),
    m_fn_block(BUFF_LEN, 200, this),
    m_number_block(BUFF_LEN, 8, this)
{

}

DVOID CVideoGatherer::append(CONST text * term_sn, ni sn_size, CONST text * fn, CONST text * v_count)
{
  ni l_m = strlen(fn);
  if (l_m >= 200)
    return;
  truefalse l_x = true;
  if (!m_id_block.append(term_sn, sn_size))
    l_x = false;
  if (!m_fn_block.append(fn, l_m))
    l_x = false;
  if (!m_number_block.append(v_count, 0))
    l_x = false;

  if (!l_x)
    post();
}

CONST text * CVideoGatherer::get_command() CONST
{
  return CONST_BS_VLC_CMD;
}


CNoVideoWarnGatherer::CNoVideoWarnGatherer():
    m_id_block(BUFF_LEN, sizeof(CNumber), this),
    m_state_block(BUFF_LEN, 400, this),
    m_datetime_block(BUFF_LEN, 25, this)
{

}

DVOID CNoVideoWarnGatherer::append(CONST text * term_sn, ni sn_size, CONST text condition)
{
  truefalse l_x = true;
  if (!m_id_block.append(term_sn, sn_size))
    l_x = false;
  if (!m_state_block.append(condition))
    l_x = false;

  text tmp[32];
  c_tools_convert_time_to_text(tmp, 20, true);
  if (!m_datetime_block.append(tmp))
    l_x = false;

  if (!l_x)
    post();
}

CONST text * CNoVideoWarnGatherer::get_command() CONST
{
  return CONST_BS_VLC_EMPTY_CMD;
}


MyHeartBeatHandler::MyHeartBeatHandler(CHandlerDirector * xptr): CParentHandler(xptr)
{
  m_proc = new CPingProc(this);
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
          m_distributor.work(false);
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
  m_distributor.work(true);
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
    C_DEBUG("ftp command received term_sn(%s) dist_id(%s)\n", client_id.to_str(), dist_id);
    status = 4;
  } else if (recv_status == '3')
  {
    status = 5;
    step = '3';
    C_DEBUG("ftp download completed term_sn(%s) dist_id(%s)\n", client_id.to_str(), dist_id);
  } else if (recv_status == '4')
  {
    status = 5;
    C_DEBUG("dist extract completed term_sn(%s) dist_id(%s)\n", client_id.to_str(), dist_id);
  } else if (recv_status == '5')
  {
    status = 5;
    C_DEBUG("dist extract failed term_sn(%s) dist_id(%s)\n", client_id.to_str(), dist_id);
  } else if (recv_status == '9')
  {
    C_DEBUG("dist download started term_sn(%s) dist_id(%s)\n", client_id.to_str(), dist_id);
    step = '2';
  } else if (recv_status == '7')
  {
    C_DEBUG("dist download failed term_sn(%s) dist_id(%s)\n", client_id.to_str(), dist_id);
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
    ((CPingContainer *)container())->download_reply_gatherer().append(dist_id, ftype, client_id.to_str(), step, ok, buff);
    if (step == '3' && ok == '1')
      ((CPingContainer *)container())->download_reply_gatherer().append(dist_id, ftype, client_id.to_str(), '4', ok, buff);
  }
  if (recv_status == '9')
    return;

  m_distributor.at_download_cmd_feedback(client_id.to_str(), dist_id, status, ok == '1');
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

  m_distributor.control_pause_stop(client_id.to_str(), dpe->data + 1, dpe->data[0]);
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
//  C_DEBUG("file md5 list from term_sn(%s) dist_id(%s): %s\n", client_id.as_string(),
//      dist_id, (*md5list? md5list: "(empty)"));
  C_DEBUG("file md5 list from client_id(%s) dist_id(%s): len = %d\n", client_id.to_str(), dist_id, strlen(md5list));

  m_distributor.at_download_checksum_feedback(client_id.to_str(), dist_id, md5list);
}


//MyHeartBeatAcceptor//

CPingAcc::CPingAcc(CParentScheduler * p1, CHandlerDirector * p2): CParentAcc(p1, p2)
{
  m_tcp_port = CCfgX::instance()->ping_port;
  m_reap_interval = REAP_TIMEOUT;
}

ni CPingAcc::make_svc_handler(CParentHandler *& sh)
{
  sh = new MyHeartBeatHandler(m_director);
  if (!sh)
  {
    C_ERROR("oom @%s\n", name());
    return -1;
  }
  sh->container((void*)this);
  sh->reactor(reactor());
  return 0;
}

CONST text * CPingAcc::name() CONST
{
  return "CPingAcc";
}


CPingScheduler::CPingScheduler(CContainer * pModule, ni numThreads):
    CParentScheduler(pModule, numThreads)
{
  m_acc = NULL;
  m_delay_clock = TIMER_DELAY_VALUE;
  msg_queue()->high_water_mark(MQ_PEAK);
}

CONST text * CPingScheduler::name() CONST
{
  return "CPingScheduler";
}

CPingAcc * CPingScheduler::acc() CONST
{
  return m_acc;
}

ni CPingScheduler::handle_timeout(CONST ACE_Time_Value &, CONST DVOID * v_x)
{
  if ((long)v_x == CParentScheduler::TID)
  {
    CMB *mb;
    ACE_Time_Value l_tv(ACE_Time_Value::zero);
    while (-1 != this->getq(mb, &l_tv))
    {
      if (unlikely(mb->size() < sizeof(CCmdHeader)))
      {
        C_ERROR("bad mb size @%s::handle_timeout\n", name());
        mb->release();
        continue;
      }
      ni l_m = ((CCmdHeader*)mb->base())->signature;
      CParentHandler * l_x = m_acc->director()->locate(l_m);
      if (!l_x)
      {
        mb->release();
        continue;
      }

      if (unlikely(CCmdHeader::PT_DISCONNECT_INTERNAL == ((CCmdHeader*)mb->base())->cmd))
      {
        l_x->handle_close(ACE_INVALID_HANDLE, 0);
        mb->release();
        continue;
      }

      ((CCmdHeader*)mb->base())->signature = CCmdHeader::SIGNATURE;

      if (l_x->post_packet(mb) < 0)
        l_x->handle_close(ACE_INVALID_HANDLE, 0);
    }
  } else if ((long)v_x == TID_PING)
  {
    CPingProc::m_heart_beat_submitter->post_if_needed();
  } else if ((long)v_x == TID_IPVER)
  {
    CPingProc::m_ip_ver_submitter->post_if_needed();
  } else if ((long)v_x == TID_DOWNLOAD_REPLY)
  {
    CPingProc::m_ftp_feedback_submitter->post_if_needed();
  }
  else if ((long)v_x == TID_DIST_TASK)
  {
    CMB * mb = CCacheX::instance()->get_mb(sizeof(ni));
    *(ni*)mb->base() = MyHeartBeatService::TIMED_DIST_TASK;
    CRunnerX::instance()->ping_component()->service()->add_request(mb, false);
  } else if ((long)v_x == TID_CLICK)
  {
    CPingProc::m_adv_click_submitter->post_if_needed();
    CPingProc::m_pc_on_off_submitter->post_if_needed();
    CPingProc::m_hardware_alarm_submitter->post_if_needed();
    CPingProc::m_vlc_submitter->post_if_needed();
    CPingProc::m_vlc_empty_submitter->post_if_needed();
  }
  return 0;
}

DVOID CPingScheduler::before_finish()
{
  m_acc = NULL;
}

DVOID CPingScheduler::before_finish_stage_1()
{

}

truefalse CPingScheduler::before_begin()
{
  if (!m_acc)
    m_acc = new CPingAcc(this, new CHandlerDirector());
  acc_add(m_acc);

  {
    ACE_Time_Value l_tv(TIMER_VALUE_PING);
    if (reactor()->schedule_timer(this, (CONST void*)TID_PING, l_tv, l_tv) < 0)
    {
      C_ERROR("schedule_timer ping: %s %s\n", name(), (CONST char*)CSysError());
      return false;
    }
  }

  {
    ACE_Time_Value l_tv(TIMER_VALUE_IP_VER);
    if (reactor()->schedule_timer(this, (CONST void*)TID_IPVER, l_tv, l_tv) < 0)
    {
      C_ERROR("schedule_timer ip ver:%s %s\n", name(), (CONST char*)CSysError());
      return false;
    }
  }

  {
    ACE_Time_Value l_tv(TIMER_VALUE_DOWNLOAD_REPLY);
    if (reactor()->schedule_timer(this, (CONST void*)TID_DOWNLOAD_REPLY, l_tv, l_tv) < 0)
    {
      C_ERROR("schedule_timer download reply:%s %s\n", name(), (CONST char*)CSysError());
      return false;
    }
  }

  {
    ACE_Time_Value l_tv(TIMER_VALUE_DIST_TASK * 60);
    if (reactor()->schedule_timer(this, (CONST void*)TID_DIST_TASK, l_tv, l_tv) < 0)
    {
      C_ERROR("schedule_timer dist task:%s %s\n", name(), (CONST char*)CSysError());
      return false;
    }
  }

  {
    ACE_Time_Value l_tv(TIMER_VALUE_CLICK * 60);
    if (reactor()->schedule_timer(this, (CONST void*)TID_CLICK, l_tv, l_tv) < 0)
    {
      C_ERROR("schedule_timer click:%s %s\n", name(), (CONST char*)CSysError());
      return false;
    }
  }

  return true;
}


CPingContainer::CPingContainer(CApp * ptr): CContainer(ptr)
{
  m_service = NULL;
  m_schduler = NULL;
  CPingProc::m_heart_beat_submitter = &m_heart_beat_gatherer;
  CPingProc::m_ip_ver_submitter = &m_ipver_gatherer;
  CPingProc::m_ftp_feedback_submitter = &m_download_reply_gatherer;
  CPingProc::m_adv_click_submitter = &m_click_gatherer;
  CPingProc::m_pc_on_off_submitter = &m_hw_power_gatherer;
  CPingProc::m_hardware_alarm_submitter = &m_hw_warn_gatherer;
  CPingProc::m_vlc_submitter = &m_video_gatherer;
  CPingProc::m_vlc_empty_submitter = &m_no_video_warn_gatherer;
}

CPingContainer::~CPingContainer()
{

}

CPingScheduler * CPingContainer::scheduler() CONST
{
  return m_schduler;
}

MyHeartBeatService * CPingContainer::service() CONST
{
  return m_service;
}

ni CPingContainer::connected_count() CONST
{
  if (unlikely(!m_schduler || !m_schduler->acc() || !m_schduler->acc()->director()))
    return 0xFFFFFF;
  return m_schduler->acc()->director()->active_count();
}

CDownloadReplyGatherer & CPingContainer::download_reply_gatherer()
{
  return m_download_reply_gatherer;
}

DVOID CPingContainer::pl()
{
  CMemProt l_x;
  if (!CRunnerX::instance()->db().load_pl(l_x))
    return;
  ACE_GUARD(ACE_Thread_Mutex, ace_mon, this->m_mutex);
  m_pl.init(l_x.get_ptr());
}

truefalse CPingContainer::get_pl(CMemProt & v_x)
{
  ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, false);
  if (!m_pl.get_ptr() || !*m_pl.get_ptr())
    return false;
  v_x.init(m_pl.get_ptr());
  return true;
}

CONST text * CPingContainer::name() CONST
{
  return "CPingContainer";
}

truefalse CPingContainer::before_begin()
{
  add_task(m_service = new MyHeartBeatService(this, 1));
  add_scheduler(m_schduler = new CPingScheduler(this));
  return true;
}

DVOID CPingContainer::before_finish()
{
  m_service = NULL;
  m_schduler = NULL;
}


//d2bs

CD2BsProc::CD2BsProc(CParentHandler * ptr): baseclass(ptr)
{
  m_handler->msg_queue()->high_water_mark(MQ_PEAK);
}

CONST text * CD2BsProc::name() CONST
{
  return "CD2BsProc";
}

CProc::OUTPUT CD2BsProc::do_read_data(CMB * mb)
{
  CMBProt guard(mb);

  if (baseclass::do_read_data(mb) != OP_OK)
    return OP_FAIL;
  CBSData * l_data = (CBSData *) mb->base();
  if (memcmp(l_data->command, CONST_BS_IP_VER_CMD, sizeof(l_data->command)) == 0)
    process_ip_ver_reply(l_data);

  ((CD2BsHandler*)m_handler)->refresh();

  return OP_OK;
}

DVOID CD2BsProc::process_ip_ver_reply(CBSData * v_data)
{
  text l_xxx[2] = {';', 0};
  CTextDelimiter l_x(v_data->data, l_xxx);
  text * l_y;
  while ((l_y = l_x.get()) != NULL)
    process_ip_ver_reply_one(l_y);
}

DVOID CD2BsProc::process_ip_ver_reply_one(text * v_ptr)
{
  text * l_sn, * l_ptr;
  l_sn = v_ptr;
  l_ptr = strchr(v_ptr, ':');
  if (unlikely(!l_ptr || l_ptr == v_ptr || *(l_ptr + 1) == 0))
    return;
  *l_ptr++ = 0;
  truefalse client_valid = !(l_ptr[0] == '*' && l_ptr[1] == 0);
  CTermSNs & id_table = CRunnerX::instance()->termSNs();
  CNumber l_term_sn(l_sn);
  ni l_xi;
  if (unlikely(!id_table.mark_valid(l_term_sn, client_valid, l_xi)))
    CRunnerX::instance()->db().mark_client_valid(l_sn, client_valid);

  if (likely(client_valid))
  {
    ni l_n = strlen(l_ptr) + 1;
    CMB * mb = CCacheX::instance()->get_mb_cmd(l_n, CCmdHeader::PT_IP_VER_REQ);
    CCmdExt * l_ptr2 = (CCmdExt *) mb->base();
    memcpy(l_ptr2->data, l_ptr, l_n);
    l_ptr2->signature = l_xi;
    c_tools_mb_putq(CRunnerX::instance()->ping_component()->scheduler(), mb, "ipver");
  } else
  {
    if (l_xi >= 0)
    {
      CMB * mb = CCacheX::instance()->get_mb_cmd(0, CCmdHeader::PT_DISCONNECT_INTERNAL);
      CCmdExt * l_ptr2 = (CCmdExt *) mb->base();
      l_ptr2->signature = l_xi;
      c_tools_mb_putq(CRunnerX::instance()->ping_component()->scheduler(), mb, "disconnect_i");
    }
  }
}


CD2BsHandler::CD2BsHandler(CHandlerDirector * p): CParentHandler(p)
{
  m_proc = new CD2BsProc(this);
}

CD2MContainer * CD2BsHandler::container() CONST
{
  return (CD2MContainer *)connector()->container();
}

DVOID CD2BsHandler::refresh()
{
  m_validator.refresh();
}

ni CD2BsHandler::handle_timeout(CONST ACE_Time_Value &, CONST DVOID *)
{
  if (m_validator.overdue())
  {
    C_ERROR("get no data @CD2BsHandler\n");
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

ni CD2BsHandler::at_start()
{
  ACE_Time_Value l_tv(30);
  if (reactor()->schedule_timer(this, (void*)0, l_tv, l_tv) < 0)
  {
    C_ERROR(ACE_TEXT("schedule_timer: %s"), (CONST char*)CSysError());
    return -1;
  }

  if (!g_is_test)
    C_INFO("schedule_timer CD2BsHandler done\n");

  CMB * mb = c_create_hb_mb();
  if (mb)
  {
    if (post_packet(mb) < 0)
      return -1;
  }
  m_validator.refresh();

  return 0;
}


DVOID CD2BsHandler::at_finish()
{

}

PREPARE_MEMORY_POOL(CD2BsHandler);



CD2BsConn::CD2BsConn(CParentScheduler * p1, CHandlerDirector * p2): CParentConn(p1, p2)
{
  m_port_of_ip = CCfgX::instance()->bs_port;
  m_retry_delay = RETRY_DELAY;
  m_remote_ip = CCfgX::instance()->bs_addr;
}

CONST text * CD2BsConn::name() CONST
{
  return "CD2BsConn";
}

ni CD2BsConn::make_svc_handler(CParentHandler *& sh)
{
  sh = new CD2BsHandler(m_director);
  if (!sh)
  {
    C_ERROR("oom @%s\n", name());
    return -1;
  }
  sh->container((void*)this);
  sh->reactor(reactor());
  return 0;
}


//d2m

CD2MProc::CD2MProc(CParentHandler * l_ptr): CParentClientProc(l_ptr)
{
  m_ver_reply_finished = false;
  m_self_ip[0] = 0;
  m_handler->msg_queue()->high_water_mark(MQ_PEAK);
}

ni CD2MProc::at_start()
{
  if (baseclass::at_start() < 0)
    return -1;

  ACE_INET_Addr l_x;
  if (m_handler->peer().get_local_addr(l_x) == 0)
    l_x.get_host_addr((char*)m_self_ip, IP_SIZE);

  return post_ver_mb();
}

CProc::OUTPUT CD2MProc::at_head_arrival()
{
  CProc::OUTPUT l_x = baseclass::at_head_arrival();
  if (l_x != OP_GO_ON)
    return OP_FAIL;

  truefalse l_y = m_data_head.cmd == CCmdHeader::PT_VER_REPLY;
  if (l_y == m_ver_reply_finished)
  {
    C_ERROR("bad data from dist, ver_reply_finished = %d, data ver_reply = %d.\n", m_ver_reply_finished, l_y);
    return OP_FAIL;
  }

  if (l_y)
  {
    if (!c_packet_check_term_ver_reply(&m_data_head))
    {
      C_ERROR("can not check term ver reply data\n");
      return OP_FAIL;
    }
    return OP_OK;
  }

  if (m_data_head.cmd == CCmdHeader::PT_HAVE_DIST_TASK)
  {
    if (!c_packet_check_have_dist_task(&m_data_head))
    {
      C_ERROR("can not check dist task notify data\n");
      return OP_FAIL;
    }
    return OP_OK;
  }

  if (m_data_head.cmd == CCmdHeader::PT_REMOTE_CMD)
  {
    if (!c_packet_check_file_md5_list(&m_data_head))
    {
      C_ERROR("can not check rmt command data\n");
      return OP_FAIL;
    }
    return OP_OK;
  }

  C_ERROR("bad data from dist, cmd = %d\n", m_data_head.cmd);
  return OP_FAIL;
}

CProc::OUTPUT CD2MProc::do_read_data(CMB * mb)
{
  CFormatProcBase::do_read_data(mb);

  CCmdHeader * l_x = (CCmdHeader *)mb->base();

  if (l_x->cmd == CCmdHeader::PT_VER_REPLY)
  {
    CProc::OUTPUT l_y = handle_ver_reply(mb);
    C_INFO("answer from pre: %s\n", (l_y == OP_OK? "OK":"Failed"));
    if (l_y == OP_OK)
    {
      ((CD2MHandler*)m_handler)->init_timer();
      sn_check_ok(true);
    }
    return l_y;
  }

  if (l_x->cmd == CCmdHeader::PT_HAVE_DIST_TASK)
  {
    CProc::OUTPUT l_y = handle_has_dist(mb);
    C_INFO("recv dist from pre\n");
    return l_y;
  }

  if (m_data_head.cmd == CCmdHeader::PT_REMOTE_CMD)
  {
    C_INFO("recv rmt from pre\n");
    CProc::OUTPUT result = handle_rmt_command(mb);
    return result;
  }

  CMBProt prot(mb);
  C_ERROR("bad data from pre, cmd = %d\n", l_x->cmd);
  return OP_FAIL;
}

ni CD2MProc::post_balance()
{
  if (!m_ver_reply_finished)
    return 0;

  CMB * mb = CCacheX::instance()->get_mb_cmd_direct(sizeof(CLoadBalanceReq), CCmdHeader::PT_LOAD_BALANCE_REQ);
  CLoadBalanceReq * l_x = (CLoadBalanceReq *) mb->base();
  l_x->set_ip(m_self_ip);
  l_x->load = CRunnerX::instance()->ping_component()->connected_count();
  C_INFO("post balance (%d) to pre...\n", l_x->load);
  return (m_handler->post_packet(mb) < 0 ? -1: 0);
}

CProc::OUTPUT CD2MProc::handle_ver_reply(CMB * mb)
{
  CMBProt prot(mb);
  m_ver_reply_finished = true;

  CONST text * prefix_msg = "dist ver result:";
  CTermVerReply * vcr = (CTermVerReply *) mb->base();
  switch (vcr->ret_subcmd)
  {
  case CTermVerReply::SC_OK:
    return CProc::OP_OK;

  case CTermVerReply::SC_OK_UP:
    C_INFO("%s ver++\n", prefix_msg);
    return CProc::OP_OK;

  case CTermVerReply::SC_NOT_MATCH:
    C_ERROR("%s ver bad\n", prefix_msg);
    return CProc::OP_FAIL;

  case CTermVerReply::SC_ACCESS_DENIED:
    C_ERROR("%s no rights\n", prefix_msg);
    return CProc::OP_FAIL;

  case CTermVerReply::SC_SERVER_BUSY:
    C_ERROR("%s all are in use\n", prefix_msg);
    return CProc::OP_FAIL;

  default:
    C_ERROR("%s recv bad answer = %d\n", prefix_msg, vcr->ret_subcmd);
    return CProc::OP_FAIL;
  }

}

CProc::OUTPUT CD2MProc::handle_has_dist(CMB * mb)
{
  CRunnerX::instance()->ping_component()->service()->add_request(mb, false);
  return OP_OK;
}

CProc::OUTPUT CD2MProc::handle_rmt_command(CMB * mb)
{
  CMBProt prot(mb);
  return OP_OK;
}

ni CD2MProc::post_ver_mb()
{
  CMB * mb = create_login_mb();
  CTerminalVerReq * proc = (CTerminalVerReq *)mb->base();
  proc->term_ver_major = 1;
  proc->term_ver_minor = 0;
  proc->term_sn = CCfgX::instance()->skey.c_str();
  proc->server_id = CCfgX::instance()->server_id;
  C_INFO("posting login to pre...\n");
  return (m_handler->post_packet(mb) < 0? -1: 0);
}


CD2MHandler::CD2MHandler(CHandlerDirector * P): CParentHandler(P)
{
  m_proc = new CD2MProc(this);
  m_tid = -1;
}

DVOID CD2MHandler::init_timer()
{
  ACE_Time_Value l_x(ACE_Time_Value::zero);
  ACE_Time_Value l_y(BALANCE_DELAY * 60);
  m_tid = reactor()->schedule_timer(this, (void*)BALANCE_TIMER, l_x, l_y);
  if (m_tid < 0)
    C_ERROR("schedule_timer: %s", (CONST char*)CSysError());
}

CD2MContainer * CD2MHandler::container() CONST
{
  return (CD2MContainer *)connector()->container();
}

ni CD2MHandler::at_start()
{
  return 0;
}

ni CD2MHandler::handle_timeout(CONST ACE_Time_Value &, CONST DVOID * v_ptr)
{
  if (long(v_ptr) == BALANCE_TIMER)
    return ((CD2MProc*)m_proc)->post_balance();
  else if (long(v_ptr) == 0)
    return -1;
  else
  {
    C_ERROR("bad handle_timeout, tid = %d\n", long(v_ptr));
    return 0;
  }
}

DVOID CD2MHandler::at_finish()
{
  if (m_tid >= 0)
    reactor()->cancel_timer(m_tid);
}

PREPARE_MEMORY_POOL(CD2MHandler);



CD2MConn::CD2MConn(CParentScheduler * p1, CHandlerDirector * p2): CParentConn(p1, p2)
{
  m_port_of_ip = CCfgX::instance()->server_port;
  m_retry_delay = RETRY_DELAY;
  m_remote_ip = CCfgX::instance()->middle_addr;
}

CONST text * CD2MConn::name() CONST
{
  return "CD2MConn";
}

ni CD2MConn::make_svc_handler(CParentHandler *& v_ptr)
{
  v_ptr = new CD2MHandler(m_director);
  if (!v_ptr)
  {
    C_ERROR("oom @%s\n", name());
    return -1;
  }
  v_ptr->container((void*)this);
  v_ptr->reactor(reactor());
  return 0;
}


CD2MSchduler::CD2MSchduler(CContainer * p, ni m): CParentScheduler(p, m)
{
  m_conn = NULL;
  m_2_bs_conn = NULL;
  msg_queue()->high_water_mark(MQ_PEAK);
  m_2_bs_mq.high_water_mark(MQ_PEAK);
}

CD2MSchduler::~CD2MSchduler()
{

}

DVOID CD2MSchduler::before_finish_stage_1()
{
  ACE_Time_Value l_x(ACE_Time_Value::zero);
  CMB * mb;
  while (m_2_bs_mq.dequeue(mb, &l_x) != -1)
    mb->release();
  while (this->msg_queue()->dequeue(mb, &l_x) != -1)
    mb->release();
}

truefalse CD2MSchduler::before_begin()
{
  if (!m_conn)
    m_conn = new CD2MConn(this, new CHandlerDirector());
  conn_add(m_conn);
  if (!m_2_bs_conn)
    m_2_bs_conn = new CD2BsConn(this, new CHandlerDirector());
  conn_add(m_2_bs_conn);
  return true;
}

truefalse CD2MSchduler::do_schedule_work()
{
  ACE_Time_Value l_x(ACE_Time_Value::zero);
  CMB * mb;
  CONST ni CONST_peak_number = 10;
  ni l_m = 0;
  while (++l_m < CONST_peak_number && this->getq(mb, &l_x) != -1)
    m_conn->director()->post_all(mb);

  l_x = ACE_Time_Value::zero;
  l_m = 0;
  while (++l_m < CONST_peak_number && m_2_bs_mq.dequeue(mb, &l_x) != -1)
    m_2_bs_conn->director()->post_all(mb);

  return true;
}

CONST text * CD2MSchduler::name() CONST
{
  return "CD2MSchduler";
}

DVOID CD2MSchduler::post_bs(CMB * mb)
{
  ACE_Time_Value l_x(ACE_Time_Value::zero);
  if (m_2_bs_mq.enqueue(mb, &l_x) < 0)
    mb->release();
}

DVOID CD2MSchduler::post_pre(CMB * mb)
{
  c_tools_mb_putq(this, mb, "CD2MSchduler::post_pre");
}

DVOID CD2MSchduler::before_finish()
{
  m_conn = NULL;
  m_2_bs_conn = NULL;
}


CD2MContainer::CD2MContainer(CApp * ptr): CContainer(ptr)
{
  m_scheduler = NULL;
}

CD2MContainer::~CD2MContainer()
{

}

CONST text * CD2MContainer::name() CONST
{
  return "CD2MContainer";
}

DVOID CD2MContainer::post_bs(CMB * mb)
{
  m_scheduler->post_bs(mb);
}

DVOID CD2MContainer::post_pre(CMB * mb)
{
  m_scheduler->post_pre(mb);
}

truefalse CD2MContainer::before_begin()
{
  add_scheduler(m_scheduler = new CD2MSchduler(this));
  return true;
}

DVOID CD2MContainer::before_finish()
{
  m_scheduler = NULL;
}


//db

CONST text * CONST_db_name = "acedb";


class CPGResultProt
{
public:
  CPGResultProt(PGresult * res): m_result(res)
  {

  }

  ~CPGResultProt()
  {
    PQclear(m_result);
  }

private:
  CPGResultProt(CONST CPGResultProt &);
  CPGResultProt & operator = (CONST CPGResultProt &);

  PGresult * m_result;
};


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

truefalse MyDB::check_online()
{
  ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, false);
  CONST text * select_sql = "select ('now'::text)::timestamp(0) without time zone";
  exec_command(select_sql);
  return validate_db_online();
}

truefalse MyDB::validate_db_online()
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
  CPGResultProt guard(pres);
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
  CPGResultProt guard(pres);
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

truefalse MyDB::load_term_SNs(CTermSNs * v_SNs)
{
  C_ASSERT_RETURN(v_SNs != NULL, "null id_table @MyDB::get_client_ids\n", false);

  CONST text * CONST_select_sql_template = "select term_sn, client_password, client_expired, auto_seq "
                                           "from tb_clients where auto_seq > %d order by auto_seq";
  text select_sql[1024];
  snprintf(select_sql, 1024 - 1, CONST_select_sql_template, v_SNs->prev_no());

  ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, false);
  PGresult * pres = PQexec(m_connection, select_sql);
  CPGResultProt guard(pres);
  if (!pres || PQresultStatus(pres) != PGRES_TUPLES_OK)
  {
    C_ERROR("MyDB::sql (%s) failed: %s\n", select_sql, PQerrorMessage(m_connection));
    return false;
  }
  ni count = PQntuples(pres);
  if (count > 0)
  {
    v_SNs->prepare_space(count);
    truefalse expired;
    CONST text * p;
    for (ni i = 0; i < count; ++i)
    {
      p = PQgetvalue(pres, i, 2);
      expired = p && (*p == 't' || *p == 'T');
      v_SNs->append(PQgetvalue(pres, i, 0), PQgetvalue(pres, i, 1), expired);
    }
    ni last_seq = atoi(PQgetvalue(pres, count - 1, 1));
    v_SNs->set_prev_no(last_seq);
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

  CONST text * insert_sql_template = "insert into tb_clients(term_sn) values('%s')";
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
  CPGResultProt guard(pres);
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
  CPGResultProt guard(pres);
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

truefalse MyDB::load_dist_clients(CTermStations * dist_clients, CTermStation * _dc_one)
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
    snprintf(sql, 512, CONST_select_sql_2, _dc_one->term_sn());
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
  CPGResultProt guard(pres);
  if (!pres || PQresultStatus(pres) != PGRES_TUPLES_OK)
  {
    C_ERROR("MyDB::sql (%s) failed: %s\n", CONST_select_sql, PQerrorMessage(m_connection));
    return -1;
  }
  ni count = PQntuples(pres);
  ni field_count = PQnfields(pres);
  ni count_added = 0;
  CTermStation * dc_one;

  if (count == 0)
    goto __exit__;
  if (unlikely(field_count != 8))
  {
    C_ERROR("wrong column number(%d) @MyDB::load_dist_clients()\n", field_count);
    return false;
  }

  CBsDistData * info;
  if (!_dc_one)
    dc_one = dist_clients->generate_term_station(PQgetvalue(pres, 0, 1));
  else
    dc_one = _dc_one;
  for (ni i = 0; i < count; ++ i)
  {
    info = dist_clients->search_dist_data(PQgetvalue(pres, i, 0));
    if (unlikely(!info))
      continue;

    if (!_dc_one)
    {
      CONST text * client_id = PQgetvalue(pres, i, 1);
      if (unlikely(!dc_one->check_term_sn(client_id)))
        dc_one = dist_clients->generate_term_station(client_id);
    }

    CDistTermItem * dc = dc_one->generate_term_item(info);

    CONST text * md5 = NULL;
    for (ni j = 0; j < field_count; ++j)
    {
      CONST text * fvalue = PQgetvalue(pres, i, j);
      if (!fvalue || !*fvalue)
        continue;

      if (j == 2)
        dc->condition = atoi(fvalue);
      else if (j == 3)
        dc->adir.init(fvalue);
      else if (j == 7)
        md5 = fvalue;
      else if (j == 5)
        dc->cmp_fn.init(fvalue);
      else if (j == 4)
        dc->prev_access = get_time_init(fvalue);
      else if (j == 6)
        dc->cmp_checksum.init(fvalue);
    }

    if (dc->condition < 3 && md5 != NULL)
      dc->checksum.init(md5);

    ++ count_added;
  }

__exit__:
  if (!_dc_one)
    C_INFO("MyDB::get %d/%d dist client infos from database\n", count_added, count);
  return count;
}

truefalse MyDB::set_dist_client_status(CDistTermItem & dist_client, ni new_status)
{
  return set_dist_client_status(dist_client.term_sn(), dist_client.dist_data->ver.get_ptr(), new_status);
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
    if (!validate_db_online())
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
  CPGResultProt guard(pres);
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
    CONST text * sql_template = "delete from tb_clients where term_sn = '%s'";
    snprintf(sql, 1024, sql_template, client_id);
  } else
  {
    CONST text * sql_template = "insert into tb_clients(term_sn, client_password) values('%s', '%s')";
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
  CPGResultProt guard(pres);
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
  CPGResultProt guard(pres);
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
