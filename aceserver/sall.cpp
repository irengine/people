#include "sall.h"
#include "app.h"
#include "sapp.h"

CBsDistData::CBsDistData(CONST text * v_did)
{
  remote_kind[0] = remote_kind[1] = 0;
  local_kind[0] = local_kind[1] = 0;
  edition.init(v_did);
  edition_size = strlen(v_did);
  checksum_opt_size = 0;
  exist = false;
  checksum_size = 0;
  remote_file_size = 0;
  key_size = 0;
  local_file_size = 0;
}

truefalse CBsDistData::have_checksum() CONST
{
  return (c_tell_type_multi(local_kind[0]));
}

truefalse CBsDistData::have_checksum_compress() CONST
{
  return !have_checksum();
}

DVOID CBsDistData::calc_checksum_opt_sum()
{
  if (have_checksum() && checksum_size > 0 && checksum_opt_size == 0)
  {
    CMemProt l_x;
    l_x.init(check_sum.get_ptr());
    CCheckSums l_obj;
    if (l_obj.load_text(l_x.get_ptr(), NULL))
      checksum_opt_size = l_obj.text_len(false) - 1;
  }
}


CBsDistReq::CBsDistReq()
{
  local_file = NULL;
  edition = NULL;
  local_kind = NULL;
  key = NULL;
  what_ = NULL;
  remote_kind = NULL;
  remote_path = NULL;
  remote_file = NULL;
  local_path = NULL;
}

CBsDistReq::CBsDistReq(CONST CBsDistData & data)
{
  what_ = NULL;
  remote_kind = (char*)data.remote_kind;
  remote_path = data.remote_path.get_ptr();
  remote_file = data.remote_file.get_ptr();
  local_path = NULL;
  local_file = data.local_file.get_ptr();
  edition = data.edition.get_ptr();
  local_kind = (char*)data.local_kind;
  key = data.key.get_ptr();
}

truefalse CBsDistReq::do_validate(CONST text * v_x, CONST text * v_y) CONST
{
  if (!v_x || !*v_x)
  {
    C_ERROR("invalid bs handleout command, no %s\n", v_y);
    return false;
  }

  return true;
}

truefalse CBsDistReq::is_ok(CONST truefalse v_acode_also) CONST
{
  if (v_acode_also && !do_validate(what_, "acode"))
    return false;

  if (!do_validate(remote_kind, "ftype"))
    return false;

  if (unlikely(remote_kind[1] != 0 || !c_tell_ftype_valid(remote_kind[0])))
  {
    C_ERROR("invalid bs handleout command, ftype = %s\n", remote_kind);
    return false;
  }

  if (!do_validate(remote_file, "findex"))
    return false;

  if (!do_validate(remote_path, "fdir"))
    return false;

  if (!do_validate(edition, "ver"))
    return false;

  if (!do_validate(local_kind, "type"))
    return false;

  if (unlikely(local_kind[1] != 0 || !c_tell_type_valid(local_kind[0])))
  {
    C_ERROR("invalid bs dist command, type = %s\n", local_kind);
    return false;
  }

  return true;
}

truefalse CBsDistReq::have_checksum() CONST
{
  return (local_kind && c_tell_type_multi(*local_kind));
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
  m_data_map.insert(std::pair<const text *, CBsDistData *>(l_x->edition.get_ptr(), l_x));
  return l_x;
}

truefalse CBsDistDatas::need_reload()
{
  return (!CRunnerX::instance()->pg().is_dist_data_new(*this));
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
  ni l_skip_n = strlen(v_req.remote_path) - 1;
  CMemProt l_to_path;
  CMemProt l_cmp_path;
  CMemProt single;
  CMemProt mfile;
  CMemProt l_to_fn;
  l_to_path.init(CCfgX::instance()->bz_files_path.c_str(), "/", v_req.edition);
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
  if (!c_tell_type_single(*v_req.local_kind))
    if (!m_comp_uniter.begin(single.get_ptr()))
      goto label_out;

  CSysFS::dir_add(v_req.remote_path, v_req.remote_file, mfile);
  l_to_fn.init(l_to_path.get_ptr(), "/", (v_req.remote_file? v_req.remote_file: v_req.local_file), ".mbz");
  bm =   m_data_comp.reduce(mfile.get_ptr(), l_skip_n, l_to_fn.get_ptr(), v_req.key);
  if (!bm && !c_tell_type_multi(*v_req.local_kind))
  {
    C_ERROR("comp(%s) to (%s)\n", mfile.get_ptr(), l_to_fn.get_ptr());
    m_comp_uniter.finish();
    return false;
  }
  if (!c_tell_type_single(*v_req.local_kind) && bm && !m_comp_uniter.append(l_to_fn.get_ptr()))
  {
    m_comp_uniter.finish();
    return false;
  }

  if (c_tell_type_single(*v_req.local_kind))
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

  l_x = i_work(mfile.get_ptr(), l_to_path.get_ptr(), l_skip_n, v_req.key);
  m_comp_uniter.finish();

label_out:
  if (!l_x)
    C_ERROR("fail to create comp files%s\n", v_req.edition);
  else
    C_INFO("creation comp files %s finished\n", v_req.edition);

  if (c_tell_type_all(*v_req.local_kind))
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
    C_INFO("will not compute checksum for task %s\n", v_req.edition);
    return true;
  }

  CCheckSums l_cs;
  if (unlikely(!l_cs.compute(v_req.remote_path, v_req.remote_file, c_tell_type_single(*v_req.local_kind))))
  {
    C_ERROR("failed to compute checksum for task %s\n", v_req.edition);
    return false;
  }
  l_cs.make_ordered();
  v_cs_size = l_cs.text_len(true);

  CCacheX::instance()->get(v_cs_size, &v_checksum);
  if (unlikely(!l_cs.save_text(v_checksum.get_ptr(), v_cs_size, true)))
  {
    C_ERROR("failed to read checksum for task %s\n", v_req.edition);
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
  text * v_x = mb->base() + CBSData::DATA_OFFSET;
  *v_x = '1';
  *(v_x + 1) = CBSData::LAST_SEPARATOR;
  return mb;
}


class CBalanceSearcher
{
public:
  CBalanceSearcher(CONST text * p)
  {
    m_ip = p;
  }

  truefalse operator()(CChargeData& x) CONST
  {
    if (!m_ip)
      return false;
    return (strcmp(m_ip, x.m_ip) == 0);
  }

private:
  CONST text * m_ip;
};



CChargeDatas::CChargeDatas()
{
  m_loads.reserve(6);
  m_ip_size = 0;
  m_ips[0] = 0;
}

DVOID CChargeDatas::refresh(CONST CChargeData & v_data)
{
  if (v_data.m_ip[0] == 0)
    return;
  ACE_MT(ACE_GUARD(ACE_Thread_Mutex, ace_mon, m_mutex));
  CChargeDataVecIt it = do_search(v_data.m_ip);
  if (it == m_loads.end())
    m_loads.push_back(v_data);
  else
  {
    it->set_load(v_data.m_load);
    it->m_prev_access_ts = g_clock_counter;
  }

  do_compute_ips();
}

DVOID CChargeDatas::del(CONST text * v_addr)
{
  if (!v_addr || !*v_addr)
    return;
  ACE_MT(ACE_GUARD(ACE_Thread_Mutex, ace_mon, m_mutex));
  CChargeDataVecIt it = do_search(v_addr);
  if (it == m_loads.end())
    return;
  m_loads.erase(it);

  do_compute_ips();
}

CChargeDatas::CChargeDataVecIt CChargeDatas::do_search(CONST text * v_addr)
{
  return find_if(m_loads.begin(), m_loads.end(), CBalanceSearcher(v_addr));
}

DVOID CChargeDatas::do_compute_ips()
{
  m_ips[0] = 0;
  sort(m_loads.begin(), m_loads.end());
  CChargeDataVecIt it;
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
    *l_p = CCmdHeader::DATA_MARK;
    ++l_p;
  }
  *l_p = 0;

  ni l_m = CCfgX::instance()->download_servers.length();
  if (unlikely(l_m + 3 > l_x))
    C_ERROR("ips too long\n");
  else
  {
    *l_p++ = CCmdHeader::LAST_MARK;
    ACE_OS::strsncpy(l_p, CCfgX::instance()->download_servers.c_str(), l_x + 1);
  }

  m_ip_size = strlen(m_ips);
  ++m_ip_size;
}

ni CChargeDatas::query_servers(text * v_result, ni v_result_size)
{
  ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, m_mutex, 0);
  if (!v_result || v_result_size < m_ip_size)
    return 0;
  ACE_OS::strsncpy(v_result, m_ips, v_result_size);
  return m_ip_size;
}

DVOID CChargeDatas::check_broken()
{
  ACE_MT(ACE_GUARD(ACE_Thread_Mutex, ace_mon, m_mutex));
  CChargeDataVecIt it;
  for (it = m_loads.begin(); it != m_loads.end(); )
  {
    if (it->m_prev_access_ts + ni(BROKEN_INTERVAL * 60 / CParentRunner::CLOCK_TIME) < g_clock_counter)
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
  C_INFO("deleted %d/%d obsolete dirs @CObsoleteDirDeleter\n", l_good_num, l_total);
}




CChargeDatas * CPositionProc::m_charge_datas = NULL;

CPositionProc::CPositionProc(CParentHandler * p): CParentServerProc(p)
{

}

CONST text * CPositionProc::title() CONST
{
  return "CPositionProc";
}

CProc::OUTPUT CPositionProc::at_head_arrival()
{
  if (CParentServerProc::at_head_arrival() == OP_FAIL)
    return OP_FAIL;

  if (m_data_head.cmd == CCmdHeader::PT_LOGIN)
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
  if (l_p->cmd == CCmdHeader::PT_LOGIN)
    return do_login_check(mb);

  CMBProt guard(mb);
  C_ERROR("get bad cmd = %d\n", l_p->cmd);
  return OP_FAIL;
}


CProc::OUTPUT CPositionProc::do_login_check(CMB * mb)
{
  CMBProt prot(mb);
  m_term_sn = "foobar";
  text ips[CChargeDatas::IP_SIZE];
  ni m = m_charge_datas->query_servers(ips, CChargeDatas::IP_SIZE);
  CMB * mb2 = i_create_mb_ver_reply(CTermVerReply::SC_GET_ALL, m);

  CTermVerReply * l_x = (CTermVerReply *)mb2->base();
  if (likely(m > 0))
    memcpy(l_x->data, ips, m);

  if (m_handler->post_packet(mb2) <= 0)
    return OP_FAIL;
  else
    return OP_OK;
}

yy_enable_cache(CPositionProc);




CPositionHandler::CPositionHandler(CHandlerDirector * p): CParentHandler(p)
{
  m_proc = new CPositionProc(this);
}

yy_enable_cache(CPositionHandler);



CPositionTask::CPositionTask(CContainer * p, ni v_thrds):
    CTaskBase(p, v_thrds)
{

}

ni CPositionTask::svc()
{
  C_INFO("Start %s::svc()\n", title());
  for (CMB * mb; getq(mb) != -1;)
    mb->release ();
  C_INFO("exiting %s::svc()\n", title());
  return 0;
}




CPositionAcc::CPositionAcc(CParentScheduler * p1, CHandlerDirector * p2): CParentAcc(p1, p2)
{
  m_tcp_port = CCfgX::instance()->pre_term_hole;
  m_reap_interval = BROKEN_DELAY;
}

ni CPositionAcc::make_svc_handler(CParentHandler *& v_x)
{
  v_x = new CPositionHandler(m_director);
  if (!v_x)
  {
    C_ERROR("oom @%s\n", title());
    return -1;
  }
  v_x->container((void*)this);
  v_x->reactor(reactor());
  return 0;
}

CONST text * CPositionAcc::title() CONST
{
  return "CPositionAcc";
}


CPositionScheduler::CPositionScheduler(CContainer * p, ni m): CParentScheduler(p, m)
{
  m_acc = NULL;
  msg_queue()->high_water_mark(MQ_PEAK);
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

CONST text * CPositionScheduler::title() CONST
{
  return "CPositionScheduler";
}



CPositionContainer::CPositionContainer(CParentRunner * p): CContainer(p)
{
  m_task = NULL;
  m_scheduler = NULL;
  CPositionProc::m_charge_datas = &m_charge_datas;
}

CPositionContainer::~CPositionContainer()
{

}

CChargeDatas * CPositionContainer::charge_datas()
{
  return &m_charge_datas;
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

CONST text * CPositionContainer::title() CONST
{
  return "CPositionContainer";
}

CBsReqProc::CBsReqProc(CParentHandler * p): baseclass(p)
{

}

CBsReqProc::~CBsReqProc()
{

}

CONST text * CBsReqProc::title() CONST
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
    l_ret = (c_tools_mb_putq(CRunnerX::instance()->bs_req_container()->bs_req_task(), m_mb,
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


  CPG & db = CRunnerX::instance()->pg();
  if (!db.check_online())
  {
    C_ERROR("no connection to db, quitting\n");
    return false;
  }

  C_INFO("prio = %s\n", plist? plist:"NULL");
  return db.write_pl(plist);
}

yy_enable_cache(CBsReqProc);


CBsReqHandler::CBsReqHandler(CHandlerDirector * p): CParentHandler(p)
{
  m_proc = new CBsReqProc(this);
}

yy_enable_cache(CBsReqHandler);


CBsReqAcc::CBsReqAcc(CParentScheduler * p1, CHandlerDirector * p2): CParentAcc(p1, p2)
{
  m_tcp_port = CCfgX::instance()->web_hole;
  m_reap_interval = BROKEN_DELAY;
}

ni CBsReqAcc::make_svc_handler(CParentHandler *& v_x)
{
  v_x = new CBsReqHandler(m_director);
  if (!v_x)
  {
    C_ERROR("oom\n");
    return -1;
  }
  v_x->container((void*)this);
  v_x->reactor(reactor());
  return 0;
}

CONST text * CBsReqAcc::title() CONST
{
  return "CBsReqAcc";
}


CBsReqTask::CBsReqTask(CContainer * p, ni m): CTaskBase(p, m)
{
  msg_queue()->high_water_mark(MQ_PEAK);
}

ni CBsReqTask::svc()
{
  C_INFO("Start %s::svc()\n", title());
  for (CMB * mb; getq(mb) != -1; )
  {
    process_mb(mb);
    mb->release();
  }
  C_INFO("exiting %s::svc()\n", title());
  return 0;
};

CONST text * CBsReqTask::title() CONST
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
  if (!c_tools_locate_key_result(l_ptr, CONST_acode, v_bs_req.what_, CONST_separator))
  {
    C_ERROR("invalid bs req: no %s\n", CONST_acode);
    return false;
  }

  CONST text * CONST_ftype = "ftype=";
  if (!c_tools_locate_key_result(l_ptr, CONST_ftype, v_bs_req.remote_kind, CONST_separator))
  {
    C_ERROR("invalid bs req: no %s\n", CONST_ftype);
    return false;
  }

  CONST text * CONST_fdir = "fdir=";
  if (!c_tools_locate_key_result(l_ptr, CONST_fdir, v_bs_req.remote_path, CONST_separator))
  {
    C_ERROR("invalid bs req: no %s\n", CONST_fdir);
    return false;
  }

  CONST text * CONST_findex = "findex=";
  if (!c_tools_locate_key_result(l_ptr, CONST_findex, v_bs_req.remote_file, CONST_separator))
  {
    C_ERROR("invalid bs req: no %s\n", CONST_findex);
    return false;
  }

  CONST text * CONST_adir = "adir=";
  if (!c_tools_locate_key_result(l_ptr, CONST_adir, v_bs_req.local_path, CONST_separator))
  {
    C_ERROR("invalid bs req: no %s\n", CONST_adir);
    return false;
  }

  CONST text * CONST_aindex = "aindex=";
  if (!c_tools_locate_key_result(l_ptr, CONST_aindex, v_bs_req.local_file, CONST_separator))
  {
    C_ERROR("invalid bs req: no %s\n", CONST_aindex);
    return false;
  }

  CONST text * CONST_ver = "ver=";
  if (!c_tools_locate_key_result(l_ptr, CONST_ver, v_bs_req.edition, CONST_separator))
  {
    C_ERROR("invalid bs req: no %s\n", CONST_ver);
    return false;
  }

  CONST text * CONST_type = "type=";
  if (!c_tools_locate_key_result(l_ptr, CONST_type, v_bs_req.local_kind, CONST_separator))
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
    l_all = strlen(tmp) + strlen(l_bs_req.edition) + 8;
    CMB * mb = CCacheX::instance()->get_mb_bs(l_all, CCMD_HANDOUT_RESULT);
    text * l_ptr = mb->base() + CBSData::DATA_OFFSET;
    sprintf(l_ptr, "%s#%c##1#%c#%s", l_bs_req.edition, *l_bs_req.remote_kind,
        l_ret? '1':'0', tmp);
    l_ptr[l_all] = CBSData::LAST_SEPARATOR;
    CRunnerX::instance()->balance_container()->scheduler()->post_bs(mb);

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
  v_bs_req.key = key;
  CPG & l_database = CRunnerX::instance()->pg();

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
    if (!CChecksumComputer::compute_single_cs(v_bs_req.edition, l_single_cs))
      return false;
  }

  if (!l_database.check_online())
  {
    C_ERROR("lost db con, no more proc of dist %s\n", v_bs_req.edition);
    return false;
  }

  if (!l_database.write_task(v_bs_req, l_cs.get_ptr(), l_single_cs.get_ptr()))
  {
    C_ERROR("can not save_dist to db\n");
    return false;
  }

  if (!l_database.write_task_terms(v_bs_req.what_, v_bs_req.local_path, v_bs_req.edition))
  {
    C_ERROR("can not save_dist_clients to db\n");
    return false;
  }

  if (unlikely(!container()->working_app()))
    return false;

  if (!l_database.refresh_task_condition())
  {
    C_ERROR("call to dist_info_update_status() failed\n");
    return false;
  }

  l_database.delete_unused_tasks();

  tell_dists();

  CObsoleteDirDeleter x;
  if (l_database.read_term_SNs(x))
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

  CPG & l_database = CRunnerX::instance()->pg();
  if (!l_database.check_online())
  {
    C_ERROR("lost db con\n");
    return false;
  }

  l_database.write_sr(backid, cmd, acode);
  if (!l_database.refresh_task_condition())
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
  CMB * mb = CCacheX::instance()->get_mb_cmd(0, CCmdHeader::PT_HAS_JOB);
  return c_tools_mb_putq(CRunnerX::instance()->balance_container()->scheduler(), mb, "dist work");
}



CBsReqScheduler::CBsReqScheduler(CContainer * p, ni m): CParentScheduler(p, m)
{
  m_acc = NULL;
}

CONST text * CBsReqScheduler::title() CONST
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


CBsReqContainer::CBsReqContainer(CParentRunner * ptr): CContainer(ptr)
{
  m_scheduler = NULL;
  m_bs_req_task = NULL;
}

CBsReqContainer::~CBsReqContainer()
{

}

CONST text * CBsReqContainer::title() CONST
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
  m_charge_datas = NULL;
  m_handler->msg_queue()->high_water_mark(MQ_PEAK);
}

CBalanceProc::~CBalanceProc()
{

}

CONST text * CBalanceProc::title() CONST
{
  return "CBalanceProc";
}

DVOID CBalanceProc::charge_datas(CChargeDatas * ptr)
{
  m_charge_datas = ptr;
}

CProc::OUTPUT CBalanceProc::at_head_arrival()
{
  if (baseclass::at_head_arrival() == OP_FAIL)
    return OP_FAIL;

  if (m_data_head.cmd == CCmdHeader::PT_LOGIN)
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

  if (m_data_head.cmd == CCmdHeader::PT_CHARGE_REPORT)
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
  if (l_ptr->cmd == CCmdHeader::PT_LOGIN)
    return term_ver_validate(mb);

  if (l_ptr->cmd == CCmdHeader::PT_CHARGE_REPORT)
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
  CChargeData dl;
  dl.set_load(l_x->load);
  dl.set_ip(l_x->ip);
  m_charge_datas->refresh(dl);
  return OP_OK;
}



CBalanceHandler::CBalanceHandler(CHandlerDirector * p): CParentHandler(p)
{
  m_proc = new CBalanceProc(this);
}

DVOID CBalanceHandler::balance_datas(CChargeDatas * p)
{
  ((CBalanceProc*)m_proc)->charge_datas(p);
}

yy_enable_cache(CBalanceHandler);



CBalanceAcc::CBalanceAcc(CParentScheduler * p1, CHandlerDirector * p2): CParentAcc(p1, p2)
{
  m_tcp_port = CCfgX::instance()->server_hole;
  m_reap_interval = REAP_DELAY;
}

ni CBalanceAcc::make_svc_handler(CParentHandler *& v_x)
{
  v_x = new CBalanceHandler(m_director);
  if (!v_x)
  {
    C_ERROR("oom\n");
    return -1;
  }
  v_x->container((void*)this);
  v_x->reactor(reactor());
  ((CBalanceHandler*)v_x)->balance_datas(CRunnerX::instance()->position_container()->charge_datas());
  return 0;
}

CONST text * CBalanceAcc::title() CONST
{
  return "CBalanceAcc";
}


CBalanceScheduler::CBalanceScheduler(CContainer * p, ni m): CParentScheduler(p, m)
{
  m_acc = NULL;
  m_bs_conn = NULL;
  msg_queue()->high_water_mark(MQ_PEAK);
}

CBalanceScheduler::~CBalanceScheduler()
{
  CTV l_x(CTV::zero);
  ni l_m = 0;
  for (CMB * mb; m_bs_mq.dequeue(mb, &l_x) != -1; )
  {
    ++l_m;
    mb->release();
  }
}

CONST text * CBalanceScheduler::title() CONST
{
  return "CBalanceScheduler";
}

DVOID CBalanceScheduler::post_bs(CMB * mb)
{
  CTV l_x(CTV::zero);
  if (m_bs_mq.enqueue(mb, &l_x) < 0)
  {
    C_ERROR("post to bs failed, %s\n", (CONST char*)CSysError());
    mb->release();
  }
}

ni CBalanceScheduler::handle_timeout(CONST CTV &, CONST DVOID *)
{
  CRunnerX::instance()->position_container()->charge_datas()->check_broken();
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

  CTV l_x(ni(CChargeDatas::BROKEN_INTERVAL * 60 / CParentRunner::CLOCK_TIME / 2));
  if (reactor()->schedule_timer(this, 0, l_x, l_x) == -1)
  {
    C_ERROR("fail to setup timer: balance check\n");
    return false;
  }
  return true;
}

truefalse CBalanceScheduler::do_schedule_work()
{
  CTV tv(CTV::zero);
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


CBalanceContainer::CBalanceContainer(CParentRunner * ptr): CContainer(ptr)
{
  m_scheduler = NULL;
}

CBalanceContainer::~CBalanceContainer()
{

}

CONST text * CBalanceContainer::title() CONST
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

CONST text * CM2BsProc::title() CONST
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

yy_enable_cache(CM2BsProc);


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

ni CM2BsHandler::handle_timeout(CONST CTV &, CONST DVOID *)
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
  CTV l_x(30);
  if (reactor()->schedule_timer(this, (void*)0, l_x, l_x) < 0)
  {
    C_ERROR("CM2BsHandler setup timer failed, %s", (CONST char*)CSysError());
    return -1;
  }

  if (!g_is_test)
    C_INFO("CM2BsHandler setup timer: OK\n");

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

yy_enable_cache(CM2BsHandler);


CM2BsConn::CM2BsConn(CParentScheduler * p1, CHandlerDirector * p2): CParentConn(p1, p2)
{
  m_port_of_ip = CCfgX::instance()->bs_hole;
  m_retry_delay = RETRY_DELAY;
  m_remote_ip = CCfgX::instance()->bs_ip;
}

CONST text * CM2BsConn::title() CONST
{
  return "CM2BsConn";
}

ni CM2BsConn::make_svc_handler(CParentHandler *& v_x)
{
  v_x = new CM2BsHandler(m_director);
  if (!v_x)
  {
    C_ERROR("oom %s\n", title());
    return -1;
  }
  v_x->container((void*)this);
  v_x->reactor(reactor());
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
    C_WARNING("recv cs reply term_sn(%s) did(%s)\n", term_sn(), dist_data->edition.get_ptr());
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
  CRunnerX::instance()->d2m_container()->post_bs(mb);
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
        dist_data->edition.get_ptr(), dist_data->remote_kind[0], term_sn(), '2', '1', tmp);

    CRunnerX::instance()->ping_component()->download_reply_gatherer().append(
        dist_data->edition.get_ptr(), dist_data->remote_kind[0], term_sn(), '3', '1', tmp);

    CRunnerX::instance()->ping_component()->download_reply_gatherer().append(
        dist_data->edition.get_ptr(), dist_data->remote_kind[0], term_sn(), '4', '1', tmp);

    post_subs(true);

    term_station->destruct_term_item(this);
    return;
  }

  if (!checksum.get_ptr() || !checksum.get_ptr()[0])
  {
    set_checksum(cs_s);
    CRunnerX::instance()->pg().write_task_term_cs(term_sn(), dist_data->edition.get_ptr(), cs_s, 2);
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
      CRunnerX::instance()->pg().write_task_term_item_condition(*this, 1);
      set_condition(1);
    }
    return true;
  }

  if (post_download())
  {
    CRunnerX::instance()->pg().write_task_term_item_condition(*this, 3);
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
    if ((dist_data->checksum_opt_size > 0 && (ni)strlen(checksum.get_ptr()) >= dist_data->checksum_opt_size) || !create_cmp_file())
    {
      cmp_fn.init(CCompFactory::single_fn());
      cmp_checksum.init(dist_data->compress_checksum.get_ptr());
    }
    CRunnerX::instance()->pg().write_task_term_mbz(term_sn(), dist_data->edition.get_ptr(), cmp_fn.get_ptr(), cmp_checksum.get_ptr());
  }

  if (post_download())
  {
    CRunnerX::instance()->pg().write_task_term_item_condition(*this, 3);
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
  ni l_x2 = dist_data->local_file_size > 0 ? dist_data->local_file_size : (ni)CCmdHeader::ITEM_NULL_SIZE;
  return dist_data->edition_size + dist_data->remote_file_size + l_x2 + l_x1 + 4 + 2 + 2;
}

DVOID CDistTermItem::format_common_header(text * v_ptr)
{
  sprintf(v_ptr, "%s%c%s%c%s%c%s%c%c%c%c%c",
      dist_data->edition.get_ptr(), CCmdHeader::DATA_MARK,
      dist_data->remote_file.get_ptr(), CCmdHeader::DATA_MARK,
      adir.get_ptr()? adir.get_ptr(): Item_NULL, CCmdHeader::DATA_MARK,
      dist_data->local_file.get_ptr()? dist_data->local_file.get_ptr(): Item_NULL, CCmdHeader::DATA_MARK,
      dist_data->remote_kind[0], CCmdHeader::DATA_MARK,
      dist_data->local_kind[0], CCmdHeader::LAST_MARK);
}

CMB * CDistTermItem::create_mb_of_download_sub(truefalse fine)
{
  CMemProt l_cs;
  text tmp[32];
  c_tools_convert_time_to_text(tmp, 32, true);
  CONST text * l_x;
  if (c_tell_type_multi(dist_data->local_kind[0]))
  {
    if (!checksum.get_ptr())
      l_x = "";
    else
    {
      l_cs.init(checksum.get_ptr());
      c_tools_text_replace(l_cs.get_ptr(), CCmdHeader::DATA_MARK, ':');
      ni len = strlen(l_cs.get_ptr());
      if (l_cs.get_ptr()[len - 1] == ':')
        l_cs.get_ptr()[len - 1] = 0;
      l_x = l_cs.get_ptr();
    }
  }
  else
    l_x = dist_data->remote_file.get_ptr();

  ni l_m = strlen(term_station->term_sn()) + strlen(dist_data->edition.get_ptr()) +
      strlen(tmp) + strlen(dist_data->remote_file.get_ptr()) + strlen(l_x) + 10;
  CMB * mb = CCacheX::instance()->get_mb_bs(l_m, CCMD_HANDOUT_MORE_INFO);
  text * l_ptr = mb->base() + CBSData::DATA_OFFSET;
  sprintf(l_ptr, "%s#%c#%s#%s#%s#%c#%c#%s", dist_data->edition.get_ptr(),
      dist_data->remote_kind[0], term_station->term_sn(), dist_data->remote_file.get_ptr(),
      l_x, dist_data->local_kind[0], fine? '1': '0', tmp);
  l_ptr[l_m] = CBSData::LAST_SEPARATOR;
  return mb;
}

truefalse CDistTermItem::post_cs()
{
  if (!dist_data->check_sum.get_ptr() || !dist_data->check_sum.get_ptr()[0] || dist_data->checksum_size <= 0)
    return false;

  ni l_cs_size = dist_data->checksum_size + 1;
  ni l_m = calc_common_header_len() + l_cs_size;
  CMB * mb = CCacheX::instance()->get_mb_cmd(l_m, CCmdHeader::PT_CHECKSUMS);
  CCmdExt * l_ptr = (CCmdExt *)mb->base();
  l_ptr->signature = term_position();
  format_common_header(l_ptr->data);
  memcpy(l_ptr->data + l_m - l_cs_size, dist_data->check_sum.get_ptr(), l_cs_size);

  prev_access = time(NULL);

  return c_tools_mb_putq(CRunnerX::instance()->ping_component()->scheduler(), mb, "checksum");
}

truefalse CDistTermItem::create_cmp_file()
{
  CMemProt l_to_dir;
  CMemProt l_cmp_path;
  CMemProt l_to_fn;
  l_to_dir.init(CCfgX::instance()->bz_files_path.c_str(), "/", dist_data->edition.get_ptr());
  l_cmp_path.init(l_to_dir.get_ptr(), "/", CCompFactory::dir_of_composite());
  l_to_fn.init(l_cmp_path.get_ptr(), "/", term_sn(), ".mbz");
  CCompUniter l_uniter;
  if (!l_uniter.begin(l_to_fn.get_ptr()))
    return false;
  CMemProt l_cs2;
  l_cs2.init(checksum.get_ptr());
  text separators[2] = { CCmdHeader::DATA_MARK, 0 };
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
  ni l_m = dist_data->edition_size + 2;
  CMB * mb = CCacheX::instance()->get_mb_cmd(l_m, CCmdHeader::PT_PAUSE_STOP);
  CCmdExt * l_ptr = (CCmdExt *)mb->base();
  l_ptr->signature = term_position();
  l_ptr->data[0] = c;
  memcpy(l_ptr->data + 1, dist_data->edition.get_ptr(), l_m - 1);
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
    l_cmp_cs = dist_data->compress_checksum.get_ptr();
  } else
  {
    download_fn = cmp_fn.get_ptr();
    l_cmp_cs = cmp_checksum.get_ptr();
  }

  ni l_m = strlen(l_cmp_cs) + 1;
  ni l_header_size = calc_common_header_len();
  ni l_download_fn_size = strlen(download_fn) + 1;
  ni l_n = l_header_size + l_download_fn_size + dist_data->key_size + 1 + l_m;
  CMB * mb = CCacheX::instance()->get_mb_cmd(l_n, CCmdHeader::PT_DOWNLOAD);
  CCmdExt * l_ptr = (CCmdExt *)mb->base();
  l_ptr->signature = term_position();
  format_common_header(l_ptr->data);
  text * l_ptr2 = l_ptr->data + l_header_size;
  memcpy(l_ptr2, download_fn, l_download_fn_size);
  l_ptr2 += l_download_fn_size;
  *(l_ptr2 - 1) = CCmdHeader::DATA_MARK;
  memcpy(l_ptr2, l_cmp_cs, l_m);
  l_ptr2 += l_m;
  *(l_ptr2 - 1) = CCmdHeader::LAST_MARK;
  memcpy(l_ptr2, dist_data->key.get_ptr(), dist_data->key_size + 1);

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
  CRunnerX::instance()->pg().destruct_task_term(m_term_sn.to_str(), v_item->dist_data->edition.get_ptr());
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
    CRunnerX::instance()->pg().read_task_terms(m_stations, this);
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
     (CTermQuickFinder(p->dist_data->edition.get_ptr(), p->term_sn()), p));
}

DVOID CTermStations::at_del_term_item(CDistTermItem * p, truefalse done)
{
  if (done)
    ++m_term_station_done;
  m_term_items.erase(CTermQuickFinder(p->dist_data->edition.get_ptr(), p->term_sn()));
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
  C_INFO("Handleout finished: jobs = %d, stations = %d, items = %d\n", m_datas->size(),  m_term_stations.size(), m_term_items.size());
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
    CRunnerX::instance()->ping_component()->prio();

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
    return (CRunnerX::instance()->pg().read_tasks(m_datas) < 0)? false:true;
  }

  return true;
}

truefalse CSpreader::do_term_stations(truefalse v_query_db)
{
  if (v_query_db)
  {
    m_stations.reset();
    if (!CRunnerX::instance()->pg().read_task_terms(&m_stations, NULL))
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
    CRunnerX::instance()->pg().write_task_term_condition(v_term_sn, v_did, v_condition);
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


CHeartBeatGatherer * CPingProc::m_ping_gatherer = NULL;
CLocationGatherer * CPingProc::m_location_gatherer = NULL;
CDownloadReplyGatherer * CPingProc::m_download_reply_gatherer = NULL;
CClickGatherer * CPingProc::m_click_gatherer = NULL;
CHwPowerTimeGatherer * CPingProc::m_HW_powertime_gatherer = NULL;
CHardwareWarnGatherer * CPingProc::m_HW_warn_gatherer = NULL;
CVideoGatherer * CPingProc::m_video_gatherer = NULL;
CNoVideoWarnGatherer * CPingProc::m_no_vide_warn_gatherer = NULL;

CPingProc::CPingProc(CParentHandler * ptr): CParentServerProc(ptr)
{
  m_handler->msg_queue()->high_water_mark(MQ_PEAK);
  m_version_driver[0] = 0;
}

CONST text * CPingProc::title() CONST
{
  return "CPingProc";
}

CProc::OUTPUT CPingProc::at_head_arrival()
{
  if (baseclass::at_head_arrival() == OP_FAIL)
    return OP_FAIL;

  if (m_data_head.cmd == CCmdHeader::PT_HEART_BEAT)
  {
    if (!c_packet_check_ping(&m_data_head))
    {
      CMemProt l_x;
      get_sinfo(l_x);
      C_ERROR("invalid ping from %s\n", l_x.get_ptr());
      return OP_FAIL;
    }

    i_ping();
    return OP_DONE;
  }

  if (m_data_head.cmd == CCmdHeader::PT_LOGIN)
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

  if (m_data_head.cmd == CCmdHeader::PT_NO_VIDEO)
  {
    if (!c_packet_check_no_video(&m_data_head))
    {
      CMemProt l_x;
      get_sinfo(l_x);
      C_ERROR("invalid video null from %s\n", l_x.get_ptr());
      return OP_FAIL;
    }
    return OP_OK;
  }


  if (m_data_head.cmd == CCmdHeader::PT_HW_WARN)
  {
    if (!c_packet_check_hw_warn(&m_data_head))
    {
      CMemProt l_x;
      get_sinfo(l_x);
      C_ERROR("invalid hw warn from %s\n", l_x.get_ptr());
      return OP_FAIL;
    }
    C_DEBUG("recv hw warn from %s\n", m_term_sn.to_str());
    return OP_OK;
  }

  if (m_data_head.cmd == CCmdHeader::PT_CHECKSUMS)
  {
    if (!c_packet_check_checksums_all(&m_data_head))
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

  if (m_data_head.cmd == CCmdHeader::PT_DOWNLOAD)
  {
    if (!c_packet_check_download_cmd(&m_data_head))
    {
      CMemProt l_x;
      get_sinfo(l_x);
      C_ERROR("invalid download reply from %s\n", l_x.get_ptr());
      return OP_FAIL;
    }
    return OP_OK;
  }

  if (m_data_head.cmd == CCmdHeader::PT_LOC_REPORT)
  {
    if (m_data_head.size != sizeof(CLocationReq) || m_data_head.signature != CCmdHeader::SIGNATURE)
    {
      CMemProt l_x;
      get_sinfo(l_x);
      C_ERROR("invalid location from %s\n", l_x.get_ptr());
      return OP_FAIL;
    }
    return OP_OK;
  }

  if (m_data_head.cmd == CCmdHeader::PT_ADV)
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

  if (m_data_head.cmd == CCmdHeader::PT_VIDEO)
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


  if (m_data_head.cmd == CCmdHeader::PT_POWER_TIME)
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

  if (m_data_head.cmd == CCmdHeader::PT_QUIZ)
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

  if (m_data_head.cmd == CCmdHeader::PT_PAUSE_STOP)
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
    CMemProt l_z;
    get_sinfo(l_z);
    C_DEBUG("recv full data: cmd = %d, size = %d from %s\n", m_data_head.cmd, m_data_head.size, l_z.get_ptr());
  }

  CCmdHeader * l_x = (CCmdHeader *)mb->base();
  if (l_x->cmd == CCmdHeader::PT_LOGIN)
    return i_ver(mb);

  if (l_x->cmd == CCmdHeader::PT_NO_VIDEO)
    return i_no_video_warn(mb);

  if (l_x->cmd == CCmdHeader::PT_HW_WARN)
    return i_hw_warn(mb);

  if (l_x->cmd == CCmdHeader::PT_CHECKSUMS)
    return i_checksums(mb);

  if (l_x->cmd == CCmdHeader::PT_DOWNLOAD)
    return i_download_feedback(mb);

  if (l_x->cmd == CCmdHeader::PT_LOC_REPORT)
    return i_location(mb);

  if (l_x->cmd == CCmdHeader::PT_ADV)
    return i_click(mb);

  if (l_x->cmd == CCmdHeader::PT_VIDEO)
    return i_video(mb);

  if (l_x->cmd == CCmdHeader::PT_POWER_TIME)
    return i_hw_powertime(mb);

  if (l_x->cmd == CCmdHeader::PT_QUIZ)
    return i_test(mb);

  if (l_x->cmd == CCmdHeader::PT_PAUSE_STOP)
    return i_pause_stop(mb);

  CMBProt guard(mb);
  C_ERROR("get unknown cmd = %d\n",
      l_x->cmd);
  return OP_FAIL;
}

DVOID CPingProc::i_ping()
{
  m_ping_gatherer->append(m_term_sn.to_str(), m_term_sn_len);
}

CProc::OUTPUT CPingProc::i_ver(CMB * mb)
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

  ACE_OS::strsncpy(m_version_driver, ((CTerminalVerReq*)mb->base())->driver_edition, 12);
  if (m_version_driver[0] == 0)
  {
    ACE_OS::strcpy(m_version_driver, "NULL");
    CMemProt l_x;
    get_sinfo(l_x);
    C_WARNING("term ver contains no hw ver: %s\n", l_x.get_ptr());
  }
  CProc::OUTPUT l_result = i_is_ver_ok(mb, term_SNs);

  m_location_gatherer->append(m_term_sn.to_str(), m_term_sn_len, m_remote_ip, m_term_ver.to_text(), m_version_driver);

  if (l_result != OP_GO_ON)
    return l_result;

  CTermData l_term_data;
  term_SNs.get_termData(m_term_loc, l_term_data);

  CMB * l_mbx;
  if (m_term_ver < CCfgX::instance()->term_edition_min)
  {
    l_mbx = i_create_mb_ver_reply(CTermVerReply::SC_NOT_MATCH, l_term_data.download_auth_len + 2);
    m_mark_down = true;
  }
  else if (m_term_ver < CCfgX::instance()->term_edition_now)
    l_mbx = i_create_mb_ver_reply(CTermVerReply::SC_OK_UP, l_term_data.download_auth_len + 2);
  else
    l_mbx = i_create_mb_ver_reply(CTermVerReply::SC_OK, l_term_data.download_auth_len + 2);

  if (!m_mark_down)
  {
    CTerminalVerReq * l_z = (CTerminalVerReq *)mb->base();
    if (l_z->handleout_id != CCfgX::instance()->sid)
      term_SNs.server_changed(m_term_loc, true);

    CMemProt l_x;
    get_sinfo(l_x);
    C_INFO(ACE_TEXT("terminal login success: %s\n"), l_x.get_ptr());
  }

  CTermVerReply * l_vr = (CTermVerReply *) l_mbx->base();
  *((u_int8_t*)l_vr->data) = CCfgX::instance()->sid;
  memcpy(l_vr->data + 1, l_term_data.download_auth, l_term_data.download_auth_len + 1);
  if (m_handler->post_packet(l_mbx) < 0)
    return OP_FAIL;
  return i_post_pq();
}

CProc::OUTPUT CPingProc::i_post_pq()
{
  CMemProt l_x;
  if (!CRunnerX::instance()->ping_component()->get_prio(l_x))
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

CProc::OUTPUT CPingProc::i_checksums(CMB * mb)
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

  CRunnerX::instance()->ping_component()->task()->append_task_delay(mb);
  return OP_OK;
}

CProc::OUTPUT CPingProc::i_download_feedback(CMB * mb)
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
  CRunnerX::instance()->ping_component()->task()->append_task(mb, true);
  if (l_mbx != NULL)
    if (m_handler->post_packet(l_mbx) < 0)
      return OP_FAIL;
  return OP_OK;
}

CProc::OUTPUT CPingProc::i_location(CMB * mb)
{
  CMBProt prot(mb);
  m_location_gatherer->append(m_term_sn.to_str(), m_term_sn_len, m_remote_ip, m_term_ver.to_text(), m_version_driver);
  return OP_OK;
}

CProc::OUTPUT CPingProc::i_click(CMB * mb)
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

  CONST text l_xxx[] = {CCmdHeader::LAST_MARK, 0};
  CTextDelimiter l_delimiter(l_ptr->data, l_xxx);
  text * l_data;
  while ((l_data = l_delimiter.get()) != NULL)
  {
    CONST text l_yyy[] = {CCmdHeader::DATA_MARK, 0};
    CTextDelimiter l_delimiter_2(l_data, l_yyy);
    CONST text * chn = l_delimiter_2.get();
    CONST text * pcode = l_delimiter_2.get();
    CONST text * l_x;
    CONST text * l_ran;
    if (unlikely(!pcode))
      continue;
    l_x = l_delimiter_2.get();
    if (unlikely(!l_x))
      continue;
    if (strlen(l_x) >= 12)
      continue;
    l_ran = l_delimiter_2.get();
    if (unlikely(!l_ran))
      continue;
    m_click_gatherer->append(m_term_sn.to_str(), m_term_sn_len, chn, pcode, l_x, l_ran);
  }

  return OP_OK;
}

CProc::OUTPUT CPingProc::i_hw_warn(CMB * mb)
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
  m_HW_warn_gatherer->append(m_term_sn.to_str(), m_term_sn_len, l_warn->x, l_warn->y, tmp);
  return OP_OK;
}

CProc::OUTPUT CPingProc::i_video(CMB * mb)
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

  text l_xxx[2] = {CCmdHeader::DATA_MARK, 0};
  CTextDelimiter l_delimiter(l_ptr->data, l_xxx);
  text * l_tag;
  while ((l_tag = l_delimiter.get()) != NULL)
  {
    text * l_p = strchr(l_tag, CCmdHeader::CENTER_MARK);
    if (!l_p)
      continue;
    *l_p ++ = 0;
    m_video_gatherer->append(m_term_sn.to_str(), m_term_sn_len, l_tag, l_p);
  }
  return OP_OK;
}

CProc::OUTPUT CPingProc::i_no_video_warn(CMB * mb)
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
    m_no_vide_warn_gatherer->append(m_term_sn.to_str(), m_term_sn_len, l_z);
  return OP_OK;
}

CProc::OUTPUT CPingProc::i_pause_stop(CMB * mb)
{
  CRunnerX::instance()->ping_component()->task()->append_task(mb, true);
  return OP_OK;
}

CProc::OUTPUT CPingProc::i_hw_powertime(CMB * mb)
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

  m_HW_powertime_gatherer->append(m_term_sn.to_str(), m_term_sn_len, l_ptr->data[0], l_ptr->data + 1);
  return OP_OK;
}

CProc::OUTPUT CPingProc::i_test(CMB * mb)
{
  C_DEBUG("handle test %d bytes...\n", mb->length());
  CCmdHeader * l_header = (CCmdHeader *) mb->base();
  l_header->signature = CCmdHeader::SIGNATURE;
  m_handler->post_packet(mb);
  return OP_OK;
}

yy_enable_cache(CPingProc);


CGatheredData::CGatheredData(ni v_chunk_len, ni piece_peak_size, CParentGatherer * v_gatherer, truefalse v_self_post)
{
  m_chunk_size = v_chunk_len;
  m_peak_piece_size = piece_peak_size + 1;
  m_gatherer = v_gatherer;
  m_post_automatic = v_self_post;
  m_mb = CCacheX::instance()->get_mb(m_chunk_size);
  v_gatherer->add_chunk(this);
  clear();
}

CGatheredData::~CGatheredData()
{
  if (m_mb)
    m_mb->release();
}

DVOID CGatheredData::clear()
{
  m_free_pos = m_mb->base();
}

truefalse CGatheredData::append(CONST text * v_data, ni v_data_size)
{
  if (v_data_size == 0)
    v_data_size = strlen(v_data);
  ++v_data_size;
  ni l_m = m_chunk_size - (m_free_pos - m_mb->base());
  if (unlikely(v_data_size > l_m))
  {
    if (m_post_automatic)
    {
      m_gatherer->post();
      l_m = m_chunk_size;
    } else
    {
      C_FATAL("CGatheredData::append too long: accept size = %d, param = %s\n", l_m, v_data);
      return false;
    }
  }
  memcpy(m_free_pos, v_data, v_data_size - 1);
  m_free_pos += v_data_size;
  *(m_free_pos - 1) = DATA_MARK;
  return (l_m - v_data_size > m_peak_piece_size);
}

truefalse CGatheredData::append(text v)
{
  text tmp[2];
  tmp[0] = v;
  tmp[1] = 0;
  return append(tmp, 1);
}

CONST text * CGatheredData::data()
{
  return m_mb->base();
}

ni CGatheredData::chunk_size() CONST
{
  ni l_x = (m_free_pos - m_mb->base());
  return std::max(l_x - 1, 0);
}


CParentGatherer::~CParentGatherer()
{

}

DVOID CParentGatherer::post()
{
  i_post(what_action());
  clear();
}

DVOID CParentGatherer::post_if_needed()
{
  if ((*m_chunks.begin())->chunk_size() == 0)
    return;

  post();
}

DVOID CParentGatherer::add_chunk(CGatheredData * ptr)
{
  m_chunks.push_back(ptr);
}

DVOID CParentGatherer::i_post(CONST text * ptr)
{
  if (unlikely((*m_chunks.begin())->chunk_size() == 0))
    return;
  CGatheredDatas::iterator it;

  ni l_m = 0;
  for (it = m_chunks.begin(); it != m_chunks.end(); ++it)
    l_m += (*it)->chunk_size() + 1;
  --l_m;

  CMB * mb = CCacheX::instance()->get_mb_bs(l_m, ptr);
  text * l_to = mb->base() + CBSData::DATA_OFFSET;
  for (it = m_chunks.begin(); ; )
  {
    ni l_n = (*it)->chunk_size();
    memcpy(l_to, (*it)->data(), l_n);
    if (++it != m_chunks.end())
    {
      l_to[l_n] = CBSData::PAR_MARK;
      l_to += (l_n + 1);
    } else
      break;
  }
  CRunnerX::instance()->d2m_container()->post_bs(mb);
}

DVOID CParentGatherer::clear()
{
  std::for_each(m_chunks.begin(), m_chunks.end(), std::mem_fun(&CGatheredData::clear));
};




CDownloadReplyGatherer::CDownloadReplyGatherer():
  m_task_chunk(BUFF_LEN, 32, this), m_ftype_chunk(BUFF_LEN, 1, this), m_term_sn_chunk(BUFF_LEN, sizeof(CNumber), this),
  m_step_chunk(BUFF_LEN, 1, this), m_fine_chunk(BUFF_LEN, 1, this), m_date_chunk(BUFF_LEN, 15, this)
{

}

CDownloadReplyGatherer::~CDownloadReplyGatherer()
{

}

CONST text * CDownloadReplyGatherer::what_action() CONST
{
  return CCMD_HANDOUT_RESULT;
}

DVOID CDownloadReplyGatherer::append(CONST text * v_did, text ftype, CONST text *term_sn, text step, text fine, CONST text * v_dt)
{
  truefalse ret = true;

  if (!m_task_chunk.append(v_did))
    ret = false;
  if (!m_term_sn_chunk.append(term_sn))
    ret = false;
  if (!m_ftype_chunk.append(ftype))
    ret = false;
  if (!m_step_chunk.append(step))
    ret = false;
  if (!m_fine_chunk.append(fine))
    ret = false;
  if (!m_date_chunk.append(v_dt))
    ret = false;

  if (!ret)
    post();
}



CHeartBeatGatherer::CHeartBeatGatherer(): m_chunk(BUFF_LEN, sizeof(CNumber), this, true)
{

}

CHeartBeatGatherer::~CHeartBeatGatherer()
{

}

DVOID CHeartBeatGatherer::append(CONST text * term_sn, CONST ni m)
{
  if (unlikely(!term_sn || !*term_sn || m <= 0))
    return;
  if (!m_chunk.append(term_sn, m))
    post();
}

CONST text * CHeartBeatGatherer::what_action() CONST
{
  return CCMD_HEART_BEAT;
}


CLocationGatherer::CLocationGatherer():
    m_term_sn_chunk(BUFF_LEN, sizeof(CNumber), this),
    m_ip_chunk(BUFF_LEN, INET_ADDRSTRLEN, this),
    m_ver_chunk(BUFF_LEN * 3 / sizeof(CNumber) + 1, 7, this)//,
{

}

DVOID CLocationGatherer::append(CONST text * term_sn, ni sn_size, CONST text * ip, CONST text * ver, CONST text *)
{
  truefalse l_x = true;
  if (!m_term_sn_chunk.append(term_sn, sn_size))
    l_x = false;
  if (!m_ip_chunk.append(ip, 0))
    l_x = false;
  if (!m_ver_chunk.append(ver, 0))
    l_x = false;

  if (!l_x)
    post();
}

CONST text * CLocationGatherer::what_action() CONST
{
  return CCMD_LOC_REPORT;
}



CHwPowerTimeGatherer::CHwPowerTimeGatherer(): m_term_sn_chunk(BUFF_LEN, sizeof(CNumber), this),
    m_on_off_chunk(BUFF_LEN / 10, 1, this), m_datetime_chunk(BUFF_LEN, 25, this)
{

}

DVOID CHwPowerTimeGatherer::append(CONST text * term_sn, ni sn_size, CONST text isOn, CONST text * v_dt)
{
  truefalse l_x = true;
  if (!m_term_sn_chunk.append(term_sn, sn_size))
    l_x = false;
  if (!m_on_off_chunk.append(isOn))
    l_x = false;
  if (!m_datetime_chunk.append(v_dt, 0))
    l_x = false;

  if (!l_x)
    post();
}

CONST text * CHwPowerTimeGatherer::what_action() CONST
{
  return CCMD_POWERON_LINK;
}


CClickGatherer::CClickGatherer() : m_term_sn_chunk(BUFF_LEN, sizeof(CNumber), this),
    m_chn_chunk(BUFF_LEN, 50, this), m_pcode_chunk(BUFF_LEN, 50, this), m_number_chunk(BUFF_LEN, 24, this),
    m_ran_chunk(BUFF_LEN, 80, this)
{

}

DVOID CClickGatherer::append(CONST text * term_sn, ni sn_size, CONST text * chn, CONST text * pcode,
    CONST text * v_count, CONST text * v_ran)
{
  truefalse l_x = true;
  if (!m_term_sn_chunk.append(term_sn, sn_size))
    l_x = false;
  if (!m_chn_chunk.append(chn, 0))
    l_x = false;
  if (!m_pcode_chunk.append(pcode, 0))
    l_x = false;
  if (!m_number_chunk.append(v_count, 0))
    l_x = false;
  if (!m_ran_chunk.append(v_ran, 0))
    l_x = false;

  if (!l_x)
    post();
}

CONST text * CClickGatherer::what_action() CONST
{
  return CCMD_ADV;
}




CHardwareWarnGatherer::CHardwareWarnGatherer():
      m_term_sn_chunk(BUFF_LEN, sizeof(CNumber), this),
      m_type_chunk(BUFF_LEN, 1, this),
      m_value_chunk(BUFF_LEN, 5, this),
      m_datetime_chunk(BUFF_LEN, 25, this)
{

}

DVOID CHardwareWarnGatherer::append(CONST text * term_sn, ni sn_size, CONST text x, CONST text y, CONST text * v_dt)
{
  truefalse l_x = true;
  if (!m_term_sn_chunk.append(term_sn, sn_size))
    l_x = false;

  if (!m_type_chunk.append(x))
    l_x = false;

  if (x != '6')
  {
    if (!m_value_chunk.append(y))
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
    if (!m_value_chunk.append(l_y))
      l_x = false;
  }

  if (!m_datetime_chunk.append(v_dt))
    l_x = false;

  if (!l_x)
    post();
}

CONST text * CHardwareWarnGatherer::what_action() CONST
{
  return CCMD_HARD_MON;
}


CVideoGatherer::CVideoGatherer():
    m_term_sn_chunk(BUFF_LEN, sizeof(CNumber), this),
    m_fn_chunk(BUFF_LEN, 200, this),
    m_number_chunk(BUFF_LEN, 8, this)
{

}

DVOID CVideoGatherer::append(CONST text * term_sn, ni sn_size, CONST text * fn, CONST text * v_count)
{
  ni l_m = strlen(fn);
  if (l_m >= 200)
    return;
  truefalse l_x = true;
  if (!m_term_sn_chunk.append(term_sn, sn_size))
    l_x = false;
  if (!m_fn_chunk.append(fn, l_m))
    l_x = false;
  if (!m_number_chunk.append(v_count, 0))
    l_x = false;

  if (!l_x)
    post();
}

CONST text * CVideoGatherer::what_action() CONST
{
  return CCMD_VIDEO;
}


CNoVideoWarnGatherer::CNoVideoWarnGatherer():
    m_term_sn_chunk(BUFF_LEN, sizeof(CNumber), this),
    m_state_chunk(BUFF_LEN, 400, this),
    m_datetime_chunk(BUFF_LEN, 25, this)
{

}

DVOID CNoVideoWarnGatherer::append(CONST text * term_sn, ni sn_size, CONST text condition)
{
  truefalse l_x = true;
  if (!m_term_sn_chunk.append(term_sn, sn_size))
    l_x = false;
  if (!m_state_chunk.append(condition))
    l_x = false;

  text tmp[32];
  c_tools_convert_time_to_text(tmp, 20, true);
  if (!m_datetime_chunk.append(tmp))
    l_x = false;

  if (!l_x)
    post();
}

CONST text * CNoVideoWarnGatherer::what_action() CONST
{
  return CCMD_NO_VIDEO;
}


CPingHandler::CPingHandler(CHandlerDirector * p): CParentHandler(p)
{
  m_proc = new CPingProc(this);
}

CTermSNs * CPingHandler::term_SNs() CONST
{
  return g_term_sns;
}

yy_enable_cache(CPingHandler);


CPingTask::CPingTask(CContainer * p, ni m): CTaskBase(p, m)
{
  msg_queue()->high_water_mark(MQ_PEAK);
  m_mq_two.high_water_mark(MQ_PEAK * 5);
}

truefalse CPingTask::append_task(CMB * mb, truefalse v_at_end)
{
  CTV l_z(CTV::zero);
  ni l_x;
  if (v_at_end)
    l_x = this->msg_queue()->enqueue_tail(mb, &l_z);
  else
    l_x = this->msg_queue()->enqueue_head(mb, &l_z);
  if (unlikely(l_x < 0))
  {
    C_ERROR("CPingTask::append_task: %s\n", (CONST text *)CSysError());
    mb->release();
    return false;
  }

  return true;
}

truefalse CPingTask::append_task_delay(CMB * mb)
{
  CTV l_x(CTV::zero);
  if (unlikely(m_mq_two.enqueue_tail(mb, &l_x) < 0))
  {
    C_ERROR("CPingTask::append_task_delay: %s\n", (CONST text *)CSysError());
    mb->release();
    return false;
  }

  return true;
}

ni CPingTask::svc()
{
  C_INFO("start %s::svc()\n", title());
  CMB * mb;
  CTV l_z(CTV::zero);
  while (CRunnerX::instance()->running())
  {
    truefalse l_x = true;
    for (; this->msg_queue()->dequeue(mb, &l_z) != -1; )
    {
      l_x = false;
      CMBProt prot(mb);
      if (mb->capacity() == sizeof(ni))
      {
        ni l_command = *(ni*)mb->base();
        if (l_command == TID_)
        {
          m_spreader.work(false);
        } else
          C_ERROR("bad cmd (%d)\n", l_command);
      } else
      {
        CCmdHeader * l_header = (CCmdHeader *) mb->base();
        if (l_header->cmd == CCmdHeader::PT_HAS_JOB)
        {
          handle_have_job();
        } else if ((l_header->cmd == CCmdHeader::PT_DOWNLOAD))
        {
          handle_download_feedback(mb);
        } else if ((l_header->cmd == CCmdHeader::PT_PAUSE_STOP))
        {
          handle_pause_stop(mb);
        } else
          C_ERROR("bad cmd: %s, cmd = %d\n", title(), l_header->cmd);
      }
    }

    if (m_mq_two.dequeue_head(mb, &l_z) != -1)
    {
      l_x = false;
      CMBProt prot(mb);
      CCmdHeader * l_xyz = (CCmdHeader *) mb->base();
      if ((l_xyz->cmd == CCmdHeader::PT_CHECKSUMS))
      {
        handle_cs_feedback(mb);
      } else
        C_ERROR("bad data @%s, cmd = %d\n", title(), l_xyz->cmd);
    }

    if (l_x)
      ACE_OS::sleep(1);
  }
  C_INFO("exiting %s::svc()\n", title());
  return 0;
}

DVOID CPingTask::handle_have_job()
{
  m_spreader.work(true);
}

DVOID CPingTask::handle_download_feedback(CMB * mb)
{
  CCmdExt * l_x = (CCmdExt*) mb->base();
  CNumber l_term_sn;
  if (unlikely(!CRunnerX::instance()->termSNs().get_sn(l_x->signature, &l_term_sn)))
  {
    C_FATAL("not found term sn @handle_download_feedback\n");
    return;
  }

  ni l_i = l_x->size - sizeof(CCmdHeader);
  if (unlikely(l_x->data[l_i - 5] != CCmdHeader::DATA_MARK))
  {
    C_ERROR("invalid download rep data @%s.1\n", title());
    return;
  }
  l_x->data[l_i - 5] = 0;
  if (unlikely(!l_x->data[0]))
  {
    C_ERROR("invalid download rep data @%s.2, no task found\n", title());
    return;
  }

  CONST text * l_task = l_x->data;
  text l_fine = l_x->data[l_i - 4];
  text l_read_state = l_x->data[l_i - 3];
  text l_ftype = l_x->data[l_i - 2];
  text l_pace = 0;
  ni l_condition;

  if (unlikely(l_fine != '0' && l_fine != '1'))
  {
    C_ERROR("bad ok flag(%c) @%s\n", l_fine, title());
    return;
  }
  if (unlikely(!c_tell_ftype_valid(l_ftype) && l_ftype != 'x'))
  {
    C_ERROR("bad ftype(%c) @%s\n", l_ftype, title());
    return;
  }

  if (l_read_state == '2')
  {
    C_DEBUG("get download cmd term_sn(%s) task(%s)\n", l_term_sn.to_str(), l_task);
    l_condition = 4;
  } else if (l_read_state == '3')
  {
    l_condition = 5;
    l_pace = '3';
    C_DEBUG("get download done term_sn(%s) task(%s)\n", l_term_sn.to_str(), l_task);
  } else if (l_read_state == '4')
  {
    l_condition = 5;
    C_DEBUG("get decompress done term_sn(%s) task(%s)\n", l_term_sn.to_str(), l_task);
  } else if (l_read_state == '5')
  {
    l_condition = 5;
    C_DEBUG("get decompress failed term_sn(%s) task(%s)\n", l_term_sn.to_str(), l_task);
  } else if (l_read_state == '9')
  {
    C_DEBUG("get download begin term_sn(%s) task(%s)\n", l_term_sn.to_str(), l_task);
    l_pace = '2';
  } else if (l_read_state == '7')
  {
    C_DEBUG("get download failed term_sn(%s) task(%s)\n", l_term_sn.to_str(), l_task);
    l_pace = '3';
    l_condition = 5;
  }
  else
  {
    C_ERROR("bad download result: %c\n", l_read_state);
    return;
  }

  if ((l_ftype != 'x') && l_pace != 0)
  {
    text tmp[32];
    c_tools_convert_time_to_text(tmp, 32, true);
    ((CPingContainer *)container())->download_reply_gatherer().append(l_task, l_ftype, l_term_sn.to_str(), l_pace, l_fine, tmp);
    if (l_pace == '3' && l_fine == '1')
      ((CPingContainer *)container())->download_reply_gatherer().append(l_task, l_ftype, l_term_sn.to_str(), '4', l_fine, tmp);
  }
  if (l_read_state == '9')
    return;

  m_spreader.at_download_cmd_feedback(l_term_sn.to_str(), l_task, l_condition, l_fine == '1');
}

DVOID CPingTask::handle_pause_stop(CMB * mb)
{
  CCmdExt * l_x = (CCmdExt*) mb->base();
  CNumber l_term_sn;
  if (unlikely(!CRunnerX::instance()->termSNs().get_sn(l_x->signature, &l_term_sn)))
  {
    C_FATAL("term sn not found CPingTask::handle_pause_stop\n");
    return;
  }

  m_spreader.control_pause_stop(l_term_sn.to_str(), l_x->data + 1, l_x->data[0]);
}

DVOID CPingTask::handle_cs_feedback(CMB * mb)
{
  CCmdExt * l_x = (CCmdExt*) mb->base();
  CNumber l_term_sn;
  if (unlikely(!CRunnerX::instance()->termSNs().get_sn(l_x->signature, &l_term_sn)))
  {
    C_FATAL("term sn not found CPingTask::handle_cs_feedback\n");
    return;
  }

  if (unlikely(!l_x->data[0]))
  {
    C_ERROR("%s::handle_cs_feedback no task\n", title());
    return;
  }
  text * l_cs_s = strchr(l_x->data, CCmdHeader::DATA_MARK);
  if (unlikely(!l_cs_s))
  {
    C_ERROR("invalid data %s::handle_cs_feedback, no task mark\n", title());
    return;
  }
  *l_cs_s ++ = 0;
  CONST text * l_task = l_x->data;
  C_DEBUG("checksum term_sn(%s) task(%s): size = %d\n", l_term_sn.to_str(), l_task, strlen(l_cs_s));
  m_spreader.at_download_checksum_feedback(l_term_sn.to_str(), l_task, l_cs_s);
}


CPingAcc::CPingAcc(CParentScheduler * p1, CHandlerDirector * p2): CParentAcc(p1, p2)
{
  m_tcp_port = CCfgX::instance()->ping_hole;
  m_reap_interval = REAP_TIMEOUT;
}

ni CPingAcc::make_svc_handler(CParentHandler *& v_x)
{
  v_x = new CPingHandler(m_director);
  if (!v_x)
  {
    C_ERROR("oom @%s\n", title());
    return -1;
  }
  v_x->container((void*)this);
  v_x->reactor(reactor());
  return 0;
}

CONST text * CPingAcc::title() CONST
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

CONST text * CPingScheduler::title() CONST
{
  return "CPingScheduler";
}

CPingAcc * CPingScheduler::acc() CONST
{
  return m_acc;
}

ni CPingScheduler::handle_timeout(CONST CTV &, CONST DVOID * v_x)
{
  if ((long)v_x == CParentScheduler::TID)
  {
    CMB *mb;
    CTV l_tv(CTV::zero);
    while (-1 != this->getq(mb, &l_tv))
    {
      if (unlikely(mb->size() < sizeof(CCmdHeader)))
      {
        C_ERROR("bad mb size @%s::handle_timeout\n", title());
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

      if (unlikely(CCmdHeader::PT_TERMINATE_CONNECTION_I == ((CCmdHeader*)mb->base())->cmd))
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
    CPingProc::m_ping_gatherer->post_if_needed();
  } else if ((long)v_x == TID_LOCATION)
  {
    CPingProc::m_location_gatherer->post_if_needed();
  } else if ((long)v_x == TID_DOWNLOAD_REPLY)
  {
    CPingProc::m_download_reply_gatherer->post_if_needed();
  }
  else if ((long)v_x == TID_HAS_JOB)
  {
    CMB * mb = CCacheX::instance()->get_mb(sizeof(ni));
    *(ni*)mb->base() = CPingTask::TID_;
    CRunnerX::instance()->ping_component()->task()->append_task(mb, false);
  } else if ((long)v_x == TID_CLICK)
  {
    CPingProc::m_click_gatherer->post_if_needed();
    CPingProc::m_HW_powertime_gatherer->post_if_needed();
    CPingProc::m_HW_warn_gatherer->post_if_needed();
    CPingProc::m_video_gatherer->post_if_needed();
    CPingProc::m_no_vide_warn_gatherer->post_if_needed();
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
    CTV l_tv(TIMER_VALUE_PING);
    if (reactor()->schedule_timer(this, (CONST void*)TID_PING, l_tv, l_tv) < 0)
    {
      C_ERROR("schedule_timer ping: %s %s\n", title(), (CONST char*)CSysError());
      return false;
    }
  }

  {
    CTV l_tv(TIMER_VALUE_LOCATION);
    if (reactor()->schedule_timer(this, (CONST void*)TID_LOCATION, l_tv, l_tv) < 0)
    {
      C_ERROR("schedule_timer ip ver:%s %s\n", title(), (CONST char*)CSysError());
      return false;
    }
  }

  {
    CTV l_tv(TIMER_VALUE_DOWNLOAD_REPLY);
    if (reactor()->schedule_timer(this, (CONST void*)TID_DOWNLOAD_REPLY, l_tv, l_tv) < 0)
    {
      C_ERROR("schedule_timer download reply:%s %s\n", title(), (CONST char*)CSysError());
      return false;
    }
  }

  {
    CTV l_tv(TIMER_VALUE_HAS_JOB * 60);
    if (reactor()->schedule_timer(this, (CONST void*)TID_HAS_JOB, l_tv, l_tv) < 0)
    {
      C_ERROR("schedule_timer dist task:%s %s\n", title(), (CONST char*)CSysError());
      return false;
    }
  }

  {
    CTV l_tv(TIMER_VALUE_CLICK * 60);
    if (reactor()->schedule_timer(this, (CONST void*)TID_CLICK, l_tv, l_tv) < 0)
    {
      C_ERROR("schedule_timer click:%s %s\n", title(), (CONST char*)CSysError());
      return false;
    }
  }

  return true;
}


CPingContainer::CPingContainer(CParentRunner * ptr): CContainer(ptr)
{
  m_ping_task = NULL;
  m_schduler = NULL;
  CPingProc::m_ping_gatherer = &m_heart_beat_gatherer;
  CPingProc::m_location_gatherer = &m_location_gatherer;
  CPingProc::m_download_reply_gatherer = &m_download_reply_gatherer;
  CPingProc::m_click_gatherer = &m_click_gatherer;
  CPingProc::m_HW_powertime_gatherer = &m_hw_power_gatherer;
  CPingProc::m_HW_warn_gatherer = &m_hw_warn_gatherer;
  CPingProc::m_video_gatherer = &m_video_gatherer;
  CPingProc::m_no_vide_warn_gatherer = &m_no_video_warn_gatherer;
}

CPingContainer::~CPingContainer()
{

}

CPingScheduler * CPingContainer::scheduler() CONST
{
  return m_schduler;
}

CPingTask * CPingContainer::task() CONST
{
  return m_ping_task;
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

DVOID CPingContainer::prio()
{
  CMemProt l_x;
  if (!CRunnerX::instance()->pg().read_pl(l_x))
    return;
  ACE_GUARD(ACE_Thread_Mutex, ace_mon, this->m_mutex);
  m_prio.init(l_x.get_ptr());
}

truefalse CPingContainer::get_prio(CMemProt & v_x)
{
  ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, false);
  if (!m_prio.get_ptr() || !*m_prio.get_ptr())
    return false;
  v_x.init(m_prio.get_ptr());
  return true;
}

CONST text * CPingContainer::title() CONST
{
  return "CPingContainer";
}

truefalse CPingContainer::before_begin()
{
  add_task(m_ping_task = new CPingTask(this, 1));
  add_scheduler(m_schduler = new CPingScheduler(this));
  return true;
}

DVOID CPingContainer::before_finish()
{
  m_ping_task = NULL;
  m_schduler = NULL;
}


//d2bs

CD2BsProc::CD2BsProc(CParentHandler * ptr): baseclass(ptr)
{
  m_handler->msg_queue()->high_water_mark(MQ_PEAK);
}

CONST text * CD2BsProc::title() CONST
{
  return "CD2BsProc";
}

CProc::OUTPUT CD2BsProc::do_read_data(CMB * mb)
{
  CMBProt guard(mb);

  if (baseclass::do_read_data(mb) != OP_OK)
    return OP_FAIL;
  CBSData * l_data = (CBSData *) mb->base();
  if (memcmp(l_data->command, CCMD_LOC_REPORT, sizeof(l_data->command)) == 0)
    i_location(l_data);

  ((CD2BsHandler*)m_handler)->refresh();

  return OP_OK;
}

DVOID CD2BsProc::i_location(CBSData * v_data)
{
  text l_xxx[2] = {';', 0};
  CTextDelimiter l_x(v_data->data, l_xxx);
  text * l_y;
  while ((l_y = l_x.get()) != NULL)
    i_location_entry(l_y);
}

DVOID CD2BsProc::i_location_entry(text * v_ptr)
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
    CRunnerX::instance()->pg().change_term_valid(l_sn, client_valid);

  if (likely(client_valid))
  {
    ni l_n = strlen(l_ptr) + 1;
    CMB * mb = CCacheX::instance()->get_mb_cmd(l_n, CCmdHeader::PT_LOC_REPORT);
    CCmdExt * l_ptr2 = (CCmdExt *) mb->base();
    memcpy(l_ptr2->data, l_ptr, l_n);
    l_ptr2->signature = l_xi;
    c_tools_mb_putq(CRunnerX::instance()->ping_component()->scheduler(), mb, "location");
  } else
  {
    if (l_xi >= 0)
    {
      CMB * mb = CCacheX::instance()->get_mb_cmd(0, CCmdHeader::PT_TERMINATE_CONNECTION_I);
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

ni CD2BsHandler::handle_timeout(CONST CTV &, CONST DVOID *)
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
  CTV l_tv(30);
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

yy_enable_cache(CD2BsHandler);



CD2BsConn::CD2BsConn(CParentScheduler * p1, CHandlerDirector * p2): CParentConn(p1, p2)
{
  m_port_of_ip = CCfgX::instance()->bs_hole;
  m_retry_delay = RETRY_DELAY;
  m_remote_ip = CCfgX::instance()->bs_ip;
}

CONST text * CD2BsConn::title() CONST
{
  return "CD2BsConn";
}

ni CD2BsConn::make_svc_handler(CParentHandler *& v_x)
{
  v_x = new CD2BsHandler(m_director);
  if (!v_x)
  {
    C_ERROR("oom @%s\n", title());
    return -1;
  }
  v_x->container((void*)this);
  v_x->reactor(reactor());
  return 0;
}


//d2m

CD2MProc::CD2MProc(CParentHandler * l_ptr): CParentClientProc(l_ptr)
{
  m_edition_back_finished = false;
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

  truefalse l_y = m_data_head.cmd == CCmdHeader::PT_LOGIN_BACK;
  if (l_y == m_edition_back_finished)
  {
    C_ERROR("bad data from dist, ver_reply_finished = %d, data ver_reply = %d.\n", m_edition_back_finished, l_y);
    return OP_FAIL;
  }

  if (l_y)
  {
    if (!c_packet_check_term_ver_back(&m_data_head))
    {
      C_ERROR("can not check term ver reply data\n");
      return OP_FAIL;
    }
    return OP_OK;
  }

  if (m_data_head.cmd == CCmdHeader::PT_HAS_JOB)
  {
    if (!c_packet_check_has_job(&m_data_head))
    {
      C_ERROR("can not check has job data\n");
      return OP_FAIL;
    }
    return OP_OK;
  }

  if (m_data_head.cmd == CCmdHeader::PT_REMOTE_CMD)
  {
    if (!c_packet_check_checksums_all(&m_data_head))
    {
      C_ERROR("can not check rmt command data\n");
      return OP_FAIL;
    }
    return OP_OK;
  }

  C_ERROR("bad data from pre, cmd = %d\n", m_data_head.cmd);
  return OP_FAIL;
}

CProc::OUTPUT CD2MProc::do_read_data(CMB * mb)
{
  CFormatProcBase::do_read_data(mb);

  CCmdHeader * l_x = (CCmdHeader *)mb->base();

  if (l_x->cmd == CCmdHeader::PT_LOGIN_BACK)
  {
    CProc::OUTPUT l_y = handle_login_back(mb);
    C_INFO("answer from pre: %s\n", (l_y == OP_OK? "OK":"Failed"));
    if (l_y == OP_OK)
    {
      ((CD2MHandler*)m_handler)->init_timer();
      sn_check_ok(true);
    }
    return l_y;
  }

  if (l_x->cmd == CCmdHeader::PT_HAS_JOB)
  {
    CProc::OUTPUT l_y = handle_has_job(mb);
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

ni CD2MProc::post_charge()
{
  if (!m_edition_back_finished)
    return 0;

  CMB * mb = CCacheX::instance()->get_mb_cmd_direct(sizeof(CLoadBalanceReq), CCmdHeader::PT_CHARGE_REPORT);
  CLoadBalanceReq * l_x = (CLoadBalanceReq *) mb->base();
  l_x->set_ip(m_self_ip);
  l_x->load = CRunnerX::instance()->ping_component()->connected_count();
  C_INFO("post balance (%d) to pre...\n", l_x->load);
  return (m_handler->post_packet(mb) < 0 ? -1: 0);
}

CProc::OUTPUT CD2MProc::handle_login_back(CMB * mb)
{
  CMBProt prot(mb);
  m_edition_back_finished = true;

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

  case CTermVerReply::SC_NO_RIGHTS:
    C_ERROR("%s no rights\n", prefix_msg);
    return CProc::OP_FAIL;

  case CTermVerReply::SC_NOT_FREE:
    C_ERROR("%s all are in use\n", prefix_msg);
    return CProc::OP_FAIL;

  default:
    C_ERROR("%s recv bad answer = %d\n", prefix_msg, vcr->ret_subcmd);
    return CProc::OP_FAIL;
  }

}

CProc::OUTPUT CD2MProc::handle_has_job(CMB * mb)
{
  CRunnerX::instance()->ping_component()->task()->append_task(mb, false);
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
  proc->term_edition_x = 1;
  proc->term_edition_y = 0;
  proc->term_sn = CCfgX::instance()->skey.c_str();
  proc->handleout_id = CCfgX::instance()->sid;
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
  CTV l_x(CTV::zero);
  CTV l_y(CHARGE_DELAY * 60);
  m_tid = reactor()->schedule_timer(this, (void*)CHARGE_TIMER, l_x, l_y);
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

ni CD2MHandler::handle_timeout(CONST CTV &, CONST DVOID * v_ptr)
{
  if (long(v_ptr) == CHARGE_TIMER)
    return ((CD2MProc*)m_proc)->post_charge();
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

yy_enable_cache(CD2MHandler);



CD2MConn::CD2MConn(CParentScheduler * p1, CHandlerDirector * p2): CParentConn(p1, p2)
{
  m_port_of_ip = CCfgX::instance()->server_hole;
  m_retry_delay = RETRY_DELAY;
  m_remote_ip = CCfgX::instance()->pre_ip;
}

CONST text * CD2MConn::title() CONST
{
  return "CD2MConn";
}

ni CD2MConn::make_svc_handler(CParentHandler *& v_ptr)
{
  v_ptr = new CD2MHandler(m_director);
  if (!v_ptr)
  {
    C_ERROR("oom @%s\n", title());
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
  CTV l_x(CTV::zero);
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
  CTV l_x(CTV::zero);
  CMB * mb;
  CONST ni CONST_peak_number = 10;
  ni l_m = 0;
  while (++l_m < CONST_peak_number && this->getq(mb, &l_x) != -1)
    m_conn->director()->post_all(mb);

  l_x = CTV::zero;
  l_m = 0;
  while (++l_m < CONST_peak_number && m_2_bs_mq.dequeue(mb, &l_x) != -1)
    m_2_bs_conn->director()->post_all(mb);

  return true;
}

CONST text * CD2MSchduler::title() CONST
{
  return "CD2MSchduler";
}

DVOID CD2MSchduler::post_bs(CMB * mb)
{
  CTV l_x(CTV::zero);
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


CD2MContainer::CD2MContainer(CParentRunner * ptr): CContainer(ptr)
{
  m_scheduler = NULL;
}

CD2MContainer::~CD2MContainer()
{

}

CONST text * CD2MContainer::title() CONST
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

class CPGResultProt
{
public:
  CPGResultProt(PGresult * p): m_ptr(p)
  {

  }

  ~CPGResultProt()
  {
    PQclear(m_ptr);
  }

private:
  CPGResultProt(CONST CPGResultProt &);
  CPGResultProt & operator = (CONST CPGResultProt &);

  PGresult * m_ptr;
};


CPG::CPG()
{
  m_pg_con = NULL;
  m_db_port = 0;
}

CPG::~CPG()
{
  make_offline();
}

time_t CPG::get_time_init(CONST text * v_ptr)
{
  SF time_t l_t = time(NULL);
  CONST time_t CONST_longevity = C_1_year * 8;

  if (unlikely(!v_ptr || !*v_ptr))
    return 0;
  struct tm l_z;
  ni l_x = sscanf(v_ptr, "%04d-%02d-%02d %02d:%02d:%02d", &l_z.tm_year, &l_z.tm_mon, &l_z.tm_mday,
      &l_z.tm_hour, &l_z.tm_min, &l_z.tm_sec);
  l_z.tm_year -= 1900;
  l_z.tm_mon -= 1;
  l_z.tm_isdst = -1;
  if (l_x != 6 || l_z.tm_year <= 0)
    return 0;

  time_t l_r = mktime(&l_z);
  if (l_r + CONST_longevity < l_t || l_t + CONST_longevity < l_r)
    return 0;

  return l_r;
}

truefalse CPG::login_to_db()
{
  ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, false);
  if (is_online())
    return true;
  CCfg * l_obj = CCfgX::instance();
  CONST text * const_text = "hostaddr=%s port=%d user='%s' password='%s' dbname=serverdata";
  CONST ni TEXT_SIZE = 1024;
  text connect_str[TEXT_SIZE];
  snprintf(connect_str, TEXT_SIZE - 1, const_text,
      l_obj->db_ip.c_str(), l_obj->db_hole, l_obj->db_login.c_str(), l_obj->db_key.c_str());
  m_pg_con = PQconnectdb(connect_str);
  C_INFO("login to db...\n");
  truefalse l_x = (PQstatus(m_pg_con) == CONNECTION_OK);
  if (!l_x)
  {
    C_ERROR("login to db failed: %s\n", PQerrorMessage(m_pg_con));
    PQfinish(m_pg_con);
    m_pg_con = NULL;
  }
  else
    C_INFO("login to db done\n");
  return l_x;
}

truefalse CPG::check_online()
{
  ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, false);
  CONST text * l_x = "select ('now'::text)::timestamp(0) without time zone";
  run_sql(l_x);
  return validate_db_online();
}

truefalse CPG::validate_db_online()
{
  if (unlikely(!is_online()))
    return false;
  ConnStatusType l_z = PQstatus(m_pg_con);
  if (l_z == CONNECTION_BAD)
  {
    C_ERROR("db not online, retrying...\n");
    PQreset(m_pg_con);
    l_z = PQstatus(m_pg_con);
    if (l_z == CONNECTION_BAD)
    {
      C_ERROR("reconnect to db failed: %s\n", PQerrorMessage(m_pg_con));
      return false;
    } else
      C_INFO("reconnect to db OK!\n");
  }
  return true;
}

DVOID CPG::make_offline()
{
  if (is_online())
  {
    PQfinish(m_pg_con);
    m_pg_con = NULL;
  }
}

truefalse CPG::is_online() CONST
{
  return m_pg_con != NULL;
}

truefalse CPG::tr_start()
{
  return run_sql("BEGIN");
}

truefalse CPG::tr_finish()
{
  return run_sql("COMMIT");
}

truefalse CPG::tr_cancel()
{
  return run_sql("ROLLBACK");
}

DVOID CPG::prepare_text(CONST text * v_str, CMemProt & v_text) CONST
{
  if (!v_str || !*v_str)
    v_text.init("null");
  else
    v_text.init("'", v_str, "'");
}

time_t CPG::get_db_time_i()
{
  CONST text * CONST_text = "select ('now'::text)::timestamp(0) without time zone";
  PGresult * l_x = PQexec(m_pg_con, CONST_text);
  CPGResultProt prot(l_x);
  if (!l_x || PQresultStatus(l_x) != PGRES_TUPLES_OK)
  {
    C_ERROR("sql (%s) failed: %s\n", CONST_text, PQerrorMessage(m_pg_con));
    return 0;
  }
  if (unlikely(PQntuples(l_x) <= 0))
    return 0;
  return get_time_init(PQgetvalue(l_x, 0, 0));
}

truefalse CPG::run_sql(CONST text * v_query, ni * v_rows_count)
{
  if (unlikely(!v_query || !*v_query))
    return false;
  PGresult * l_x = PQexec(m_pg_con, v_query);
  CPGResultProt prot(l_x);
  if (!l_x || (PQresultStatus(l_x) != PGRES_COMMAND_OK && PQresultStatus(l_x) != PGRES_TUPLES_OK))
  {
    C_ERROR("run_sql(%s) failed: %s\n", v_query, PQerrorMessage(m_pg_con));
    return false;
  } else
  {
    if (v_rows_count)
    {
      CONST text * l_text = PQcmdTuples(l_x);
      if (!l_text || !*l_text)
        *v_rows_count = 0;
      else
        *v_rows_count = atoi(PQcmdTuples(l_x));
    }
    return true;
  }
}

truefalse CPG::load_term_SNs(CTermSNs * v_SNs)
{
  C_ASSERT_RETURN(v_SNs != NULL, "null param\n", false);

  CONST text * CONST_cmd = "select term_sn, term_key, term_bad, term_serial "
                                           "from x_terms where term_serial > %d order by term_serial";
  text l_cmd[1024];
  snprintf(l_cmd, 1024 - 1, CONST_cmd, v_SNs->prev_no());

  ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, false);
  PGresult * l_x = PQexec(m_pg_con, l_cmd);
  CPGResultProt prot(l_x);
  if (!l_x || PQresultStatus(l_x) != PGRES_TUPLES_OK)
  {
    C_ERROR("(%s) failed: %s\n", l_cmd, PQerrorMessage(m_pg_con));
    return false;
  }
  ni l_m = PQntuples(l_x);
  if (l_m > 0)
  {
    v_SNs->prepare_space(l_m);
    truefalse l_not_valid;
    CONST text * l_ptr;
    for (ni k = 0; k < l_m; ++k)
    {
      l_ptr = PQgetvalue(l_x, k, 2);
      l_not_valid = l_ptr && (*l_ptr == 't' || *l_ptr == 'T');
      v_SNs->append(PQgetvalue(l_x, k, 0), PQgetvalue(l_x, k, 1), l_not_valid);
    }
    ni l_xyz = atoi(PQgetvalue(l_x, l_m - 1, 1));
    v_SNs->set_prev_no(l_xyz);
  }

  C_INFO("load %d term SNs from db\n", l_m);
  return true;
}

truefalse CPG::save_term_sn(CONST text * v_str)
{
  CNumber l_sn = v_str;
  l_sn.rtrim();
  if (l_sn.to_str()[0] == 0)
    return false;

  CONST text * const_cmd = "insert into x_terms(term_sn) values('%s')";
  text l_cmd[1024];
  snprintf(l_cmd, 1024, const_cmd, l_sn.to_str());

  ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, false);
  return run_sql(l_cmd);
}

truefalse CPG::write_task(CBsDistReq & v_req, CONST text * v_cs, CONST text * v_mbz_cs)
{
  CONST text * const_text = "insert into x_handleout_data("
               "ho_no, ho_kind, ho_term_file, ho_server_file, ho_server_path,"
               "ho_server_kind, ho_key, ho_checksum, ho_zip_checksum) "
               "values('%s', '%s', %s, '%s', '%s', '%s', '%s', '%s', '%s')";
  CONST text * l_cs = v_cs ? v_cs : "";
  CONST text * l_mbz_cs = v_mbz_cs ? v_mbz_cs : "";
  ni l_m = strlen(const_text) + strlen(l_cs) + strlen(l_mbz_cs) + 2000;
  CMemProt l_cmd;
  CCacheX::instance()->get(l_m, &l_cmd);
  CMemProt aindex;
  prepare_text(v_req.local_file, aindex);
  snprintf(l_cmd.get_ptr(), l_m - 1, const_text,
      v_req.edition, v_req.local_kind, aindex.get_ptr(), v_req.remote_file, v_req.remote_path,
      v_req.remote_kind, v_req.key, l_cs, l_mbz_cs);

  ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, false);
  return run_sql(l_cmd.get_ptr());
}

truefalse CPG::write_sr(text * dids, CONST text * cmd, text * v_sn_s)
{
  CONST text * const_cmd = "update x_handout_details set hd_state = %d where hd_no = '%s' and hd_term_sn = '%s'";
  ni l_condition = *cmd == '1'? 5: 7;

  text l_cmd[1024];

  ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, false);

  text l_xxx[2] = {';', 0};
  CONST ni NUM_IN_ONE_RUN = 20;
  ni mm = 0, l_all = 0, l_fine = 0;
  CTextDelimiter l_terms_delimiter(v_sn_s, l_xxx);
  CTextDelimiter l_task_delimiter(dids, l_xxx);
  std::list<char *> l_term_SNs, l_tasks;
  text * term_sn, * task;
  while ((term_sn = l_terms_delimiter.get()) != NULL)
    l_term_SNs.push_back(term_sn);
  while((task = l_task_delimiter.get()) != NULL)
    l_tasks.push_back(task);
  std::list<char *>::iterator l_z1, l_z_two;
  for (l_z1 = l_tasks.begin(); l_z1 != l_tasks.end(); ++ l_z1)
  {
    task = *l_z1;
    for (l_z_two = l_term_SNs.begin(); l_z_two != l_term_SNs.end(); ++ l_z_two)
    {
      l_all ++;
      term_sn = *l_z_two;
      if (mm == 0)
      {
        if (!tr_start())
        {
          C_ERROR("failed to begin transaction @MyDB::save_sr\n");
          return false;
        }
      }
      snprintf(l_cmd, 1024, const_cmd, l_condition, task, term_sn);
      run_sql(l_cmd);
      ++mm;
      if (mm == NUM_IN_ONE_RUN)
      {
        if (!tr_finish())
        {
          C_ERROR("tr_finish write_sr\n");
          tr_cancel();
        } else
          l_fine += mm;
        mm = 0;
      }
    }
  }

  if (mm != 0)
  {
    if (!tr_finish())
    {
      C_ERROR("tr_finish write_sr.2\n");
      tr_cancel();
    } else
      l_fine += mm;
  }

  C_INFO("write_sr done: %d/%d\n", l_fine, l_all);
  return true;
}

truefalse CPG::write_pl(CONST text * v_plist)
{
  if (!v_plist || !*v_plist)
    return false;
  text l_cmd[2048];
  CONST text * const_cmd = "update x_sinfo set sdata = '%s' where skey = 2";
  snprintf(l_cmd, 2048, const_cmd, v_plist);
  ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, false);
  return run_sql(l_cmd);
}

truefalse CPG::write_task_terms(text * v_term_SNs, text * v_adir_s, CONST text * v_task)
{
  CONST text * const_cmd1 = "insert into x_handout_details(hd_no, hd_term_sn, hd_term_path) values('%s', '%s', '%s')";
  CONST text * const_cmd2 = "insert into x_handout_details(hd_no, hd_term_sn) values('%s', '%s')";
  text l_cmd[2048];

  ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, false);

  text l_xxx[2] = {';', 0};
  CONST ni NUM_IN_ONE_RUN = 20;
  ni mm = 0, l_all = 0, l_fine = 0;
  CTextDelimiter l_term_SN_delimiter(v_term_SNs, l_xxx);
  CTextDelimiter l_adir_delimiter(v_adir_s, l_xxx);
  text * l_term_sn, * l_adir;
  while ((l_term_sn = l_term_SN_delimiter.get()) != NULL)
  {
    l_adir = l_adir_delimiter.get();
    l_all ++;
    if (mm == 0)
    {
      if (!tr_start())
      {
        C_ERROR("tr_start() write_task_terms\n");
        return false;
      }
    }
    if (l_adir)
      snprintf(l_cmd, 2048, const_cmd1, v_task, l_term_sn, l_adir);
    else
      snprintf(l_cmd, 2048, const_cmd2, v_task, l_term_sn);
    run_sql(l_cmd);
    ++mm;
    if (mm == NUM_IN_ONE_RUN)
    {
      if (!tr_finish())
      {
        C_ERROR("tr_finish write_task_terms\n");
        tr_cancel();
      } else
        l_fine += mm;

      mm = 0;
    }
  }

  if (mm != 0)
  {
    if (!tr_finish())
    {
      C_ERROR("tr_finish write_task_terms.2\n");
      tr_cancel();
    } else
      l_fine += mm;
  }

  C_INFO("write_task_terms done: %d/%d\n", l_fine, l_all);
  return true;
}

ni CPG::read_tasks(CBsDistDatas & v_datas)
{
  CONST text * const_text = "select ho_no, ho_kind, ho_term_file, ho_server_file, ho_server_path,"
                                  " ho_server_kind, ho_when, ho_key, ho_zip_checksum, ho_checksum"
                                   " from x_handleout_data order by ho_when";

  ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, false);

  PGresult * l_x = PQexec(m_pg_con, const_text);
  CPGResultProt prot(l_x);
  if (!l_x || PQresultStatus(l_x) != PGRES_TUPLES_OK)
  {
    C_ERROR("PQexec(%s): %s\n", const_text, PQerrorMessage(m_pg_con));
    return -1;
  }

  ni l_num = PQntuples(l_x);
  ni l_m = PQnfields(l_x);
  if (unlikely(l_m != 10))
  {
    C_ERROR("bad read_tasks.col(%d)\n", l_m);
    return -1;
  }

  v_datas.alloc_spaces(l_num);
  for (ni l_n = 0; l_n < l_num; ++ l_n)
  {
    CBsDistData * v_data = v_datas.alloc_data(PQgetvalue(l_x, l_n, 0));

    for (ni l_k = 0; l_k < l_m; ++l_k)
    {
      CONST text * l_xyz = PQgetvalue(l_x, l_n, l_k);
      if (!l_xyz || !*l_xyz)
        continue;

      if (l_k == 5)
        v_data->remote_kind[0] = *l_xyz;
      else if (l_k == 4)
        v_data->remote_path.init(l_xyz);
      else if (l_k == 3)
      {
        v_data->remote_file.init(l_xyz);
        v_data->remote_file_size = strlen(l_xyz);
      }
      else if (l_k == 9)
      {
        v_data->check_sum.init(l_xyz);
        v_data->checksum_size = strlen(l_xyz);
      }
      else if (l_k == 1)
        v_data->local_kind[0] = *l_xyz;
      else if (l_k == 7)
      {
        v_data->key.init(l_xyz);
        v_data->key_size = strlen(l_xyz);
      }
      else if (l_k == 6)
      {
        v_data->when_handleout.init(l_xyz);
      }
      else if (l_k == 2)
      {
        v_data->local_file.init(l_xyz);
        v_data->local_file_size = strlen(l_xyz);
      }
      else if (l_k == 8)
        v_data->compress_checksum.init(l_xyz);
    }

    v_data->calc_checksum_opt_sum();
  }

  C_INFO("read_tasks: %d task(s) from db\n", l_num);
  return l_num;
}


truefalse CPG::write_task_cs(CONST text * v_task, CONST text * v_cs, ni v_cs_size)
{
  if (unlikely(!v_task || !*v_task || !v_cs))
    return false;

  CONST text * const_cmd = "update x_handleout_data set ho_checksum = '%s' "
                                     "where ho_no = '%s'";
  ni v_m = v_cs_size + strlen(const_cmd) + strlen(v_task) + 20;
  CMemProt l_cmd;
  CCacheX::instance()->get(v_m, &l_cmd);
  snprintf(l_cmd.get_ptr(), v_m, const_cmd, v_cs, v_task);

  ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, false);
  return run_sql(l_cmd.get_ptr());
}

truefalse CPG::write_task_download_cs(CONST text * v_task, CONST text * v_cs)
{
  if (unlikely(!v_task || !*v_task || !v_cs || !*v_cs))
    return false;

  CONST text * const_cmd = "update x_handleout_data set ho_zip_checksum = '%s' "
                                     "where ho_no = '%s'";
  text l_cmd[1024];
  snprintf(l_cmd, 1024, const_cmd, v_cs, v_task);

  ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, false);
  return run_sql(l_cmd);
}

truefalse CPG::read_task_terms(CTermStations * v_stations, CTermStation * v_station)
{
  C_ASSERT_RETURN(v_stations != NULL, "null param\n", false);

  CONST text * CONST_cmd1 = "select hd_no, hd_term_sn, hd_state, hd_term_path, hd_prev_access,"
      " hd_zip_name, hd_zip_checksum, hd_checksum"
      " from x_handout_details order by hd_term_sn";
  CONST text * CONST_cmd2 = "select hd_no, hd_term_sn, hd_state, hd_term_path, hd_prev_access,"
      " hd_zip_name, hd_zip_checksum, hd_checksum"
      " from x_handout_details where hd_term_sn = '%s'";
  CONST text * CONST_cmd;

  text l_cmd[512];
  if (!v_station)
    CONST_cmd = CONST_cmd1;
  else
  {
    snprintf(l_cmd, 512, CONST_cmd2, v_station->term_sn());
    CONST_cmd = l_cmd;
  }

  ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, false);

  PGresult * l_x = PQexec(m_pg_con, CONST_cmd);
  CPGResultProt prot(l_x);
  if (!l_x || PQresultStatus(l_x) != PGRES_TUPLES_OK)
  {
    C_ERROR("PQexec (%s): %s\n", CONST_cmd, PQerrorMessage(m_pg_con));
    return -1;
  }
  ni l_num = PQntuples(l_x);
  ni l_m = PQnfields(l_x);
  ni l_ok = 0;
  CTermStation * l_station;

  if (l_num == 0)
    goto __exit__;
  if (unlikely(l_m != 8))
  {
    C_ERROR("read_task_terms: bad col(%d)\n", l_m);
    return false;
  }

  CBsDistData * l_data;
  if (!v_station)
    l_station = v_stations->generate_term_station(PQgetvalue(l_x, 0, 1));
  else
    l_station = v_station;
  for (ni l_k = 0; l_k < l_num; ++ l_k)
  {
    l_data = v_stations->search_dist_data(PQgetvalue(l_x, l_k, 0));
    if (unlikely(!l_data))
      continue;

    if (!v_station)
    {
      CONST text * l_term_sn = PQgetvalue(l_x, l_k, 1);
      if (unlikely(!l_station->check_term_sn(l_term_sn)))
        l_station = v_stations->generate_term_station(l_term_sn);
    }

    CDistTermItem * l_item = l_station->generate_term_item(l_data);

    CONST text * l_checksum = NULL;
    for (ni l_o = 0; l_o < l_m; ++l_o)
    {
      CONST text * l_ptr = PQgetvalue(l_x, l_k, l_o);
      if (!l_ptr || !*l_ptr)
        continue;

      if (l_o == 2)
        l_item->condition = atoi(l_ptr);
      else if (l_o == 3)
        l_item->adir.init(l_ptr);
      else if (l_o == 7)
        l_checksum = l_ptr;
      else if (l_o == 5)
        l_item->cmp_fn.init(l_ptr);
      else if (l_o == 4)
        l_item->prev_access = get_time_init(l_ptr);
      else if (l_o == 6)
        l_item->cmp_checksum.init(l_ptr);
    }

    if (l_item->condition < 3 && l_checksum != NULL)
      l_item->checksum.init(l_checksum);

    ++ l_ok;
  }

__exit__:
  if (!v_station)
    C_INFO("read_task_terms: %d/%d\n", l_ok, l_num);
  return l_num;
}

truefalse CPG::write_task_term_item_condition(CDistTermItem & v_item, ni v_condtion)
{
  return write_task_term_condition(v_item.term_sn(), v_item.dist_data->edition.get_ptr(), v_condtion);
}

truefalse CPG::write_task_term_condition(CONST text * v_term_sn, CONST text * v_task, ni v_condition)
{
  CONST text * const_cmd = "update x_handout_details set hd_state = %d "
                                     "where hd_no = '%s' and hd_term_sn='%s' and hd_state < %d";
  text l_cmd[1024];
  snprintf(l_cmd, 1024, const_cmd, v_condition, v_task, v_term_sn, v_condition);

  ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, false);
  return run_sql(l_cmd);
}

truefalse CPG::write_task_term_cs(CONST text * v_term_sn, CONST text * v_task, CONST text * v_cs, ni v_condition)
{
  CONST text * const_cmd = "update x_handout_details set hd_state = %d, hd_checksum = '%s' "
                                     "where hd_no = '%s' and hd_term_sn='%s' and hd_state < %d";
  ni l_m = strlen(const_cmd) + strlen(v_cs) + strlen(v_term_sn) + strlen(v_task) + 40;
  CMemProt l_cmd;
  CCacheX::instance()->get(l_m, &l_cmd);
  snprintf(l_cmd.get_ptr(), l_m, const_cmd, v_condition, v_cs, v_task, v_term_sn, v_condition);

  ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, false);
  ni l_i = 0;
  return run_sql(l_cmd.get_ptr(), &l_i) && l_i == 1;
}

truefalse CPG::write_task_term_mbz(CONST text * v_term_sn, CONST text * v_task, CONST text * v_mbz, CONST text * v_cs_mbz)
{
  CONST text * const_cmd = "update x_handout_details set hd_zip_name = '%s', hd_zip_checksum = '%s' "
                                     "where hd_no = '%s' and hd_term_sn='%s' and hd_state < 3";
  ni l_m = strlen(const_cmd) + strlen(v_mbz) + strlen(v_term_sn)
          + strlen(v_task) + 40 + strlen(v_cs_mbz);
  CMemProt l_cmd;
  CCacheX::instance()->get(l_m, &l_cmd);
  snprintf(l_cmd.get_ptr(), l_m, const_cmd, v_mbz, v_cs_mbz, v_task, v_term_sn);

  ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, false);
  ni k = 0;
  return run_sql(l_cmd.get_ptr(), &k) && k == 1;
}

truefalse CPG::destruct_task_term(CONST text * v_term_sn, CONST text * v_task)
{
  CONST text * const_cmd = "delete from x_handout_details where hd_no = '%s' and hd_no='%s'";
  text l_cmd[1024];
  snprintf(l_cmd, 1024, const_cmd, v_task, v_term_sn);
  ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, false);
  return run_sql(l_cmd);
}

truefalse CPG::is_dist_data_new(CBsDistDatas & v_datas)
{
  {
    ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, false);
    if (!validate_db_online())
      return true;
  }
  CMemProt l_x;
  if (!read_xinfo(1, l_x))
    return true;
  truefalse l_y = strcmp(v_datas.prev_query_ts.get_ptr(), l_x.get_ptr()) == 0;
  if (!l_y)
    v_datas.prev_query_ts.init(l_x.get_ptr());
  return l_y;
}

truefalse CPG::read_pl(CMemProt & v_x)
{
  return read_xinfo(2, v_x);
}

truefalse CPG::refresh_task_condition()
{
  ni l_t = (ni)time(NULL);
  ni l_m = random() % 0xFFFFFF;
  text tmp[64];
  snprintf(tmp, 64, "%d-%d", l_t, l_m);
  return write_xinfo(1, tmp);
}

truefalse CPG::delete_unused_tasks()
{
  CONST text * const_cmd = "select last_func()";
  ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, false);
  return run_sql(const_cmd);
}

truefalse CPG::read_term_SNs(CObsoleteDirDeleter & v_obj)
{
  CONST text * const_cmd = "select ho_no from x_handleout_data";
  ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, false);
  PGresult * l_x = PQexec(m_pg_con, const_cmd);
  CPGResultProt prot(l_x);
  if (!l_x || PQresultStatus(l_x) != PGRES_TUPLES_OK)
  {
    C_ERROR("PQexec(%s): %s\n", const_cmd, PQerrorMessage(m_pg_con));
    return false;
  }
  ni l_m = PQntuples(l_x);
  if (l_m > 0)
  {
    for (ni k = 0; k < l_m; ++k)
      v_obj.append_did(PQgetvalue(l_x, k, 0));
  }
  return true;
}

truefalse CPG::change_term_valid(CONST text * v_term_sn, truefalse v_ok)
{
  text l_cmd[1024];
  if (!v_ok)
  {
    CONST text * const_cmd = "delete from x_terms where term_sn = '%s'";
    snprintf(l_cmd, 1024, const_cmd, v_term_sn);
  } else
  {
    CONST text * const_cmd = "insert into x_terms(term_sn, term_key) values('%s', '%s')";
    snprintf(l_cmd, 1024, const_cmd, v_term_sn, v_term_sn);
  }

  ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, false);
  return run_sql(l_cmd);
}

truefalse CPG::write_xinfo(CONST ni v_key, CONST text * v_x)
{
  CONST text * const_cmd = "update x_sinfo set sdata = '%s' where skey = %d";
  text l_cmd[1024];
  snprintf(l_cmd, 1024, const_cmd, v_x, v_key);

  ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, false);
  return run_sql(l_cmd);
}

truefalse CPG::read_xinfo(CONST ni v_key, CMemProt & v_x)
{
  ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, false);
  return read_xinfo_i(v_key, v_x);
}

truefalse CPG::read_xinfo_i(CONST ni v_key, CMemProt & v_x)
{
  CONST text * const_cmd = "select sdata from x_sinfo where skey = %d";
  text l_cmd[1024];
  snprintf(l_cmd, 1024, const_cmd, v_key);

  PGresult * l_x = PQexec(m_pg_con, l_cmd);
  CPGResultProt prot(l_x);
  if (!l_x || PQresultStatus(l_x) != PGRES_TUPLES_OK)
  {
    C_ERROR("PQexec(%s): %s\n", l_cmd, PQerrorMessage(m_pg_con));
    return false;
  }
  ni l_m = PQntuples(l_x);
  if (l_m > 0)
  {
    v_x.init(PQgetvalue(l_x, 0, 0));
    return true;
  } else
    return false;
}


truefalse CPG::do_read_db_time(time_t & v_t)
{
  CONST text * const_cmd = "select ('now'::text)::timestamp(0) without time zone";
  PGresult * l_x = PQexec(m_pg_con, const_cmd);
  CPGResultProt prot(l_x);
  if (!l_x || PQresultStatus(l_x) != PGRES_TUPLES_OK)
  {
    C_ERROR("PQexec(%s): %s\n", const_cmd, PQerrorMessage(m_pg_con));
    return false;
  }
  if (PQntuples(l_x) <= 0)
    return false;
  v_t = get_time_init(PQgetvalue(l_x, 0, 0));
  return true;
}
