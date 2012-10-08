#include "component.h"
#include "app.h"

CTermSNs * g_term_sns = NULL;


CTermVer::CTermVer()
{
  init(0, 0);
}

CTermVer::CTermVer(u8 v1, u8 v2)
{
  init(v1, v2);
}

DVOID CTermVer::init(u8 v1, u8 v2)
{
  m_v1 = v1;
  m_v2 = v2;
  prepare_buff();
}

DVOID CTermVer::prepare_buff()
{
  snprintf(m_data, DATA_LEN, "%hhu.%hhu", m_v1, m_v2);
}


truefalse CTermVer::init(CONST text * s)
{
  if (unlikely(!s || !*s))
    return false;
  ni v1, v2;
  sscanf(s, "%d.%d", &v1, &v2);
  if (v1 > 255 || v1 < 0 || v2 > 255 || v2 < 0)
    return false;
  m_v1 = (u8)v1;
  m_v2 = (u8)v2;
  prepare_buff();
  return true;
}

CONST text * CTermVer::to_text() CONST
{
  return m_data;
}

truefalse CTermVer::operator < (CONST CTermVer & o)
{
  if (m_v1 < o.m_v1)
    return true;
  else if (m_v1 > o.m_v1)
    return false;
  else
    return (m_v2 < o.m_v2);
}



CDirConverter::CDirConverter()
{

}

truefalse CDirConverter::prepare(CONST text * mf)
{
  if (!mf || !*mf)
    return true;
  m_value.init(mf);
  m_dir.init(mf);
  text * p = strrchr(m_dir.get_ptr(), '.');
  if (unlikely(!p))
  {
    C_ERROR("bad param(%s)\n", mf);
    return false;
  }
  else
    *p = 0;
  return true;
}

CONST text * CDirConverter::dir() CONST
{
  return m_dir.get_ptr();
}

CONST text * CDirConverter::value() CONST
{
  return m_value.get_ptr();
}

CONST text * CDirConverter::convert(CONST text * src)
{
  if (!m_dir.get_ptr())
    return src;

  if (unlikely(!src))
    return NULL;

  CONST text * p = strchr(src, '/');
  if (unlikely(!p))
    return m_value.get_ptr();
  else
  {
    m_value_converted.init(m_dir.get_ptr(), p);
    return m_value_converted.get_ptr();
  }
}



CTermData::CTermData()
{
  connected = false;
  invalid = false;
  server_changed = false;
  set_download_auth(NULL);
}

CTermData::CTermData(CONST CNumber & sn, CONST text * auth, truefalse v_invalid): term_sn(sn)
{
  connected = false;
  invalid = v_invalid;
  server_changed = false;
  set_download_auth(auth);
}

DVOID CTermData::set_download_auth(CONST text * auth)
{
  if (!auth || !*auth)
  {
    download_auth[0] = 0;
    download_auth_len = 0;
    return;
  }

  ACE_OS::strsncpy(download_auth, auth, AUTH_SIZE);
  download_auth_len  = strlen(download_auth);
}




CTermSNs::CTermSNs()
{
  m_prev_no = 0;
}

CTermSNs::~CTermSNs()
{
  m_SNs.clear();
  m_fast_locater.clear();
}

truefalse CTermSNs::have(CONST CNumber & sn)
{
  return (find_location(sn) >= 0);
}

DVOID CTermSNs::append_new(CONST CNumber & sn, CONST text * auth, truefalse v_invalid)
{
  if (do_locate(sn) >= 0)
    return;
  CTermData info(sn, auth, v_invalid);
  m_SNs.push_back(info);
  m_fast_locater[sn] = m_SNs.size() - 1;
}

DVOID CTermSNs::append(CONST CNumber & sn)
{
  ACE_WRITE_GUARD(ACE_RW_Thread_Mutex, ace_mon, m_mutex);
  append_new(sn, NULL, false);
}

DVOID CTermSNs::append(CONST text * sn, CONST text * auth, truefalse _invalid)
{
  if (unlikely(!sn || !*sn))
    return;
  while (*sn == ' ')
    sn++;
  if (!*sn)
    return;
  CNumber l_x(sn);
  l_x.rtrim();
  ACE_WRITE_GUARD(ACE_RW_Thread_Mutex, ace_mon, m_mutex);
  append_new(l_x, auth, _invalid);
}

DVOID CTermSNs::append_lot(text * s)
{
  if (!s)
    return;
  CONST text * CONST_mark = ";\r\n\t ";
  text * l_ptr, * l_val, * l_tmp;

  ACE_WRITE_GUARD(ACE_RW_Thread_Mutex, ace_mon, m_mutex);
  for (l_ptr = s; ; l_ptr = NULL)
  {
    l_val = strtok_r(l_ptr, CONST_mark, &l_tmp);
    if (l_val == NULL)
      break;
    if (!*l_val)
      continue;
    CNumber sn(l_val);
    append_new(sn, NULL, false);
  }
}

ni CTermSNs::find_location(CONST CNumber & sn)
{
  ACE_READ_GUARD_RETURN(ACE_RW_Thread_Mutex, ace_mon, m_mutex, -1);
  return do_locate(sn);
}

ni CTermSNs::do_locate(CONST CNumber & sn, CTermSNs_map::iterator * v_ptr)
{
  CTermSNs_map::iterator l_x = m_fast_locater.find(sn);
  if (v_ptr)
    *v_ptr = l_x;
  if (l_x == m_fast_locater.end())
    return -1;
  if (unlikely(l_x->second < 0 || l_x->second >= (ni)m_SNs.size()))
  {
    C_ERROR("bad index = %d, limit = %d\n", l_x->second, (ni)m_SNs.size());
    return -1;
  }
  return l_x->second;
}

ni CTermSNs::number()
{
  ACE_READ_GUARD_RETURN(ACE_RW_Thread_Mutex, ace_mon, m_mutex, -1);
  return m_SNs.size();
}

truefalse CTermSNs::get_sn(ni loc, CNumber * sn)
{
  if (unlikely(loc < 0) || !sn)
    return false;
  ACE_READ_GUARD_RETURN(ACE_RW_Thread_Mutex, ace_mon, m_mutex, false);
  if (unlikely(loc >= (ni)m_SNs.size() || loc < 0))
    return false;
  *sn = m_SNs[loc].term_sn;
  return true;
}

truefalse CTermSNs::get_termData(ni loc, CTermData & td)
{
  ACE_READ_GUARD_RETURN(ACE_RW_Thread_Mutex, ace_mon, m_mutex, false);
  if (unlikely(loc >= (ni)m_SNs.size() || loc < 0))
    return false;
  td = m_SNs[loc];
  return true;
}

truefalse CTermSNs::connected(CONST CNumber & sn, ni & loc, truefalse & server_changed)
{
  ACE_READ_GUARD_RETURN(ACE_RW_Thread_Mutex, ace_mon, m_mutex, false);
  if (loc < 0 || loc >= (ni)m_SNs.size())
    loc = do_locate(sn);
  if (unlikely(loc < 0))
    return false;
  server_changed = m_SNs[loc].server_changed;
  return m_SNs[loc].connected;
}

truefalse CTermSNs::connected(ni loc)
{
  ACE_READ_GUARD_RETURN(ACE_RW_Thread_Mutex, ace_mon, m_mutex, false);
  if (unlikely(loc < 0 || loc > (ni)m_SNs.size()))
    return false;
  return m_SNs[loc].connected;
}

DVOID CTermSNs::set_connected(ni loc, truefalse bconnected)
{
  ACE_WRITE_GUARD(ACE_RW_Thread_Mutex, ace_mon, m_mutex);
  if (unlikely(loc < 0 || loc > (ni)m_SNs.size()))
    return;
  m_SNs[loc].connected = bconnected;
}

DVOID CTermSNs::server_changed(ni loc, truefalse bserver_changed)
{
  ACE_WRITE_GUARD(ACE_RW_Thread_Mutex, ace_mon, m_mutex);
  if (unlikely(loc < 0 || loc > (ni)m_SNs.size()))
    return;
  m_SNs[loc].server_changed = bserver_changed;
}

DVOID CTermSNs::set_invalid(ni loc, truefalse binvalid)
{
  ACE_WRITE_GUARD(ACE_RW_Thread_Mutex, ace_mon, m_mutex);
  if (unlikely(loc < 0 || loc > (ni)m_SNs.size()))
    return;
  m_SNs[loc].invalid = binvalid;
}

truefalse CTermSNs::mark_valid(CONST CNumber & id, truefalse valid, ni & loc)
{
  ACE_READ_GUARD_RETURN(ACE_RW_Thread_Mutex, ace_mon, m_mutex, true);
  loc = do_locate(id);
  truefalse b_ok = (loc >= 0 && !m_SNs[loc].invalid);
  if (likely(b_ok == valid))
    return true;
  if (valid)
  {
    if (loc < 0)
      append_new(id, id.to_str(), false);
    else
      m_SNs[loc].invalid = false;
  } else //!valid
    m_SNs[loc].invalid = true;
  return false;
}

ni CTermSNs::prev_no() CONST
{
  return m_prev_no;
}

DVOID CTermSNs::set_prev_no(ni i)
{
  m_prev_no = i;
}

DVOID CTermSNs::prepare_space(ni v_m)
{
  m_SNs.reserve(std::max(ni((m_SNs.size() + v_m) * 1.5), 990));
}




CCheckSum::CCheckSum(CONST text * fn, CONST text * checksum, ni ignore_lead_n, CONST text * _replace)
{
  m_checksum[0] = 0;
  m_size = 0;
  if (unlikely(!fn || ! *fn))
    return;

  ni m = strlen(fn);
  if (unlikely(m <= ignore_lead_n))
  {
    C_FATAL("bad param(%s, %d)\n", fn, ignore_lead_n);
    return;
  }
  if (!_replace || !*_replace)
  {
    m_size = m - ignore_lead_n + 1;
    m_fn.init(fn + ignore_lead_n);
  } else
  {
    m_size = strlen(_replace) + 1;
    m_fn.init(_replace);
  }

  if (!checksum)
  {
    CMemProt l_x;
    if (c_tools_tally_md5(fn, l_x))
      memcpy(m_checksum, l_x.get_ptr(), CHECK_SUM_SIZE);
  } else
    memcpy((void*)m_checksum, (void*)checksum, CHECK_SUM_SIZE);
}




CCheckSums::CCheckSums()
{
  m_root_path_len = 0;
  m_locator = NULL;
}

CCheckSums::~CCheckSums()
{
  std::for_each(m_checksums.begin(), m_checksums.end(), CPoolObjectDeletor());
  if (m_locator)
    delete m_locator;
}

DVOID CCheckSums::init_locator()
{
  if (m_locator == NULL)
    m_locator = new CheckSumLocator();
}

truefalse CCheckSums::root_path(CONST text * p)
{
  if (unlikely(!p || !*p))
  {
    C_FATAL("CCheckSums::root_path(null p)\n");
    return false;
  }

  m_root_path_len = strlen(p) + 1;
  m_root_path.init(p);
  return true;
}

truefalse CCheckSums::contains(CONST text * fn)
{
  return do_search(fn) != NULL;
}

CCheckSum * CCheckSums::do_search(CONST text * fn)
{
  if (unlikely(!fn || !*fn))
    return NULL;
  C_ASSERT_RETURN(m_locator != NULL, "null ptr\n", NULL);

  CheckSumLocator::iterator l_x;
  l_x = m_locator->find(fn);
  if (l_x == m_locator->end())
    return NULL;
  else
    return l_x->second;
}

DVOID CCheckSums::substract(CCheckSums & v_dest, CDirConverter * pObj, truefalse remove_file)
{
  CCheckSumVec::iterator l_p1 = m_checksums.begin(), l_p2 = v_dest.m_checksums.begin(), it;
  text fn[PATH_MAX];
  while (l_p1 != m_checksums.end() && l_p2 != v_dest.m_checksums.end())
  {
    CONST text * new_name = pObj? pObj->convert((**l_p1).fn()): (**l_p1).fn();
    CCheckSum md5_copy(new_name, (**l_p1).value(), 0);

    if (md5_copy < **l_p2)
      ++l_p1;
    else if (**l_p2 < md5_copy)
    {
      if (remove_file)
      {
        snprintf(fn, PATH_MAX - 1, "%s/%s", v_dest.m_root_path.get_ptr(), (**l_p2).fn());
        remove(fn);
      }
      ++l_p2;
    }
    else if (md5_copy.checksum_equal(**l_p2))//==
    {
      CPoolObjectDeletor dlt;
      dlt(*l_p1);
      l_p1 = m_checksums.erase(l_p1);
      ++l_p2;
    } else
    {
      ++l_p1;
      ++l_p2;
    }
  }

  if (remove_file)
  {
    while (l_p2 != v_dest.m_checksums.end())
    {
      snprintf(fn, PATH_MAX - 1, "%s/%s", v_dest.m_root_path.get_ptr(), (**l_p2).fn());
      remove(fn);
      ++l_p2;
    }
  }
}

DVOID CCheckSums::delete_unused(CONST text * fn)
{
  if (unlikely(!fn || !*fn))
    return;

  i_delete_unused(fn, strlen(fn) + 1);
}

DVOID CCheckSums::make_ordered()
{
  std::sort(m_checksums.begin(), m_checksums.end(), CPtrLess());
}

truefalse CCheckSums::append_checksum(CONST text * v_fn, CONST text * v_val, ni ignore_lead_n)
{
  if (unlikely(!v_fn || !*v_fn || ignore_lead_n < 0))
    return false;

  DVOID * p = CCacheX::instance()->get_raw(sizeof(CCheckSum));
  CCheckSum * fm = new (p) CCheckSum(v_fn, v_val, ignore_lead_n);
  if (fm->check())
  {
    m_checksums.push_back(fm);
    return true;
  }
  else
  {
    CPoolObjectDeletor dlt;
    dlt(fm);
    return false;
  }
}

truefalse CCheckSums::append_checksum(CONST text * pathname, CONST text * filename, ni prefix_len, CONST text * alias)
{
  if (unlikely(!pathname || !filename))
    return false;
  ni len = strlen(pathname);
  if (unlikely(len + 1 < prefix_len || len  + strlen(filename) + 2 > PATH_MAX))
  {
    C_FATAL("bad param(%s, %s, %d)\n", pathname, filename, prefix_len);
    return false;
  }
  CCheckSum * fm;
  text buff[PATH_MAX];
  snprintf(buff, PATH_MAX, "%s/%s", pathname, filename);
  DVOID * p = CCacheX::instance()->get_raw(sizeof(CCheckSum));
  fm = new(p) CCheckSum(buff, NULL, prefix_len, alias);

  truefalse ret = fm->check();
  if (likely(ret))
    m_checksums.push_back(fm);
  else
    delete fm;
  return ret;
}

ni CCheckSums::text_len(truefalse full)
{
  ni m = 0;
  CCheckSumVec::iterator l_x;
  for (l_x = m_checksums.begin(); l_x != m_checksums.end(); ++l_x)
  {
    CCheckSum & cs = **l_x;
    if (unlikely(!cs.check()))
      continue;
    m += cs.size(full);
  }
  return m + 1;
}

truefalse CCheckSums::save_text(text * v_ptr, ni v_size, truefalse full)
{
  CCheckSumVec::iterator l_x;
  if (unlikely(!v_ptr || v_size <= 0))
  {
    C_ERROR("bad param(%s, %d)\n", v_ptr, v_size);
    return false;
  }
  ni m = 0;
  for (l_x = m_checksums.begin(); l_x != m_checksums.end(); ++l_x)
  {
    CCheckSum & cs = **l_x;
    if (unlikely(!cs.check()))
      continue;
    if (unlikely(v_size <= m + cs.size(full)))
    {
      C_ERROR("bad text size(size=%d, size_need=%d)\n", v_size, m + cs.size(full) + 1);
      return false;
    }
    ni n = cs.size(false);
    memcpy(v_ptr + m, cs.fn(), n);
    v_ptr[m + n - 1] = full? CCmdHeader::MIDDLE_SEPARATOR: CCmdHeader::ITEM_SEPARATOR;
    m += n;
    if (full)
    {
      memcpy(v_ptr + m, cs.value(), CCheckSum::CHECK_SUM_SIZE);
      m += CCheckSum::CHECK_SUM_SIZE;
      v_ptr[m++] = CCmdHeader::ITEM_SEPARATOR;
    }
  }
  v_ptr[m] = 0;
  return true;
}

truefalse CCheckSums::load_text(text * v_ptr, CDirConverter * v_pObj)
{
  if (!v_ptr || !*v_ptr)
    return true;

  text delimitors[2] = {CCmdHeader::ITEM_SEPARATOR, 0};
  text *l_ptr, *l_val, *l_tmp, *l_cs;

  for (l_ptr = v_ptr; ; l_ptr = NULL)
  {
    l_val = strtok_r(l_ptr, delimitors, &l_tmp);
    if (l_val == NULL)
      break;
    if (unlikely(!*l_val))
      continue;
    l_cs = strchr(l_val, CCmdHeader::MIDDLE_SEPARATOR);
    if (unlikely(l_cs == l_val || !l_cs))
    {
      C_ERROR("broken cs: %s\n", l_val);
      return false;
    }
    *l_cs++ = 0;
    if (unlikely(strlen(l_cs) != CCheckSum::CHECK_SUM_SIZE))
    {
      C_ERROR("null cs: %s\n", l_val);
      return false;
    }
    DVOID * p = CCacheX::instance()->get_raw(sizeof(CCheckSum));
    CONST text * l_fn = v_pObj? v_pObj->convert(l_val): l_val;
    CCheckSum * csObj = new(p) CCheckSum(l_fn, l_cs, 0);
    if (m_locator != NULL)
      m_locator->insert(std::pair<const text *, CCheckSum *>(csObj->fn(), csObj));
    m_checksums.push_back(csObj);
  }

  return true;
}

truefalse CCheckSums::compute_diverse(CONST text * v_path, CDirConverter * v_pObj)
{
  C_ASSERT_RETURN(v_path && *v_path, "null param()\n", false);
  CMemProt fn;
  ni n = strlen(v_path);
  CCheckSumVec::iterator it;
  for (it = m_checksums.begin(); it != m_checksums.end(); )
  {
    CONST text * true_fn = v_pObj? v_pObj->convert((**it).fn()): (**it).fn();
    fn.init(v_path, "/", true_fn);
    CCheckSum cs(fn.get_ptr(), NULL, n + 1);
    if (!cs.check() || !cs.checksum_equal(**it))
      ++ it;
    else
    {
      CCheckSum * p = *it;
      it = m_checksums.erase(it);
      if (m_locator)
        m_locator->erase(p->fn());
      CPoolObjectDeletor g;
      g(p);
    }
  }
  return true;
}

truefalse CCheckSums::compute(CONST text * v_path, CONST text * mfile, truefalse only_one)
{
  C_ASSERT_RETURN(v_path && *v_path, "NULL param\n", false);
  root_path(v_path);

  if (mfile && *mfile)
  {
    CMemProt l_fn;
    ni n = CSysFS::dir_add(v_path, mfile, l_fn);
    append_checksum(l_fn.get_ptr(), NULL, n);
    if (only_one)
      return true;
    if (unlikely(!CSysFS::dir_from_mfile(l_fn, n)))
      return false;
    return i_tally_path(l_fn.get_ptr(), n);
  } else
  {
    if (only_one)
    {
      C_ERROR("unexpected\n");
      return false;
    }
    return i_tally_path(v_path, strlen(v_path) + 1);
  }
}

truefalse CCheckSums::i_tally_path(CONST text * v_path, ni v_begin_len)
{
  DIR * dir = opendir(v_path);
  if (!dir)
  {
    if (ACE_OS::last_error() != ENOENT)
    {
      C_ERROR("opendir: %s %s\n", v_path, (CONST char*)CSysError());
      return false;
    } else
      return true;
  }

  struct dirent * de;
  text txt[PATH_MAX];
  while ((de = readdir(dir)) != NULL)
  {
    if (!de->d_name)
      continue;
    if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
      continue;

    if (de->d_type == DT_REG)
    {
      if (!append_checksum(v_path, de->d_name, v_begin_len, NULL))
      {
        closedir(dir);
        return false;
      }
    }
    else if(de->d_type == DT_DIR)
    {
      snprintf(txt, PATH_MAX - 1, "%s/%s", v_path, de->d_name);
      if (!i_tally_path(txt, v_begin_len))
      {
        closedir(dir);
        return false;
      }
    } else
      C_WARNING("unknown file type (=%d) %s/%s\n", de->d_type, v_path, de->d_name);
  };

  closedir(dir);
  return true;
}

DVOID CCheckSums::i_delete_unused(CONST text * v_path, ni v_begin_len)
{
  DIR * dir = opendir(v_path);
  if (!dir)
  {
    if (ACE_OS::last_error() != ENOENT)
      C_ERROR("can not open directory: %s %s\n", v_path, (CONST char*)CSysError());
    return;
  }

  struct dirent * de;
  text txt[PATH_MAX];
  CMemProt l_fn;
  while ((de = readdir(dir)) != NULL)
  {
    if (!de->d_name)
      continue;
    if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
      continue;

    if (de->d_type == DT_REG)
    {
      l_fn.init(v_path, "/", de->d_name);
      if (!contains(l_fn.get_ptr() + v_begin_len))
        CSysFS::remove(l_fn.get_ptr(), true);
    }
    else if(de->d_type == DT_DIR)
    {
      snprintf(txt, PATH_MAX - 1, "%s/%s", v_path, de->d_name);
      i_delete_unused(txt, v_begin_len);
    } else
      C_WARNING("unknown file type (=%d) %s/%s\n", de->d_type, v_path, de->d_name);
  };

  closedir(dir);
  CSysFS::remove(v_path, true);
  return;
}




CBaseFileReader::CBaseFileReader()
{
  m_size = 0;
}

truefalse CBaseFileReader::open(CONST text * v_ptr)
{
  if (unlikely(!v_ptr || !*v_ptr))
  {
    C_ERROR("empty param\n");
    return false;
  }

  if (!m_f.open_nowrite(v_ptr))
    return false;

  struct stat l_x;
  if (::fstat(m_f.get_fd(), &l_x) == -1)
  {
    C_ERROR("stat(%s) %s\n", v_ptr, (CONST char*)CSysError());
    return false;
  }
  m_size = l_x.st_size;
  return true;
}

ni CBaseFileReader::read(text * v_ptr, ni size)
{
  return read_i(v_ptr, size);
}

ni CBaseFileReader::read_i(text * v_ptr, ni size)
{
  ni n = ::read(m_f.get_fd(), v_ptr, size);
  if (unlikely(n < 0))
    C_ERROR("read file %s %s\n", m_fn.get_ptr(), (CONST char*)CSysError());
  return n;
}

DVOID CBaseFileReader::close()
{
  m_f.bind_fd(CFileProt::BAD_FD);
  m_fn.free();
}


truefalse CCompFileReader::open(CONST text * filename)
{
  if (!baseclass::open(filename))
    return false;
  return load_begining();
}

ni CCompFileReader::read(text * buff, ni buff_len)
{
  ni n = std::min(buff_len, m_more_size);
  if (n <= 0)
    return 0;
  ni n2 = read_i(buff, n);
  m_more_size -= n2;

  if (m_more_comp_size > 0)
  {
    ni buff_remain_len = buff_len;
    u8 output[16];
    text * ptr = buff;
    while (m_more_comp_size > 0 && buff_remain_len >= 16)
    {
      aes_decrypt(&m_x, (u8*)ptr, output);
      memcpy(ptr, output, 16);
      buff_remain_len -= 16;
      m_more_comp_size -= 16;
      ptr += 16;
    }
    if (m_more_comp_size < 0)
      n2 += m_more_comp_size;
  }

  return n2;
}

CONST text * CCompFileReader::fn() CONST
{
  return ((CCompBegining*)m_begining.get_ptr())->fn;
}


truefalse CCompFileReader::load_begining()
{
  CCompBegining begining;
  if (read_i((char*)&begining, sizeof(begining)) != sizeof(begining))
    return false;
  if (begining.signature != CCompBegining::SIGNATURE)
  {
    C_ERROR("bad file %s\n", m_fn.get_ptr());
    return false;
  }

  ni m = begining.begining_size - sizeof(begining);
  if (m <= 1 || m > PATH_MAX)
  {
    C_ERROR("bad comp beginning fn size: %s\n", m_fn.get_ptr());
    return false;
  }

  if (begining.processed_size < 0 || begining.processed_size > begining.data_size)
  {
    C_ERROR("bad data size\n");
    return false;
  }

  CCacheX::instance()->get(begining.begining_size, &m_begining);
  memcpy((void*)m_begining.get_ptr(), &begining, sizeof(begining));
  text * p = m_begining.get_ptr() + sizeof(begining);
  if (!read_i(p, m))
    return false;
  p[m - 1] = 0;

  m_more_size = begining.data_size;
  m_more_comp_size = begining.processed_size;
  return true;
};

truefalse CCompFileReader::get_more()
{
  return load_begining();
}

truefalse CCompFileReader::finished() CONST
{
  return (m_size <= (ni)::lseek(m_f.get_fd(), 0, SEEK_CUR));
}

DVOID CCompFileReader::password(CONST text * v_password)
{
  u8 l_x[32];
  memset((void*)l_x, 0, sizeof(l_x));
  if (v_password)
    ACE_OS::strsncpy((char*)l_x, v_password, sizeof(l_x));
  aes_set_key(&m_x, l_x, 256);
}




truefalse CBaseFileWriter::open(CONST text * v_fn)
{
  if (unlikely(!v_fn || !*v_fn))
  {
    C_ERROR("invalid param\n");
    return false;
  }
  m_fn.init(v_fn);
  return open_i();
}

truefalse CBaseFileWriter::open(CONST text * v_path, CONST text * v_fn)
{
  if (unlikely(!v_fn || !*v_fn || !v_fn || !*v_fn))
  {
    C_ERROR("invalid param\n");
    return false;
  }
  m_fn.init(v_path, v_fn);
  return open_i();
}

truefalse CBaseFileWriter::open_i()
{
  return m_f.open_write(m_fn.get_ptr(), true, true, false, false);
}

truefalse CBaseFileWriter::write(text * v_ptr, ni size)
{
  return write_i(v_ptr, size);
}

truefalse CBaseFileWriter::write_i(text * v_ptr, ni size)
{
  if (unlikely(!v_ptr || size <= 0))
    return true;

  ni n = ::write(m_f.get_fd(), v_ptr, size);
  if (unlikely(n != size))
  {
    C_ERROR("write file %s %s\n", m_fn.get_ptr(), (CONST char*)CSysError());
    return false;
  }
  return true;
}

DVOID CBaseFileWriter::close()
{
  m_f.bind_fd(CFileProt::BAD_FD);
  m_fn.free();
}




truefalse CCompFileWriter::write(text * v_ptr, ni size)
{
  if (unlikely(size < 0))
    return false;
  if (unlikely(size == 0))
    return true;

  m_size += size;

  if (m_more_comp_size > 0)
  {
    ni to_buffer_len = std::min(size, m_more_comp_size);
    memcpy(m_comp_cache.get_ptr(), v_ptr, to_buffer_len);
    m_more_comp_size -= to_buffer_len;
    if (m_more_comp_size > 0)
      return true;
    else if (!comp_save())
      return false;

    if (size - to_buffer_len > 0)
      return write_i(v_ptr + to_buffer_len, size - to_buffer_len);
    else
      return true;
  }

  return write_i(v_ptr, size);
}

truefalse CCompFileWriter::begin(CONST text * v_fn, ni skip_n)
{
  if (unlikely(skip_n < 0 || skip_n >= (ni)strlen(v_fn)))
  {
    C_ERROR("bad param begin(%s, %d)\n", v_fn, skip_n);
    return false;
  }
  if (unlikely(v_fn[skip_n] != '/' || v_fn[skip_n + 1] == '/'))
  {
    C_ERROR("bad param.2 begin(%s, %d)\n", v_fn, skip_n);
    return false;
  }

  m_size = 0;
  m_comp_size = 0;
  m_more_comp_size = BUFFER_SIZE;
  CCacheX::instance()->get(BUFFER_SIZE, &m_comp_cache);
  return save_begining(v_fn + skip_n + 1);
}

truefalse CCompFileWriter::end()
{
  if (m_more_comp_size > 0)
  {
    if (!comp_save())
      return false;
  }

  m_begining.data_size = m_size;

  if (::lseek(m_f.get_fd(), 0, SEEK_SET) == -1)
  {
    C_ERROR("lseek(%s): %s\n", m_fn.get_ptr(), (CONST char*)CSysError());
    return false;
  }

  return write_i((char*)&m_begining, sizeof(m_begining));
}

DVOID CCompFileWriter::password(CONST text * _password)
{
  u8 l_x[32];
  memset((void*)l_x, 0, sizeof(l_x));
  if (_password)
    ACE_OS::strsncpy((char*)l_x, _password, sizeof(l_x));
  aes_set_key(&m_x, l_x, 256);
}

truefalse CCompFileWriter::save_begining(CONST text * v_fn)
{
  if (unlikely(!v_fn || !*v_fn))
    return false;
  ni filename_len = strlen(v_fn) + 1;
  m_begining.signature = CCompBegining::SIGNATURE;
  m_begining.begining_size = sizeof(m_begining) + filename_len;
  m_begining.data_size = -1;
  m_begining.processed_size = -1;
  if (!write_i((char*)&m_begining, sizeof(m_begining)))
    return false;
  if (!write_i((char*)v_fn, filename_len))
    return false;
  return true;
}

truefalse CCompFileWriter::comp_save()
{
  ni l_m = BUFFER_SIZE - m_more_comp_size;
  m_begining.processed_size = l_m;
  if (l_m == 0)
    return true;

  ni l_padding = (16 - l_m % 16) % 16;
  if (l_padding > 0)
  {
    m_size += l_padding;
    memset(m_comp_cache.get_ptr() + l_m, 0, l_padding);
  }
  l_m += l_padding;
  u8 output[16];
  text * p = m_comp_cache.get_ptr();
  ni m = l_m;
  while (m >= 16)
  {
    aes_encrypt(&m_x, (u8*)p, output);
    memcpy(p, output, 16);
    p += 16;
    m -= 16;
  }
  return write_i(m_comp_cache.get_ptr(), l_m);
}



DVOID * CBZMemBridge::intf_alloc(DVOID *, ni n, ni m)
{
  return CCacheX::instance()->get_raw(n * m);
}

DVOID CBZMemBridge::intf_free(DVOID *, DVOID * ptr)
{
  CCacheX::instance()->put_raw(ptr);
}



CDataComp::CDataComp()
{
  m_s.bzalloc = CBZMemBridge::intf_alloc;
  m_s.bzfree = CBZMemBridge::intf_free;
  m_s.opaque = 0;
}

truefalse CDataComp::init()
{
  return (m_in.get_ptr() || CCacheX::instance()->get(BUFF_SIZE, &m_in)) &&
         (m_out.get_ptr() || CCacheX::instance()->get(BUFF_SIZE, &m_out));
}

truefalse CDataComp::reduce_i(CBaseFileReader * v_r, CBaseFileWriter * v_w)
{
  ni l_m, l_n, l_i;

  while (true)
  {
    l_n = v_r->read(m_in.get_ptr(), BUFF_SIZE);
    if (l_n < 0)
      return false;
    else if (l_n == 0)
      break;

    m_s.avail_in = l_n;
    m_s.next_in = m_in.get_ptr();
    while (true)
    {
      m_s.avail_out = BUFF_SIZE;
      m_s.next_out = m_out.get_ptr();
      l_m = BZ2_bzCompress(&m_s, BZ_RUN);
      if (l_m != BZ_RUN_OK)
      {
        C_ERROR("BZ2_bzCompress(BZ_RUN) = %d\n", l_m);
        return false;
      };

      if (m_s.avail_out < BUFF_SIZE)
      {
        l_i = BUFF_SIZE - m_s.avail_out;
        if (!v_w->write(m_out.get_ptr(), l_i))
         return false;
      }

      if (m_s.avail_in == 0)
        break;
    }

   if (l_n < BUFF_SIZE)
    break;
  }

  while (true)
  {
    m_s.avail_out = BUFF_SIZE;
    m_s.next_out = m_out.get_ptr();
    l_m = BZ2_bzCompress(&m_s, BZ_FINISH);
    if (l_m != BZ_FINISH_OK && l_m != BZ_STREAM_END)
    {
      C_ERROR("BZ2_bzCompress(BZ_FINISH) = %d\n", l_m);
      return false;
    };

    if (m_s.avail_out < BUFF_SIZE)
    {
      l_i = BUFF_SIZE - m_s.avail_out;
      if (!v_w->write(m_out.get_ptr(), l_i))
        return false;
    }

    if (l_m == BZ_STREAM_END)
      return true;
  }

  ACE_NOTREACHED(return true);
}

truefalse CDataComp::reduce(CONST text * from_fn, ni skip_n, CONST text * to_fn, CONST text * v_password)
{
  CBaseFileReader l_r;
  if (!l_r.open(from_fn))
    return false;
  CCompFileWriter l_w;
  if (!l_w.open(to_fn))
    return false;
  l_w.password(v_password);
  if (!l_w.begin(from_fn + skip_n))
    return false;
  init();
  ni l_m = BZ2_bzCompressInit(&m_s, AGGRESSIVE, 0, 30);
  if (l_m != BZ_OK)
  {
    C_ERROR("BZ2_bzCompressInit() = %d\n", l_m);
    return false;
  }

  truefalse n = reduce_i(&l_r, &l_w);
  if (!n)
    C_ERROR("reduce_i %s => %s\n", from_fn, to_fn);
  BZ2_bzCompressEnd(&m_s);

  if (!l_w.end())
    return false;
  return n;
}

truefalse CDataComp::bloat_i(CBaseFileReader * v_r, CBaseFileWriter * v_w)
{
  ni l_m, l_n, l_i;

  m_s.avail_out = BUFF_SIZE;
  m_s.next_out = m_out.get_ptr();
  m_s.avail_in = 0;

  while (true)
  {
    if (m_s.avail_in == 0)
    {
       l_m = v_r->read(m_in.get_ptr(), BUFF_SIZE);
       if (l_m < 0)
         return false;
       else if (l_m == 0)
       {
         C_ERROR("error: unexpected eof\n");
         return false;
       }
       m_s.avail_in = l_m;
       m_s.next_in = m_in.get_ptr();
    }

    l_i = BZ2_bzDecompress(&m_s);

    if (l_i != BZ_OK && l_i != BZ_STREAM_END)
    {
      C_ERROR("BZ2_bzDecompress() = %d\n", l_i);
      return false;
    };

    if (m_s.avail_out < BUFF_SIZE)
    {
      l_n = BUFF_SIZE - m_s.avail_out;
      if (!v_w->write(m_out.get_ptr(), l_n))
        return false;
      m_s.avail_out = BUFF_SIZE;
      m_s.next_out = m_out.get_ptr();
    }

    if (l_i == BZ_STREAM_END)
      return true;
  }

  ACE_NOTREACHED(return true);
}

truefalse CDataComp::bloat(CONST text * from_fn, CONST text * to_path, CONST text * v_password, CONST text * new_name)
{
  CCompFileReader l_r;
  if (!l_r.open(from_fn))
    return false;
  CBaseFileWriter l_w;
  init();
  l_r.password(v_password);

  CDirConverter converter;
  if (!converter.prepare(new_name))
    return false;

  ni l_m;
  while (true)
  {
    CONST text * l_x = converter.convert(l_r.fn());
    if (unlikely(!l_x))
      return false;

    if (!CSysFS::create_dir(to_path, l_x, true, true))
    {
      C_ERROR("create_dir %s/%s %s\n", to_path, l_x, (CONST char*)CSysError());
      return false;
    }
    CMemProt true_fn;
    true_fn.init(to_path, "/", l_x);

    if (!l_w.open(true_fn.get_ptr()))
      return false;

    l_m = BZ2_bzDecompressInit(&m_s, 0, 0);
    if (l_m != BZ_OK)
    {
      C_ERROR("BZ2_bzCompressInit() = %d\n", l_m);
      return false;
    }

    truefalse l_b = bloat_i(&l_r, &l_w);
    BZ2_bzDecompressEnd(&m_s);
    if (!l_b)
    {
      C_ERROR("bloat %s => %s\n", from_fn, to_path);
      return false;
    }
    if (l_r.finished())
      return true;
    if (!l_r.get_more())
      return false;
    l_w.close();
  };

  ACE_NOTREACHED(return true);
}




truefalse CCompUniter::begin(CONST text * v_ptr)
{
  return m_f.open_write(v_ptr, true, true, true, false);
}

DVOID CCompUniter::finish()
{
  m_f.bind_fd(CFileProt::BAD_FD);
}

truefalse CCompUniter::append(CONST text * v_fn)
{
  if (!m_f.ok())
    return true;
  CFileProt fd;
  if (!fd.open_nowrite(v_fn))
    return false;
  truefalse b = CSysFS::copy_file_by_fd(fd.get_fd(), m_f.get_fd());
  if (!b)
    C_ERROR("append(%s)\n", v_fn);
  return b;
}

truefalse CCompUniter::append_batch(text * v_fns, CONST text * v_dir, CONST text mark, CONST text * ext)
{
  text l_marks[2];
  l_marks[0] = mark;
  l_marks[1] = 0;
  text *ptr, *val, *tmp;

  for (ptr = v_fns; ; ptr = NULL)
  {
    val = strtok_r(ptr, l_marks, &tmp);
    if (!val)
      break;
    if (!*val)
      continue;
    if ((!v_dir || !*v_dir) && (!ext || !*ext))
    {
      if (!append(val))
        return false;
    } else
    {
      CMemProt fn;
      fn.init(v_dir, "/", val, ext);
      if (!append(fn.get_ptr()))
        return false;
    }
  }

  return true;
}





CProc::CProc(CParentHandler * v_h)
{
  m_handler = v_h;
  m_mark_down = false;
  m_lastest_action = g_clock_counter;
  m_term_loc = -1;
  m_term_sn_len = 0;
}

CProc::~CProc()
{

}

DVOID CProc::get_sinfo(CMemProt & ) CONST
{

}

ni CProc::at_start()
{
  return 0;
}

DVOID CProc::at_finish()
{

}

truefalse CProc::get_mark_down() CONST
{
  return m_mark_down;
}

DVOID CProc::set_mark_down()
{
  m_mark_down = true;
}

ni CProc::handle_input()
{
  return 0;
}

truefalse CProc::ok_to_post(CMB * ) CONST
{
  return true;
}

CONST text * CProc::name() CONST
{
  return "CProc";
}

ni CProc::on_read_data_at_down()
{
  text txt[4096];
  ssize_t l_x = m_handler->peer().recv (txt, 4096);
  ni n = c_tools_socket_outcome(l_x);
  if (n < 0)
    return -1;
  if (n > 0)
    C_DEBUG("ignore %d since closing()\n", l_x, name());
  return (m_handler->msg_queue()->is_empty ()) ? -1 : 0;
}


truefalse CProc::broken() CONST
{
  return m_lastest_action + 100 < g_clock_counter;
}

DVOID CProc::set_lastest_action()
{
  m_lastest_action = g_clock_counter;
}

long CProc::get_lastest_action() CONST
{
  return m_lastest_action;
}

CONST CNumber & CProc::term_sn() CONST
{
  return m_term_sn;
}

DVOID CProc::set_term_sn(CONST text * sn)
{
  m_term_sn = sn;
}

truefalse CProc::term_sn_check_done() CONST
{
  return false;
}

int32_t CProc::term_sn_loc() CONST
{
  return m_term_loc;
}




CFormatProcBase::CFormatProcBase(CParentHandler * handler): baseclass(handler)
{
  m_remote_ip[0] = 0;
}

CONST text * CFormatProcBase::name() CONST
{
  return "CFormatProcBase";
}

DVOID CFormatProcBase::get_sinfo(CMemProt & v_x) CONST
{
  CONST text * str_id = m_term_sn.to_str();
  if (!*str_id)
    str_id = "NULL";
  CONST text * ss[5];
  ss[0] = "(remote addr=";
  ss[1] = m_remote_ip;
  ss[2] = ", client_id=";
  ss[3] = m_term_sn.to_str();
  ss[4] = ")";
  v_x.inits(ss, 5);
}

ni CFormatProcBase::at_start()
{
  ACE_INET_Addr peer_addr;
  if (m_handler->peer().get_remote_addr(peer_addr) == 0)
    peer_addr.get_host_addr((char*)m_remote_ip, IP_LEN);
  if (m_remote_ip[0] == 0)
    ACE_OS::strsncpy((char*)m_remote_ip, "unknown", IP_LEN);
  return 0;
}

ni CFormatProcBase::data_len()
{
  return m_data_head.size;
}

CProc::OUTPUT CFormatProcBase::at_head_arrival()
{
  return OP_GO_ON;
}

CProc::OUTPUT CFormatProcBase::do_read_data(CMB * mb)
{
  CCmdHeader * header = (CCmdHeader *)mb->base();
  header->signature = m_term_loc;
  return OP_OK;
}

CMB * CFormatProcBase::create_login_mb(CONST ni x)
{
  CMB * mb = CCacheX::instance()->get_mb_cmd_direct(sizeof(CTerminalVerReq) + x, CCmdHeader::PT_VER_REQ);
  return mb;
}




CBSProceBase::CBSProceBase(CParentHandler * h): baseclass(h)
{

}

CProc::OUTPUT CBSProceBase::at_head_arrival()
{
  return (m_data_head.validate_header()? OP_OK : OP_FAIL);
}

CProc::OUTPUT CBSProceBase::do_read_data(CMB * mb)
{
  CBSData * p = (CBSData *) mb->base();
  if (!p->fix_data())
  {
    C_ERROR("bad data from bs, no tail\n");
    return OP_FAIL;
  }
  return OP_OK;
}

ni CBSProceBase::data_len()
{
  return m_data_head.data_len();
}



CParentServerProc::CParentServerProc(CParentHandler * h) : CFormatProcBase(h)
{

}

CParentServerProc::~CParentServerProc()
{

}

CONST text * CParentServerProc::name() CONST
{
  return "CParentServerProc";
}

truefalse CParentServerProc::term_sn_check_done() CONST
{
  return !m_term_sn.empty();
}

truefalse CParentServerProc::ok_to_post(CMB *) CONST
{
  return term_sn_check_done();
}

CProc::OUTPUT CParentServerProc::at_head_arrival()
{
  CProc::OUTPUT r = baseclass::at_head_arrival();
  if (r != OP_GO_ON)
    return r;

  truefalse l_sn_Ok = term_sn_check_done();
  truefalse l_ver_ok = (m_data_head.cmd == CCmdHeader::PT_VER_REQ);
  if (l_sn_Ok == l_ver_ok)
  {
    CMemProt l_x;
    get_sinfo(l_x);
    C_ERROR("Get bad data(cmd = %d, verified = %d, version ok = %d) from %s\n",
        m_data_head.cmd, l_sn_Ok, l_ver_ok, l_x.get_ptr());
    return OP_FAIL;
  }

  return OP_GO_ON;
}

CProc::OUTPUT CParentServerProc::i_is_ver_ok(CMB * mb, CTermSNs & term_SNs)
{
  CTerminalVerReq * l_header = (CTerminalVerReq *) mb->base();
  l_header->fix_data();
  CMB * reply_mb = NULL;
  m_term_ver.init(l_header->term_ver_major, l_header->term_ver_minor);
  ni m = term_SNs.find_location(l_header->term_sn);
  truefalse l_ok = false;

  m_term_loc = m;
  m_term_sn = l_header->term_sn;
  m_term_sn_len = strlen(m_term_sn.to_str());

  if (m >= 0)
  {
    CTermData term_data;
    if (term_SNs.get_termData(m, term_data))
      l_ok = ! term_data.invalid;
  }
  if (!l_ok)
  {
    m_mark_down = true;
    C_WARNING("terminate client because bad sn = %s\n", l_header->term_sn.to_str());
    reply_mb = i_create_mb_ver_reply(CTermVerReply::SC_ACCESS_DENIED);
  }

  if (m_mark_down)
  {
    if (m_handler->post_packet(reply_mb) <= 0)
      return OP_FAIL;
    else
      return OP_OK;
  }

  m_handler->handler_director()->sn_at_location(m_handler, m, m_handler->term_SNs());
  return OP_GO_ON;
}

CMB * CParentServerProc::i_create_mb_ver_reply(CTermVerReply::SUBCMD x, ni more_space)
{
  ni l_x = sizeof(CTermVerReply) + more_space;
  CMB * mb = CCacheX::instance()->get_mb_cmd_direct(l_x, CCmdHeader::PT_VER_REPLY);
  CTermVerReply * l_header = (CTermVerReply *) mb->base();
  l_header->ret_subcmd = x;
  return mb;
}


CParentClientProc::CParentClientProc(CParentHandler * handler) : CFormatProcBase(handler)
{
  m_sn_check_ok = false;
}

CParentClientProc::~CParentClientProc()
{

}

CONST text * CParentClientProc::name() CONST
{
  return "CParentClientProc";
}

truefalse CParentClientProc::term_sn_check_done() CONST
{
  return m_sn_check_ok;
}

DVOID CParentClientProc::sn_check_ok(truefalse bOK)
{
  m_sn_check_ok = bOK;
}

truefalse CParentClientProc::ok_to_post(CMB * mb) CONST
{
  CCmdHeader * l_header = (CCmdHeader*) mb->base();
  truefalse bVerReq = l_header->cmd == CCmdHeader::PT_VER_REQ;
  truefalse sn_check_done = term_sn_check_done();
  return bVerReq != sn_check_done;
}


ni CParentClientProc::at_start()
{

  if (baseclass::at_start() < 0)
    return -1;

  if (g_is_test)
  {
    ni pending_count = m_handler->handler_director()->waiting_count();
    if (pending_count > 0 &&  pending_count <= CParentConn::ONCE_COUNT / 2)
      m_handler->connector()->on_can_connect();
  }
  return 0;
}

DVOID CParentClientProc::at_finish()
{
  if (g_is_test)
  {
    ni pending_count = m_handler->handler_director()->waiting_count();
    if (pending_count > 0 &&  pending_count <= CParentConn::ONCE_COUNT / 2)
      m_handler->connector()->on_can_connect();
  }
}

CProc::OUTPUT CParentClientProc::at_head_arrival()
{
  CProc::OUTPUT result = baseclass::at_head_arrival();
  if (result != OP_GO_ON)
    return result;

  truefalse bVerified = term_sn_check_done();
  truefalse bVersionCheck = (m_data_head.cmd == CCmdHeader::PT_VER_REPLY);
  if (bVerified == bVersionCheck)
  {
    CMemProt info;
    get_sinfo(info);
    C_ERROR(ACE_TEXT("Bad request received (cmd = %d, verified = %d, request version check = %d) from %s \n"),
        m_data_head.cmd, bVerified, bVersionCheck, info.get_ptr());
    return OP_FAIL;
  }

  return OP_GO_ON;
}




CHandlerDirector::CHandlerDirector()
{
  m_count = 0;
  m_data_get = 0;
  m_data_post = 0;
  m_forced_count = 0;
  m_down = false;
  m_waiting_count = 0;
  m_all_count = 0;
}

CHandlerDirector::~CHandlerDirector()
{
  CHandlersAllIt l_x;
  CParentHandler * l_h;
  CHandlerDirectorDownProt obj(this);
  for (l_x = m_handlers.begin(); l_x != m_handlers.end(); ++l_x)
  {
    l_h = l_x->first;
    if (l_h)
      l_h->handle_close(ACE_INVALID_HANDLE, 0);
  }
}

ni CHandlerDirector::active_count() CONST
{
  return m_count;
}

ni CHandlerDirector::total_count() CONST
{
  return m_all_count;
}

ni CHandlerDirector::forced_count() CONST
{
  return m_forced_count;
}

ni CHandlerDirector::waiting_count() CONST
{
  return m_waiting_count;
}

i64 CHandlerDirector::data_get() CONST
{
  return m_data_get;
}

i64 CHandlerDirector::data_post() CONST
{
  return m_data_post;
}

DVOID CHandlerDirector::on_data_get(ni m)
{
  m_data_get += m;
}

DVOID CHandlerDirector::on_data_post(ni m)
{
  m_data_post += m;
}

DVOID CHandlerDirector::down()
{
  m_down = true;
}

DVOID CHandlerDirector::up()
{
  m_down = false;
}

truefalse CHandlerDirector::is_down() CONST
{
  return m_down;
}

DVOID CHandlerDirector::print_all()
{
  i_print();
}

DVOID CHandlerDirector::post_all(CMB * mb)
{
  i_post(mb, true);
}

DVOID CHandlerDirector::post_one(CMB * mb)
{
  i_post(mb, false);
}

DVOID CHandlerDirector::i_post(CMB * mb, truefalse to_all)
{
  if (unlikely(!mb))
    return;

  typedef std::vector<CParentHandler *, CCppAllocator<CParentHandler *> > PVEC;
  PVEC vec;
  CMBProt g(mb);

  CHandlersAllIt l_x;
  for (l_x = m_handlers.begin(); l_x != m_handlers.end(); ++l_x)
  {
    if (l_x->second == HWaiting)
      continue;
    if (!to_all)
    {
      CParentHandler * l_h = l_x->first;
      C_DEBUG("do_send: handler=%X, socket=%d, length=%d\n", (ni)(long)l_h, l_h->get_handle(), mb->length());
    }
    if (l_x->first->post_packet(mb->duplicate()) < 0)
      vec.push_back(l_x->first);
    else if (!to_all)
      break;
  }

  PVEC::iterator l_x2;
  for (l_x2 = vec.begin(); l_x2 != vec.end(); ++l_x2)
    (*l_x2)->handle_close();
}

DVOID CHandlerDirector::i_print()
{
  CONST ni DATA_LEN = 1024;
  text tmp[DATA_LEN];
  snprintf(tmp, DATA_LEN, "        active = %d\n", active_count());
  ACE_DEBUG((LM_INFO, tmp));
  snprintf(tmp, DATA_LEN, "        total = %d\n", total_count());
  ACE_DEBUG((LM_INFO, tmp));
  snprintf(tmp, DATA_LEN, "        dead = %d\n", forced_count());
  ACE_DEBUG((LM_INFO, tmp));
  snprintf(tmp, DATA_LEN, "        read = %lld\n", (long long int) data_get());
  ACE_DEBUG((LM_INFO, tmp));
  snprintf(tmp, DATA_LEN, "        write = %lld\n", (long long int) data_post());
  ACE_DEBUG((LM_INFO, tmp));
}


DVOID CHandlerDirector::delete_broken(ni _to)
{
  CHandlersAllIt l_x;
  CParentHandler * h;
  CHandlerDirectorDownProt o(this);
  long deadline = g_clock_counter - long(_to * 60 / CApp::CLOCK_TIME);
  for (l_x = m_handlers.begin(); l_x != m_handlers.end();)
  {
    h = l_x->first;
    if (!h)
    {
      m_handlers.erase(l_x++);
      --m_count;
      ++m_forced_count;
      continue;
    }

    if (h->get_proc()->get_lastest_action() < deadline)
    {
      if (l_x->second == HWaiting)
        -- m_waiting_count;
      h->prepare_close();
      delete_at_map(h, h->term_SNs());
      h->handle_close(ACE_INVALID_HANDLE, 0);
      m_handlers.erase(l_x++);
      --m_count;
      ++m_forced_count;
    }
    else
      ++l_x;
  }
}

DVOID CHandlerDirector::sn_at_location(CParentHandler * h, ni v_idx, CTermSNs * sns)
{
  if (unlikely(!h || m_down || v_idx < 0))
    return;
  CHandlersMapIt l_x = m_map.lower_bound(v_idx);
  if (sns)
    sns->set_connected(v_idx, true);
  if (l_x != m_map.end() && (l_x->first == v_idx))
  {
    CParentHandler * handler_old = l_x->second;
    l_x->second = h;
    if (handler_old)
    {
      delete_at_container(handler_old);
      CMemProt s;
      handler_old->get_proc()->get_sinfo(s);
      C_DEBUG("down old socket %s\n", s.get_ptr());
      handler_old->prepare_close();
      handler_old->handle_close(ACE_INVALID_HANDLE, 0);
    }
  } else
    m_map.insert(l_x, CHandlersMap::value_type(v_idx, h));
}

CParentHandler * CHandlerDirector::locate(ni loc)
{
  CHandlersMapIt l_x = do_locate(loc);
  if (l_x == m_map.end())
    return NULL;
  else
    return l_x->second;
}

DVOID CHandlerDirector::add(CParentHandler * v_h, CHow how)
{
  if (!v_h || m_down)
    return;
  CHandlersAllIt l_x = m_handlers.lower_bound(v_h);
  if (l_x != m_handlers.end() && (l_x->first == v_h))
  {
    if (l_x->second != how)
      m_waiting_count += (how == HWaiting ? 1:-1);
    l_x->second = how;
  } else
  {
    if (how == HWaiting)
      ++ m_waiting_count;
    m_handlers.insert(l_x, CHandlersAll::value_type(v_h, how));
    ++m_count;
    ++m_all_count;
  }
}

DVOID CHandlerDirector::change_how(CParentHandler * v_h, CHow how)
{
  add(v_h, how);
}

DVOID CHandlerDirector::remove_x(CParentHandler * v_h, CTermSNs * sns)
{
  if (unlikely(m_down))
    return;

  delete_at_container(v_h);
  delete_at_map(v_h, sns);
}

DVOID CHandlerDirector::delete_at_container(CParentHandler * v_h)
{
  CHandlersAllIt l_x = do_search(v_h);
  if (l_x != m_handlers.end())
  {
    if (l_x->second == HWaiting)
      -- m_waiting_count;
    m_handlers.erase(l_x);
    --m_count;
  }
}

DVOID CHandlerDirector::delete_at_map(CParentHandler * v_h, CTermSNs * sns)
{
  ni loc = v_h->get_proc()->term_sn_loc();
  if (loc < 0)
    return;

  CHandlersMapIt l_x = do_locate(loc);
  if (l_x != m_map.end() && (l_x->second == v_h || l_x->second == NULL))
  {
    m_map.erase(l_x);
    if (sns)
      sns->set_connected(loc, false);
  }
}

CHandlerDirector::CHandlersAllIt CHandlerDirector::do_search(CParentHandler * v_h)
{
  return m_handlers.find(v_h);
}

CHandlerDirector::CHandlersMapIt CHandlerDirector::do_locate(ni loc)
{
  return m_map.find(loc);
}



CParentHandler::CParentHandler(CHandlerDirector * p)
{
  m_marked_for_close = false;
  m_handler_director = p;
  m_proc = NULL;
  m_container = NULL;
}

CHandlerDirector * CParentHandler::handler_director()
{
  return m_handler_director;
}

CProc * CParentHandler::get_proc() CONST
{
  return m_proc;
}

ni CParentHandler::at_start()
{
  return 0;
}

ni CParentHandler::open(DVOID * p)
{
  if (baseclass::open(p) == -1)
    return -1;
  if (at_start() < 0)
    return -1;
  if (m_proc->at_start() < 0)
    return -1;
  if (m_handler_director)
    m_handler_director->change_how(this, CHandlerDirector::HConnected);
  return 0;
}

ni CParentHandler::post_packet(CMB * mb)
{
  if (unlikely(!m_proc->ok_to_post(mb)))
  {
    mb->release();
    return 0;
  }
  m_proc->set_lastest_action();
  ni l_n = mb->length();
  ni l_m = c_tools_post_mbq(this, mb, true);
  if (l_m >= 0)
  {
    if (m_handler_director)
      m_handler_director->on_data_post(l_n);
  }
  return l_m;
}

DVOID CParentHandler::prepare_close()
{
  m_marked_for_close = true;
}

ni CParentHandler::handle_input(ACE_HANDLE h)
{
  ACE_UNUSED_ARG(h);
  return m_proc->handle_input();
}

CTermSNs * CParentHandler::term_SNs() CONST
{
  return NULL;
}

DVOID CParentHandler::at_finish()
{

}

ni CParentHandler::handle_close (ACE_HANDLE handle, ACE_Reactor_Mask close_mask)
{
  ACE_UNUSED_ARG(handle);
  ACE_UNUSED_ARG(close_mask);

  CMB *mb;
  ACE_Time_Value t(ACE_Time_Value::zero);
  while (-1 != this->getq(mb, &t))
    mb->release();
  if (m_handler_director && !m_marked_for_close)
    m_handler_director->remove_x(this, term_SNs());
  at_finish();
  m_proc->at_finish();
  delete this;
  return 0;
}

ni CParentHandler::handle_output (ACE_HANDLE)
{
  CMB *mb;
  ACE_Time_Value t (ACE_Time_Value::zero);
  while (-1 != this->getq(mb, &t))
  {
    if (c_tools_post_mb(this, mb) < 0)
    {
      mb->release();
      return -1;
    }
    if (mb->length() > 0)
    {
      this->ungetq(mb);
      break;
    }
    mb->release();
  }
  if (this->msg_queue()->is_empty())
    this->reactor()->cancel_wakeup(this, ACE_Event_Handler::WRITE_MASK);
  else
    this->reactor()->schedule_wakeup(this, ACE_Event_Handler::WRITE_MASK);

  return 0;
}

CParentHandler::~CParentHandler()
{
  delete m_proc;
}




CParentAcc::CParentAcc(CParentScheduler * p1, CHandlerDirector * p2): m_scheduler(p1), m_director(p2)
{
  m_reap_interval = 0;
  m_tcp_port = 0;
  m_container = m_scheduler->container();
  m_reaper_id = -1;
}

CParentAcc::~CParentAcc()
{
  if (m_director)
    delete m_director;
}

CContainer * CParentAcc::container() CONST
{
  return m_container;
}

CParentScheduler * CParentAcc::scheduler() CONST
{
  return m_scheduler;
}

CHandlerDirector * CParentAcc::director() CONST
{
  return m_director;
}

truefalse CParentAcc::before_begin()
{
  return true;
}

DVOID CParentAcc::before_finish()
{

}

ni CParentAcc::handle_timeout(CONST ACE_Time_Value &, CONST DVOID *m)
{
  if (long(m) == TID_reap_broken)
    m_director->delete_broken(m_reap_interval);
  return 0;
}

ni CParentAcc::begin()
{
  if (m_tcp_port <= 0)
  {
    C_FATAL("bad listen port %d\n", m_tcp_port);
    return -1;
  }
  ACE_INET_Addr l_addr (m_tcp_port);
  m_director->up();

  ni l_x = baseclass::open (l_addr, m_scheduler->reactor(), ACE_NONBLOCK);
  if (l_x == 0)
    C_INFO("%s listening on port %d... OK\n", container()->name(), m_tcp_port);
  else if (l_x < 0)
  {
    C_ERROR("%s acceptor.open on port %d failed!\n", container()->name(), m_tcp_port);
    return -1;
  }

  if (m_reap_interval > 0)
  {
    ACE_Time_Value tv( m_reap_interval * 60);
    m_reaper_id = reactor()->schedule_timer(this, (void*)TID_reap_broken, tv, tv);
    if (m_reaper_id < 0)
    {
      C_ERROR("can not setup dead connection timer @%s\n", name());
      return -1;
    }
  }

  if (!before_begin())
    return -1;

  return 0;
}

ni CParentAcc::end()
{
  before_finish();
  m_director->down();
  if (m_reaper_id >= 0)
    reactor()->cancel_timer(m_reaper_id);
  close();
  return 0;
}

DVOID CParentAcc::i_print()
{
  m_director->print_all();
}

DVOID CParentAcc::print_info()
{
  ACE_DEBUG((LM_INFO, "      +++ Acc: %s start\n", name()));
  i_print();
  ACE_DEBUG((LM_INFO, "      +++ Acc: %s end\n", name()));
}

CONST text * CParentAcc::name() CONST
{
  return "CParentAcc";
}


CParentConn::CParentConn(CParentScheduler * p1, CHandlerDirector * p2): m_scheduler(p1), m_director(p2)
{
  m_unfinished_count = 0;
  m_port_of_ip = 0;
  m_conn_count = 1;
  m_retry_delay = 0;
  m_retry_num = 0;
  m_retry_tid = -1;
  m_container = m_scheduler->container();
  m_no_activity_delay = 0;
  m_no_activity_tid = -1;
}

CParentConn::~CParentConn()
{
  if (m_director)
    delete m_director;
}

CContainer * CParentConn::container() CONST
{
  return m_container;
}

CHandlerDirector * CParentConn::director() CONST
{
  return m_director;
}

CParentScheduler * CParentConn::scheduler() CONST
{
  return m_scheduler;
}

DVOID CParentConn::tcp_addr(CONST text * addr)
{
  m_remote_ip = (addr? addr:"");
}

truefalse CParentConn::before_reconnect()
{
  return true;
}

ni CParentConn::handle_timeout(CONST ACE_Time_Value &current_time, CONST DVOID *act)
{
  ACE_UNUSED_ARG(current_time);
  if (long(act) == TID_retry && m_retry_delay > 0)
  {
    if (m_director->active_count() < m_conn_count)
    {
      if (g_is_test)
      {
        if (m_unfinished_count > 0)
          return 0;
      }
      if (before_reconnect())
      {
        m_retry_num++;
        i_socket_connect(m_conn_count - m_director->active_count(), true);
      }
    }
  } else if (long(act) == TID_reap_broken && m_no_activity_delay > 0)
    m_director->delete_broken(m_no_activity_delay);

  return 0;
}

truefalse CParentConn::before_begin()
{
  return true;
}

DVOID CParentConn::before_finish()
{

}

ni CParentConn::begin()
{
  m_director->up();
  if (g_is_test)
    m_unfinished_count = 0;
  if (open(m_scheduler->reactor(), ACE_NONBLOCK) == -1)
    return -1;
  m_retry_num = 0;

  if (m_port_of_ip <= 0)
  {
    C_FATAL(ACE_TEXT ("attempt to connect to an invalid port %d @%s\n"), m_port_of_ip, name());
    return -1;
  }

  if (m_remote_ip.length() == 0)
  {
    C_FATAL(ACE_TEXT ("attempt to connect to an NULL host from @%s\n"), name());
    return -1;
  }

  if (before_reconnect())
  {
    m_retry_num++;
    i_socket_connect(m_conn_count, true);
  }

  if (m_retry_delay > 0)
  {
    ACE_Time_Value interval (m_retry_delay * 60);
    m_retry_tid = reactor()->schedule_timer (this, (void*)TID_retry, interval, interval);
    if (m_retry_tid < 0)
      C_ERROR(ACE_TEXT("%s setup reconnect timer failed, %s\n"), name(), (CONST char*)CSysError());
  }

  if (m_no_activity_delay > 0)
  {
    ACE_Time_Value tv( m_no_activity_delay * 60);
    m_no_activity_tid = reactor()->schedule_timer(this, (void*)TID_reap_broken, tv, tv);
    if (m_no_activity_tid < 0)
    {
      C_ERROR("can not setup dead connection timer @%s\n", name());
      return -1;
    }
  }

  if (!before_begin())
    return -1;

  return 0; //
}

DVOID CParentConn::i_print()
{
  m_director->print_all();
}

DVOID CParentConn::print_data()
{
  ACE_DEBUG((LM_INFO, "      +++ Conn: %s start\n", name()));
  i_print();
  ACE_DEBUG((LM_INFO, "      +++ Conn: %s end\n", name()));
}

CONST text * CParentConn::name() CONST
{
  return "CParentConn";
}

ni CParentConn::end()
{
  before_finish();
  if (m_retry_tid >= 0)
    reactor()->cancel_timer(m_retry_tid);
  if (m_no_activity_tid >= 0)
    reactor()->cancel_timer(m_no_activity_tid);
  m_director->down();
  close();
  return 0;
}

ni CParentConn::on_can_connect()
{
  if (g_is_test)
    return i_socket_connect(0, false);
  else
    return 0;
}

DVOID CParentConn::reset_retry_count()
{
  m_retry_num = 0;
}

ni CParentConn::i_socket_connect(ni v_num, truefalse is_new)
{
  if (g_is_test)
  {
    if (unlikely(v_num <= 0 && m_unfinished_count == 0))
      return 0;

    if (unlikely(v_num > m_conn_count))
    {
      C_FATAL("bad con num = %d > max (=%d)", v_num, m_conn_count);
      return -1;
    }

    if (m_director->waiting_count() >= ONCE_COUNT / 2)
      return 0;

    truefalse l_x = m_unfinished_count > 0;
    if (l_x && is_new)
      return 0;
    ni actual_number;
    if (l_x)
      actual_number = std::min(m_unfinished_count, (ONCE_COUNT - m_director->waiting_count()));
    else
      actual_number = std::min(v_num, (ni)ONCE_COUNT);

    if (actual_number <= 0)
      return 0;

    ACE_INET_Addr port_to_connect(m_port_of_ip, m_remote_ip.c_str());
    CParentHandler * l_h = NULL;
    ni num_done = 0, num_waiting = 0;

    ACE_Time_Value timeout(60);
    ACE_Synch_Options synch_options(ACE_Synch_Options::USE_REACTOR | ACE_Synch_Options::USE_TIMEOUT, timeout);

    for (ni i = 1; i <= actual_number; ++i)
    {
      l_h = NULL;
      ni l_y = connect(l_h, port_to_connect, synch_options);
      if (l_y == 0)
      {
        ++num_done;
      }
      else if (l_y == -1)
      {
        if (errno == EWOULDBLOCK)
        {
          num_waiting++;
          m_director->add(l_h, CHandlerDirector::HWaiting);
        }
      }
    }

    if (l_x)
      m_unfinished_count -= actual_number;
    else if (is_new)
      m_unfinished_count = v_num - actual_number;

    C_INFO("%s connecting to %s:%d (all=%d, done=%d, failed=%d, waiting=%d)... \n", name(),
        m_remote_ip.c_str(), m_port_of_ip, actual_number, num_done, actual_number - num_done- num_waiting, num_waiting);

    return num_done + num_waiting > 0;
  } else
  {
    ACE_INET_Addr l_addr(m_port_of_ip, m_remote_ip.c_str());
    CParentHandler * l_h = NULL;
    ACE_Time_Value tv(60);
    ACE_Synch_Options synch_options(ACE_Synch_Options::USE_REACTOR | ACE_Synch_Options::USE_TIMEOUT, tv);
    C_INFO("%s connecting to %s:%d ...\n", name(), m_remote_ip.c_str(), m_port_of_ip);
    if (connect(l_h, l_addr, synch_options) == -1)
    {
      if (errno == EWOULDBLOCK)
        m_director->add(l_h, CHandlerDirector::HWaiting);
    }
    return 0;
  }
}


CTaskBase::CTaskBase(CContainer * module, ni numThreads):
    m_container(module), m_num_threads(numThreads)
{

}

CContainer * CTaskBase::container() CONST
{
  return m_container;
}

ni CTaskBase::begin()
{
  if (open(NULL) == -1)
    return -1;
  if (msg_queue()->deactivated())
    msg_queue()->activate();
  msg_queue()->flush();
  return activate (THR_NEW_LWP, m_num_threads);
}

ni CTaskBase::end()
{
  msg_queue()->deactivate();
  msg_queue()->flush();
  wait();
  return 0;
}

DVOID CTaskBase::print_all()
{

}

DVOID CTaskBase::i_print()
{

}

truefalse CTaskBase::add_new(DVOID * p, ni type_of_cmd)
{
  if (unlikely(!p))
    return true;

  CMB * mb = CCacheX::instance()->get_mb(sizeof(ni) + sizeof(DVOID *));
  *((ni*)mb->base()) = type_of_cmd;
  *(text **)(mb->base() + sizeof(ni)) = (char*)p;

  text tmp[100];
  snprintf(tmp, 100, "cmd pkt (%d) to %s", type_of_cmd, name());
  return c_tools_mb_putq(this, mb, tmp);
}

DVOID * CTaskBase::task_convert(CMB * mb, ni & task_type) CONST
{
  if (unlikely(mb->capacity() != sizeof(DVOID *) + sizeof(ni)))
    return NULL;

  task_type = *(ni*)mb->base();
  return *((text **)(mb->base() + sizeof(ni)));
}


CONST text * CTaskBase::name() CONST
{
  return "CTaskBase";
}


CParentScheduler::CParentScheduler(CContainer * p, ni v_threads): m_container(p), m_post_batch_count(50), m_thread_count(v_threads)
{
  m_reactor = NULL;
  m_delay_clock = 0;
  m_finished_init = false;
}

CParentScheduler::~CParentScheduler()
{
  if (m_reactor)
    delete m_reactor;
}

ni CParentScheduler::open (DVOID *)
{
  m_reactor = new ACE_Reactor(new ACE_Dev_Poll_Reactor(ACE::max_handles()), true);
  reactor(m_reactor);

  if (m_delay_clock > 0)
  {
    ACE_Time_Value interval(m_delay_clock);
    if (m_reactor->schedule_timer(this, (CONST void*)TID, interval, interval) < 0)
    {
      C_ERROR("can not setup timer %s %s\n", name(), (CONST char*)CSysError());
      return -1;
    }
  }

  return 0;
}

DVOID CParentScheduler::conn_add(CParentConn * p)
{
  if (!p)
  {
    C_FATAL("NULL param\n");
    return;
  }
  m_conns.push_back(p);
}

DVOID CParentScheduler::acc_add(CParentAcc * p)
{
  if (!p)
  {
    C_FATAL("NULL param\n");
    return;
  }
  m_accs.push_back(p);
}

truefalse CParentScheduler::before_begin()
{
  return true;
}

ni CParentScheduler::begin()
{
  return activate (THR_NEW_LWP, m_thread_count);
}

truefalse CParentScheduler::do_schedule_work()
{
  return true;
}

DVOID CParentScheduler::before_finish()
{

}

DVOID CParentScheduler::before_finish_stage_1()
{

}

ni CParentScheduler::end()
{
  wait();
  return 0;
}

CONST text * CParentScheduler::name() CONST
{
  return "CParentScheduler";
}

DVOID CParentScheduler::print_data()
{
  ACE_DEBUG((LM_INFO, "    --- scheduler: %s start\n", name()));
  i_print();
  std::for_each(m_conns.begin(), m_conns.end(), std::mem_fun(&CParentConn::print_data));
  std::for_each(m_accs.begin(), m_accs.end(), std::mem_fun(&CParentAcc::print_info));
  ACE_DEBUG((LM_INFO, "    --- scheduler: %s end\n", name()));
}

DVOID CParentScheduler::i_print()
{

}

CContainer * CParentScheduler::container() CONST
{
  return m_container;
}

truefalse CParentScheduler::i_begin()
{
  ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, 0);
  if (!m_finished_init)
  {
    m_finished_init = true;
    if (open(NULL) == -1)
      return false;
    msg_queue()->flush();
    if (!before_begin())
      return false;
    std::for_each(m_conns.begin(), m_conns.end(), std::mem_fun(&CParentConn::begin));
    std::for_each(m_accs.begin(), m_accs.end(), std::mem_fun(&CParentAcc::begin));
  }
  return true;
}

DVOID CParentScheduler::i_end()
{
  ACE_GUARD(ACE_Thread_Mutex, ace_mon, this->m_mutex);
  if (!m_reactor) //reuse m_reactor as cleanup flag
    return;
  before_finish_stage_1();
  msg_queue()->flush();
  if (m_reactor && m_delay_clock > 0)
    m_reactor->cancel_timer(this);
  std::for_each(m_conns.begin(), m_conns.end(), std::mem_fun(&CParentConn::end));
  std::for_each(m_accs.begin(), m_accs.end(), std::mem_fun(&CParentAcc::end));
  std::for_each(m_conns.begin(), m_conns.end(), CObjDeletor());
  std::for_each(m_accs.begin(), m_accs.end(), CObjDeletor());
  if (m_reactor)
    m_reactor->close();
  m_conns.clear();
  m_accs.clear();
  before_finish();
  delete m_reactor;
  m_reactor = NULL;
}

ni CParentScheduler::svc()
{
  C_INFO("Start %s::svc()\n", name());

  if (!i_begin())
    return -1;

  while (m_container->working_app())
  {
    ACE_Time_Value timeout(2);
    ni ret = reactor()->handle_events(&timeout);
    if (ret == -1)
    {
      if (errno == EINTR)
        continue;
      C_INFO("exiting %s::svc() because %s\n", name(), (CONST char*)CSysError());
      break;
    }
    if (!do_schedule_work())
      break;
  }

  C_INFO("exiting %s::svc()\n", name());
  i_end();
  return 0;
}


CContainer::CContainer(CApp * p): m_app(p), m_is_working(false)
{

}

CContainer::~CContainer()
{
  end();
}

truefalse CContainer::working() CONST
{
  return m_is_working;
}

CApp * CContainer::app() CONST
{
  return m_app;
}

truefalse CContainer::working_app() CONST
{
  return (m_is_working && m_app->running());
}

truefalse CContainer::before_begin()
{
  return true;
}

DVOID CContainer::before_finish()
{

}


ni CContainer::begin()
{
  if (m_is_working)
    return 0;

  if (!before_begin())
    return -1;
  m_is_working = true;
  std::for_each(m_tasks.begin(), m_tasks.end(), std::mem_fun(&CTaskBase::begin));
  std::for_each(m_schedulers.begin(), m_schedulers.end(), std::mem_fun(&CParentScheduler::begin));
  return 0;
}

ni CContainer::end()
{
  if (!m_is_working)
    return 0;
  m_is_working = false;
  std::for_each(m_tasks.begin(), m_tasks.end(), std::mem_fun(&CTaskBase::end));
  std::for_each(m_schedulers.begin(), m_schedulers.end(), std::mem_fun(&CParentScheduler::end));
  std::for_each(m_tasks.begin(), m_tasks.end(), CObjDeletor());
  std::for_each(m_schedulers.begin(), m_schedulers.end(), CObjDeletor());
  m_tasks.clear();
  m_schedulers.clear();
  before_finish();
  return 0;
}

CONST text * CContainer::name() CONST
{
  return "CContainer";
}

DVOID CContainer::print_all()
{
  ACE_DEBUG((LM_INFO, "  *** container: %s begin\n", name()));
  i_print();
  std::for_each(m_schedulers.begin(), m_schedulers.end(), std::mem_fun(&CParentScheduler::print_data));
  std::for_each(m_tasks.begin(), m_tasks.end(), std::mem_fun(&CTaskBase::print_all));
  ACE_DEBUG((LM_INFO, "  *** container: %s finish\n", name()));
}

DVOID CContainer::i_print()
{

}

DVOID CContainer::add_task(CTaskBase * _service)
{
  if (!_service)
  {
    C_FATAL("NULL param\n");
    return;
  }
  m_tasks.push_back(_service);
}

DVOID CContainer::add_scheduler(CParentScheduler * p)
{
  if (!p)
  {
    C_FATAL("NULL param\n");
    return;
  }
  m_schedulers.push_back(p);
}
