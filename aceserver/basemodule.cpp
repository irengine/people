#include "basemodule.h"
#include "baseapp.h"

MyClientIDTable * g_client_id_table = NULL;

//MyClientVerson//

MyClientVerson::MyClientVerson()
{
  init(0, 0);
}

MyClientVerson::MyClientVerson(u_int8_t major, u_int8_t minor)
{
  init(major, minor);
}

void MyClientVerson::init(u_int8_t major, u_int8_t minor)
{
  m_major = major;
  m_minor = minor;
  prepare_buff();
}

void MyClientVerson::prepare_buff()
{
  ACE_OS::snprintf(m_data, DATA_BUFF_SIZE, "%hhu.%hhu", m_major, m_minor);
}


bool MyClientVerson::from_string(const char * s)
{
  if (unlikely(!s || !*s))
    return false;
  int major, minor;
  sscanf(s, "%d.%d", &major, &minor);
  if (major > 255 || major < 0 || minor > 255 || minor < 0)
    return false;
  m_major = (u_int8_t)major;
  m_minor = (u_int8_t)minor;
  prepare_buff();
  return true;
}

const char * MyClientVerson::to_string() const
{
  return m_data;
}

bool MyClientVerson::operator < (const MyClientVerson & rhs)
{
  if (m_major < rhs.m_major)
    return true;
  else if (m_major > rhs.m_major)
    return false;
  else
    return (m_minor < rhs.m_minor);
}


//MyMfileSplitter//

MyMfileSplitter::MyMfileSplitter()
{

}

bool MyMfileSplitter::init(const char * mfile)
{
  if (!mfile || !*mfile)
    return true;
  m_mfile.init_from_string(mfile);
  m_path.init_from_string(mfile);
  char * ptr = ACE_OS::strrchr(m_path.data(), '.');
  if (unlikely(!ptr))
  {
    MY_ERROR("bad file name @MyMfileSplitter::init(%s)\n", mfile);
    return false;
  }
  else
    *ptr = 0;
  return true;
}

const char * MyMfileSplitter::path() const
{
  return m_path.data();
}

const char * MyMfileSplitter::mfile() const
{
  return m_mfile.data();
}

const char * MyMfileSplitter::translate(const char * src)
{
  if (!m_path.data())
    return src;

  if (unlikely(!src))
    return NULL;

  const char * ptr = ACE_OS::strchr(src, '/');
  if (unlikely(!ptr))
    return m_mfile.data();
  else
  {
    m_translated_name.init_from_string(m_path.data(), ptr);
    return m_translated_name.data();
  }
}


//MyClientInfo//

MyClientInfo::MyClientInfo()
{
  active = false;
  expired = false;
  switched = false;
  set_password(NULL);
}

MyClientInfo::MyClientInfo(const MyClientID & id, const char * _ftp_password, bool _expired): client_id(id)
{
  active = false;
  expired = _expired;
  switched = false;
  set_password(_ftp_password);
}

void MyClientInfo::set_password(const char * _ftp_password)
{
  if (!_ftp_password || !*_ftp_password)
  {
    ftp_password[0] = 0;
    password_len = 0;
    return;
  }

  ACE_OS::strsncpy(ftp_password, _ftp_password, FTP_PASSWORD_LEN);
  password_len  = ACE_OS::strlen(ftp_password);
}


//MyClientIDTable//

MyClientIDTable::MyClientIDTable()
{
  m_last_sequence = 0;
}

MyClientIDTable::~MyClientIDTable()
{
  m_table.clear();
  m_map.clear();
}

bool MyClientIDTable::contains(const MyClientID & id)
{
  return (index_of(id) >= 0);
}

void MyClientIDTable::add_i(const MyClientID & id, const char *ftp_password, bool expired)
{
  if (index_of_i(id) >= 0)
    return;
  MyClientInfo info(id, ftp_password, expired);
  m_table.push_back(info);
  m_map[id] = m_table.size() - 1;
}

void MyClientIDTable::add(const MyClientID &id)
{
  ACE_WRITE_GUARD(ACE_RW_Thread_Mutex, ace_mon, m_mutex);
  add_i(id, NULL, false);
}

void MyClientIDTable::add(const char * str_id, const char *ftp_password, bool expired)
{
  if (unlikely(!str_id || !*str_id))
    return;
  while (*str_id == ' ')
    str_id++;
  if (!*str_id)
    return;
  MyClientID id(str_id);
  id.trim_tail_space();
  ACE_WRITE_GUARD(ACE_RW_Thread_Mutex, ace_mon, m_mutex);
  add_i(id, ftp_password, expired);
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
    add_i(id, NULL, false);
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
  if (unlikely(it->second < 0 || it->second >= (int)m_table.size()))
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

bool MyClientIDTable::value(int index, MyClientID * id)
{
  if (unlikely(index < 0) || !id)
    return false;
  ACE_READ_GUARD_RETURN(ACE_RW_Thread_Mutex, ace_mon, m_mutex, false);
  if (unlikely(index >= (int)m_table.size() || index < 0))
    return false;
  *id = m_table[index].client_id;
  return true;
}

bool MyClientIDTable::value_all(int index, MyClientInfo & client_info)
{
  ACE_READ_GUARD_RETURN(ACE_RW_Thread_Mutex, ace_mon, m_mutex, false);
  if (unlikely(index >= (int)m_table.size() || index < 0))
    return false;
  client_info = m_table[index];
  return true;
}

bool MyClientIDTable::active(const MyClientID & id, int & index, bool & switched)
{
  ACE_READ_GUARD_RETURN(ACE_RW_Thread_Mutex, ace_mon, m_mutex, false);
  if (index < 0 || index >= (int)m_table.size())
    index = index_of_i(id);
  if (unlikely(index < 0))
    return false;
  switched = m_table[index].switched;
  return m_table[index].active;
}

//void MyClientIDTable::active(const MyClientID & id, bool _active)
//{
//  ACE_WRITE_GUARD(ACE_RW_Thread_Mutex, ace_mon, m_mutex);
//  int idx = index_of_i(id);
//  if (unlikely(idx < 0))
//    return;
//  m_table[idx].active = _active;
//}

bool MyClientIDTable::active(int index)
{
  ACE_READ_GUARD_RETURN(ACE_RW_Thread_Mutex, ace_mon, m_mutex, false);
  if (unlikely(index < 0 || index > (int)m_table.size()))
    return false;
  return m_table[index].active;
}

void MyClientIDTable::active(int index, bool _active)
{
  ACE_WRITE_GUARD(ACE_RW_Thread_Mutex, ace_mon, m_mutex);
  if (unlikely(index < 0 || index > (int)m_table.size()))
    return;
  m_table[index].active = _active;
}

void MyClientIDTable::switched(int index, bool _switched)
{
  ACE_WRITE_GUARD(ACE_RW_Thread_Mutex, ace_mon, m_mutex);
  if (unlikely(index < 0 || index > (int)m_table.size()))
    return;
  m_table[index].switched = _switched;
}

void MyClientIDTable::expired(int index, bool _expired)
{
  ACE_WRITE_GUARD(ACE_RW_Thread_Mutex, ace_mon, m_mutex);
  if (unlikely(index < 0 || index > (int)m_table.size()))
    return;
  m_table[index].expired = _expired;
}

bool MyClientIDTable::mark_valid(const MyClientID & id, bool valid, int & index)
{
  ACE_READ_GUARD_RETURN(ACE_RW_Thread_Mutex, ace_mon, m_mutex, true);
  index = index_of_i(id);
  bool i_valid = (index >= 0 && !m_table[index].expired);
  if (likely(i_valid == valid))
    return true;
  if (valid)
  {
    if (index < 0)
      add_i(id, id.as_string(), false);
    else
      m_table[index].expired = false;
  } else //!valid
    m_table[index].expired = true;
  return false;
}

int MyClientIDTable::last_sequence() const
{
  return m_last_sequence;
}

void MyClientIDTable::last_sequence(int _seq)
{
  m_last_sequence = _seq;
}

void MyClientIDTable::prepare_space(int _count)
{
  m_table.reserve(std::max(int((m_table.size() + _count) * 1.4), 1000));
}


//MyFileMD5//

MyFileMD5::MyFileMD5(const char * _filename, const char * md5, int prefix_len, const char * alias)
{
  m_md5[0] = 0;
  m_size = 0;
  if (unlikely(!_filename || ! *_filename))
    return;

  int len = strlen(_filename);
  if (unlikely(len <= prefix_len))
  {
    MY_FATAL("invalid parameter in MyFileMD5::MyFileMD5(%s, %d)\n", _filename, prefix_len);
    return;
  }
  if (!alias || !*alias)
  {
    m_size = len - prefix_len + 1;
    m_file_name.init_from_string(_filename + prefix_len);
  } else
  {
    m_size = ACE_OS::strlen(alias) + 1;
    m_file_name.init_from_string(alias);
  }

  if (!md5)
  {
    MD5_CTX mdContext;
    md5file(_filename, 0, &mdContext, m_md5, MD5_STRING_LENGTH);
//    if (!md5file(_filename, 0, &mdContext, m_md5, MD5_STRING_LENGTH))
//      MY_ERROR("failed to calculate md5 value of file %s\n", _filename);
  } else
    memcpy((void*)m_md5, (void*)md5, MD5_STRING_LENGTH);
}


//MyFileMD5s//

MyFileMD5s::MyFileMD5s()
{
  m_base_dir_len = 0;
}

MyFileMD5s::~MyFileMD5s()
{
  std::for_each(m_file_md5_list.begin(), m_file_md5_list.end(), MyPooledObjectDeletor());
}

bool MyFileMD5s::base_dir(const char * dir)
{
  if (unlikely(!dir || !*dir))
  {
    MY_FATAL("MyFileMD5s::base_dir(empty dir)\n");
    return false;
  }

  m_base_dir_len = strlen(dir) + 1;
  m_base_dir.init_from_string(dir);
  return true;
}

void MyFileMD5s::minus(MyFileMD5s & target, MyMfileSplitter * spl, bool do_delete)
{
  MyFileMD5List::iterator it1 = m_file_md5_list.begin(), it2 = target.m_file_md5_list.begin(), it;
  //the below algorithm is based on STL's set_difference() function
  char fn[PATH_MAX];
  while (it1 != m_file_md5_list.end() && it2 != target.m_file_md5_list.end())
  {
    const char * new_name = spl? spl->translate((**it1).filename()): (**it1).filename();
    MyFileMD5 md5_copy(new_name, (**it1).md5(), 0);

    if (md5_copy < **it2)
      ++it1;
    else if (**it2 < md5_copy)
    {
      if (do_delete)
      {
        ACE_OS::snprintf(fn, PATH_MAX - 1, "%s/%s", target.m_base_dir.data(), (**it2).filename());
        //MY_INFO("deleting file %s\n", fn);
        remove(fn);
      }
      ++it2;
    }
    else if (md5_copy.same_md5(**it2))//==
    {
      MyPooledObjectDeletor dlt;
      dlt(*it1);
      it1 = m_file_md5_list.erase(it1);
      ++it2;
    } else
    {
      ++it1;
      ++it2;
    }
  }

  if (do_delete)
  {
    while (it2 != target.m_file_md5_list.end())
    {
      ACE_OS::snprintf(fn, PATH_MAX - 1, "%s/%s", target.m_base_dir.data(), (**it2).filename());
      //MY_INFO("deleting file %s\n", fn);
      remove(fn);
      ++it2;
    }
  }
}

void MyFileMD5s::sort()
{
  std::sort(m_file_md5_list.begin(), m_file_md5_list.end(), MyPointerLess());
}

bool MyFileMD5s::add_file(const char * filename, const char * md5, int prefix_len)
{
  if (unlikely(!filename || !*filename || prefix_len < 0))
    return false;

  void * p = MyMemPoolFactoryX::instance()->get_mem_x(sizeof(MyFileMD5));
  MyFileMD5 * fm = new (p) MyFileMD5(filename, md5, prefix_len);
  if (fm->ok())
  {
    m_file_md5_list.push_back(fm);
    return true;
  }
  else
  {
    MyPooledObjectDeletor dlt;
    dlt(fm);
    return false;
  }
}

bool MyFileMD5s::add_file(const char * pathname, const char * filename, int prefix_len, const char * alias)
{
  if (unlikely(!pathname || !filename))
    return false;
  int len = ACE_OS::strlen(pathname);
  if (unlikely(len + 1 < prefix_len || len  + strlen(filename) + 2 > PATH_MAX))
  {
    MY_FATAL("invalid parameter @ MyFileMD5s::add_file(%s, %s, %d)\n", pathname, filename, prefix_len);
    return false;
  }
  MyFileMD5 * fm;
  char buff[PATH_MAX];
  ACE_OS::snprintf(buff, PATH_MAX, "%s/%s", pathname, filename);
  void * p = MyMemPoolFactoryX::instance()->get_mem_x(sizeof(MyFileMD5));
  fm = new(p) MyFileMD5(buff, NULL, prefix_len, alias);

  bool ret = fm->ok();
  if (likely(ret))
    m_file_md5_list.push_back(fm);
  else
    delete fm;
  return ret;
}

int MyFileMD5s::total_size(bool include_md5_value)
{
  int result = 0;
  MyFileMD5List::iterator it;
  for (it = m_file_md5_list.begin(); it != m_file_md5_list.end(); ++it)
  {
    MyFileMD5 & fm = **it;
    if (unlikely(!fm.ok()))
      continue;
    result += fm.size(include_md5_value);
  }
  return result + 1;
}

bool MyFileMD5s::to_buffer(char * buff, int buff_len, bool include_md5_value)
{
  MyFileMD5List::iterator it;
  if (unlikely(!buff || buff_len <= 0))
  {
    MY_ERROR("invalid parameter MyFileMD5s::to_buffer(%s, %d)\n", buff, buff_len);
    return false;
  }
  int len = 0;
  for (it = m_file_md5_list.begin(); it != m_file_md5_list.end(); ++it)
  {
    MyFileMD5 & fm = **it;
    if (unlikely(!fm.ok()))
      continue;
    if (unlikely(buff_len <= len + fm.size(include_md5_value)))
    {
      MY_ERROR("buffer is too small @MyFileMD5s::to_buffer(buff_len=%d, need_length=%d)\n",
          buff_len, len + fm.size(include_md5_value) + 1);
      return false;
    }
    int fm_file_length = fm.size(false);
    ACE_OS::memcpy(buff + len, fm.filename(), fm_file_length);
    buff[len + fm_file_length - 1] = include_md5_value? MyDataPacketHeader::MIDDLE_SEPARATOR: MyDataPacketHeader::ITEM_SEPARATOR;
    len += fm_file_length;
    if (include_md5_value)
    {
      ACE_OS::memcpy(buff + len, fm.md5(), MyFileMD5::MD5_STRING_LENGTH);
      len += MyFileMD5::MD5_STRING_LENGTH;
      buff[len++] = MyDataPacketHeader::ITEM_SEPARATOR;
    }
  }
  buff[len] = 0;
  return true;
}

bool MyFileMD5s::from_buffer(char * buff, MyMfileSplitter * spl)
{
  if (!buff || !*buff)
    return true;

  char seperator[2] = {MyDataPacketHeader::ITEM_SEPARATOR, 0};
  char *str, *token, *saveptr, *md5;

//  ACE_WRITE_GUARD(ACE_RW_Thread_Mutex, ace_mon, m_mutex);
  for (str = buff; ; str = NULL)
  {
    token = strtok_r(str, seperator, &saveptr);
    if (token == NULL)
      break;
    if (unlikely(!*token))
      continue;
    md5 = ACE_OS::strchr(token, MyDataPacketHeader::MIDDLE_SEPARATOR);
    if (unlikely(md5 == token || !md5))
    {
      MY_ERROR("bad file/md5 list item @MyFileMD5s::from_buffer: %s\n", token);
      return false;
    }
    *md5++ = 0;
    if (unlikely(ACE_OS::strlen(md5) != MyFileMD5::MD5_STRING_LENGTH))
    {
      MY_ERROR("empty md5 in file/md5 list @MyFileMD5s::from_buffer: %s\n", token);
      return false;
    }
    void * p = MyMemPoolFactoryX::instance()->get_mem_x(sizeof(MyFileMD5));
    const char * filename = spl? spl->translate(token): token;
    MyFileMD5 * fm = new(p) MyFileMD5(filename, md5, 0);
    m_file_md5_list.push_back(fm);
  }

  return true;
}

bool MyFileMD5s::calculate(const char * dirname, const char * mfile, bool single)
{
  if (unlikely(!dirname || !*dirname))
    return false;
  base_dir(dirname);

  if (mfile && *mfile)
  {
    MyPooledMemGuard mfile_name;
    int n = MyFilePaths::cat_path(dirname, mfile, mfile_name);
    if (unlikely(!add_file(mfile_name.data(), NULL, n)))
      return true;
    if (single)
      return true;
    if (unlikely(!MyFilePaths::get_correlate_path(mfile_name, n)))
      return false;
    return do_scan_directory(mfile_name.data(), n);
  } else
  {
    if (single)
    {
      MY_ERROR("unsupported operation @MyFileMD5s::calculate\n");
      return false;
    }
    return do_scan_directory(dirname, ACE_OS::strlen(dirname) + 1);
  }
}

bool MyFileMD5s::do_scan_directory(const char * dirname, int start_len)
{
  DIR * dir = opendir(dirname);
  if (!dir)
  {
    if (ACE_OS::last_error() != ENOENT)
    {
      MY_ERROR("can not open directory: %s %s\n", dirname, (const char*)MyErrno());
      return false;
    } else
      return true;
  }

  struct dirent *entry;
  char buff[PATH_MAX];
  while ((entry = readdir(dir)) != NULL)
  {
    if (!entry->d_name)
      continue;
    if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
      continue;

    if (entry->d_type == DT_REG)
    {
      if (!add_file(dirname, entry->d_name, start_len, NULL))
      {
        closedir(dir);
        return false;
      }
    }
    else if(entry->d_type == DT_DIR)
    {
      ACE_OS::snprintf(buff, PATH_MAX - 1, "%s/%s", dirname, entry->d_name);
      if (!do_scan_directory(buff, start_len))
      {
        closedir(dir);
        return false;
      }
    } else
      MY_WARNING("unknown file type (= %d) for file @MyFileMD5s::do_scan_directory file = %s/%s\n",
           entry->d_type, dirname, entry->d_name);
  };

  closedir(dir);
  return true;
}


//MyBaseArchiveReader//

MyBaseArchiveReader::MyBaseArchiveReader()
{
  m_file_length = 0;
}

bool MyBaseArchiveReader::open(const char * filename)
{
  if (unlikely(!filename || !*filename))
  {
    MY_ERROR("empty file name @MyBaseArchiveReader::open()\n");
    return false;
  }

  if (!m_file.open_read(filename))
    return false;

  struct stat sbuf;
  if (::fstat(m_file.handle(), &sbuf) == -1)
  {
    MY_ERROR("can not get file info @MyBaseArchiveReader::open(), name = %s %s\n", filename, (const char*)MyErrno());
    return false;
  }
  m_file_length = sbuf.st_size;
  return true;
}

int MyBaseArchiveReader::read(char * buff, int buff_len)
{
  return do_read(buff, buff_len);
}

int MyBaseArchiveReader::do_read(char * buff, int buff_len)
{
  int n = ::read(m_file.handle(), buff, buff_len);
  if (unlikely(n < 0))
    MY_ERROR("read file %s %s\n", m_file_name.data(), (const char*)MyErrno());
  return n;
}

void MyBaseArchiveReader::close()
{
  m_file.attach(MyUnixHandleGuard::INVALID_HANDLE);
  m_file_name.free();
}


//MyWrappedArchiveReader//

bool MyWrappedArchiveReader::open(const char * filename)
{
  if (!super::open(filename))
    return false;
  return read_header();
}

int MyWrappedArchiveReader::read(char * buff, int buff_len)
{
  int n = std::min(buff_len, m_remain_length);
  if (n <= 0)
    return 0;
  int n2 = do_read(buff, n);
  m_remain_length -= n2;

  if (m_remain_encrypted_length > 0)
  {
    int buff_remain_len = buff_len;
    u_int8_t output[16];
    char * ptr = buff;
    while (m_remain_encrypted_length > 0 && buff_remain_len >= 16)
    {
      aes_decrypt(&m_aes_context, (u_int8_t*)ptr, output);
      memcpy(ptr, output, 16);
      buff_remain_len -= 16;
      m_remain_encrypted_length -= 16;
      ptr += 16;
    }
    if (m_remain_encrypted_length < 0)
      n2 += m_remain_encrypted_length;
  }

  return n2;
}

const char * MyWrappedArchiveReader::file_name() const
{
  return ((MyWrappedHeader*)m_wrapped_header.data())->file_name;
}


bool MyWrappedArchiveReader::read_header()
{
  MyWrappedHeader header;
  if (do_read((char*)&header, sizeof(header)) != sizeof(header))
    return false;
  if (header.magic != MyWrappedHeader::HEADER_MAGIC)
  {
    MY_ERROR("corrupted compressed file %s\n", m_file_name.data());
    return false;
  }

  int name_length = header.header_length - sizeof(header);
  if (name_length <= 1 || name_length > PATH_MAX)
  {
    MY_ERROR("invalid compressed header file name length: %s\n", m_file_name.data());
    return false;
  }

  if (header.encrypted_data_length < 0 || header.encrypted_data_length > header.data_length)
  {
    MY_ERROR("invalid encrypted data length value\n");
    return false;
  }

  MyMemPoolFactoryX::instance()->get_mem(header.header_length, &m_wrapped_header);
  ACE_OS::memcpy((void*)m_wrapped_header.data(), &header, sizeof(header));
  char * name_ptr = m_wrapped_header.data() + sizeof(header);
  if (!do_read(name_ptr, name_length))
    return false;
  name_ptr[name_length - 1] = 0;

  m_remain_length = header.data_length;
  m_remain_encrypted_length = header.encrypted_data_length;
  return true;
};

bool MyWrappedArchiveReader::next()
{
  return read_header();
}

bool MyWrappedArchiveReader::eof() const
{
  return (m_file_length <= (int)::lseek(m_file.handle(), 0, SEEK_CUR));
}

void MyWrappedArchiveReader::set_key(const char * skey)
{
  u_int8_t aes_key[32];
  memset((void*)aes_key, 0, sizeof(aes_key));
  if (skey)
    ACE_OS::strsncpy((char*)aes_key, skey, sizeof(aes_key));
  aes_set_key(&m_aes_context, aes_key, 256);
}


//MyBaseArchiveWriter//

bool MyBaseArchiveWriter::open(const char * filename)
{
  if (unlikely(!filename || !*filename))
  {
    MY_ERROR("empty file name @MyBaseArchiveWriter::open()\n");
    return false;
  }
  m_file_name.init_from_string(filename);
  return do_open();
}

bool MyBaseArchiveWriter::open(const char * dir, const char * filename)
{
  if (unlikely(!filename || !*filename || !filename || !*filename))
  {
    MY_ERROR("empty dir/file name @MyBaseArchiveWriter::open(,)\n");
    return false;
  }
  m_file_name.init_from_string(dir, filename);
  return do_open();
}

bool MyBaseArchiveWriter::do_open()
{
  return m_file.open_write(m_file_name.data(), true, true, false, false);
}

bool MyBaseArchiveWriter::write(char * buff, int buff_len)
{
  return do_write(buff, buff_len);
}

bool MyBaseArchiveWriter::do_write(char * buff, int buff_len)
{
  if (unlikely(!buff || buff_len <= 0))
    return true;

  int n = ::write(m_file.handle(), buff, buff_len);
  if (unlikely(n != buff_len))
  {
    MY_ERROR("write file %s %s\n", m_file_name.data(), (const char*)MyErrno());
    return false;
  }
  return true;
}

void MyBaseArchiveWriter::close()
{
  m_file.attach(MyUnixHandleGuard::INVALID_HANDLE);
  m_file_name.free();
}


//MyWrappedArchiveWriter//

bool MyWrappedArchiveWriter::write(char * buff, int buff_len)
{
  if (unlikely(buff_len < 0))
    return false;
  if (unlikely(buff_len == 0))
    return true;

  m_data_length += buff_len;

  if (m_remain_encrypted_length > 0)
  {
    int to_buffer_len = std::min(buff_len, m_remain_encrypted_length);
    ACE_OS::memcpy(m_encrypt_buffer.data(), buff, to_buffer_len);
    m_remain_encrypted_length -= to_buffer_len;
    if (m_remain_encrypted_length > 0)
      return true;
    else if (!encrypt_and_write())
      return false;

    if (buff_len - to_buffer_len > 0)
      return do_write(buff + to_buffer_len, buff_len - to_buffer_len);
    else
      return true;
  }

  return do_write(buff, buff_len);
}

bool MyWrappedArchiveWriter::start(const char * filename, int prefix_len)
{
  if (unlikely(prefix_len < 0 || prefix_len >= (int)ACE_OS::strlen(filename)))
  {
    MY_ERROR("invalid prefix_len @MyWrappedArchiveWriter::start(%s, %d)\n", filename, prefix_len);
    return false;
  }
  if (unlikely(filename[prefix_len] != '/' || filename[prefix_len + 1] == '/'))
  {
    MY_ERROR("bad prefix_len split @MyWrappedArchiveWriter::start(%s, %d)\n", filename, prefix_len);
    return false;
  }

  m_data_length = 0;
  m_encrypted_length = 0;
  m_remain_encrypted_length = ENCRYPT_DATA_LENGTH;
  MyMemPoolFactoryX::instance()->get_mem(ENCRYPT_DATA_LENGTH, &m_encrypt_buffer);
  return write_header(filename + prefix_len + 1);
}

bool MyWrappedArchiveWriter::finish()
{
  if (m_remain_encrypted_length > 0)
  {
    if (!encrypt_and_write())
      return false;
  }

  m_wrapped_header.data_length = m_data_length;

  if (::lseek(m_file.handle(), 0, SEEK_SET) == -1)
  {
    MY_ERROR("fseek on file %s failed %s\n", m_file_name.data(), (const char*)MyErrno());
    return false;
  }

  return do_write((char*)&m_wrapped_header, sizeof(m_wrapped_header));
}

void MyWrappedArchiveWriter::set_key(const char * skey)
{
  u_int8_t aes_key[32];
  memset((void*)aes_key, 0, sizeof(aes_key));
  if (skey)
    ACE_OS::strsncpy((char*)aes_key, skey, sizeof(aes_key));
  aes_set_key(&m_aes_context, aes_key, 256);
}

bool MyWrappedArchiveWriter::write_header(const char * filename)
{
  if (unlikely(!filename || !*filename))
    return false;
  int filename_len = ACE_OS::strlen(filename) + 1;
  m_wrapped_header.magic = MyWrappedHeader::HEADER_MAGIC;
  m_wrapped_header.header_length = sizeof(m_wrapped_header) + filename_len;
  m_wrapped_header.data_length = -1;
  m_wrapped_header.encrypted_data_length = -1;
  if (!do_write((char*)&m_wrapped_header, sizeof(m_wrapped_header)))
    return false;
  if (!do_write((char*)filename, filename_len))
    return false;
  return true;
}

bool MyWrappedArchiveWriter::encrypt_and_write()
{
  int bytes = ENCRYPT_DATA_LENGTH - m_remain_encrypted_length;
  m_wrapped_header.encrypted_data_length = bytes;
  if (bytes == 0)
    return true;

  int stuff_bytes = (16 - bytes % 16) % 16;
  if (stuff_bytes > 0)
  {
    m_data_length += stuff_bytes;
    memset(m_encrypt_buffer.data() + bytes, 0, stuff_bytes);
  }
  bytes += stuff_bytes;
  u_int8_t output[16];
  char * ptr = m_encrypt_buffer.data();
  int count = bytes;
  while (count >= 16)
  {
    aes_encrypt(&m_aes_context, (u_int8_t*)ptr, output);
    memcpy(ptr, output, 16);
    ptr += 16;
    count -= 16;
  }
  return do_write(m_encrypt_buffer.data(), bytes);
}


void * MyBZMemPoolAdaptor::my_alloc(void *, int n, int m)
{
  return MyMemPoolFactoryX::instance()->get_mem_x(n * m);
}

void MyBZMemPoolAdaptor::my_free(void *, void * ptr)
{
  MyMemPoolFactoryX::instance()->free_mem_x(ptr);
}


//MyBZCompressor//

MyBZCompressor::MyBZCompressor()
{
  m_bz_stream.bzalloc = MyBZMemPoolAdaptor::my_alloc;
  m_bz_stream.bzfree = MyBZMemPoolAdaptor::my_free;
  m_bz_stream.opaque = 0;
}

bool MyBZCompressor::prepare_buffers()
{
  return (m_buff_in.data() || MyMemPoolFactoryX::instance()->get_mem(BUFFER_LEN, &m_buff_in)) &&
         (m_buff_out.data() || MyMemPoolFactoryX::instance()->get_mem(BUFFER_LEN, &m_buff_out));
}

bool MyBZCompressor::do_compress(MyBaseArchiveReader * _reader, MyBaseArchiveWriter * _writer)
{
  int ret, n, n2;

  while (true)
  {
    n = _reader->read(m_buff_in.data(), BUFFER_LEN);
    if (n < 0)
      return false;
    else if (n == 0)
      break;

    m_bz_stream.avail_in = n;
    m_bz_stream.next_in = m_buff_in.data();
    while (true)
    {
      m_bz_stream.avail_out = BUFFER_LEN;
      m_bz_stream.next_out = m_buff_out.data();
      ret = BZ2_bzCompress(&m_bz_stream, BZ_RUN);
      if (ret != BZ_RUN_OK)
      {
        MY_ERROR("BZ2_bzCompress(BZ_RUN) returns %d\n", ret);
        return false;
      };

      if (m_bz_stream.avail_out < BUFFER_LEN)
      {
        n2 = BUFFER_LEN - m_bz_stream.avail_out;
        if (!_writer->write(m_buff_out.data(), n2))
         return false;
      }

     if (m_bz_stream.avail_in == 0)
       break;
   }

   if (n < BUFFER_LEN)
    break;
  }

  while (true)
  {
    m_bz_stream.avail_out = BUFFER_LEN;
    m_bz_stream.next_out = m_buff_out.data();
    ret = BZ2_bzCompress(&m_bz_stream, BZ_FINISH);
    if (ret != BZ_FINISH_OK && ret != BZ_STREAM_END)
    {
      MY_ERROR("BZ2_bzCompress(BZ_FINISH) returns %d\n", ret);
      return false;
    };

    if (m_bz_stream.avail_out < BUFFER_LEN)
    {
      n2 = BUFFER_LEN - m_bz_stream.avail_out;
      if (!_writer->write(m_buff_out.data(), n2))
        return false;
    }

    if (ret == BZ_STREAM_END)
      return true;
  }

  ACE_NOTREACHED(return true);
}

bool MyBZCompressor::compress(const char * srcfn, int prefix_len, const char * destfn, const char * key)
{
  MyBaseArchiveReader reader;
  if (!reader.open(srcfn))
    return false;
  MyWrappedArchiveWriter writer;
  if (!writer.open(destfn))
    return false;
  writer.set_key(key);
  if (!writer.start(srcfn + prefix_len))
    return false;
//  MY_DEBUG("MyBZCompressor::compress, srcfn=%s, destfn=%d, save_as=%s\n", srcfn, destfn, srcfn + prefix_len);
  prepare_buffers();
  int ret = BZ2_bzCompressInit(&m_bz_stream, COMPRESS_100k, 0, 30);
  if (ret != BZ_OK)
  {
    MY_ERROR("BZ2_bzCompressInit() return value = %d\n", ret);
    return false;
  }

  bool result = do_compress(&reader, &writer);
  if (!result)
    MY_ERROR("failed to compress file: %s to %s\n", srcfn, destfn);
  BZ2_bzCompressEnd(&m_bz_stream);

  if (!writer.finish())
    return false;
  return result;
}

bool MyBZCompressor::do_decompress(MyBaseArchiveReader * _reader, MyBaseArchiveWriter * _writer)
{
  int n, n2, ret;

  m_bz_stream.avail_out = BUFFER_LEN;
  m_bz_stream.next_out = m_buff_out.data();
  m_bz_stream.avail_in = 0;

  while (true)
  {
    if (m_bz_stream.avail_in == 0)
    {
       n = _reader->read(m_buff_in.data(), BUFFER_LEN);
       if (n < 0)
         return false;
       else if (n == 0)
       {
         MY_ERROR("error: unexpected eof\n");
         return false;
       }
       m_bz_stream.avail_in = n;
       m_bz_stream.next_in = m_buff_in.data();
    }

    ret = BZ2_bzDecompress(&m_bz_stream);

    if (ret != BZ_OK && ret != BZ_STREAM_END)
    {
      MY_ERROR("BZ2_bzDecompress() returns %d\n", ret);
      return false;
    };

    if (m_bz_stream.avail_out < BUFFER_LEN)
    {
      n2 = BUFFER_LEN - m_bz_stream.avail_out;
      if (!_writer->write(m_buff_out.data(), n2))
        return false;
      m_bz_stream.avail_out = BUFFER_LEN;
      m_bz_stream.next_out = m_buff_out.data();
    }

    if (ret == BZ_STREAM_END)
      return true;
  }

  ACE_NOTREACHED(return true);
}

bool MyBZCompressor::decompress(const char * srcfn, const char * destdir, const char * key, const char * _rename)
{
  MyWrappedArchiveReader reader;
  if (!reader.open(srcfn))
    return false;
  MyBaseArchiveWriter writer;
  prepare_buffers();
  reader.set_key(key);

  MyMfileSplitter spl;
  if (!spl.init(_rename))
    return false;

  int ret;
  while (true)
  {
    const char * _file_name = spl.translate(reader.file_name());
    if (unlikely(!_file_name))
      return false;

    if (!MyFilePaths::make_path(destdir, _file_name, true, true))
    {
      MY_ERROR("can not mkdir %s/%s %s\n", destdir, _file_name, (const char*)MyErrno());
      return false;
    }
    MyPooledMemGuard dest_file_name;
    dest_file_name.init_from_string(destdir, "/", _file_name);

    if (!writer.open(dest_file_name.data()))
      return false;

    ret = BZ2_bzDecompressInit(&m_bz_stream, 0, 0);
    if (ret != BZ_OK)
    {
      MY_ERROR("BZ2_bzCompressInit() return value = %d\n", ret);
      return false;
    }

    bool result = do_decompress(&reader, &writer);
    BZ2_bzDecompressEnd(&m_bz_stream);
    if (!result)
    {
      MY_ERROR("failed to decompress file: %s to %s\n", srcfn, destdir);
      return false;
    }
    if (reader.eof())
      return true;
    if (!reader.next())
      return false;
    writer.close();
  };

  ACE_NOTREACHED(return true);
}


//MyBZCompositor//

bool MyBZCompositor::open(const char * filename)
{
  return m_file.open_write(filename, true, true, true, false);
}

void MyBZCompositor::close()
{
  m_file.attach(MyUnixHandleGuard::INVALID_HANDLE);
}

bool MyBZCompositor::add(const char * filename)
{
  if (!m_file.valid())
    return true;
  MyUnixHandleGuard src;
  if (!src.open_read(filename))
    return false;
  bool result = MyFilePaths::copy_file_by_fd(src.handle(), m_file.handle());
  if (!result)
    MY_ERROR("MyBZCompositor::add(%s) failed\n", filename);
  return result;
}

bool MyBZCompositor::add_multi(char * filenames, const char * path, const char separator, const char * ext)
{
  char _seperators[2];
  _seperators[0] = separator;
  _seperators[1] = 0;
  char *str, *token, *saveptr;

  for (str = filenames; ; str = NULL)
  {
    token = strtok_r(str, _seperators, &saveptr);
    if (!token)
      break;
    if (!*token)
      continue;
    if ((!path || !*path) && (!ext || !*ext))
    {
      if (!add(token))
        return false;
    } else
    {
      MyPooledMemGuard fn;
      fn.init_from_string(path, "/", token, ext);
      if (!add(fn.data()))
        return false;
    }
  }

  return true;
}



//MyBaseProcessor//

MyBaseProcessor::MyBaseProcessor(MyBaseHandler * handler)
{
  m_handler = handler;
  m_wait_for_close = false;
  m_last_activity = g_clock_tick;
  m_client_id_index = -1;
  m_client_id_length = 0;
}

MyBaseProcessor::~MyBaseProcessor()
{

}

void MyBaseProcessor::info_string(MyPooledMemGuard & info) const
{
  ACE_UNUSED_ARG(info);
}

int MyBaseProcessor::on_open()
{
  return 0;
}

void MyBaseProcessor::on_close()
{

}

bool MyBaseProcessor::wait_for_close() const
{
  return m_wait_for_close;
}

void MyBaseProcessor::prepare_to_close()
{
  m_wait_for_close = true;
}

int MyBaseProcessor::handle_input()
{
  return 0;
}

bool MyBaseProcessor::can_send_data(ACE_Message_Block * mb) const
{
  ACE_UNUSED_ARG(mb);
  return true;
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

const MyClientID & MyBaseProcessor::client_id() const
{
  return m_client_id;
}

void MyBaseProcessor::client_id(const char *id)
{
  m_client_id = id;
}

bool MyBaseProcessor::client_id_verified() const
{
  return false;
}

int32_t MyBaseProcessor::client_id_index() const
{
  return m_client_id_index;
}


//MyBaseRemoteAccessProcessor//

MyBaseRemoteAccessProcessor::MyBaseRemoteAccessProcessor(MyBaseHandler * handler):
    MyBaseProcessor(handler)
{
  m_mb = NULL;
}

MyBaseRemoteAccessProcessor::~MyBaseRemoteAccessProcessor()
{
  if (m_mb)
    m_mb->release();
}

int MyBaseRemoteAccessProcessor::handle_input()
{
  if (m_mb == NULL)
    m_mb = MyMemPoolFactoryX::instance()->get_message_block(MAX_COMMAND_LINE_LENGTH);
  if (mycomutil_recv_message_block(m_handler, m_mb) < 0)
    return -1;
  int i, len = m_mb->length();
  char * ptr = m_mb->base();
  m_handler->connection_manager()->on_data_received(len);
  for (i = 0; i < len; ++ i)
    if (ptr[i] == '\r' || ptr[i] == '\n')
      break;
  if (i >= len)
  {
    if (len == MAX_COMMAND_LINE_LENGTH)
    {
      char buff[100];
      ACE_OS::snprintf(buff, 100 - 1, "Error: command line too long, max line length = %d\n", MAX_COMMAND_LINE_LENGTH);
      send_string(buff);
      return 0;
    }
    return 0;
  }

  char last_cr_lf = ptr[i];

  ptr[i] = 0;
  if (process_command_line(m_mb->base()) < 0)
    return -1;

  ++i;
  while (i < len && (ptr[i] == '\r' || ptr[i] == '\n') && (ptr[i] != last_cr_lf))
    ++i;
  if (i < len)
    ACE_OS::memmove(ptr, ptr + i, len - i);
  m_mb->wr_ptr(m_mb->base() + len - i);
  m_mb->rd_ptr(m_mb->base());
  return 0;
}

int MyBaseRemoteAccessProcessor::on_open()
{
  return say_hello();
}

int MyBaseRemoteAccessProcessor::send_string(const char * s)
{
  if (!s || !*s)
    return 0;
  int len = ACE_OS::strlen(s);
  ACE_Message_Block * mb = MyMemPoolFactoryX::instance()->get_message_block(len + 1);
  ACE_OS::memcpy(mb->base(), s, len + 1);
  mb->wr_ptr(mb->capacity());
  return (m_handler->send_data(mb) < 0 ? -1:0);
}

int MyBaseRemoteAccessProcessor::process_command_line(char * cmd)
{
  if (!cmd || !*cmd)
    return send_string(">");

  char * ptr_start = cmd, * ptr_end;
  while (*ptr_start == ' ' || *ptr_start == '\t')
    ++ptr_start;
  ptr_end = ptr_start;
  while (*ptr_end && *ptr_end != ' ' && *ptr_end != '\t')
    ++ptr_end;
  if (*ptr_end)
    *ptr_end++ = 0;
  return do_command(ptr_start, ptr_end);
}

int MyBaseRemoteAccessProcessor::do_command(const char * cmd, char * parameter)
{
  if (!ACE_OS::strcmp(cmd, "help"))
    return on_command_help();
  if (!ACE_OS::strcmp(cmd, "quit") || !ACE_OS::strcmp(cmd, "exit"))
    return on_command_quit();
  return on_command(cmd, parameter);
}

int MyBaseRemoteAccessProcessor::on_command(const char * cmd, char * parameter)
{
  ACE_UNUSED_ARG(cmd);
  ACE_UNUSED_ARG(parameter);
  return 0;
}

int MyBaseRemoteAccessProcessor::on_unsupported_command(const char * cmd)
{
  char buff[4096];
  ACE_OS::snprintf(buff, 4096 - 1, "Error: unknown command '%s', to see a list of supported commands, type 'help'\n>", cmd);
  return send_string(buff);
}

int MyBaseRemoteAccessProcessor::on_command_help()
{
  return 0;
}

int MyBaseRemoteAccessProcessor::on_command_quit()
{
  send_string("Bye!\n");
  return -1;
}

int MyBaseRemoteAccessProcessor::say_hello()
{
  return send_string("Welcome\n>");
}



//MyBasePacketProcessor//

MyBasePacketProcessor::MyBasePacketProcessor(MyBaseHandler * handler): super(handler)
{
  m_peer_addr[0] = 0;
}


void MyBasePacketProcessor::info_string(MyPooledMemGuard & info) const
{
  const char * str_id = m_client_id.as_string();
  if (!*str_id)
    str_id = "NULL";
  const char * ss[5];
  ss[0] = "(remote addr=";
  ss[1] = m_peer_addr;
  ss[2] = ", client_id=";
  ss[3] = m_client_id.as_string();
  ss[4] = ")";
  info.init_from_strings(ss, 5);
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

int MyBasePacketProcessor::packet_length()
{
  return m_packet_header.length;
}


MyBaseProcessor::EVENT_RESULT MyBasePacketProcessor::on_recv_header()
{
  return ER_CONTINUE;
}

MyBaseProcessor::EVENT_RESULT MyBasePacketProcessor::on_recv_packet_i(ACE_Message_Block * mb)
{
  MyDataPacketHeader * header = (MyDataPacketHeader *)mb->base();
  header->magic = m_client_id_index;
  return ER_OK;
}

ACE_Message_Block * MyBasePacketProcessor::make_version_check_request_mb()
{
  ACE_Message_Block * mb = MyMemPoolFactoryX::instance()->get_message_block_cmd_direct(sizeof(MyClientVersionCheckRequest), MyDataPacketHeader::CMD_CLIENT_VERSION_CHECK_REQ);
  return mb;
}


//MyBSBasePacketProcessor//

MyBSBasePacketProcessor::MyBSBasePacketProcessor(MyBaseHandler * handler): super(handler)
{

}

MyBaseProcessor::EVENT_RESULT MyBSBasePacketProcessor::on_recv_header()
{
  return (m_packet_header.check_header()? ER_OK : ER_ERROR);
}

MyBaseProcessor::EVENT_RESULT MyBSBasePacketProcessor::on_recv_packet_i(ACE_Message_Block * mb)
{
  MyBSBasePacket * bspacket = (MyBSBasePacket *) mb->base();
  if (!bspacket->guard())
  {
    MY_ERROR("bad packet recieved from bs, no tail terminator\n");
    return ER_ERROR;
  }
  return ER_OK;
}

int MyBSBasePacketProcessor::packet_length()
{
  return m_packet_header.packet_len();
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

bool MyBaseServerProcessor::can_send_data(ACE_Message_Block * mb) const
{
  ACE_UNUSED_ARG(mb);
  return client_id_verified();
}

MyBaseProcessor::EVENT_RESULT MyBaseServerProcessor::on_recv_header()
{
  MyBaseProcessor::EVENT_RESULT result = super::on_recv_header();
  if (result != ER_CONTINUE)
    return result;

  bool bVerified = client_id_verified();
  bool bVersionCheck = (m_packet_header.command == MyDataPacketHeader::CMD_CLIENT_VERSION_CHECK_REQ);
  if (bVerified == bVersionCheck)
  {
    MyPooledMemGuard info;
    info_string(info);
    MY_ERROR(ACE_TEXT("Bad request received (cmd = %d, verified = %d, request version check = %d) from %s, \n"),
        m_packet_header.command, bVerified, bVersionCheck, info.data());
    return ER_ERROR;
  }

  return ER_CONTINUE;
}

MyBaseProcessor::EVENT_RESULT MyBaseServerProcessor::do_version_check_common(ACE_Message_Block * mb, MyClientIDTable & client_id_table)
{
  MyClientVersionCheckRequestProc vcr;
  vcr.attach(mb->base());
  vcr.validate_data();
  ACE_Message_Block * reply_mb = NULL;
  m_client_version.init(vcr.data()->client_version_major, vcr.data()->client_version_minor);
  int client_id_index = client_id_table.index_of(vcr.data()->client_id);
  bool valid = false;

  m_client_id_index = client_id_index;
  m_client_id = vcr.data()->client_id;
  m_client_id_length = strlen(m_client_id.as_string());

  if (client_id_index >= 0)
  {
    MyClientInfo client_info;
    if (client_id_table.value_all(client_id_index, client_info))
      valid = ! client_info.expired;
  }
  if (!valid)
  {
    m_wait_for_close = true;
    MY_WARNING(ACE_TEXT("closing connection due to invalid client_id = %s\n"), vcr.data()->client_id.as_string());
    reply_mb = make_version_check_reply_mb(MyClientVersionCheckReply::VER_ACCESS_DENIED);
  }

  if (m_wait_for_close)
  {
    if (m_handler->send_data(reply_mb) <= 0)
      return ER_ERROR;
    else
      return ER_OK;
  }

  m_handler->connection_manager()->set_connection_client_id_index(m_handler, client_id_index, m_handler->client_id_table());
  return ER_CONTINUE;
}

ACE_Message_Block * MyBaseServerProcessor::make_version_check_reply_mb
   (MyClientVersionCheckReply::REPLY_CODE code, int extra_len)
{
  int total_len = sizeof(MyClientVersionCheckReply) + extra_len;
  ACE_Message_Block * mb = MyMemPoolFactoryX::instance()->get_message_block_cmd_direct(total_len, MyDataPacketHeader::CMD_CLIENT_VERSION_CHECK_REPLY);
  MyClientVersionCheckReply * vcr = (MyClientVersionCheckReply *) mb->base();
  vcr->reply_code = code;
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

void MyBaseClientProcessor::client_id_verified(bool _verified)
{
  m_client_id_verified = _verified;
}

bool MyBaseClientProcessor::can_send_data(ACE_Message_Block * mb) const
{
  MyDataPacketHeader * dph = (MyDataPacketHeader*) mb->base();
  bool is_request = dph->command == MyDataPacketHeader::CMD_CLIENT_VERSION_CHECK_REQ;
  bool client_verified = client_id_verified();
  return is_request != client_verified;
}


int MyBaseClientProcessor::on_open()
{

  if (super::on_open() < 0)
    return -1;

  if (g_test_mode)
  {
    int pending_count = m_handler->connection_manager()->pending_count();
    if (pending_count > 0 &&  pending_count <= MyBaseConnector::BATCH_CONNECT_NUM / 2)
      m_handler->connector()->connect_ready();
  }
  return 0;
}

void MyBaseClientProcessor::on_close()
{
  if (g_test_mode)
  {
    int pending_count = m_handler->connection_manager()->pending_count();
    if (pending_count > 0 &&  pending_count <= MyBaseConnector::BATCH_CONNECT_NUM / 2)
      m_handler->connector()->connect_ready();
  }
}

MyBaseProcessor::EVENT_RESULT MyBaseClientProcessor::on_recv_header()
{
  MyBaseProcessor::EVENT_RESULT result = super::on_recv_header();
  if (result != ER_CONTINUE)
    return result;

  bool bVerified = client_id_verified();
  bool bVersionCheck = (m_packet_header.command == MyDataPacketHeader::CMD_CLIENT_VERSION_CHECK_REPLY);
  if (bVerified == bVersionCheck)
  {
    MyPooledMemGuard info;
    info_string(info);
    MY_ERROR(ACE_TEXT("Bad request received (cmd = %d, verified = %d, request version check = %d) from %s \n"),
        m_packet_header.command, bVerified, bVersionCheck, info.data());
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
  m_reaped_connections = 0;
  m_locked = false;
  m_pending = 0;
  m_total_connections = 0;
}

MyBaseConnectionManager::~MyBaseConnectionManager()
{
  MyConnectionsPtr it;
  MyBaseHandler * handler;
  MyConnectionManagerLockGuard guard(this);
  for (it = m_active_connections.begin(); it != m_active_connections.end(); ++it)
  {
    handler = it->first;
    if (handler)
      handler->handle_close(ACE_INVALID_HANDLE, 0);
  }
}

int MyBaseConnectionManager::active_connections() const
{
  return m_num_connections;
}

int MyBaseConnectionManager::total_connections() const
{
  return m_total_connections;
}

int MyBaseConnectionManager::reaped_connections() const
{
  return m_reaped_connections;
}

int MyBaseConnectionManager::pending_count() const
{
  return m_pending;
}

long long int MyBaseConnectionManager::bytes_received() const
{
  return m_bytes_received;
}

long long int MyBaseConnectionManager::bytes_sent() const
{
  return m_bytes_sent;
}

void MyBaseConnectionManager::on_data_received(int data_size)
{
  m_bytes_received += data_size;
}

void MyBaseConnectionManager::on_data_send(int data_size)
{
  m_bytes_sent += data_size;
}

void MyBaseConnectionManager::lock()
{
  m_locked = true;
}

void MyBaseConnectionManager::unlock()
{
  m_locked = false;
}

bool MyBaseConnectionManager::locked() const
{
  return m_locked;
}

void MyBaseConnectionManager::dump_info()
{
  do_dump_info();
}

void MyBaseConnectionManager::broadcast(ACE_Message_Block * mb)
{
  do_send(mb, true);
}

void MyBaseConnectionManager::send_single(ACE_Message_Block * mb)
{
  do_send(mb, false);
}

void MyBaseConnectionManager::do_send(ACE_Message_Block * mb, bool broadcast)
{
  if (unlikely(!mb))
    return;

  typedef std::vector<MyBaseHandler *, MyAllocator<MyBaseHandler *> > pointers;
  pointers ptrs;
  MyMessageBlockGuard guard(mb);

  MyConnectionsPtr it;
  for (it = m_active_connections.begin(); it != m_active_connections.end(); ++it)
  {
    if (it->second == CS_Pending)
      continue;
    if (it->first->send_data(mb->duplicate()) < 0)
      ptrs.push_back(it->first);
    else if (!broadcast)
      break;
  }

  pointers::iterator it2;
  for (it2 = ptrs.begin(); it2 != ptrs.end(); ++it2)
    (*it2)->handle_close();
}

void MyBaseConnectionManager::do_dump_info()
{
  const int BUFF_LEN = 1024;
  char buff[BUFF_LEN];
  //it seems that ACE's logging system can not handle 64bit formatting, let's do it ourself
  ACE_OS::snprintf(buff, BUFF_LEN, "        active connections = %d\n", active_connections());
  ACE_DEBUG((LM_INFO, buff));
  ACE_OS::snprintf(buff, BUFF_LEN, "        total connections = %d\n", total_connections());
  ACE_DEBUG((LM_INFO, buff));
  ACE_OS::snprintf(buff, BUFF_LEN, "        dead connections closed = %d\n", reaped_connections());
  ACE_DEBUG((LM_INFO, buff));
  ACE_OS::snprintf(buff, BUFF_LEN, "        bytes_received = %lld\n", (long long int) bytes_received());
  ACE_DEBUG((LM_INFO, buff));
  ACE_OS::snprintf(buff, BUFF_LEN, "        bytes_sent = %lld\n", (long long int) bytes_sent());
  ACE_DEBUG((LM_INFO, buff));
}


void MyBaseConnectionManager::detect_dead_connections(int timeout)
{
  MyConnectionsPtr it;
  MyBaseHandler * handler;
  MyConnectionManagerLockGuard guard(this);
  long deadline = g_clock_tick - long(timeout * 60 / MyBaseApp::CLOCK_INTERVAL);
  for (it = m_active_connections.begin(); it != m_active_connections.end();)
  {
    handler = it->first;
    if (!handler)
    {
      m_active_connections.erase(it++);
      --m_num_connections;
      ++m_reaped_connections;
      continue;
    }

    if (handler->processor()->last_activity() < deadline)
    {
      if (it->second == CS_Pending)
        -- m_pending;
      handler->mark_as_reap();
      remove_from_handler_map(handler, handler->client_id_table());
      handler->handle_close(ACE_INVALID_HANDLE, 0);
      m_active_connections.erase(it++);
      --m_num_connections;
      ++m_reaped_connections;
    }
    else
      ++it;
  }
}

void MyBaseConnectionManager::set_connection_client_id_index(MyBaseHandler * handler, int index, MyClientIDTable * id_table)
{
  if (unlikely(!handler || m_locked || index < 0))
    return;
  MyIndexHandlerMapPtr it = m_index_handler_map.lower_bound(index);
  if (id_table)
    id_table->active(index, true);
  if (it != m_index_handler_map.end() && (it->first == index))
  {
    MyBaseHandler * handler_old = it->second;
    it->second = handler;
    if (handler_old)
    {
      remove_from_active_table(handler_old);
      MyPooledMemGuard info;
      handler_old->processor()->info_string(info);
      MY_DEBUG("closing previous connection %s\n", info.data());
      handler_old->mark_as_reap();
      handler_old->handle_close(ACE_INVALID_HANDLE, 0);
    }
  } else
    m_index_handler_map.insert(it, MyIndexHandlerMap::value_type(index, handler));
}

MyBaseHandler * MyBaseConnectionManager::find_handler_by_index(int index)
{
  MyIndexHandlerMapPtr it = find_handler_by_index_i(index);
  if (it == m_index_handler_map.end())
    return NULL;
  else
    return it->second;
}

void MyBaseConnectionManager::add_connection(MyBaseHandler * handler, Connection_State state)
{
  if (!handler || m_locked)
    return;
  MyConnectionsPtr it = m_active_connections.lower_bound(handler);
  if (it != m_active_connections.end() && (it->first == handler))
  {
    if (it->second != state)
      m_pending += (state == CS_Pending ? 1:-1);
    it->second = state;
  } else
  {
    if (state == CS_Pending)
      ++ m_pending;
    m_active_connections.insert(it, MyConnections::value_type(handler, state));
    ++m_num_connections;
    ++m_total_connections;
  }
}

void MyBaseConnectionManager::set_connection_state(MyBaseHandler * handler, Connection_State state)
{
  add_connection(handler, state);
}

void MyBaseConnectionManager::remove_connection(MyBaseHandler * handler, MyClientIDTable * id_table)
{
  if (unlikely(m_locked))
    return;

  remove_from_active_table(handler);
  remove_from_handler_map(handler, id_table);
}

void MyBaseConnectionManager::remove_from_active_table(MyBaseHandler * handler)
{
  MyConnectionsPtr ptr = find(handler);
  if (ptr != m_active_connections.end())
  {
    if (ptr->second == CS_Pending)
      -- m_pending;
    m_active_connections.erase(ptr);
    --m_num_connections;
  }
}

void MyBaseConnectionManager::remove_from_handler_map(MyBaseHandler * handler, MyClientIDTable * id_table)
{
  if (unlikely(m_locked))
    return;

  int index = handler->processor()->client_id_index();
  if (index < 0)
    return;

  MyIndexHandlerMapPtr ptr2 = find_handler_by_index_i(index);
  if (ptr2 != m_index_handler_map.end() && (ptr2->second == handler || ptr2->second == NULL))
  {
    m_index_handler_map.erase(ptr2);
    if (id_table)
      id_table->active(index, false);
  }
}

MyBaseConnectionManager::MyConnectionsPtr MyBaseConnectionManager::find(MyBaseHandler * handler)
{
  return m_active_connections.find(handler);
}

MyBaseConnectionManager::MyIndexHandlerMapPtr MyBaseConnectionManager::find_handler_by_index_i(int index)
{
  return m_index_handler_map.find(index);
}


//MyBaseHandler//

MyBaseHandler::MyBaseHandler(MyBaseConnectionManager * xptr)
{
  m_reaped = false;
  m_connection_manager = xptr;
  m_processor = NULL;
}

MyBaseConnectionManager * MyBaseHandler::connection_manager()
{
  return m_connection_manager;
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
//  MY_DEBUG("MyBaseHandler::open(void * p = %X), this = %X\n", long(p), long(this));
  if (super::open(p) == -1)
    return -1;
  if (on_open() < 0)
    return -1;
  if (m_processor->on_open() < 0)
    return -1;
  if (m_connection_manager)
    m_connection_manager->set_connection_state(this, MyBaseConnectionManager::CS_Connected);
  return 0;
}

int MyBaseHandler::send_data(ACE_Message_Block * mb)
{
  if (unlikely(!m_processor->can_send_data(mb)))
  {
    mb->release();
    return 0;
  }
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

void MyBaseHandler::mark_as_reap()
{
  m_reaped = true;
}

int MyBaseHandler::handle_input(ACE_HANDLE h)
{
  ACE_UNUSED_ARG(h);
//  MY_DEBUG("handle_input (handle = %d)\n", h);
  return m_processor->handle_input();
}

MyClientIDTable * MyBaseHandler::client_id_table() const
{
  return NULL;
}

void MyBaseHandler::on_close()
{

}

int MyBaseHandler::handle_close (ACE_HANDLE handle,
                          ACE_Reactor_Mask close_mask)
{
  ACE_UNUSED_ARG(handle);
  //  MY_DEBUG("handle_close.y (handle = %d, mask=%x)\n", handle, close_mask);
  if (close_mask == ACE_Event_Handler::WRITE_MASK)
  {
    if (!m_processor->wait_for_close())
      return 0;
  }
//  else if (!m_processor->wait_for_close())
//  {
//    //m_processor->handle_input();
//  }

  ACE_Message_Block *mb;
  ACE_Time_Value nowait(ACE_Time_Value::zero);
  while (-1 != this->getq(mb, &nowait))
    mb->release();
  if (m_connection_manager && !m_reaped)
    m_connection_manager->remove_connection(this, client_id_table());
  on_close();
  m_processor->on_close();
  //here comes the tricky part, parent class will NOT call delete as it normally does
  //since we override the operator new/delete pair, the same thing parent class does
  //see ACE_Svc_Handler @ Svc_Handler.cpp
  //ctor: this->dynamic_ = ACE_Dynamic::instance ()->is_dynamic ();
  //destroy(): if (this->mod_ == 0 && this->dynamic_ && this->closing_ == false)
  //             delete this;
  //so do NOT use the normal method: return super::handle_close(handle, close_mask);
  //for it will cause memory leaks
//  MY_DEBUG("handle_close.3 deleting object (handle = %d, mask=%x)\n", handle, close_mask);
  delete this;
  return 0;
  //return super::handle_close (handle, close_mask); //do NOT use
}

int MyBaseHandler::handle_output (ACE_HANDLE fd)
{
  ACE_UNUSED_ARG(fd);
  ACE_Message_Block *mb;
  ACE_Time_Value nowait (ACE_Time_Value::zero);
  while (-1 != this->getq(mb, &nowait))
  {
    if (mycomutil_send_message_block(this, mb) < 0)
    {
      mb->release();
//      reactor()->remove_handler(this, ACE_Event_Handler::WRITE_MASK | ACE_Event_Handler::READ_MASK |
//                                ACE_Event_Handler::DONT_CALL);
      return handle_close(get_handle(), 0); //todo: more graceful shutdown
    }
    if (mb->length() > 0)
    {
      this->ungetq(mb);
      break;
    }
    mb->release();
  }
  return this->msg_queue()->is_empty() ? -1:0;
}

MyBaseHandler::~MyBaseHandler()
{
  delete m_processor;
}


//MyBaseAcceptor//

MyBaseAcceptor::MyBaseAcceptor(MyBaseDispatcher * _dispatcher, MyBaseConnectionManager * _manager):
    m_dispatcher(_dispatcher), m_connection_manager(_manager)
{
  m_tcp_port = 0;
  m_module = m_dispatcher->module_x();
  m_idle_connection_timer_id = -1;
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

MyBaseDispatcher * MyBaseAcceptor::dispatcher() const
{
  return m_dispatcher;
}

MyBaseConnectionManager * MyBaseAcceptor::connection_manager() const
{
  return m_connection_manager;
}

bool MyBaseAcceptor::on_start()
{
  return true;
}

void MyBaseAcceptor::on_stop()
{

}

int MyBaseAcceptor::handle_timeout(const ACE_Time_Value &, const void *act)
{
  if (long(act) == TIMER_ID_check_dead_connection)
    m_connection_manager->detect_dead_connections(m_idle_time_as_dead);
  return 0;
}

int MyBaseAcceptor::start()
{
  if (m_tcp_port <= 0)
  {
    MY_FATAL(ACE_TEXT ("attempt to listen on invalid port %d\n"), m_tcp_port);
    return -1;
  }
  ACE_INET_Addr port_to_listen (m_tcp_port);
  m_connection_manager->unlock();

  int ret = super::open (port_to_listen, m_dispatcher->reactor(), ACE_NONBLOCK);
  if (ret == 0)
    MY_INFO(ACE_TEXT ("%s listening on port %d... OK\n"), module_x()->name(), m_tcp_port);
  else if (ret < 0)
  {
    MY_ERROR(ACE_TEXT ("%s acceptor.open on port %d failed!\n"), module_x()->name(), m_tcp_port);
    return -1;
  }

  if (m_idle_time_as_dead > 0)
  {
    ACE_Time_Value tv( m_idle_time_as_dead * 60);
    m_idle_connection_timer_id = reactor()->schedule_timer(this, (void*)TIMER_ID_check_dead_connection, tv, tv);
    if (m_idle_connection_timer_id < 0)
    {
      MY_ERROR("can not setup dead connection timer @%s\n", name());
      return -1;
    }
  }

  if (!on_start())
    return -1;

  return 0;
}

int MyBaseAcceptor::stop()
{
  on_stop();
  m_connection_manager->lock();
  if (m_idle_connection_timer_id >= 0)
    reactor()->cancel_timer(m_idle_connection_timer_id);
  close();
  return 0;
}

void MyBaseAcceptor::do_dump_info()
{
  m_connection_manager->dump_info();
}

void MyBaseAcceptor::dump_info()
{
  ACE_DEBUG((LM_INFO, "      +++ acceptor dump: %s start\n", name()));
  do_dump_info();
  ACE_DEBUG((LM_INFO, "      +++ acceptor dump: %s end\n", name()));
}

const char * MyBaseAcceptor::name() const
{
  return "MyBaseAcceptor";
}


//MyBaseAcceptor//

MyBaseConnector::MyBaseConnector(MyBaseDispatcher * _dispatcher, MyBaseConnectionManager * _manager):
        m_dispatcher(_dispatcher), m_connection_manager(_manager)
{
  m_tcp_port = 0;
  m_num_connection = 1;
  m_reconnect_interval = 0;
  m_reconnect_retry_count = 0;
  m_reconnect_timer_id = -1;
  m_module = m_dispatcher->module_x();
  m_idle_time_as_dead = 0; //in minutes
  m_idle_connection_timer_id = -1;
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

MyBaseDispatcher * MyBaseConnector::dispatcher() const
{
  return m_dispatcher;
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
  if (long(act) == TIMER_ID_reconnect && m_reconnect_interval > 0)
  {
    if (m_connection_manager->active_connections() < m_num_connection)
    {
      if (g_test_mode)
      {
        if (m_remain_to_connect > 0)
          return 0;
      }
      if (before_reconnect())
      {
        m_reconnect_retry_count++;
        do_connect(m_num_connection - m_connection_manager->active_connections(), true);
      }
    }
  } else if (long(act) == TIMER_ID_check_dead_connection && m_idle_time_as_dead > 0)
    m_connection_manager->detect_dead_connections(m_idle_time_as_dead);

  return 0;
}

bool MyBaseConnector::on_start()
{
  return true;
}

void MyBaseConnector::on_stop()
{

}

int MyBaseConnector::start()
{
  m_connection_manager->unlock();
  if (g_test_mode)
    m_remain_to_connect = 0;
  if (open(m_dispatcher->reactor(), ACE_NONBLOCK) == -1)
    return -1;
  m_reconnect_retry_count = 0;

  if (m_tcp_port <= 0)
  {
    MY_FATAL(ACE_TEXT ("attempt to connect to an invalid port %d @%s\n"), m_tcp_port, name());
    return -1;
  }

  if (m_tcp_addr.length() == 0)
  {
    MY_FATAL(ACE_TEXT ("attempt to connect to an NULL host from @%s\n"), name());
    return -1;
  }

  if (before_reconnect())
  {
    m_reconnect_retry_count++;
    do_connect(m_num_connection, true);
  }

  if (m_reconnect_interval > 0)
  {
    ACE_Time_Value interval (m_reconnect_interval * 60);
    m_reconnect_timer_id = reactor()->schedule_timer (this, (void*)TIMER_ID_reconnect, interval, interval);
    if (m_reconnect_timer_id < 0)
      MY_ERROR(ACE_TEXT("%s setup reconnect timer failed, %s\n"), name(), (const char*)MyErrno());
  }

  if (m_idle_time_as_dead > 0)
  {
    ACE_Time_Value tv( m_idle_time_as_dead * 60);
    m_idle_connection_timer_id = reactor()->schedule_timer(this, (void*)TIMER_ID_check_dead_connection, tv, tv);
    if (m_idle_connection_timer_id < 0)
    {
      MY_ERROR("can not setup dead connection timer @%s\n", name());
      return -1;
    }
  }

  if (!on_start())
    return -1;

  return 0; //
}

void MyBaseConnector::do_dump_info()
{
  m_connection_manager->dump_info();
}

void MyBaseConnector::dump_info()
{
  ACE_DEBUG((LM_INFO, "      +++ connector dump: %s start\n", name()));
  do_dump_info();
  ACE_DEBUG((LM_INFO, "      +++ connector dump: %s end\n", name()));
}

const char * MyBaseConnector::name() const
{
  return "MyBaseConnector";
}

int MyBaseConnector::stop()
{
  on_stop();
  if (m_reconnect_timer_id >= 0)
    reactor()->cancel_timer(m_reconnect_timer_id);
  if (m_idle_connection_timer_id >= 0)
    reactor()->cancel_timer(m_idle_connection_timer_id);
  m_connection_manager->lock();
  close();
  return 0;
}

int MyBaseConnector::connect_ready()
{
  if (g_test_mode)
    return do_connect(0, false);
  else
    return 0;
}

void MyBaseConnector::reset_retry_count()
{
  m_reconnect_retry_count = 0;
}

int MyBaseConnector::do_connect(int count, bool bNew)
{
  if (g_test_mode)
  {
    if (unlikely(count <= 0 && m_remain_to_connect == 0))
      return 0;

    if (unlikely(count > m_num_connection))
    {
      MY_FATAL(ACE_TEXT("invalid connect count = %d, maximum allowed connections = %d"), count, m_num_connection);
      return -1;
    }

    if (m_connection_manager->pending_count() >= BATCH_CONNECT_NUM / 2)
      return 0;

    bool b_remain_connect = m_remain_to_connect > 0;
    if (b_remain_connect && bNew)
      return 0;
    int true_count;
    if (b_remain_connect)
      true_count = std::min(m_remain_to_connect, (BATCH_CONNECT_NUM - m_connection_manager->pending_count()));
    else
      true_count = std::min(count, (int)BATCH_CONNECT_NUM);

    if (true_count <= 0)
      return 0;

    ACE_INET_Addr port_to_connect(m_tcp_port, m_tcp_addr.c_str());
    MyBaseHandler * handler = NULL;
    int ok_count = 0, pending_count = 0;

    ACE_Time_Value timeout(30);
    ACE_Synch_Options synch_options(ACE_Synch_Options::USE_REACTOR | ACE_Synch_Options::USE_TIMEOUT, timeout);

    for (int i = 1; i <= true_count; ++i)
    {
      handler = NULL;
      int ret_i = connect(handler, port_to_connect, synch_options);
  //    MY_DEBUG("connect result = %d, handler = %X\n", ret_i, handler);
      if (ret_i == 0)
      {
        ++ok_count;
      }
      else if (ret_i == -1)
      {
        if (errno == EWOULDBLOCK)
        {
          pending_count++;
          m_connection_manager->add_connection(handler, MyBaseConnectionManager::CS_Pending);
        }
      }
    }

    if (b_remain_connect)
      m_remain_to_connect -= true_count;
    else if (bNew)
      m_remain_to_connect = count - true_count;

    MY_INFO(ACE_TEXT("%s connecting to %s:%d (total=%d, ok=%d, failed=%d, pending=%d)... \n"), name(),
        m_tcp_addr.c_str(), m_tcp_port, true_count, ok_count, true_count - ok_count- pending_count, pending_count);

    return ok_count + pending_count > 0;
  } else
  {
    ACE_INET_Addr port_to_connect(m_tcp_port, m_tcp_addr.c_str());
    MyBaseHandler * handler = NULL;
    ACE_Time_Value timeout(30);
    ACE_Synch_Options synch_options(ACE_Synch_Options::USE_REACTOR | ACE_Synch_Options::USE_TIMEOUT, timeout);
    MY_INFO(ACE_TEXT("%s connecting to %s:%d ...\n"), name(), m_tcp_addr.c_str(), m_tcp_port);
    if (connect(handler, port_to_connect, synch_options) == -1)
    {
      if (errno == EWOULDBLOCK)
        m_connection_manager->add_connection(handler, MyBaseConnectionManager::CS_Pending);
    }
    return 0;
  }
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

void MyBaseService::dump_info()
{

}

void MyBaseService::do_dump_info()
{

}

bool MyBaseService::do_add_task(void * p, int task_type)
{
  if (unlikely(!p))
    return true;

  ACE_Message_Block * mb = MyMemPoolFactoryX::instance()->get_message_block(sizeof(int) + sizeof(void *));
  *((int*)mb->base()) = task_type;
  *(char **)(mb->base() + sizeof(int)) = (char*)p;

  ACE_Time_Value tv(ACE_Time_Value::zero);
  if (putq(mb, &tv) < 0)
  {
    MY_ERROR("failed to place task %d command packet to %s %s\n", task_type, name(), (const char*)MyErrno());
    mb->release();
    return false;
  } else
    return true;
}

void * MyBaseService::get_task(ACE_Message_Block * mb, int & task_type) const
{
  if (unlikely(mb->capacity() != sizeof(void *) + sizeof(int)))
    return NULL;

  task_type = *(int*)mb->base();
  return *((char **)(mb->base() + sizeof(int)));
}


const char * MyBaseService::name() const
{
  return "MyBaseService";
}


//MyBaseDispatcher//

MyBaseDispatcher::MyBaseDispatcher(MyBaseModule * pModule, int numThreads):
    m_module(pModule), m_numThreads(numThreads), m_numBatchSend(50)
{
  m_reactor = NULL;
  m_clock_interval = 0;
  m_init_done = false;
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
    if (m_reactor->schedule_timer(this, (const void*)TIMER_ID_BASE, interval, interval) < 0)
    {
      MY_ERROR("setup timer failed %s %s\n", name(), (const char*)MyErrno());
      return -1;
    }
  }

  return 0;
}

void MyBaseDispatcher::add_connector(MyBaseConnector * _connector)
{
  if (!_connector)
  {
    MY_FATAL("MyBaseDispatcher::add_connector NULL _connector\n");
    return;
  }
  m_connectors.push_back(_connector);
}

void MyBaseDispatcher::add_acceptor(MyBaseAcceptor * _acceptor)
{
  if (!_acceptor)
  {
    MY_FATAL("MyBaseDispatcher::add_acceptor NULL _acceptor\n");
    return;
  }
  m_acceptors.push_back(_acceptor);
}

bool MyBaseDispatcher::on_start()
{
  return true;
}

int MyBaseDispatcher::start()
{
  return activate (THR_NEW_LWP, m_numThreads);
}

bool MyBaseDispatcher::on_event_loop()
{
  return true;
}

void MyBaseDispatcher::on_stop()
{

}

void MyBaseDispatcher::on_stop_stage_1()
{

}

int MyBaseDispatcher::stop()
{
  wait();
  return 0;
}

const char * MyBaseDispatcher::name() const
{
  return "MyBaseDispatcher";
}

void MyBaseDispatcher::dump_info()
{
  ACE_DEBUG((LM_INFO, "    --- dispatcher dump: %s start\n", name()));
  do_dump_info();
  std::for_each(m_connectors.begin(), m_connectors.end(), std::mem_fun(&MyBaseConnector::dump_info));
  std::for_each(m_acceptors.begin(), m_acceptors.end(), std::mem_fun(&MyBaseAcceptor::dump_info));
  ACE_DEBUG((LM_INFO, "    --- dispatcher dump: %s end\n", name()));
}

void MyBaseDispatcher::do_dump_info()
{

}

MyBaseModule * MyBaseDispatcher::module_x() const
{
  return m_module;
}

bool MyBaseDispatcher::do_start_i()
{
  ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, 0);
  if (!m_init_done)
  {
    m_init_done = true;
    if (open(NULL) == -1)
      return false;
    msg_queue()->flush();
    if (!on_start())
      return false;
    std::for_each(m_connectors.begin(), m_connectors.end(), std::mem_fun(&MyBaseConnector::start));
    std::for_each(m_acceptors.begin(), m_acceptors.end(), std::mem_fun(&MyBaseAcceptor::start));
  }
  return true;
}

void MyBaseDispatcher::do_stop_i()
{
  ACE_GUARD(ACE_Thread_Mutex, ace_mon, this->m_mutex);
  if (!m_reactor) //reuse m_reactor as cleanup flag
    return;
  msg_queue()->flush();
  on_stop_stage_1();
  if (m_reactor && m_clock_interval > 0)
    m_reactor->cancel_timer(this);
  std::for_each(m_connectors.begin(), m_connectors.end(), std::mem_fun(&MyBaseConnector::stop));
  std::for_each(m_acceptors.begin(), m_acceptors.end(), std::mem_fun(&MyBaseAcceptor::stop));
  std::for_each(m_connectors.begin(), m_connectors.end(), MyObjectDeletor());
  std::for_each(m_acceptors.begin(), m_acceptors.end(), MyObjectDeletor());
  if (m_reactor)
    m_reactor->close();
  m_connectors.clear();
  m_acceptors.clear();
  on_stop();
  delete m_reactor;
  m_reactor = NULL;
}

int MyBaseDispatcher::svc()
{
  MY_INFO(ACE_TEXT ("running %s::svc()\n"), name());

  if (!do_start_i())
    return -1;

  while (m_module->running_with_app())
  {
    ACE_Time_Value timeout(2);
    int ret = reactor()->handle_events(&timeout);
    if (ret == -1)
    {
      if (errno == EINTR)
        continue;
      MY_INFO(ACE_TEXT ("exiting %s::svc() due to %s\n"), name(), (const char*)MyErrno());
      break;
    }
    if (!on_event_loop())
      break;
    //MY_DEBUG("    returning from reactor()->handle_events()\n");
  }

  MY_INFO(ACE_TEXT ("exiting %s::svc()\n"), name());
  do_stop_i();
  return 0;
}


//MyBaseModule//

MyBaseModule::MyBaseModule(MyBaseApp * app): m_app(app), m_running(false)
{

}

MyBaseModule::~MyBaseModule()
{
  stop();
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

bool MyBaseModule::on_start()
{
  return true;
}

void MyBaseModule::on_stop()
{

}


int MyBaseModule::start()
{
  if (m_running)
    return 0;

  if (!on_start())
    return -1;
  m_running = true;
  std::for_each(m_services.begin(), m_services.end(), std::mem_fun(&MyBaseService::start));
  std::for_each(m_dispatchers.begin(), m_dispatchers.end(), std::mem_fun(&MyBaseDispatcher::start));
  return 0;
}

int MyBaseModule::stop()
{
  if (!m_running)
    return 0;
  m_running = false;
  std::for_each(m_services.begin(), m_services.end(), std::mem_fun(&MyBaseService::stop));
  std::for_each(m_dispatchers.begin(), m_dispatchers.end(), std::mem_fun(&MyBaseDispatcher::stop));
  std::for_each(m_services.begin(), m_services.end(), MyObjectDeletor());
  std::for_each(m_dispatchers.begin(), m_dispatchers.end(), MyObjectDeletor());
  m_services.clear();
  m_dispatchers.clear();
  on_stop();
  return 0;
}

const char * MyBaseModule::name() const
{
  return "MyBaseModule";
}

void MyBaseModule::dump_info()
{
  ACE_DEBUG((LM_INFO, "  *** module dump: %s start\n", name()));
  do_dump_info();
  std::for_each(m_dispatchers.begin(), m_dispatchers.end(), std::mem_fun(&MyBaseDispatcher::dump_info));
  std::for_each(m_services.begin(), m_services.end(), std::mem_fun(&MyBaseService::dump_info));
  ACE_DEBUG((LM_INFO, "  *** module dump: %s end\n", name()));
}

void MyBaseModule::do_dump_info()
{

}

void MyBaseModule::add_service(MyBaseService * _service)
{
  if (!_service)
  {
    MY_FATAL("MyBaseModule::add_service() NULL _service\n");
    return;
  }
  m_services.push_back(_service);
}

void MyBaseModule::add_dispatcher(MyBaseDispatcher * _dispatcher)
{
  if (!_dispatcher)
  {
    MY_FATAL("MyBaseModule::add_dispatcher() NULL _dispatcher\n");
    return;
  }
  m_dispatchers.push_back(_dispatcher);
}
