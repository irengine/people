#include "basemodule.h"
#include "baseapp.h"

//MyClientInfos//

MyClientIDTable::MyClientIDTable()
{
  m_last_sequence = 0;
}

bool MyClientIDTable::contains(const MyClientID & id)
{
  return (index_of(id) >= 0);
}

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
  while (*str_id == ' ')
    str_id++;
  if (!*str_id)
    return;
  MyClientID id(str_id);
  id.trim_tail_space();
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

bool MyClientIDTable::value(int index, MyClientID * id)
{
  if (unlikely(index < 0) || !id)
    return false;
  ACE_READ_GUARD_RETURN(ACE_RW_Thread_Mutex, ace_mon, m_mutex, false);
  if (unlikely(index >= (int)m_table.size()))
    return false;
  *id = m_table[index];
  return true;
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

MyFileMD5::MyFileMD5(const char * _filename, const char * md5, int prefix_len)
{
  m_md5[0] = 0;
  m_size = 0;
  if (!_filename || ! *_filename)
    return;

  int len = strlen(_filename);
  if (unlikely(len <= prefix_len))
  {
    MY_FATAL("invalid parameter in MyFileMD5::MyFileMD5(%s, %d)\n", _filename, prefix_len);
    return;
  }
  m_size = len - prefix_len + 1;
  if (unlikely(!MyMemPoolFactoryX::instance()->get_mem(m_size, &m_file_name)))
  {
     MY_ERROR("not enough memory for file name = %s @MyFileMD5\n", _filename);
     return;
  }
  memcpy((void*)m_file_name.data(), (void*)(_filename + prefix_len), m_size);
  if (!md5)
  {
    MD5_CTX mdContext;
    if (!md5file(_filename, 0, &mdContext, m_md5, MD5_STRING_LENGTH))
      MY_ERROR("failed not calculate md5 value of file %s\n", _filename);
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
  std::for_each(m_file_md5_list.begin(), m_file_md5_list.end(), MyObjectDeletor());
}

bool MyFileMD5s::base_dir(const char * dir)
{
  if (unlikely(!dir || !*dir))
  {
    MY_FATAL("MyFileMD5s::base_dir(empty dir)\n");
    return false;
  }

  int len = strlen(dir) + 1;
  if (unlikely(!MyMemPoolFactoryX::instance()->get_mem(len, &m_base_dir)))
  {
     MY_ERROR("not enough memory for file name = %s @MyFileMD5s\n", dir);
     return false;
  }
  m_base_dir_len = len;
  ACE_OS::memcpy((void*)m_base_dir.data(), dir, len);
  return true;
}

void MyFileMD5s::minus(MyFileMD5s & target)
{
  MyFileMD5List::iterator it1 = m_file_md5_list.begin(), it2 = target.m_file_md5_list.begin(), it;
  //the below algorithm is based on STL's set_difference() function
  char fn[PATH_MAX];
  while (it1 != m_file_md5_list.end() && it2 != target.m_file_md5_list.end())
  {
    if (**it1 < **it2)
      ++it1;
    else if (**it2 < **it1)
    {
      ACE_OS::snprintf(fn, PATH_MAX - 1, "%s/%s", target.m_base_dir.data(), (**it2).filename());
      MY_INFO("deleting file %s\n", fn);
      //remove(fn);
      ++it2;
    }
    else if ((**it1).same_md5(**it2))//==
    {
      delete *it1;
      it1 = m_file_md5_list.erase(it1);
      ++it2;
    } else
    {
      ++it1;
      ++it2;
    }
  }

  while (it2 != target.m_file_md5_list.end())
  {
    ACE_OS::snprintf(fn, PATH_MAX - 1, "%s/%s", target.m_base_dir.data(), (**it2).filename());
    MY_INFO("deleting file %s\n", fn);
    //remove(fn);
    ++it2;
  }
}

void MyFileMD5s::sort()
{
  std::sort(m_file_md5_list.begin(), m_file_md5_list.end(), MyPointerLess());
}

void MyFileMD5s::add_file(const char * filename, const char * md5)
{
  if (unlikely(!filename || !*filename))
    return;
  MyFileMD5 * fm = new MyFileMD5(filename, md5, 0);
  if (fm->ok())
    m_file_md5_list.push_back(fm);
  else
    delete fm;
}

void MyFileMD5s::add_file(const char * pathname, const char * filename, int prefix_len)
{
  if (unlikely(!pathname || !filename))
    return;
  int len = ACE_OS::strlen(pathname);
  if (unlikely(len + 1 < prefix_len || len  + strlen(filename) + 2 > PATH_MAX))
  {
    MY_FATAL("invalid parameter @ MyFileMD5s::add_file(%s, %s, %d)\n", pathname, filename, prefix_len);
    return;
  }
  MyFileMD5 * fm;
//  if (len == prefix_len)
//    fm = new MyFileMD5(filename, NULL, 0);
//  else
//  {
    char buff[PATH_MAX];
    ACE_OS::sprintf(buff, "%s/%s", pathname, filename);
    fm = new MyFileMD5(buff, NULL, prefix_len);
//  }

  if (likely(fm->ok()))
    m_file_md5_list.push_back(fm);
  else
    delete fm;

}

int MyFileMD5s::total_size(bool include_md5_value)
{
  int result = 0;
  MyFileMD5List::iterator it;
  for (it = m_file_md5_list.begin(); it != m_file_md5_list.end(); ++it)
  {
    MyFileMD5 & fm = **it;
    if (!fm.ok())
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
    if (!fm.ok())
      continue;
    if (unlikely(buff_len <= len + fm.size(include_md5_value)))
    {
      MY_ERROR("buffer is too small @MyFileMD5s::to_buffer(buff_len=%d, need_length=%d)\n",
          buff_len, len + fm.size(include_md5_value) + 1);
      return false;
    }
    int fm_file_length = fm.size(false);
    ACE_OS::memcpy(buff + len, fm.filename(), fm_file_length);
    buff[len + fm_file_length - 1] = include_md5_value? SEPARATOR_MIDDLE: SEPARATOR_END;
    len += fm_file_length;
    if (include_md5_value)
    {
      ACE_OS::memcpy(buff + len, fm.md5(), MyFileMD5::MD5_STRING_LENGTH);
      len += MyFileMD5::MD5_STRING_LENGTH;
      buff[len++] = SEPARATOR_END;
    }
  }
  buff[len] = 0;
  return true;
}

bool MyFileMD5s::from_buffer(char * buff)
{
  if (!buff || !*buff)
    return true;

  char seperator[2] = {SEPARATOR_END, 0};
  char *str, *token, *saveptr, *md5;

//  ACE_WRITE_GUARD(ACE_RW_Thread_Mutex, ace_mon, m_mutex);
  for (str = buff; ; str = NULL)
  {
    token = strtok_r(str, seperator, &saveptr);
    if (token == NULL)
      break;
    if (!*token)
      continue;
    md5 = ACE_OS::strchr(token, SEPARATOR_MIDDLE);
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
    MyFileMD5 * fm = new MyFileMD5(token, md5, 0);
    m_file_md5_list.push_back(fm);
  }

  return true;
}

void MyFileMD5s::scan_directory(const char * dirname)
{
  if (!dirname || !*dirname)
    return;
  base_dir(dirname);
  do_scan_directory(dirname, strlen(dirname) + 1);
}

void MyFileMD5s::do_scan_directory(const char * dirname, int start_len)
{
  DIR * dir = opendir(dirname);
  if (!dir)
  {
    MY_ERROR("can not open directory: %s %s\n", dirname, (const char*)MyErrno());
    return;
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
      add_file(dirname, entry->d_name, start_len);
    else if(entry->d_type == DT_DIR)
    {
      ACE_OS::snprintf(buff, PATH_MAX - 1, "%s/%s", dirname, entry->d_name);
      do_scan_directory(buff, start_len);
    } else
      MY_WARNING("unknown file type (= %d) for file @MyFileMD5s::do_scan_directory file = %s/%s\n",
           entry->d_type, dirname, entry->d_name);
  };

  closedir(dir);
}


//MyBaseArchiveReader//

bool MyBaseArchiveReader::open(const char * filename)
{
  if (unlikely(!filename || !*filename))
  {
    MY_ERROR("empty file name @MyBaseArchiveReader::open()\n");
    return false;
  }

  int fd = ::open(filename, O_RDONLY);
  if (fd < 0)
  {
    MY_ERROR("can not open file for read @MyBaseArchiveReader::open(), name = %s %s\n", filename, (const char*)MyErrno());
    return false;
  }
  m_file.attach(fd);
  return true;
}

int MyBaseArchiveReader::read(char * buff, int buff_len)
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



//MyBaseArchiveWriter//

bool MyBaseArchiveWriter::open(const char * filename)
{
  if (unlikely(!filename || !*filename))
  {
    MY_ERROR("empty file name @MyBaseArchiveWriter::open()\n");
    return false;
  }

  int fd = ::open(filename, O_CREAT | O_TRUNC | O_RDWR, S_IRUSR | S_IWUSR);
  if (fd < 0)
  {
    MY_ERROR("can not open file for write @MyBaseArchiveWriter::open(), name = %s %s\n", filename, (const char*)MyErrno());
    return false;
  }
  m_file.attach(fd);
  return true;

}

bool MyBaseArchiveWriter::write(char * buff, int buff_len)
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


//MyBZCompressor//

MyBZCompressor::MyBZCompressor()
{
  m_bz_stream.bzalloc = NULL;
  m_bz_stream.bzfree = NULL;
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

bool MyBZCompressor::compress(const char * srcfn, const char * destfn)
{
  MyBaseArchiveReader reader;
  if (!reader.open(srcfn))
    return false;
  MyBaseArchiveWriter writer;
  if (!writer.open(destfn))
    return false;

  prepare_buffers();

  int ret = BZ2_bzCompressInit(&m_bz_stream, COMPRESS_100k, 0, 30);
  if (ret != BZ_OK)
  {
    printf("BZ2_bzCompressInit() return value = %d\n", ret);
    return false;
  }

  bool result = do_compress(&reader, &writer);
  if (!result)
    MY_ERROR("failed to compress file: %s to %s\n", srcfn, destfn);
  BZ2_bzCompressEnd(&m_bz_stream);
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
       n = _reader->read (m_buff_in.data(), BUFFER_LEN);
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

bool MyBZCompressor::decompress(const char * srcfn, const char * destfn)
{
  MyBaseArchiveReader reader;
  if (!reader.open(srcfn))
    return false;
  MyBaseArchiveWriter writer;
  if (!writer.open(destfn))
    return false;

  prepare_buffers();

  int ret;
  ret = BZ2_bzDecompressInit(&m_bz_stream, 0, 0);
  if (ret != BZ_OK)
  {
    MY_ERROR("BZ2_bzCompressInit() return value = %d\n", ret);
    return false;
  }

  bool result = do_decompress(&reader, &writer);
  BZ2_bzDecompressEnd(&m_bz_stream);
  if (!result)
    MY_ERROR("failed to decompress file: %s to %s\n", srcfn, destfn);
  return result;
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

std::string MyBaseProcessor::info_string() const
{
  return "";
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

MyBasePacketProcessor::MyBasePacketProcessor(MyBaseHandler * handler): MyBaseProcessor(handler)
{
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
  ACE_OS::snprintf(buff, 512 - 1, "(remote addr=%s, client_id=%s)", m_peer_addr, m_client_id.as_string());
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
  if (mb->size() < sizeof(MyDataPacketHeader))
  {
    MY_ERROR(ACE_TEXT("message block size too little ( = %d)"), mb->size());
    mb->release();
    return ER_ERROR;
  }
  mb->rd_ptr(mb->base());

  return on_recv_packet_i(mb);
}


MyBaseProcessor::EVENT_RESULT MyBasePacketProcessor::on_recv_packet_i(ACE_Message_Block * mb)
{
  MyDataPacketHeader * header = (MyDataPacketHeader *)mb->base();
  header->magic = m_client_id_index;
  return ER_OK;
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
  m_handler->connection_manager()->set_connection_client_id_index(m_handler, client_id_index);
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

void MyBaseClientProcessor::client_id_verified(bool _verified)
{
  m_client_id_verified = _verified;
}

int MyBaseClientProcessor::on_open()
{

  if (super::on_open() < 0)
    return -1;

#ifdef MY_client_test
  int pending_count = m_handler->connection_manager()->pending_count();
  if (pending_count > 0 &&  pending_count <= MyBaseConnector::BATCH_CONNECT_NUM / 2)
    m_handler->connector()->connect_ready();
  return 0;
#endif
}

void MyBaseClientProcessor::on_close()
{

#ifdef MY_client_test
  int pending_count = m_handler->connection_manager()->pending_count();
  if (pending_count > 0 &&  pending_count <= MyBaseConnector::BATCH_CONNECT_NUM / 2)
    m_handler->connector()->connect_ready();
#endif
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
    MY_ERROR(ACE_TEXT("Bad request received (cmd = %d, verified = %d, request version check = %d) from %s \n"),
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
      handler->handle_close(handler->get_handle(), 0);
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
      handler->handle_close(handler->get_handle(), 0);
      m_active_connections.erase(it++);
      --m_num_connections;
      ++m_reaped_connections;
    }
    else
      ++it;
  }
}

void MyBaseConnectionManager::set_connection_client_id_index(MyBaseHandler * handler, int index)
{
  if (!handler || m_locked || index < 0)
    return;
  MyIndexHandlerMapPtr it = m_index_handler_map.lower_bound(index);
  if (it != m_index_handler_map.end() && (it->first == index))
  {
    MyBaseHandler * handler_old = it->second;
    it->second = handler;
    if (handler_old)
    {
      MY_INFO("closing previous connection %s\n", handler_old->processor()->info_string().c_str());
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

void MyBaseConnectionManager::remove_connection(MyBaseHandler * handler)
{
  if (m_locked)
    return;
  MyConnectionsPtr ptr = find(handler);
  if (ptr != m_active_connections.end())
  {
    if (ptr->second == CS_Pending)
      -- m_pending;
    m_active_connections.erase(ptr);
    --m_num_connections;
  }

  int index = handler->processor()->client_id_index();
  if (index < 0)
    return;

  MyIndexHandlerMapPtr ptr2 = find_handler_by_index_i(index);
  if (ptr2 != m_index_handler_map.end() && (ptr2->second == handler || ptr2->second == NULL))
    m_index_handler_map.erase(ptr2);
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
  ACE_UNUSED_ARG(h);
//  MY_DEBUG("handle_input (handle = %d)\n", h);
  return m_processor->handle_input();
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
  } else if (!m_processor->wait_for_close())
  {
    //m_processor->handle_input();
  }
  ACE_Message_Block *mb;
  ACE_Time_Value nowait(ACE_Time_Value::zero);
  while (-1 != this->getq(mb, &nowait))
    mb->release();
  if (m_connection_manager)
    m_connection_manager->remove_connection(this);
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
  return (this->msg_queue()->is_empty()) ? -1 : 0;
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


//////////////
//MyBaseAcceptor//

MyBaseConnector::MyBaseConnector(MyBaseDispatcher * _dispatcher, MyBaseConnectionManager * _manager):
        m_dispatcher(_dispatcher), m_connection_manager(_manager)
{
  m_tcp_port = 0;
  m_num_connection = 1;
  m_reconnect_interval = 0;
  m_reconnect_retry_count = 3;
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
#ifdef MY_client_test
      if (m_remain_to_connect > 0)
        return 0;
#endif
      if (before_reconnect())
      {
        m_reconnect_retry_count++;
        do_connect(m_num_connection - m_connection_manager->active_connections());
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
  m_remain_to_connect = 0;
  if (open(m_dispatcher->reactor(), ACE_NONBLOCK) == -1)
    return -1;
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

  do_connect(m_num_connection);
  if (m_reconnect_interval > 0)
  {
    ACE_Time_Value interval (m_reconnect_interval * 60);
    m_reconnect_timer_id = reactor()->schedule_timer (this, (void*)TIMER_ID_reconnect, interval, interval);
    if (m_reconnect_timer_id < 0)
      MY_ERROR(ACE_TEXT("MyBaseConnector setup reconnect timer failed, %s"), (const char*)MyErrno());
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

#ifdef MY_client_test
int MyBaseConnector::connect_ready()
{
  return do_connect(0);
}
#endif

int MyBaseConnector::do_connect(int count)
{
#ifdef MY_client_test
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
  int true_count;
  if (b_remain_connect)
    true_count = std::min(m_remain_to_connect, (BATCH_CONNECT_NUM - m_connection_manager->pending_count()));
  else
    true_count = std::min(count, (int)BATCH_CONNECT_NUM);

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
  else
    m_remain_to_connect = count - true_count;

  MY_INFO(ACE_TEXT("connecting on %s:%d (total=%d, ok=%d, failed=%d, pending=%d)... \n"),
      m_tcp_addr.c_str(), m_tcp_port, true_count, ok_count, true_count - ok_count- pending_count, pending_count);

  return ok_count + pending_count > 0;

#else
  ACE_INET_Addr port_to_connect(m_tcp_port, m_tcp_addr.c_str());
  MyBaseHandler * handler = NULL;
  ACE_Time_Value timeout(30);
  ACE_Synch_Options synch_options(ACE_Synch_Options::USE_REACTOR | ACE_Synch_Options::USE_TIMEOUT, timeout);
  if (connect(handler, port_to_connect, synch_options) == -1)
  {
    if (errno == EWOULDBLOCK)
      m_connection_manager->add_connection(handler, MyBaseConnectionManager::CS_Pending);
  }
  return 0;
#endif
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
    m_reactor->schedule_timer (this,
                             0,
                             interval,
                             interval);
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

void MyBaseDispatcher::on_stop()
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
