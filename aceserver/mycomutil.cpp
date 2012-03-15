/*
 * mycomutil.cpp
 *
 *  Created on: Jan 2, 2012
 *      Author: root
 */

#include <algorithm>
#include "mycomutil.h"
#include "baseapp.h"

bool g_use_mem_pool = true;

//MyCached_Message_Block//

MyCached_Message_Block::MyCached_Message_Block(size_t size,
                ACE_Allocator * allocator_strategy,
                ACE_Allocator * data_block_allocator,
                ACE_Allocator * message_block_allocator,
                ACE_Message_Type type)
     :ACE_Message_Block(
        size,
        type,
        0, //ACE_Message_Block * cont
        0, //const char * data
        allocator_strategy,
        0, //ACE_Lock * locking_strategy
        ACE_DEFAULT_MESSAGE_BLOCK_PRIORITY, //unsigned long priority
        ACE_Time_Value::zero, //const ACE_Time_Value & execution_time
        ACE_Time_Value::max_time, //const ACE_Time_Value & deadline_time
        data_block_allocator,
        message_block_allocator)
{

}


//MyPooledMemGuard//

void MyPooledMemGuard::init_from_string(const char * src)
{
  int len = src? ACE_OS::strlen(src) + 1: 1;
  MyMemPoolFactoryX::instance()->get_mem(len, this);
  if (len == 1)
    data()[0] = 0;
  else
    ACE_OS::memcpy(data(), src, len);
}

void MyPooledMemGuard::init_from_string(const char * src1, const char * src2)
{
  if (!src1 || !*src1)
  {
    init_from_string(src2);
    return;
  }
  if (!src2 || !*src2)
  {
    init_from_string(src1);
    return;
  }
  int len1 = ACE_OS::strlen(src1);
  int len2 = ACE_OS::strlen(src2) + 1;
  MyMemPoolFactoryX::instance()->get_mem(len1 + len2, this);
  ACE_OS::memcpy(data(), src1, len1);
  ACE_OS::memcpy(data() + len1, src2, len2);
}

void MyPooledMemGuard::init_from_string(const char * src1, const char * src2, const char * src3)
{
  if (!src1 || !*src1)
  {
    init_from_string(src2, src3);
    return;
  }
  if (!src2 || !*src2)
  {
    init_from_string(src1, src3);
    return;
  }
  if (!src3 || !*src3)
  {
    init_from_string(src1, src2);
    return;
  }

  int len1 = ACE_OS::strlen(src1);
  int len2 = ACE_OS::strlen(src2);
  int len3 = ACE_OS::strlen(src3) + 1;
  MyMemPoolFactoryX::instance()->get_mem(len1 + len2 + len3, this);
  ACE_OS::memcpy(data(), src1, len1);
  ACE_OS::memcpy(data() + len1, src2, len2);
  ACE_OS::memcpy(data() + len1 + len2, src3, len3);
}

void MyPooledMemGuard::init_from_string(const char * src1, const char * src2, const char * src3, const char * src4)
{
  if (!src1 || !*src1)
  {
    init_from_string(src2, src3, src4);
    return;
  }
  if (!src2 || !*src2)
  {
    init_from_string(src1, src3, src4);
    return;
  }
  if (!src3 || !*src3)
  {
    init_from_string(src1, src2, src4);
    return;
  }
  if (!src4 || !*src4)
  {
    init_from_string(src1, src2, src3);
    return;
  }

  int len1 = ACE_OS::strlen(src1);
  int len2 = ACE_OS::strlen(src2);
  int len3 = ACE_OS::strlen(src3);
  int len4 = ACE_OS::strlen(src4) + 1;
  MyMemPoolFactoryX::instance()->get_mem(len1 + len2 + len3 + len4, this);
  ACE_OS::memcpy(data(), src1, len1);
  ACE_OS::memcpy(data() + len1, src2, len2);
  ACE_OS::memcpy(data() + len1 + len2, src3, len3);
  ACE_OS::memcpy(data() + len1 + len2 + len3, src4, len4);
}

void MyPooledMemGuard::init_from_strings(const char * arr[], int len)
{
  if (unlikely(!arr || len <= 0))
    return;
  int total_len = 0;
  int i;
  for (i = 0; i < len; ++i)
  {
    if (likely(arr[i] != NULL))
      total_len += ACE_OS::strlen(arr[i]);
  }
  total_len += 1;

  MyMemPoolFactoryX::instance()->get_mem(total_len, this);

  m_buff[0] = 0;
  for (i = 0; i < len; ++i)
  {
    if (likely(arr[i] != NULL))
      ACE_OS::strcat(m_buff, arr[i]);
  }
}

void mycomutil_hex_dump(void * ptr, int len, char * result_buff, int buff_len)
{
  if (unlikely(!ptr || len <= 0 || buff_len < 2 * len))
    return;
  unsigned char v;
  for (int i = 0; i < len; ++i)
  {
    v = ((unsigned char*)ptr)[i] >> 4;
    if (v < 10)
      result_buff[i * 2] = '0' + v;
    else
      result_buff[i * 2] = 'A' + (v - 10);

    v = ((unsigned char*)ptr)[i] & 0x0F;
    if (v < 10)
      result_buff[i * 2 + 1] = '0' + v;
    else
      result_buff[i * 2 + 1] = 'A' + (v - 10);
  }
}

void mycomutil_generate_random_password(char * buff, const int password_len)
{
  if (unlikely(!buff || password_len <= 1))
    return;

  int i = password_len - 1;
  buff[i] = 0;
  const char schar[] = "~!@#$^&_-+=/\\";
  //0-9 a-Z A-Z schar
  const long total = 10 + 26 + 26 + sizeof(schar) / sizeof(char) - 1;
  while ((--i) >= 0)
  {
    long val = random() % total;
    if (val <= 9)
      buff[i] = '0' + val;
    else if (val <= 9 + 26)
      buff[i] = 'a' + (val - 10);
    else if (val <= 9 + 26 + 26)
      buff[i] = 'A' + (val - 10 - 26);
    else
      buff[i] = schar[val - 10 - 26 - 26];
  }
}


bool mycomutil_find_tag_value(char * & ptr, const char * tag, char * & value, char terminator)
{
  if (unlikely(!ptr || !*ptr || !tag))
    return false;
  int key_len = ACE_OS::strlen(tag);
  if (ACE_OS::memcmp(ptr, tag, key_len) != 0)
    return false;
  ptr += key_len;
  value = ptr;
  if (terminator)
  {
    ptr = ACE_OS::strchr(ptr, terminator);
    if (ptr)
    {
      *ptr ++ = 0;
    }
  } else
    ptr += ACE_OS::strlen(ptr);
  return true;
}

bool mycomutil_calculate_file_md5(const char * _file, MyPooledMemGuard & md5_result)
{
  char buff[32 + 1];
  MD5_CTX mdContext;
  if (!md5file(_file, 0, &mdContext, buff, 32))
    return false;
  buff[32] = 0;
  md5_result.init_from_string(buff);
  return true;
}

bool mycomutil_generate_time_string(char * result_buff, int buff_len, bool full, time_t t)
{
  MY_ASSERT_RETURN(full? buff_len > 19: buff_len > 15, "buffer len too small @mycomutil_generate_time_string\n", false);
  struct tm _tm;
  if (unlikely(localtime_r(&t, &_tm) == NULL))
    return false;
  const char * fmt_str = full? "%04d-%02d-%02d %02d:%02d:%02d" : "%04d%02d%02d %02d%02d%02d";
  ACE_OS::snprintf(result_buff, buff_len, fmt_str, _tm.tm_year + 1900, _tm.tm_mon + 1,
      _tm.tm_mday, _tm.tm_hour, _tm.tm_min, _tm.tm_sec);
  return true;
}

size_t mycomutil_string_hash(const char * str)
{
  unsigned long __h = 0;
  while (*str != 0)
    __h = 5*__h + *str++;
  return size_t(__h);
}

bool mycomutil_string_end_with(const char * src, const char * key)
{
  int len1 = ACE_OS::strlen(src);
  int len2 = ACE_OS::strlen(key);
  if (len1 < len2)
    return false;
  return ACE_OS::memcmp(src + len1 - len2, key, len2) == 0;
}

void mycomutil_string_replace_char(char * s, const char src, const char dest)
{
  if (unlikely(!s))
    return;
  char * ptr = s;
  while ((ptr = strchr(ptr, src)) != NULL)
    *ptr ++ = dest;
}

bool mycomutil_mb_putq(ACE_Task<ACE_MT_SYNCH> * target, ACE_Message_Block * mb, const char * err_msg)
{
  ACE_Time_Value tv(ACE_Time_Value::zero);
  if (unlikely(target->putq(mb, &tv) < 0))
  {
    if (err_msg)
      MY_ERROR("can not put message %s: %s\n", err_msg, (const char *)MyErrno());
    mb->release();
    return false;
  }

  return true;
}


int mycomutil_send_message_block(ACE_Svc_Handler<ACE_SOCK_STREAM, ACE_NULL_SYNCH> * handler, ACE_Message_Block *mb);

int mycomutil_translate_tcp_result(ssize_t transfer_return_value)
{
  if (transfer_return_value == 0)
    return -1;
  int err = ACE_OS::last_error();
  if (transfer_return_value < 0)
  {
    if (err == EWOULDBLOCK || err == EAGAIN || err == ENOBUFS) //see POSIX.1-2001
      return 0;
    return -1;
  }
  return 1;
}

int mycomutil_send_message_block(ACE_Svc_Handler<ACE_SOCK_STREAM, ACE_NULL_SYNCH> * handler,
    ACE_Message_Block *mb)
{
  if (!handler || !mb)
    return -1;
  if (mb->length() == 0)
    return 0;
  ssize_t send_cnt = handler->peer().send(mb->rd_ptr(), mb->length());//TEMP_FAILURE_RETRY(handler->peer().send(mb->rd_ptr(), mb->length()));
  int ret = mycomutil_translate_tcp_result(send_cnt);
  if (ret < 0)
    return ret;
  if (send_cnt > 0)
    mb->rd_ptr(send_cnt);
  return (mb->length() == 0 ? 0:1);
}

int mycomutil_send_message_block_queue(ACE_Svc_Handler<ACE_SOCK_STREAM, ACE_NULL_SYNCH> * handler,
    ACE_Message_Block *mb, bool discard)
{
/*************
  if (!mb)
    return -1;
  int ret;
  if (!handler)
  {
    MY_FATAL("null handler @mycomutil_send_message_block_queue.\n");
    ret = -1;
    goto _exit_;
  }

  if (!handler->msg_queue()->is_empty())
  {
    ACE_Time_Value nowait(ACE_OS::gettimeofday());
    if (handler->putq(mb, &nowait) < 0)
    {
      ret = -1;
      goto _exit_;
    }
    else return 1;
  }

  ret = mycomutil_send_message_block(handler, mb);
  if (ret < 0)
  {
    ret = -1;
    goto _exit_;
  }

  if (mb->length() == 0)
  {
    ret = 0;
    goto _exit_;
  } else
  {
    ACE_Time_Value nowait(ACE_OS::gettimeofday());
    if (handler->putq(mb, &nowait) < 0)
    {
      ret = -1;
      goto _exit_;
    }
    handler->reactor()->register_handler(handler, ACE_Event_Handler::WRITE_MASK);
    return 1;
  }

_exit_:
  if (discard)
    mb->release();
  return ret;
*******/

//the above implementation is error prone, rewrite to a simpler one
  if (!mb)
    return -1;
  if (!handler)
  {
    MY_FATAL("null handler @mycomutil_send_message_block_queue.\n");
    return -1;
  }

  MyMessageBlockGuard guard(discard ? mb: NULL);

  if (!handler->msg_queue()->is_empty()) //sticky avoiding
  {
    ACE_Time_Value nowait(ACE_Time_Value::zero);
    if (handler->putq(mb, &nowait) < 0)
      return -1;
    else
    {
      guard.detach();
      return 1;
    }
  }

  if (mycomutil_send_message_block(handler, mb) < 0)
    return -1;

  if (mb->length() == 0)
    return 0;
  else
  {
    ACE_Time_Value nowait(ACE_Time_Value::zero);
    if (handler->putq(mb, &nowait) < 0)
      return -1;
    else
      guard.detach();
    handler->reactor()->register_handler(handler, ACE_Event_Handler::WRITE_MASK);
    return 1;
  }
}

int mycomutil_recv_message_block(ACE_Svc_Handler<ACE_SOCK_STREAM, ACE_NULL_SYNCH> * handler, ACE_Message_Block *mb)
{
//  MY_DEBUG("on enter: mb->space()=%d\n", mb->space());
  if (!mb || !handler)
    return -1;
  if (mb->space() == 0)
    return 0;
  ssize_t recv_cnt = handler->peer().recv(mb->wr_ptr(), mb->space());//TEMP_FAILURE_RETRY(handler->peer().recv(mb->wr_ptr(), mb->space()));
//  MY_DEBUG("handler->recv() returns %d\n", (int)recv_cnt);
  int ret = mycomutil_translate_tcp_result(recv_cnt);
//  MY_DEBUG("tcp result = %d\n", ret);
  if (ret < 0)
    return -1;
  if (recv_cnt > 0)
    mb->wr_ptr(recv_cnt);
//  MY_DEBUG("on exit: mb->space()=%d\n", mb->space());
  return (mb->space() == 0 ? 0:1);
}


//MyFilePaths//

bool MyFilePaths::exist(const char * path)
{
  struct stat buf;
  return (::stat(path, &buf) == 0);
}

bool MyFilePaths::make_path(const char* path, bool self_only)
{
  return (mkdir(path, self_only? DIR_FLAG_SELF : DIR_FLAG_ALL) == 0 || ACE_OS::last_error() == EEXIST);
}

bool MyFilePaths::make_path(char * path, int prefix_len, bool is_file, bool self_only)
{
  if (!path || !*path)
    return false;
  if (prefix_len > (int)strlen(path))
    return false;
  char * ptr = path + prefix_len;
  while (*ptr == '/')
    ++ptr;
  char * end_ptr;
  while ((end_ptr = strchr(ptr, '/')) != NULL)
  {
    *end_ptr = 0;
    if (!make_path(path, self_only))
      return false;
    //MY_INFO("mkdir: %s\n", path);
    *end_ptr = '/';
    ptr = end_ptr + 1;
  }

  if (!is_file)
    return make_path(path, self_only);
    //MY_INFO("mkdir: %s\n", path);
  return true;
}

bool MyFilePaths::make_path_const(const char* path, int prefix_len, bool is_file, bool self_only)
{
  MyPooledMemGuard path_copy;
  path_copy.init_from_string(path);
  return MyFilePaths::make_path(path_copy.data(), prefix_len, is_file, self_only);
}

bool MyFilePaths::make_path(const char * path, const char * subpath, bool is_file, bool self_only)
{
  if (unlikely(!path || !subpath))
    return false;
  MyPooledMemGuard path_x;
  path_x.init_from_string(path, "/", subpath);
  return make_path(path_x.data(), strlen(path) + 1, is_file, self_only);
}

bool MyFilePaths::copy_path(const char * srcdir, const char * destdir, bool self_only)
{
  if (unlikely(!srcdir || !*srcdir || !destdir || !*destdir))
    return false;
  if (!make_path(destdir, self_only))
  {
    MY_ERROR("can not create directory %s, %s\n", destdir, (const char *)MyErrno());
    return false;
  }

  DIR * dir = opendir(srcdir);
  if (!dir)
  {
    MY_ERROR("can not open directory: %s %s\n", srcdir, (const char*)MyErrno());
    return false;
  }

  int len1 = ACE_OS::strlen(srcdir);
  int len2 = ACE_OS::strlen(destdir);

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
    ACE_OS::sprintf(msrc.data(), "%s/%s", srcdir, entry->d_name);
    MyMemPoolFactoryX::instance()->get_mem(len2 + len + 2, &mdest);
    ACE_OS::sprintf(mdest.data(), "%s/%s", destdir, entry->d_name);

    if (entry->d_type == DT_REG)
    {
      if (!copy_file(msrc.data(), mdest.data(), self_only))
      {
        MY_ERROR("copy_file(%s) to (%s) failed %s\n", msrc.data(), mdest.data(), (const char *)MyErrno());
        closedir(dir);
        return false;
      }
    }
    else if(entry->d_type == DT_DIR)
    {
      if (!copy_path(msrc.data(), mdest.data(), self_only))
      {
        closedir(dir);
        return false;
      }
    } else
      MY_WARNING("unknown file type (= %d) for file @MyFilePaths::copy_directory file = %s/%s\n",
           entry->d_type, srcdir, entry->d_name);
  };

  closedir(dir);
  return true;
}

bool MyFilePaths::copy_path_zap(const char * srcdir, const char * destdir, bool self_only, bool zap)
{
  if (unlikely(!srcdir || !*srcdir || !destdir || !*destdir))
    return false;

  if (zap)
    remove_path(destdir, true);

  if (!make_path_const(destdir, 1, false, self_only))
  {
    MY_ERROR("can not create directory %s, %s\n", destdir, (const char *)MyErrno());
    return false;
  }

  DIR * dir = opendir(srcdir);
  if (!dir)
  {
    MY_ERROR("can not open directory: %s %s\n", srcdir, (const char*)MyErrno());
    return false;
  }

  int len1 = ACE_OS::strlen(srcdir);
  int len2 = ACE_OS::strlen(destdir);

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
    ACE_OS::sprintf(msrc.data(), "%s/%s", srcdir, entry->d_name);
    MyMemPoolFactoryX::instance()->get_mem(len2 + len + 2, &mdest);
    ACE_OS::sprintf(mdest.data(), "%s/%s", destdir, entry->d_name);

    if (entry->d_type == DT_REG)
    {
      if (!copy_file(msrc.data(), mdest.data(), self_only))
      {
        MY_ERROR("copy_file(%s) to (%s) failed %s\n", msrc.data(), mdest.data(), (const char *)MyErrno());
        closedir(dir);
        return false;
      }
    }
    else if(entry->d_type == DT_DIR)
    {
      if (!copy_path_zap(msrc.data(), mdest.data(), self_only, true))
      {
        closedir(dir);
        return false;
      }
    } else
      MY_WARNING("unknown file type (= %d) for file @MyFilePaths::copy_directory file = %s/%s\n",
           entry->d_type, srcdir, entry->d_name);
  };

  closedir(dir);
  return true;
}

bool MyFilePaths::remove_path(const char * path, bool ignore_eror)
{
  if (unlikely(!path || !*path))
    return false;

  DIR * dir = opendir(path);
  if (!dir)
  {
    if (!ignore_eror)
      MY_ERROR("can not open directory: %s %s\n", path, (const char*)MyErrno());
    return false;
  }

  bool ret = true;
  int len1 = ACE_OS::strlen(path);

  struct dirent *entry;
  while ((entry = readdir(dir)) != NULL)
  {
    if (!entry->d_name)
      continue;
    if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
      continue;

    MyPooledMemGuard msrc;
    int len = ACE_OS::strlen(entry->d_name);
    MyMemPoolFactoryX::instance()->get_mem(len1 + len + 2, &msrc);
    ACE_OS::sprintf(msrc.data(), "%s/%s", path, entry->d_name);

    if(entry->d_type == DT_DIR)
    {
      if (!remove_path(msrc.data(), ignore_eror))
      {
        closedir(dir);
        return false;
      }
    } else
    {
      if (unlink(msrc.data()) != 0)
      {
        if (!ignore_eror)
          MY_ERROR("can not remove file %s %s\n", msrc.data(), (const char*)MyErrno());
        ret = false;
      }
    }
  };

  closedir(dir);
  ret = ::remove(path) == 0;
  return ret;
}

bool MyFilePaths::remove_old_files(const char * path, time_t deadline)
{
  if (unlikely(!path || !*path))
    return false;

  struct stat buf;
  if (::stat(path, &buf) != 0)
    return false;

  if (S_ISREG(buf.st_mode))
  {
    if (buf.st_mtime < deadline)
      return remove(path);
  }
  else if (S_ISDIR(buf.st_mode))
  {
    DIR * dir = opendir(path);
    if (!dir)
    {
      MY_ERROR("can not open directory: %s %s\n", path, (const char*)MyErrno());
      return false;
    }

    bool ret = true;
    int len1 = ACE_OS::strlen(path);

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL)
    {
      if (!entry->d_name)
        continue;
      if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
        continue;

      MyPooledMemGuard msrc;
      int len = ACE_OS::strlen(entry->d_name);
      MyMemPoolFactoryX::instance()->get_mem(len1 + len + 2, &msrc);
      ACE_OS::sprintf(msrc.data(), "%s/%s", path, entry->d_name);

      if (!remove_old_files(msrc.data(), deadline))
        ret = false;
    };
    closedir(dir);
    return ret;
  } else
  {
    MY_ERROR("unknown type for file(%s) stat.st_mode(%d)\n", path, buf.st_mode);
    return false;
  }

  return true;
}

bool MyFilePaths::copy_file_by_fd(int src_fd, int dest_fd)
{
  const int BLOCK_SIZE = 4096;
  char buff[BLOCK_SIZE];
  int n_read, n_write;
  while (true)
  {
    n_read = ::read(src_fd, buff, BLOCK_SIZE);
    if (n_read == 0)
      return true;
    else if (n_read < 0)
    {
      MY_ERROR("can not read from file %s\n", (const char*)MyErrno());
      return false;
    }

    n_write = ::write(dest_fd, buff, n_read);
    if (n_write != n_read)
    {
      MY_ERROR("can not write to file %s\n", (const char*)MyErrno());
      return false;
    }

    if (n_read < BLOCK_SIZE)
      return true;
  }

  ACE_NOTREACHED(return true);
}

bool MyFilePaths::copy_file(const char * src, const char * dest, bool self_only)
{
  MyUnixHandleGuard hsrc, hdest;
  if (!hsrc.open_read(src))
    return false;
  if (!hdest.open_write(dest, true, true, false, self_only))
    return false;
  return copy_file_by_fd(hsrc.handle(), hdest.handle());
}

int MyFilePaths::cat_path(const char * path, const char * subpath, MyPooledMemGuard & result)
{
  if (unlikely(!path || !*path || !subpath || !*subpath))
    return -1;
  int dir_len = ACE_OS::strlen(path);
  bool separator_trailing = (path[dir_len -1] == '/');
  result.init_from_string(path, (separator_trailing? NULL: "/"), subpath);
  return (separator_trailing? dir_len: (dir_len + 1));
}

bool MyFilePaths::get_correlate_path(MyPooledMemGuard & pathfile, int skip)
{
  char * ptr = pathfile.data() + skip + 1;
  char * ptr2 = ACE_OS::strrchr(ptr, '.');
  if (unlikely(!ptr2 || ptr2 <= ptr))
    return false;
  *ptr2 = 0;
  if (unlikely(*(ptr2 - 1) == '/'))
    return false;
  return true;
}

bool MyFilePaths::rename(const char *old_path, const char * new_path, bool ignore_eror)
{
  bool result = (::rename(old_path, new_path) == 0);
  if (!result && !ignore_eror)
    MY_ERROR("rename %s to %s failed %s\n", old_path, new_path, (const char*)MyErrno());
  return result;
}

bool MyFilePaths::remove(const char *pathfile, bool ignore_error)
{
  bool result = (::remove(pathfile) == 0);
  if (!result && !ignore_error)
    MY_ERROR("remove %s failed %s\n", pathfile, (const char*)MyErrno());
  return result;
}

bool MyFilePaths::stat(const char *pathfile, struct stat * _stat)
{
  return (::stat(pathfile, _stat) == 0);
}

bool MyFilePaths::zap_path_except_mfile(const MyPooledMemGuard & path, const MyPooledMemGuard & mfile, bool ignore_error)
{
  MyPooledMemGuard mfile_path;
  mfile_path.init_from_string(mfile.data());
  char * ptr = ACE_OS::strrchr(mfile_path.data(), '.');
  if (ptr)
    *ptr = 0;

  DIR * dir = opendir(path.data());
  if (!dir)
  {
    if (!ignore_error)
      MY_ERROR("can not open directory: %s %s\n", path.data(), (const char*)MyErrno());
    return false;
  }

  struct dirent *entry;
  bool ret = true;
  while ((entry = readdir(dir)) != NULL)
  {
    if (!entry->d_name)
      continue;
    if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..") || !strcmp(entry->d_name, mfile.data())
        || !strcmp(entry->d_name, mfile_path.data()) )
      continue;

    MyPooledMemGuard msrc;
    msrc.init_from_string(path.data(), "/", entry->d_name);

    if(entry->d_type == DT_DIR)
    {
      if (!remove_path(msrc.data(), ignore_error))
        ret =  false;
    } else if (!remove(msrc.data(), ignore_error))
      ret = false;
  };

  closedir(dir);
  return ret;
}

void MyFilePaths::zap_empty_paths(const MyPooledMemGuard & path)
{
  DIR * dir = opendir(path.data());
  if (!dir)
    return;

  struct dirent *entry;
  while ((entry = readdir(dir)) != NULL)
  {
    if (!entry->d_name)
      continue;
    if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
      continue;

    if(entry->d_type == DT_DIR)
    {
      MyPooledMemGuard msrc;
      msrc.init_from_string(path.data(), "/", entry->d_name);
      zap_empty_paths(msrc);
    }
  };
  closedir(dir);
  remove(path.data(), true);
}

//MyTestClientPathGenerator//

void MyTestClientPathGenerator::make_paths(const char * app_data_path, int64_t _start, int _count)
{
  if (!app_data_path || !*app_data_path)
    return;
  char buff[PATH_MAX], str_client_id[64];
  ACE_OS::snprintf(buff, PATH_MAX - 1, "%s/", app_data_path);
  int prefix_len = strlen(buff);
  for (long long id = _start; id < _start + _count; ++ id)
  {
    ACE_OS::snprintf(str_client_id, 64 - 1, "%lld", (long long)id);
    client_id_to_path(str_client_id, buff + prefix_len, PATH_MAX - prefix_len - 1);
    MyFilePaths::make_path(buff, prefix_len + 1, false, true);
  }
}

void MyTestClientPathGenerator::make_paths_from_id_table(const char * app_data_path, MyClientIDTable * id_table)
{
  if (!app_data_path || !*app_data_path || !id_table)
    return;
  char buff[PATH_MAX], str_client_id[64];
  ACE_OS::snprintf(buff, PATH_MAX - 1, "%s/", app_data_path);
  int prefix_len = strlen(buff);
  int count = id_table->count();
  MyClientID id;
  MyPooledMemGuard path_x;
  for (int i = 0; i < count; ++ i)
  {
    id_table->value(i, &id);
    ACE_OS::snprintf(str_client_id, 64, "%s", id.as_string());
    client_id_to_path(str_client_id, buff + prefix_len, PATH_MAX - prefix_len - 1);
    MyFilePaths::make_path(buff, prefix_len + 1, false, true);
    path_x.init_from_string(buff, "/download");
    MyFilePaths::make_path(path_x.data(), true);
    path_x.init_from_string(buff, "/daily");
    MyFilePaths::make_path(path_x.data(), true);
    path_x.init_from_string(buff, "/tmp");
    MyFilePaths::remove_path(path_x.data(), true);
    MyFilePaths::make_path(path_x.data(), true);
    path_x.init_from_string(buff, "/backup");
    MyFilePaths::make_path(path_x.data(), true);
  }
}

bool MyTestClientPathGenerator::client_id_to_path(const char * id, char * result, int result_len)
{
  if (!id || !*id || !result)
    return false;
  int len = ACE_OS::strlen(id);
  if (result_len < len + 4)
  {
    MY_ERROR("not enough result_len\n");
    return false;
  }

  char prefix[3];
  len = (len >= 2 ? len - 2: 0);
  prefix[0] = id[len];
  prefix[1] = id[len + 1];
  prefix[2] = 0;
  ACE_OS::sprintf(result, "%s/%s", prefix, id);
  return true;
}


//MyUnixHandleGuard//

bool MyUnixHandleGuard::do_open(const char * filename, bool readonly, bool create, bool truncate, bool append, bool self_only)
{
  int fd;
  if (unlikely(!filename || !*filename))
    return false;
  if (readonly)
    fd = ::open(filename, O_RDONLY);//O_CREAT | O_TRUNC | O_RDWR, S_IRUSR | S_IWUSR);
  else
  {
    int flag = O_RDWR;
    if (create)
      flag |= O_CREAT;
    if (truncate)
      flag |= O_TRUNC;
    if (append)
      flag |= O_APPEND;
    fd = ::open(filename, flag, (self_only ? MyFilePaths::FILE_FLAG_SELF : MyFilePaths::FILE_FLAG_ALL));
  }
  if (fd < 0)
  {
    if (m_error_report)
      MY_ERROR("can not open file %s, %s\n", filename, (const char *)MyErrno());
    return false;
  }
  attach(fd);
  return true;
}


//MyMemPoolFactory//

MyMemPoolFactory::MyMemPoolFactory()
{
  m_message_block_pool = NULL;
  m_data_block_pool = NULL;
  m_global_alloc_count = 0;
}

MyMemPoolFactory::~MyMemPoolFactory()
{
  if (m_message_block_pool)
    delete m_message_block_pool;
  if (m_data_block_pool)
    delete m_data_block_pool;
  for (size_t i = 0; i < m_pools.size(); ++i)
    delete m_pools[i];
}

void MyMemPoolFactory::init(MyConfig * config)
{
  if(!g_use_mem_pool)
      return;

  const int KB = 1024;
  const int MB = 1024 * 1024;
  const int pool_size[] = {16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8 * KB, 16 * KB, 32 * KB,
                           64 * KB, 128 * KB, 256 * KB, 512 * KB, 2 * MB};
  //todo: change default pool size
  int count = sizeof (pool_size) / sizeof (int);
  m_pools.reserve(count);
  m_pool_sizes.reserve(count);

  if (config->is_client())
  {
    for(size_t i = 0;i < sizeof (pool_size) / sizeof (int);++i)
    {
      int m;
      if (pool_size[i] <= 8 * KB)
        m = 200;
      else if (pool_size[i] < 512 * KB)
        m = 20;
      else
        m = 2;
      m_pool_sizes.push_back(pool_size[i]);
      m_pools.push_back(new My_Cached_Allocator<ACE_Thread_Mutex>(m, pool_size[i]));
      m_pools[i]->setup();
    }
  }
  else if (MyConfigX::instance()->is_dist_server())
  {
    int m;

    for(size_t i = 0;i < sizeof (pool_size) / sizeof (int);++i)
    {
      if (pool_size[i] <= 8 * KB)
        m = std::max((int)((config->max_clients * 1.2)), 3000);
      else if (pool_size[i] < 512 * KB)
        m = 2 * MB / pool_size[i];
      else
        m = 2;
      m_pool_sizes.push_back(pool_size[i]);
      m_pools.push_back(new My_Cached_Allocator<ACE_Thread_Mutex>(m, pool_size[i]));
      m_pools[i]->setup();
    }
  }
  else if (config->is_middle_server())
  {
    for(size_t i = 0;i < sizeof (pool_size) / sizeof (int);++i)
    {
      int m;
      if (pool_size[i] <= 8 * KB)
        m = 2000;
      else if (pool_size[i] < 512 * KB)
        m = MB / pool_size[i];
      else
        m = 2;
      m_pool_sizes.push_back(pool_size[i]);
      m_pools.push_back(new My_Cached_Allocator<ACE_Thread_Mutex>(m, pool_size[i]));
      m_pools[i]->setup();
    }
  }

  int mb_number;
  if (config->is_client())
    mb_number = 200;
  else if (config->is_dist_server())
    mb_number = std::max((int)((config->max_clients * 4)), 4000);
  else
    mb_number = std::max((int)((config->max_clients * 2)), 2000);
  m_message_block_pool = new My_Cached_Allocator<ACE_Thread_Mutex>(mb_number, sizeof (ACE_Message_Block));
  m_data_block_pool = new My_Cached_Allocator<ACE_Thread_Mutex>(mb_number, sizeof (ACE_Data_Block));
}

int MyMemPoolFactory::find_first_index(int capacity)
{
  int count = m_pool_sizes.size();
  for (int i = 0; i < count; ++i)
  {
    if (capacity <= m_pool_sizes[i])
      return i;
  }
  return INVALID_INDEX;
}

int MyMemPoolFactory::find_pool(void * ptr)
{
  int count = m_pools.size();
  for (int i = 0; i < count; ++i)
  {
    if (m_pools[i]->in_range(ptr))
      return i;
  }
  return INVALID_INDEX;
}

ACE_Message_Block * MyMemPoolFactory::get_message_block(int capacity)
{
  if (unlikely(capacity <= 0))
  {
    MY_ERROR(ACE_TEXT("calling MyMemPoolFactory::get_message_block() with invalid capacity = %d\n"), capacity);
    return NULL;
  }
  if (!g_use_mem_pool)
  {
    ++ m_global_alloc_count;
    return new ACE_Message_Block(capacity);
  }
  int count = m_pools.size();
  ACE_Message_Block * result;
  bool bRetried = false;
  void * p;
  int idx = find_first_index(capacity);
  for (int i = idx; i < count; ++i)
  {
    p = m_message_block_pool->malloc();
    if (!p) //no way to go on
    {
      ++ m_global_alloc_count;
      return new ACE_Message_Block(capacity);
    }
    result = new (p) MyCached_Message_Block(capacity, m_pools[i], m_data_block_pool, m_message_block_pool);
    if (!result->data_block())
    {
      result->release();
      if (!bRetried)
      {
        bRetried = true;
        continue;
      } else
      {
        ++ m_global_alloc_count;
        //MY_DEBUG("global alloc of size(%d)\n", capacity);
        return new ACE_Message_Block(capacity);
      }
    } else
      return result;
  }
  ++ m_global_alloc_count;
  return new ACE_Message_Block(capacity);
}

ACE_Message_Block * MyMemPoolFactory::get_message_block_cmd_direct(int capacity, int command, bool is_send)
{
  return get_message_block_cmd(capacity - sizeof(MyDataPacketHeader), command, is_send);
}

ACE_Message_Block * MyMemPoolFactory::get_message_block_cmd(int capacity, int command, bool _send)
{
  if (unlikely(capacity < 0))
  {
    MY_FATAL("too samll capacity value (=%d) @MyMemPoolFactory::get_message_block(command)\n", capacity);
    return NULL;
  }
  ACE_Message_Block * mb = get_message_block(capacity + (int)sizeof(MyDataPacketHeader));
  if (likely(_send))
    mb->wr_ptr(mb->capacity());
  MyDataPacketHeader * dph = (MyDataPacketHeader *) mb->base();
  dph->command = command;
  dph->length = capacity + (int)sizeof(MyDataPacketHeader);
  dph->magic = MyDataPacketHeader::DATAPACKET_MAGIC;
  return mb;
}

ACE_Message_Block * MyMemPoolFactory::get_message_block_bs(int data_len, const char * cmd)
{
  if (unlikely(data_len < 0 || data_len > 10 * 1024 * 1024))
  {
    MY_FATAL("unexpected data_len (=%d) @MyMemPoolFactory::get_message_block_bs\n", data_len);
    return NULL;
  }
  int total_len = data_len + 8 + 4 + 2 + 1;
  ACE_Message_Block * mb = get_message_block(total_len);
  mb->wr_ptr(mb->capacity());
  char * ptr = mb->base();
  ptr[total_len - 1] = MyBSBasePacket::BS_PACKET_END_MARK;
  ACE_OS::snprintf(ptr, 9, "%08d", total_len);
  ACE_OS::memcpy(ptr + 8, "vc5X", 4);
  ACE_OS::memcpy(ptr + 12, cmd, 2);
  return mb;
}

bool MyMemPoolFactory::get_mem(int size, MyPooledMemGuard * guard)
{
  if (unlikely(!guard))
    return false;
  if (unlikely(guard->data() != NULL))
  {
    if (guard->m_size >= size)
      return true;
    else
      free_mem(guard);
  }

  char * p;
  int idx = g_use_mem_pool? find_first_index(size): INVALID_INDEX;
  if (idx == INVALID_INDEX || (p = (char*)m_pools[idx]->malloc()) == NULL)
  {
    if (g_use_mem_pool)
      MY_DEBUG("global alloc of size(%d)\n", size);
    ++ m_global_alloc_count;
    p = new char[size];
    guard->data(p, INVALID_INDEX, size);
    return true;
  }
  guard->data(p, idx, m_pools[idx]->chunk_size());
  return true;
}

void * MyMemPoolFactory::get_mem_x(int size)
{
  void * p;
  int idx = g_use_mem_pool? find_first_index(size): INVALID_INDEX;
  if (idx == INVALID_INDEX || (p = m_pools[idx]->malloc()) == NULL)
  {
    if (g_use_mem_pool)
      MY_DEBUG("global alloc of size(%d)\n", size);
    ++ m_global_alloc_count;
    p = (void*)new char[size];
  }
  return p;
}

void MyMemPoolFactory::free_mem_x(void * ptr)
{
  if (ptr == NULL)
  {
    ::delete [](char*)ptr;
    return;
  }

  int idx = g_use_mem_pool? find_pool(ptr): INVALID_INDEX;
  if (idx != INVALID_INDEX)
    m_pools[idx]->free(ptr);
  else
    ::delete [](char*)ptr;
}

void MyMemPoolFactory::free_mem(MyPooledMemGuard * guard)
{
  if (!guard || !guard->data())
    return;
  int idx = guard->index();
  if (idx == INVALID_INDEX)
    delete [] (char*)guard->data();
  else if (unlikely(idx < 0 || idx >= (int)m_pools.size()))
    MY_FATAL("attempt to release bad mem_pool data: index = %d, pool.size() = %d\n",
        idx, (int)m_pools.size());
  else
    m_pools[idx]->free(guard->data());
  guard->m_buff = NULL;
  guard->m_size = 0;
}

void MyMemPoolFactory::dump_info()
{
  ACE_DEBUG((LM_INFO, ACE_TEXT("    Global mem pool: alloc outside of mem pool=%d\n"), m_global_alloc_count.value()));
  if (!g_use_mem_pool)
    return;

  long nAlloc = 0, nFree = 0, nMaxUse = 0, nAllocFull = 0;
  int chunks;
  m_message_block_pool->get_usage(nAlloc, nFree, nMaxUse, nAllocFull);
  chunks = m_message_block_pool->chunks();
  MyBaseApp::mem_pool_dump_one("MessageBlockCtrlPool", nAlloc, nFree, nMaxUse, nAllocFull, m_message_block_pool->chunk_size(), chunks);

  nAlloc = 0, nFree = 0, nMaxUse = 0, nAllocFull = 0;
  m_data_block_pool->get_usage(nAlloc, nFree, nMaxUse, nAllocFull);
  chunks = m_data_block_pool->chunks();
  MyBaseApp::mem_pool_dump_one("DataBlockCtrlPool", nAlloc, nFree, nMaxUse, nAllocFull, m_data_block_pool->chunk_size(), chunks);

  const int BUFF_LEN = 64;
  char buff[BUFF_LEN];
  for(int i = 0; i < (int)m_pools.size(); ++i)
  {
    nAlloc = 0, nFree = 0, nMaxUse = 0, nAllocFull = 0;
    m_pools[i]->get_usage(nAlloc, nFree, nMaxUse, nAllocFull);
    chunks = m_pools[i]->chunks();
    ACE_OS::snprintf(buff, BUFF_LEN, "DataPool.%02d", i + 1);
    MyBaseApp::mem_pool_dump_one(buff, nAlloc, nFree, nMaxUse, nAllocFull, m_pools[i]->chunk_size(), chunks);
  }
}


//MyStringTokenizer//

MyStringTokenizer::MyStringTokenizer(char * str, const char * separator)
{
  m_str = str;
  m_separator = separator;
}

char * MyStringTokenizer::get_token()
{
  char * token;
  while (true)
  {
    token = strtok_r(m_str, m_separator, &m_savedptr);
    if (!token)
    {
      m_str = NULL;
      return NULL;
    }
//    if (unlikely(!*token))
//      continue;
    m_str = NULL;
    return token;
  }

  ACE_NOTREACHED(return NULL);
}
