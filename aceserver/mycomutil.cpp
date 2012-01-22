/*
 * mycomutil.cpp
 *
 *  Created on: Jan 2, 2012
 *      Author: root
 */

#include <algorithm>
#include "mycomutil.h"
#include "baseapp.h"

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
  if (!mb || !handler)
    return -1;
  if (mb->space() == 0)
    return 0;
  ssize_t recv_cnt = handler->peer().recv(mb->wr_ptr(), mb->space());//TEMP_FAILURE_RETRY(handler->peer().recv(mb->wr_ptr(), mb->space()));
  int ret = mycomutil_translate_tcp_result(recv_cnt);
  if (ret < 0)
    return -1;
  mb->wr_ptr(recv_cnt);
  return (mb->space() == 0 ? 0:1);
}

bool MyFilePaths::make_path(char * path, int prefix_len, bool is_file)
{
  if (!path || !*path)
    return false;
  if (prefix_len >= (int)strlen(path))
    return false;
  char * ptr = path + prefix_len;
  while (*ptr == '/')
    ++ptr;
  char * end_ptr;
  while ((end_ptr = strchr(ptr, '/')) != NULL)
  {
    *end_ptr = 0;
    mkdir(path, S_IRWXU);
    //MY_INFO("mkdir: %s\n", path);
    *end_ptr = '/';
    ptr = end_ptr + 1;
  }

  if (!is_file)
    mkdir(path, S_IRWXU);
    //MY_INFO("mkdir: %s\n", path);
  return true;
}

bool MyFilePaths::make_path(const char * path, const char * subpath, bool is_file)
{
  if (!path || !subpath)
    return false;
  char buff[PATH_MAX];
  ACE_OS::snprintf(buff, PATH_MAX - 1, "%s/%s", path, subpath);
  return make_path(buff, strlen(path) + 1, is_file);
}

#if defined(MY_client_test) || defined(MY_server_test)

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
    MyFilePaths::make_path(buff, prefix_len + 1, false);
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
  for (int i = 0; i < count; ++ i)
  {
    id_table->value(i, &id);
    ACE_OS::snprintf(str_client_id, 64 - 1, "%s", id.as_string());
    client_id_to_path(str_client_id, buff + prefix_len, PATH_MAX - prefix_len - 1);
    MyFilePaths::make_path(buff, prefix_len + 1, false);
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

#endif

//MyMemPoolFactory//

MyMemPoolFactory::MyMemPoolFactory()
{
  m_message_block_pool = NULL;
  m_data_block_pool = NULL;
  m_use_mem_pool = false;
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
  m_use_mem_pool = config->use_mem_pool;
  if (!m_use_mem_pool)
    return;

  const int pool_size[] = {16, 32, 64, 128, 256, 512, 1024, 2048, 4096};
  //todo: change default pool size
  int count = sizeof(pool_size) / sizeof(int);
  m_pools.reserve(count);
  for (size_t i = 0; i < sizeof(pool_size) / sizeof(int); ++i)
    m_pools.push_back(new My_Cached_Allocator<ACE_Thread_Mutex>
      (/*config->module_heart_beat_mem_pool_size*/ 3000, pool_size[i]));
//todo: change default pool's chunk number
  m_message_block_pool = new My_Cached_Allocator<ACE_Thread_Mutex>
    (config->message_control_block_mem_pool_size, sizeof(ACE_Message_Block));
  m_data_block_pool = new My_Cached_Allocator<ACE_Thread_Mutex>
    (config->message_control_block_mem_pool_size, sizeof(ACE_Data_Block));
}

int MyMemPoolFactory::find_first_index(int capacity)
{
  int count = m_pools.size();
  for (int i = 0; i < count; ++i)
  {
    if (size_t(capacity) <= m_pools[i]->chunk_size())
      return i;
  }
  return INVALID_INDEX;
}

ACE_Message_Block * MyMemPoolFactory::get_message_block(int capacity)
{
  if (capacity <= 0)
  {
    MY_ERROR(ACE_TEXT("calling MyMemPoolFactory::get_message_block() with invalid capacity = %d\n"), capacity);
    return NULL;
  }
  if (!m_use_mem_pool)
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
        return new ACE_Message_Block(capacity);
      }
    } else
      return result;
  }
  ++ m_global_alloc_count;
  return new ACE_Message_Block(capacity);
}

bool MyMemPoolFactory::get_mem(int size, MyPooledMemGuard * guard)
{
  if (unlikely(!guard))
    return false;
  if (unlikely(guard->data() != NULL))
    free_mem(guard);

  char * p;
  int idx = m_use_mem_pool? find_first_index(size): INVALID_INDEX;
  if (idx == INVALID_INDEX || (p = (char*)m_pools[idx]->malloc()) == NULL)
  {
    ++ m_global_alloc_count;
    p = new char[size];
    guard->data(p, INVALID_INDEX);
    return true;
  }
  guard->data(p, idx);
  return true;
}

void MyMemPoolFactory::free_mem(MyPooledMemGuard * guard)
{
  if (!guard || !guard->data())
    return;
  int idx = guard->index();
  if (idx == INVALID_INDEX)
    delete [] (char*)guard->data();
  else if (idx < 0 || idx >= (int)m_pools.size())
    MY_FATAL("attempt to release bad mem_pool data: index = %d, pool.size() = %d\n",
        idx, (int)m_pools.size());
  else
    m_pools[idx]->free(guard->data());
}

void MyMemPoolFactory::dump_info()
{
  ACE_DEBUG((LM_INFO, ACE_TEXT("    Global mem pool: alloc outside of mem pool =%d\n"), m_global_alloc_count.value()));
  if (!m_use_mem_pool)
    return;

  long nAlloc = 0, nFree = 0, nMaxUse = 0, nAllocFull = 0;
  m_message_block_pool->get_usage(nAlloc, nFree, nMaxUse, nAllocFull);
  MyBaseApp::mem_pool_dump_one("MessageBlockCtrlPool", nAlloc, nFree, nMaxUse, nAllocFull, m_message_block_pool->chunk_size());

  nAlloc = 0, nFree = 0, nMaxUse = 0, nAllocFull = 0;
  m_data_block_pool->get_usage(nAlloc, nFree, nMaxUse, nAllocFull);
  MyBaseApp::mem_pool_dump_one("DataBlockCtrlPool", nAlloc, nFree, nMaxUse, nAllocFull, m_data_block_pool->chunk_size());

  const int BUFF_LEN = 64;
  char buff[BUFF_LEN];
  for(int i = 0; i < (int)m_pools.size(); ++i)
  {
    nAlloc = 0, nFree = 0, nMaxUse = 0, nAllocFull = 0;
    m_pools[i]->get_usage(nAlloc, nFree, nMaxUse, nAllocFull);
    ACE_OS::snprintf(buff, BUFF_LEN, "DataPool.%d", i + 1);
    MyBaseApp::mem_pool_dump_one(buff, nAlloc, nFree, nMaxUse, nAllocFull, m_pools[i]->chunk_size());
  }
}
