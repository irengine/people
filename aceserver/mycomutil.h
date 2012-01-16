/*
 * mycomutil.h
 *
 *  Created on: Dec 29, 2011
 *      Author: root
 *      common utility
 */

#ifndef MYCOMUTIL_H_
#define MYCOMUTIL_H_

#include <ace/Log_Msg.h>
#include <ace/Message_Block.h>
#include <ace/SOCK_Stream.h>
#include <ace/Svc_Handler.h>
#include <ace/Malloc_T.h>
#include <new>
#include <vector>

#include "common.h"

#define INFO_PREFIX       ACE_TEXT ("(%D %P|%t %N/%l)\n  INFO %I")
#define MY_INFO(FMT, ...)     \
        ACE_DEBUG(( LM_INFO,  \
                    INFO_PREFIX FMT, \
                    ## __VA_ARGS__))

#define DEBUG_PREFIX       ACE_TEXT("(%D %P|%t %N/%l)\n  DEBUG  %I")
#define MY_DEBUG(FMT, ...)     \
        ACE_DEBUG(( LM_DEBUG,  \
                    DEBUG_PREFIX FMT, \
                    ## __VA_ARGS__))

#define WARNING_PREFIX       ACE_TEXT("(%D %P|%t %N/%l)\n  WARN  %I")
#define MY_WARNING(FMT, ...)     \
        ACE_DEBUG(( LM_WARNING,  \
                    WARNING_PREFIX FMT, \
                    ## __VA_ARGS__))

#define ERROR_PREFIX       ACE_TEXT("(%D %P|%t %N/%l)\n  ERROR  %I")
#define MY_ERROR(FMT, ...)     \
        ACE_DEBUG(( LM_ERROR,  \
                    ERROR_PREFIX  FMT, \
                    ## __VA_ARGS__))

#define FATAL_PREFIX       ACE_TEXT("(%D %P|%t %N.%l)\n  FATAL  %I")
#define MY_FATAL(FMT, ...)     \
        ACE_DEBUG(( LM_ERROR,  \
                    FATAL_PREFIX  FMT, \
                    ## __VA_ARGS__))


class MyErrno
{
public:
  MyErrno(int err = ACE_OS::last_error())
  {
    format_message(err);
  }
  operator const char *() //convert this object into a string
  {
    return buff;
  }
private:
  void format_message(int err)
  {
    ACE_OS::snprintf(buff, BUFF_LEN, "errno = %d msg = ", err);
    int len = ACE_OS::strlen(buff);
    //ACE is using _GNU_SOURCE, so we can not get the POSIX version of strerror_r as per POSIX200112L
    //using another buffer is needed here, since the GNU version is crapped
    char temp[BUFF_LEN];
    const char * ret = strerror_r(err, temp, BUFF_LEN);
    ACE_OS::strsncpy(buff + len, (ret ? ret: "NULL"), BUFF_LEN - len);
  }
  enum { BUFF_LEN = 256 };
  char buff[BUFF_LEN];
};

class MyObjectDeletor
{
public:
  template <typename T> void operator()(const T * ptr)
  {
    delete ptr;
  }
};

class MyPointerLess
{
public:
  template <typename T> bool operator()(T t1, T t2) const
  {
    return *t1 < *t2;
  }
};

class MyMessageBlockGuard
{
public:
  MyMessageBlockGuard(ACE_Message_Block * mb): m_mb(mb)
  {}
  ~MyMessageBlockGuard()
  {
    if (m_mb)
      m_mb->release();
  }
  void detach()
  {
    m_mb = NULL;
  }
private:
  ACE_Message_Block * m_mb;
};

template <class ACE_LOCK> class My_Cached_Allocator: public ACE_Dynamic_Cached_Allocator<ACE_LOCK>
{
public:
  typedef ACE_Dynamic_Cached_Allocator<ACE_LOCK> super;

  My_Cached_Allocator (size_t n_chunks, size_t chunk_size): super(n_chunks, chunk_size)
  {
    m_alloc_count = 0;
    m_free_count = 0;
    m_max_in_use_count = 0;
    m_chunk_size = chunk_size;
    m_alloc_on_full_count = 0;
  }

  virtual ~My_Cached_Allocator() {}

  virtual void *malloc (size_t nbytes = 0)
  {
    void * result = super::malloc(nbytes);

    {
      ACE_MT (ACE_GUARD_RETURN(ACE_LOCK, ace_mon, this->m_mutex, result));
      if (result)
      {
        ++m_alloc_count;
        if (m_alloc_count - m_free_count > m_max_in_use_count)
          m_max_in_use_count = m_alloc_count - m_free_count;
      } else
        ++m_alloc_on_full_count;
    }

//    MY_DEBUG(ACE_TEXT("call My_Cached_Allocator.malloc(%d) = %@ from chunk_size = %d\n"),
//        nbytes, result, m_chunk_size);
    return result;
  }

  virtual void *calloc (size_t nbytes,
                          char initial_value = '\0')
  {
    void * result = super::calloc(nbytes, initial_value);
    {
      ACE_MT (ACE_GUARD_RETURN(ACE_LOCK, ace_mon, this->m_mutex, result));
      if (result)
      {
        ++m_alloc_count;
        if (m_alloc_count - m_free_count > m_max_in_use_count)
          m_max_in_use_count = m_alloc_count - m_free_count;
      } else
        ++m_alloc_on_full_count;
    }

//    MY_DEBUG(ACE_TEXT("call My_Cached_Allocator.calloc(%d) = %@ from chunk_size = %d\n"),
//        nbytes, result, m_chunk_size);
    return result;
  }
// NOT implemented
//  virtual void *calloc (size_t n_elem,  size_t elem_size,
//                        char initial_value = '\0')
  void free (void * p)
  {
    {
      ACE_MT (ACE_GUARD(ACE_LOCK, ace_mon, this->m_mutex));
//      MY_DEBUG(ACE_TEXT("call My_Cached_Allocator.free(%@) from chunk_size = %d\n"), p, m_chunk_size);
      if (p != NULL)
        ++m_free_count;
    }
    super::free(p);
  }

  void get_usage(long & alloc_count, long &free_count, long & max_in_use_count, long &alloc_on_full_count)
  {
    ACE_MT (ACE_GUARD(ACE_LOCK, ace_mon, this->m_mutex));
    alloc_count = m_alloc_count;
    free_count = m_free_count;
    max_in_use_count = m_max_in_use_count;
    alloc_on_full_count = m_alloc_on_full_count;
  }

  size_t chunk_size() const
  {
    return m_chunk_size;
  }

private:
  ACE_LOCK m_mutex;
  size_t m_chunk_size;
  long m_alloc_count;
  long m_free_count;
  long m_max_in_use_count;
  long m_alloc_on_full_count;
};

#define DECLARE_MEMORY_POOL(Cls, Mutex) \
  public: \
    typedef My_Cached_Allocator<Mutex> Mem_Pool; \
    static void* operator new(size_t _size, std::new_handler p = 0) \
    { \
      ACE_UNUSED_ARG(p); \
      if (_size != sizeof(Cls) || !MyConfigX::instance()->use_mem_pool) \
        return ::operator new(_size); \
      void* _ptr = m_mem_pool->malloc(); \
      if (_ptr) \
        return _ptr; \
      else \
        throw std::bad_alloc(); \
    } \
    static void * operator new (size_t _size, const std::nothrow_t &) \
    { \
      return operator new(_size, 0); \
    } \
    static void operator delete(void* _ptr) \
    { \
      if (_ptr != NULL) \
      { \
        if (!MyConfigX::instance()->use_mem_pool) \
        { \
          ::operator delete(_ptr); \
          return; \
        } \
        m_mem_pool->free(_ptr); \
      } \
    } \
    static void init_mem_pool(int pool_size) \
    { \
      if (MyConfigX::instance()->use_mem_pool) \
        m_mem_pool = new Mem_Pool(pool_size, sizeof(Cls)); \
    } \
    static void fini_mem_pool() \
    { \
      if (m_mem_pool) \
      { \
        delete m_mem_pool; \
        m_mem_pool = NULL; \
      } \
    } \
    static Mem_Pool * mem_pool() \
    { \
      return m_mem_pool; \
    } \
  private: \
    static Mem_Pool * m_mem_pool

#define DECLARE_MEMORY_POOL__NOTHROW(Cls, Mutex) \
  public: \
    typedef My_Cached_Allocator<Mutex> Mem_Pool; \
    static void* operator new(size_t _size, std::new_handler p = 0) throw() \
    { \
      ACE_UNUSED_ARG(p); \
      if (_size != sizeof(Cls) || !MyConfigX::instance()->use_mem_pool) \
        return ::operator new(_size); \
      return m_mem_pool->malloc(); \
    } \
    static void operator delete(void* _ptr) \
    { \
      if (_ptr != NULL) \
      { \
        if (!MyConfigX::instance()->use_mem_pool) \
        { \
          ::operator delete(_ptr); \
          return; \
        } \
        m_mem_pool->free(_ptr); \
      } \
    } \
    static void init_mem_pool(int pool_size) \
    { \
      if (MyConfigX::instance()->use_mem_pool) \
        m_mem_pool = new Mem_Pool(pool_size, sizeof(Cls)); \
    } \
    static void fini_mem_pool() \
    { \
      if (m_mem_pool) \
      { \
        delete m_mem_pool; \
        m_mem_pool = NULL; \
      } \
    } \
    static Mem_Pool * mem_pool() \
    { \
      return m_mem_pool; \
    } \
  private: \
    static Mem_Pool * m_mem_pool

#define PREPARE_MEMORY_POOL(Cls) \
  Cls::Mem_Pool * Cls::m_mem_pool = NULL

#if defined(MY_client_test) || defined(MY_server_test)

//simple implementation, not thread safe, multiple calls to put on the same id will generate duplicate
//IDs for later gets. but it works for our test. that is enough
class MyTestClientIDGenerator
{
public:
  MyTestClientIDGenerator(int64_t _start, int _count)
  {
    m_start = _start;
    m_count = _count;
    m_id_list.reserve(m_count);
    for (int64_t i = m_start + m_count - 1; i >= m_start; --i)
      m_id_list.push_back(i);
  }
  const char * get()
  {
    if (m_id_list.empty())
      return NULL;
    int64_t id = m_id_list.back();
    m_id_list.pop_back();
    ACE_OS::snprintf(m_result, BUFF_LEN, "%lld", (long long)id);
    return m_result;
  }
  void put(const char * id)
  {
    if (!id || !*id)
      return;
    int64_t val = atoll(id);
    m_id_list.push_back(val);
  }
  bool empty() const
  {
    return m_id_list.empty();
  }
  int count() const
  {
    return m_id_list.size();
  }
private:
  typedef std::vector<int64_t> MyClientIDList;
  enum { BUFF_LEN = 32 };
  char  m_result[BUFF_LEN];
  int64_t m_start;
  int     m_count;
  MyClientIDList m_id_list;
};

class MyTestClientPathGenerator
{
public:
  static void make_paths(const char * app_data_path, int64_t _start, int _count);
  static bool make_path(char* path, int prefix_len, bool is_file);
  static bool make_path(const char * path, const char * subpath, bool is_file);
  static bool client_id_to_path(const char * id, char * result, int result_len);
};

#endif //MY_client_test

void mycomutil_hex_dump(void * ptr, int len, char * result_buff, int buff_len);

int mycomutil_translate_tcp_result(ssize_t transfer_return_value);
int mycomutil_send_message_block(ACE_Svc_Handler<ACE_SOCK_STREAM, ACE_NULL_SYNCH> * handler, ACE_Message_Block *mb);
int mycomutil_send_message_block_queue(ACE_Svc_Handler<ACE_SOCK_STREAM, ACE_NULL_SYNCH> * handler, ACE_Message_Block *mb, bool discard);
int mycomutil_recv_message_block(ACE_Svc_Handler<ACE_SOCK_STREAM, ACE_NULL_SYNCH> * handler, ACE_Message_Block *mb);

#endif /* MYCOMUTIL_H_ */
