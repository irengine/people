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

extern bool g_use_mem_pool;

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
  MyMessageBlockGuard(): m_mb(NULL)
  {}
  MyMessageBlockGuard(ACE_Message_Block * mb): m_mb(mb)
  {}
  ~MyMessageBlockGuard()
  {
    if (m_mb)
      m_mb->release();
  }
  void attach(ACE_Message_Block * mb)
  {
    if (unlikely(m_mb == mb))
      return;
    if (m_mb)
      m_mb->release();
    m_mb = mb;
  }
  ACE_Message_Block * detach()
  {
    ACE_Message_Block * result = m_mb;
    m_mb = NULL;
    return result;
  }
  ACE_Message_Block * data() const
  {
    return m_mb;
  }
private:
  ACE_Message_Block * m_mb;
};

class MyUnixHandleGuard
{
public:
  enum { INVALID_HANDLE = -1 };
  MyUnixHandleGuard(): m_handle(INVALID_HANDLE)
  {}
  MyUnixHandleGuard(int _handle): m_handle(_handle)
  {}
  ~MyUnixHandleGuard()
  {
    if (m_handle >= 0)
      close(m_handle);
  }

  bool open_read(const char * filename)
  {
    return do_open(filename, true, false, false, false);
  }

  bool open_write(const char * filename, bool create, bool truncate, bool append)
  {
    return do_open(filename, false, create, truncate, append);
  }

  int handle() const
  {
    return m_handle;
  }
  void attach(int _handle)
  {
    if (unlikely(m_handle == _handle))
      return;
    if (m_handle >= 0)
      close(m_handle);
    m_handle = _handle;
  }
  int detach()
  {
    int h = m_handle;
    m_handle = INVALID_HANDLE;
    return h;
  }
  bool valid() const
  {
    return m_handle >= 0;
  }

private:
  bool do_open(const char * filename, bool readonly, bool create, bool truncate, bool append)
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
      fd = ::open(filename, flag, S_IRUSR | S_IWUSR);
    }
    if (fd < 0)
    {
      MY_ERROR("can not open file %s, %s\n", filename, (const char *)MyErrno());
      return false;
    }
    attach(fd);
    return true;
  }

  int m_handle;

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
    m_chunks = n_chunks;
  }

  void setup()
  {
    m_end = super::malloc();
    super::free(m_end);
    m_begin = (void*)((char*)m_end - m_chunk_size * (m_chunks - 1)); //close interval
  }

  bool in_range(void * ptr) const
  {
    return (ptr >= m_begin && ptr <= m_end);
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
  int  m_chunks;
  long m_alloc_count;
  long m_free_count;
  long m_max_in_use_count;
  long m_alloc_on_full_count;
  void * m_begin;
  void * m_end;
};

#define DECLARE_MEMORY_POOL(Cls, Mutex) \
  public: \
    typedef My_Cached_Allocator<Mutex> Mem_Pool; \
    static void* operator new(size_t _size, std::new_handler p = 0) \
    { \
      ACE_UNUSED_ARG(p); \
      if (_size != sizeof(Cls) || !g_use_mem_pool) \
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
        if (!g_use_mem_pool) \
        { \
          ::operator delete(_ptr); \
          return; \
        } \
        m_mem_pool->free(_ptr); \
      } \
    } \
    static void init_mem_pool(int pool_size) \
    { \
      if (g_use_mem_pool) \
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
      if (_size != sizeof(Cls) || !g_use_mem_pool) \
        return ::operator new(_size); \
      return m_mem_pool->malloc(); \
    } \
    static void operator delete(void* _ptr) \
    { \
      if (_ptr != NULL) \
      { \
        if (!g_use_mem_pool) \
        { \
          ::operator delete(_ptr); \
          return; \
        } \
        m_mem_pool->free(_ptr); \
      } \
    } \
    static void init_mem_pool(int pool_size) \
    { \
      if (g_use_mem_pool) \
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

class MyClientIDTable;

class MyTestClientPathGenerator
{
public:
  static void make_paths(const char * app_data_path, int64_t _start, int _count);
  static bool client_id_to_path(const char * id, char * result, int result_len);
  static void make_paths_from_id_table(const char * app_data_path, MyClientIDTable * id_table);
};

#endif //MY_client_test


class MyCached_Message_Block: public ACE_Message_Block
{
public:
  MyCached_Message_Block(size_t size,
                ACE_Allocator * allocator_strategy,
                ACE_Allocator * data_block_allocator,
                ACE_Allocator * message_block_allocator,
                ACE_Message_Type type = MB_DATA);
};

class MyConfig;
class MyPooledMemGuard;

class MyMemPoolFactory
{
public:
  MyMemPoolFactory();
  ~MyMemPoolFactory();
  void init(MyConfig * config);
  ACE_Message_Block * get_message_block(int capacity);
  bool get_mem(int size, MyPooledMemGuard * guard);
  void * get_mem_x(int size);
  void free_mem_x(void * ptr); //use _x to avoid ambiguous of NULL pointer as parameter
  void free_mem(MyPooledMemGuard * guard);
  void dump_info();

private:
  enum { INVALID_INDEX = 9999 };
  typedef My_Cached_Allocator<ACE_Thread_Mutex> MyMemPool;
  typedef std::vector<MyMemPool *> MyMemPools;
  typedef ACE_Atomic_Op<ACE_Thread_Mutex, long> COUNTER;

  int find_first_index(int capacity);
  int find_pool(void * ptr);
  My_Cached_Allocator<ACE_Thread_Mutex> *m_message_block_pool;
  My_Cached_Allocator<ACE_Thread_Mutex> *m_data_block_pool;
  MyMemPools m_pools;
  COUNTER m_global_alloc_count;
};
typedef ACE_Unmanaged_Singleton<MyMemPoolFactory, ACE_Null_Mutex> MyMemPoolFactoryX;

class MyPooledMemGuard
{
public:
  MyPooledMemGuard(): m_buff(NULL), m_index(-1)
  {}

  ~MyPooledMemGuard()
  {
    free();
  }

  char * data() const
  {
    return (char*)m_buff;
  }

  void free()
  {
    if (m_buff)
    {
      MyMemPoolFactoryX::instance()->free_mem(this);
      m_buff = NULL;
    }
  }

  void init_from_string(const char * src);
  void init_from_string(const char * src1, const char * src2);
  void init_from_string(const char * src1, const char * src2, const char * src3);
  void init_from_string(const char * src1, const char * src2, const char * src3, const char * src4);
  void init_from_strings(const char * arr[], int len);

protected:
  friend class MyMemPoolFactory;

  void data(void * _buff, int index)
  {
    if (m_buff)
      MY_ERROR("memory leak @MyPooledMemGuard, index = %d\n", m_index);
    m_buff = (char*)_buff;
    m_index = index;
  }
  int index() const
  {
    return m_index;
  }

private:
  MyPooledMemGuard(const MyPooledMemGuard &);
  MyPooledMemGuard & operator = (const MyPooledMemGuard &);
  char * m_buff;
  int m_index;
};

template<typename T> class MyAllocator
{
public:
  typedef std::size_t size_type;
  typedef std::ptrdiff_t difference_type;
  typedef T *pointer;
  typedef const T *const_pointer;
  typedef T& reference;
  typedef const T& const_reference;
  typedef T value_type;

  pointer address(reference val) const { return &val; }
  const_pointer address(const_reference val) const { return &val; }

  template<class Other> struct rebind
  {
    typedef MyAllocator<Other> other;
  };

  MyAllocator() throw() {}

  template<class Other>
  MyAllocator(const MyAllocator<Other>&) throw() {}

  template<class Other>
  MyAllocator& operator=(const MyAllocator<Other>&) { return *this; }

  pointer allocate(size_type count, const void * = 0)
  {
    return static_cast<pointer> (MyMemPoolFactoryX::instance()->get_mem_x(count * sizeof(T)));
  }

  void deallocate(pointer ptr, size_type)
  {
    MyMemPoolFactoryX::instance()->free_mem_x(ptr);
  }

  void construct(pointer ptr, const T& val)
  {
    new ((void *)ptr) T(val);
  }

  void destroy(pointer ptr)
  {
    ptr->T::~T();
  }

  size_type max_size() const throw()
  {
    return UINT_MAX / sizeof(T);
  }
};

class MyPooledObjectDeletor
{
public:
  template <typename T> void operator()(const T * ptr)
  {
    ptr->T::~T();
    MyMemPoolFactoryX::instance()->free_mem_x((void*)ptr);
  }
};

class MyFilePaths
{
public:
  static bool make_path(char* path, int prefix_len, bool is_file);
  static bool make_path(const char * path, const char * subpath, bool is_file);
  static bool copy_path(const char * srcdir, const char * destdir);
  static bool remove_path(const char * path);
  static bool copy_file(int src_fd, int dest_fd);
  static int  cat_path(const char * path, const char * subpath, MyPooledMemGuard & result);
  static bool get_correlate_path(MyPooledMemGuard & pathfile, int skip);
};

class MyStringTokenizer
{
public:
  MyStringTokenizer(char * str, const char * separator);
  char * get_token();

private:
  char * m_str;
  char * m_savedptr;
  const char * m_separator;
};

void mycomutil_hex_dump(void * ptr, int len, char * result_buff, int buff_len);
void mycomutil_generate_random_password(char * buff, const int password_len);
bool mycomutil_find_tag_value(char * & ptr, const char * tag, char * & value, char terminator);

int mycomutil_translate_tcp_result(ssize_t transfer_return_value);
int mycomutil_send_message_block(ACE_Svc_Handler<ACE_SOCK_STREAM, ACE_NULL_SYNCH> * handler, ACE_Message_Block *mb);
int mycomutil_send_message_block_queue(ACE_Svc_Handler<ACE_SOCK_STREAM, ACE_NULL_SYNCH> * handler, ACE_Message_Block *mb, bool discard);
int mycomutil_recv_message_block(ACE_Svc_Handler<ACE_SOCK_STREAM, ACE_NULL_SYNCH> * handler, ACE_Message_Block *mb);

#endif /* MYCOMUTIL_H_ */
