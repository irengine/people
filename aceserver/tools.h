#ifndef MYCOMUTIL_H_
#define MYCOMUTIL_H_

#include <ace/Log_Msg.h>
#include <ace/Message_Block.h>
#include <ace/SOCK_Stream.h>
#include <ace/Svc_Handler.h>
#include <ace/Malloc_T.h>
#include <ace/FILE_IO.h>
#include <ace/OS_NS_string.h>
#include <ace/INET_Addr.h>
#include <uuid/uuid.h>
#include <new>
#include <vector>
#include <sys/types.h>
#include <stddef.h>

#ifndef MY_client_test
#define MY_client_test
#endif

#ifndef MY_server_test
#define MY_server_test
#endif

#ifdef __GNUC__
  #define likely(x)       __builtin_expect((x),1)
  #define unlikely(x)     __builtin_expect((x),0)
#else
  #define likely(x)       (x)
  #define unlikely(x)     (x)
#endif

typedef int8_t       i8;
typedef u_int8_t     u8;
typedef int16_t      i16;
typedef u_int16_t    u16;
typedef int32_t      i32;
typedef u_int32_t    u32;
typedef int64_t      i64;
typedef u_int64_t    u64;

extern bool g_use_mem_pool;

#define INFO_PREFIX       ACE_TEXT ("(%D %P|%t %N/%l)\n  INFO %I")
#define C_INFO(FMT, ...)     \
        ACE_DEBUG(( LM_INFO,  \
                    INFO_PREFIX FMT, \
                    ## __VA_ARGS__))

#define DEBUG_PREFIX       ACE_TEXT("(%D %P|%t %N/%l)\n  DEBUG  %I")
#define C_DEBUG(FMT, ...)     \
        ACE_DEBUG(( LM_DEBUG,  \
                    DEBUG_PREFIX FMT, \
                    ## __VA_ARGS__))

#define WARNING_PREFIX       ACE_TEXT("(%D %P|%t %N/%l)\n  WARN  %I")
#define C_WARNING(FMT, ...)     \
        ACE_DEBUG(( LM_WARNING,  \
                    WARNING_PREFIX FMT, \
                    ## __VA_ARGS__))

#define ERROR_PREFIX       ACE_TEXT("(%D %P|%t %N/%l)\n  ERROR  %I")
#define C_ERROR(FMT, ...)     \
        ACE_DEBUG(( LM_ERROR,  \
                    ERROR_PREFIX  FMT, \
                    ## __VA_ARGS__))

#define FATAL_PREFIX       ACE_TEXT("(%D %P|%t %N.%l)\n  FATAL  %I")
#define C_FATAL(FMT, ...)     \
        ACE_DEBUG(( LM_ERROR,  \
                    FATAL_PREFIX  FMT, \
                    ## __VA_ARGS__))

#define ASSERT_PREFIX       ACE_TEXT("(%D %P|%t %N.%l)\n  ASSERT failed %I")
#define __C_ASSERT(FMT, ...)     \
        ACE_DEBUG(( LM_ERROR,  \
                    ASSERT_PREFIX  FMT, \
                    ## __VA_ARGS__))


#ifndef NO_C_ASSERT

  #define C_ASSERT(condition, msg) \
    if (unlikely(!(condition))) \
      __C_ASSERT(msg);

  #define C_ASSERT_RETURN(condition, msg, ret) \
    if (unlikely(!(condition))) \
    { \
      __C_ASSERT(msg); \
      return (ret); \
    }

#else
  #define C_ASSERT(condition, msg) ((void) 0)
  #define C_ASSERT_RETURN (condition, msg, ret) ((void) 0)
#endif

class CErrno
{
public:
  CErrno(int err = ACE_OS::last_error())
  {
    format_message(err);
  }
  operator const char *()
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

class CObjDeletor
{
public:
  template <typename T> void operator()(const T * ptr)
  {
    delete ptr;
  }
};

class CPtrLess
{
public:
  template <typename T> bool operator()(T t1, T t2) const
  {
    return *t1 < *t2;
  }
};

const time_t const_one_hour = 60 * 60;
const time_t const_one_day = const_one_hour * 24;
const time_t const_one_month = const_one_day * 30;
const time_t const_one_year = const_one_month * 12;

class CMBGuard
{
public:
  CMBGuard(): m_mb(NULL)
  {}
  CMBGuard(ACE_Message_Block * mb): m_mb(mb)
  {}
  ~CMBGuard()
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

class CUnixFileGuard
{
public:
  enum { INVALID_HANDLE = -1 };
  CUnixFileGuard(): m_handle(INVALID_HANDLE)
  { m_error_report = true; }
  CUnixFileGuard(int _handle): m_handle(_handle), m_error_report(true)
  {}
  ~CUnixFileGuard()
  {
    if (m_handle >= 0)
      close(m_handle);
  }

  bool open_read(const char * filename)
  {
    return do_open(filename, true, false, false, false, false);
  }

  bool open_write(const char * filename, bool create, bool truncate, bool append, bool self_only)
  {
    return do_open(filename, false, create, truncate, append, self_only);
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

  void error_report(bool b)
  {
    m_error_report = b;
  }

private:
  bool do_open(const char * filename, bool readonly, bool create, bool truncate, bool append, bool self_only);
  int  m_handle;
  bool m_error_report;
};


class CSStreamGuard
{
public:
  CSStreamGuard(ACE_SOCK_Stream & s): m_ss(s)
  {}
  ~CSStreamGuard()
  {
    m_ss.close();
  }
private:
  ACE_SOCK_Stream & m_ss;
};


class CFIOGuard
{
public:
  CFIOGuard(ACE_FILE_IO & fio): m_fio(fio)
  {}
  ~CFIOGuard()
  {
    m_fio.close();
  }
private:
  ACE_FILE_IO & m_fio;
};

template <class ACE_LOCK> class CCachedAllocator: public ACE_Dynamic_Cached_Allocator<ACE_LOCK>
{
public:
  typedef ACE_Dynamic_Cached_Allocator<ACE_LOCK> super;

  CCachedAllocator (size_t n_chunks, size_t chunk_size): super(n_chunks, chunk_size)
  {
    m_begin = NULL;
    m_end = NULL;
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

  virtual ~CCachedAllocator() {}

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

    return result;
  }

  virtual void *calloc (size_t nbytes, char initial_value = '\0')
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

  int chunks() const
  {
    return m_chunks;
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
    typedef CCachedAllocator<Mutex> Mem_Pool; \
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
    typedef CCachedAllocator<Mutex> Mem_Pool; \
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

class CClientIDS;

class CClientPathGenerator
{
public:
  static void make_paths(const char * app_data_path, int64_t _start, int _count);
  static bool client_id_to_path(const char * id, char * result, int result_len);
  static void make_paths_from_id_table(const char * app_data_path, CClientIDS * id_table);
};

class CCachedMB: public ACE_Message_Block
{
public:
  CCachedMB(size_t size,
                ACE_Allocator * allocator_strategy,
                ACE_Allocator * data_block_allocator,
                ACE_Allocator * message_block_allocator,
                ACE_Message_Type type = MB_DATA);
};

class CCfg;
class CMemGuard;

class CMemPool
{
public:
  CMemPool();
  ~CMemPool();
  void init(CCfg * config);
  ACE_Message_Block * get_mb_bs(int data_len, const char * cmd);
  ACE_Message_Block * get_mb_ack(ACE_Message_Block * src);
  ACE_Message_Block * get_mb_cmd(int extra, int command, bool b_no_uuid = true);
  ACE_Message_Block * get_mb(int capacity);
  ACE_Message_Block * get_mb_cmd_direct(int capacity, int command, bool b_no_uuid = true);
  void release_mem_x(void * ptr); //use _x to avoid ambiguous of NULL pointer as parameter
  void release_mem(CMemGuard * guard);
  bool alloc_mem(int size, CMemGuard * guard);
  void * alloc_mem_x(int size);
  void print_info();

private:
  enum { INVALID_INDEX = 9999 };
  typedef ACE_Atomic_Op<ACE_Thread_Mutex, long> COUNTER;
  typedef std::vector<int> CPoolSizes;
  typedef CCachedAllocator<ACE_Thread_Mutex> CCachedPool;
  typedef std::vector<CCachedPool *> CCachedPools;

  int get_first_index(int capacity);
  int get_pool(void * ptr);
  CCachedAllocator<ACE_Thread_Mutex> *m_mb_pool;
  CCachedAllocator<ACE_Thread_Mutex> *m_data_block_pool;
  CPoolSizes m_pool_sizes;
  CCachedPools m_pools;
  COUNTER m_g_alloc_number;
};
typedef ACE_Unmanaged_Singleton<CMemPool, ACE_Null_Mutex> CMemPoolX;

class CMemGuard
{
public:
  CMemGuard(): m_buff(NULL), m_index(-1), m_size(0)
  {}

  ~CMemGuard()
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
      CMemPoolX::instance()->release_mem(this);
      m_buff = NULL;
    }
  }

  void from_string(const char * src);
  void from_string(const char * src1, const char * src2);
  void from_string(const char * src1, const char * src2, const char * src3);
  void from_string(const char * src1, const char * src2, const char * src3, const char * src4);
  void from_strings(const char * arr[], int len);

protected:
  friend class CMemPool;

  void data(void * _buff, int index, int size)
  {
    if (unlikely(m_buff != NULL))
      C_ERROR("mem leak @MyPooledMemGuard index=%d\n", m_index);
    m_buff = (char*)_buff;
    m_index = index;
    m_size = size;
  }
  int index() const
  {
    return m_index;
  }

private:
  CMemGuard(const CMemGuard &);
  CMemGuard & operator = (const CMemGuard &);
  char * m_buff;
  int m_index;
  int m_size;
};

template<typename T> class CCppAllocator
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
    typedef CCppAllocator<Other> other;
  };

  CCppAllocator() throw() {}

  template<class Other>
  CCppAllocator(const CCppAllocator<Other>&) throw() {}

  template<class Other>
  CCppAllocator& operator=(const CCppAllocator<Other>&) { return *this; }

  pointer allocate(size_type count, const void * = 0)
  {
    return static_cast<pointer> (CMemPoolX::instance()->alloc_mem_x(count * sizeof(T)));
  }

  void deallocate(pointer ptr, size_type)
  {
    CMemPoolX::instance()->release_mem_x(ptr);
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

class CPoolObjectDeletor
{
public:
  template <typename T> void operator()(const T * ptr)
  {
    ptr->T::~T();
    CMemPoolX::instance()->release_mem_x((void*)ptr);
  }
};

class CSysFS
{
public:
  enum
  {
    FILE_FLAG_SELF = S_IRUSR | S_IWUSR,
    FILE_FLAG_ALL = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH,
    DIR_FLAG_SELF = S_IRWXU,
    DIR_FLAG_ALL = S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH
  };
  static bool exist(const char * path);
  static bool make_path(const char* path, bool self_only);
  static bool make_path(char* path, int prefix_len, bool is_file, bool self_only);
  static bool make_path_const(const char* path, int prefix_len, bool is_file, bool self_only);
  static bool make_path(const char * path, const char * subpath, bool is_file, bool self_only);
  static bool copy_path(const char * srcdir, const char * destdir, bool self_only, bool syn);
  static bool copy_path_zap(const char * srcdir, const char * destdir, bool self_only, bool zap, bool syn);
  static bool remove_path(const char * path, bool ignore_eror);
  static bool remove_old_files(const char * path, time_t deadline);
  static bool copy_file_by_fd(int src_fd, int dest_fd);
  static bool copy_file(const char * src, const char * dest, bool self_only, bool syn);
  static int  cat_path(const char * path, const char * subpath, CMemGuard & result);
  static bool get_correlate_path(CMemGuard & pathfile, int skip);
  static bool remove(const char *pathfile, bool ignore_error = false);
  static bool zap(const char *pathfile, bool ignore_error);
  static bool rename(const char *old_path, const char * new_path, bool ignore_eror);
  static bool stat(const char *pathfile, struct stat * _stat);
  static int  filesize(const char *pathfile);
  static bool zap_path_except_mfile(const CMemGuard & path, const CMemGuard & mfile, bool ignore_error);
  static void zap_empty_paths(const CMemGuard & parent_path);
};

class CStringTokenizer
{
public:
  CStringTokenizer(char * str, const char * separator);
  char * get();

private:
  char * m_str;
  char * m_savedptr;
  const char * m_separator;
};

#define ftype_is_led(ftype) ((ftype) == '7' || (ftype) == '9')
#define ftype_is_adv(ftype) ((ftype) == '3' || (ftype) == '5' || (ftype) == '6')
#define ftype_is_adv_list(ftype) ((ftype) == '6')
#define ftype_is_chn(ftype) ((ftype) == '1' || (ftype) == '2' || (ftype) == '4')
#define ftype_is_frame(ftype) ((ftype) == '0')
#define ftype_is_backgnd(ftype) ((ftype) == '8')
#define ftype_is_vd(ftype) ((ftype) == '3' || (ftype) == '5' || (ftype) == '6' || (ftype) == '8')
#define ftype_is_valid(ftype) ((ftype) >= '0' && (ftype) <= '9')

#define type_is_valid(type) ((type) == '0' || (type) == '1' || (type) == '3')
#define type_is_single(type) ((type) == '0')
#define type_is_multi(type) ((type) == '1')
#define type_is_all(type) ((type) == '3')

bool c_util_mb_putq(ACE_Task<ACE_MT_SYNCH> * target, ACE_Message_Block * mb, const char * err_msg);
int  c_util_send_message_block_queue(ACE_Svc_Handler<ACE_SOCK_STREAM, ACE_NULL_SYNCH> * handler, ACE_Message_Block *mb, bool discard);
int  c_util_recv_message_block(ACE_Svc_Handler<ACE_SOCK_STREAM, ACE_NULL_SYNCH> * handler, ACE_Message_Block *mb);
int  c_util_translate_tcp_result(ssize_t transfer_return_value);
int  c_util_send_message_block(ACE_Svc_Handler<ACE_SOCK_STREAM, ACE_NULL_SYNCH> * handler, ACE_Message_Block *mb);

bool c_util_generate_time_string(char * result_buff, int buff_len, bool full, time_t t = time(NULL));
bool c_util_find_tag_value(char * & ptr, const char * tag, char * & value, char terminator);
bool c_util_calculate_file_md5(const char * _file, CMemGuard & md5_result);
size_t c_util_string_hash(const char * str);
bool c_util_string_end_with(const char * src, const char * key);
void c_util_generate_random_password(char * buff, const int password_len);
void c_util_string_replace_char(char * s, const char src, const char dest);
void c_util_hex_dump(void * ptr, int len, char * result_buff, int buff_len);

class CStrHasher
{
public:
  size_t operator()(const char * x) const
  {
    return c_util_string_hash(x);
  }
};

class CStrEqual
{
public:
  bool operator()(const char * x, const char * y) const
  {
    return ACE_OS::strcmp(x, y) == 0;
  }
};

typedef struct
{
    u_int32_t erk[64];
    u_int32_t drk[64];
    int nr;
} aes_context;

int  aes_set_key( aes_context *ctx, u_int8_t *key, int nbits );
void aes_encrypt( aes_context *ctx, u_int8_t input[16], u_int8_t output[16] );
void aes_decrypt( aes_context *ctx, u_int8_t input[16], u_int8_t output[16] );

#pragma pack(push, 1)

class MyClientID
{
public:
  union ClientID
  {
    char    as_string[];
    i64 as_long[3];
  }client_id;

  enum
  {
    ID_LENGTH_AS_INT64 = sizeof(client_id)/sizeof(int64_t),
    ID_LENGTH_AS_STRING = sizeof(client_id)/sizeof(char)
  };

#define client_id_value_i client_id.as_long
#define client_id_value_s client_id.as_string

  MyClientID()
  {
    ACE_OS::memset((void*)client_id_value_i, 0, ID_LENGTH_AS_STRING);
  }

  MyClientID(const char * s)
  {
    ACE_OS::memset((void*)client_id_value_i, 0, ID_LENGTH_AS_STRING);

    if (!s || !*s)
      return;
    while(*s == ' ')
      ++s;
    ACE_OS::strsncpy(client_id_value_s, s, ID_LENGTH_AS_STRING);
  }

  void fix_data()
  {
    client_id_value_s[ID_LENGTH_AS_STRING - 1] = 0;
  }

  MyClientID & operator = (const char * s)
  {
    ACE_OS::memset((void*)client_id_value_i, 0, ID_LENGTH_AS_STRING);

    if (!s || !*s)
      return *this;
    while(*s == ' ')
      ++s;
    ACE_OS::strsncpy(client_id_value_s, s, ID_LENGTH_AS_STRING);
    return *this;
  }

  MyClientID & operator = (const MyClientID & rhs)
  {
    if (&rhs == this)
      return *this;
    ACE_OS::memcpy(client_id.as_string, rhs.client_id.as_string, ID_LENGTH_AS_STRING);
    client_id_value_s[ID_LENGTH_AS_STRING - 1] = 0;
    return *this;
  }

  const char * as_string() const
  {
    return client_id_value_s;
  }

  bool is_null() const
  {
    return (client_id_value_s[0] == 0);
  }

  bool operator < (const MyClientID & rhs) const
  {
    for (int i = 0; i < ID_LENGTH_AS_INT64; ++i)
    {
      if (client_id_value_i[i] < rhs.client_id_value_i[i])
        return true;
      if (client_id_value_i[i] > rhs.client_id_value_i[i])
        return false;
    }
    return false;
  }

  bool operator == (const MyClientID & rhs) const
  {
    for (int i = 0; i < ID_LENGTH_AS_INT64; ++i)
    {
      if (client_id_value_i[i] != rhs.client_id_value_i[i])
        return false;
    }
    return true;
  }

  bool operator != (const MyClientID & rhs) const
  {
    return ! operator == (rhs);
  }

  void trim_tail_space()
  {
    char * ptr = client_id_value_s;
    for (int i = ID_LENGTH_AS_STRING - 1; i >= 0; --i)
    {
      if (ptr[i] == 0)
        continue;
      else if (ptr[i] == ' ')
        ptr[i] = 0;
      else
        break;
    }
  }

};


#ifndef Null_Item
  #define Null_Item "!"
#endif
//every packet commute between server and clients at least has this head
class MyDataPacketHeader
{
public:
  enum { DATAPACKET_MAGIC = 0x80089397 };
  enum { ITEM_SEPARATOR = '*', MIDDLE_SEPARATOR = '?', FINISH_SEPARATOR = ':' };
  enum { NULL_ITEM_LENGTH = 1 };

  enum COMMAND
  {
    CMD_NULL = 0,
    CMD_HEARTBEAT_PING,
    CMD_CLIENT_VERSION_CHECK_REQ,
    CMD_CLIENT_VERSION_CHECK_REPLY,
    CMD_LOAD_BALANCE_REQ,
    CMD_SERVER_FILE_MD5_LIST,
    CMD_HAVE_DIST_TASK,
    CMD_FTP_FILE,
    CMD_IP_VER_REQ,
    CMD_UI_CLICK,
    CMD_PC_ON_OFF,
    CMD_HARDWARE_ALARM,
    CMD_VLC,
    CMD_REMOTE_CMD,
    CMD_ACK,
    CMD_VLC_EMPTY,
    CMD_TEST,
    CMD_PSP,
    CMD_TQ,
    CMD_END,
    CMD_DISCONNECT_INTERNAL
  };
  i32 length;
  u32 magic;
  uuid_t  uuid;
  i16 command;
};

class MyDataPacketExt: public MyDataPacketHeader
{
public:
  char data[0];

  bool guard();
};

class MyClientVersionCheckRequest: public MyDataPacketHeader
{
public:
  u8 client_version_major;
  u8 client_version_minor;
  u8 server_id;
  MyClientID client_id;
  char hw_ver[0];

  void validate_data()
  {
    client_id.fix_data();
  }

};

class MyIpVerRequest: public MyDataPacketHeader
{
public:
  u8 client_version_major;
  u8 client_version_minor;
};

class MyClientVersionCheckReply: public MyDataPacketHeader
{
public:
  enum REPLY_CODE
  {
    VER_OK = 1,
    VER_OK_CAN_UPGRADE,
    VER_MISMATCH,
    VER_ACCESS_DENIED,
    VER_SERVER_BUSY,
    VER_SERVER_LIST
  };
  enum { MAX_REPLY_DATA_LENGTH = 4096 };
  i8 reply_code;
  char data[0]; //placeholder
};

bool my_dph_validate_base(const MyDataPacketHeader * header);
bool my_dph_validate_file_md5_list(const MyDataPacketHeader * header);
bool my_dph_validate_ftp_file(const MyDataPacketHeader * header);
bool my_dph_validate_plc_alarm(const MyDataPacketHeader * header);
bool my_dph_validate_load_balance_req(const MyDataPacketHeader * header);
bool my_dph_validate_client_version_check_reply(const MyDataPacketHeader * header);
bool my_dph_validate_client_version_check_req(const MyDataPacketHeader * header, const int extra = 0);
bool my_dph_validate_vlc_empty(const MyDataPacketHeader * header);
#define my_dph_validate_have_dist_task my_dph_validate_base
#define my_dph_validate_heart_beat my_dph_validate_base

class MyLoadBalanceRequest: public MyDataPacketHeader
{
public:
  enum { IP_ADDR_LENGTH = INET_ADDRSTRLEN };
  char ip_addr[IP_ADDR_LENGTH];
  i32 clients_connected;

  void set_ip_addr(const char * s)
  {
    if (unlikely(!s || !*s))
      ip_addr[0] = 0;
    else
    {
      ACE_OS::memset(ip_addr, 0, MyLoadBalanceRequest::IP_ADDR_LENGTH); //noise muffler
      ACE_OS::strsncpy(ip_addr, s, MyLoadBalanceRequest::IP_ADDR_LENGTH);
    }
  }

};

class MyPLCAlarm: public MyDataPacketHeader
{
public:
  char x;
  char y;
};

class MyBSBasePacket
{
public:
  enum { LEN_SIZE = 8, MAGIC_SIZE = 4, CMD_SIZE = 2, DATA_OFFSET = LEN_SIZE + MAGIC_SIZE + CMD_SIZE };
  enum { BS_PARAMETER_SEPARATOR = '#', BS_PACKET_END_MARK = '$' };

  void packet_len(int _len);
  int  packet_len() const;
  void packet_magic();
  bool check_header() const;
  void packet_cmd(const char * _cmd);
  bool is_cmd(const char * _cmd);
  bool guard();

  char len[LEN_SIZE];
  char magic[4];
  char cmd[2];
  char data[0];
};

#define MY_BS_HEART_BEAT_CMD    "04"
#define MY_BS_ADV_CLICK_CMD     "05"
#define MY_BS_IP_VER_CMD        "01"
#define MY_BS_HARD_MON_CMD      "03"
#define MY_BS_DIST_FEEDBACK_CMD "02"
#define MY_BS_DIST_FBDETAIL_CMD "12"
#define MY_BS_POWERON_LINK_CMD  "07"
#define MY_BS_PATCH_FILE_CMD    "06"
#define MY_BS_VLC_CMD           "10"
#define MY_BS_VLC_EMPTY_CMD     "13"

#pragma pack(pop)


#endif
