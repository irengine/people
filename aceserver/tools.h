#ifndef tools_h_akjd81pajkjf5
#define tools_h_akjd81pajkjf5

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
typedef int          ni;
typedef unsigned int ui;
typedef bool         truefalse;
typedef char         text;
typedef unsigned char utext;
typedef ACE_Message_Block CMB;

#define EXTERN extern
#define SF     static
#define CONST  const
#define DVOID  void

EXTERN truefalse g_use_mem_pool;

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
  #define C_ASSERT(condition, msg) ((DVOID) 0)
  #define C_ASSERT_RETURN (condition, msg, ret) ((DVOID) 0)
#endif

class CErrno
{
public:
  CErrno(ni err = ACE_OS::last_error())
  {
    format_message(err);
  }
  operator CONST text *()
  {
    return buff;
  }
private:
  DVOID format_message(ni err)
  {
    snprintf(buff, BUFF_LEN, "errno = %d msg = ", err);
    ni len = strlen(buff);
    //ACE is using _GNU_SOURCE, so we can not get the POSIX version of strerror_r as per POSIX200112L
    //using another buffer is needed here, since the GNU version is crapped
    text temp[BUFF_LEN];
    CONST text * ret = strerror_r(err, temp, BUFF_LEN);
    ACE_OS::strsncpy(buff + len, (ret ? ret: "NULL"), BUFF_LEN - len);
  }
  enum { BUFF_LEN = 256 };
  text buff[BUFF_LEN];
};

class CObjDeletor
{
public:
  template <typename T> DVOID operator()(CONST T * ptr)
  {
    delete ptr;
  }
};

class CPtrLess
{
public:
  template <typename T> truefalse operator()(T t1, T t2) CONST
  {
    return *t1 < *t2;
  }
};

CONST time_t CONST_one_hour = 60 * 60;
CONST time_t CONST_one_day = CONST_one_hour * 24;
CONST time_t CONST_one_month = CONST_one_day * 30;
CONST time_t CONST_one_year = CONST_one_month * 12;

class CMBGuard
{
public:
  CMBGuard(): m_mb(NULL)
  {}
  CMBGuard(CMB * mb): m_mb(mb)
  {}
  ~CMBGuard()
  {
    if (m_mb)
      m_mb->release();
  }
  DVOID attach(CMB * mb)
  {
    if (unlikely(m_mb == mb))
      return;
    if (m_mb)
      m_mb->release();
    m_mb = mb;
  }
  CMB * detach()
  {
    CMB * result = m_mb;
    m_mb = NULL;
    return result;
  }
  CMB * data() CONST
  {
    return m_mb;
  }
private:
  CMB * m_mb;
};

class CUnixFileGuard
{
public:
  enum { INVALID_HANDLE = -1 };
  CUnixFileGuard(): m_handle(INVALID_HANDLE)
  { m_error_report = true; }
  CUnixFileGuard(ni _handle): m_handle(_handle), m_error_report(true)
  {}
  ~CUnixFileGuard()
  {
    if (m_handle >= 0)
      close(m_handle);
  }

  truefalse open_read(CONST text * filename)
  {
    return do_open(filename, true, false, false, false, false);
  }

  truefalse open_write(CONST text * filename, truefalse create, truefalse truncate, truefalse append, truefalse self_only)
  {
    return do_open(filename, false, create, truncate, append, self_only);
  }

  ni handle() CONST
  {
    return m_handle;
  }
  DVOID attach(ni _handle)
  {
    if (unlikely(m_handle == _handle))
      return;
    if (m_handle >= 0)
      close(m_handle);
    m_handle = _handle;
  }
  ni detach()
  {
    ni h = m_handle;
    m_handle = INVALID_HANDLE;
    return h;
  }
  truefalse valid() CONST
  {
    return m_handle >= 0;
  }

  DVOID error_report(truefalse b)
  {
    m_error_report = b;
  }

private:
  truefalse do_open(CONST text * filename, truefalse readonly, truefalse create, truefalse truncate, truefalse append, truefalse self_only);
  ni  m_handle;
  truefalse m_error_report;
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

  DVOID setup()
  {
    m_end = super::malloc();
    super::free(m_end);
    m_begin = (void*)((char*)m_end - m_chunk_size * (m_chunks - 1)); //close interval
  }

  truefalse in_range(DVOID * ptr) CONST
  {
    return (ptr >= m_begin && ptr <= m_end);
  }

  virtual ~CCachedAllocator() {}

  virtual DVOID *malloc (size_t nbytes = 0)
  {
    DVOID * result = super::malloc(nbytes);

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

  virtual DVOID *calloc (size_t nbytes, text initial_value = '\0')
  {
    DVOID * result = super::calloc(nbytes, initial_value);
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
//  virtual DVOID *calloc (size_t n_elem,  size_t elem_size,
//                        text initial_value = '\0')
  DVOID free (DVOID * p)
  {
    {
      ACE_MT (ACE_GUARD(ACE_LOCK, ace_mon, this->m_mutex));
      if (p != NULL)
        ++m_free_count;
    }
    super::free(p);
  }

  DVOID get_usage(long & alloc_count, long &free_count, long & max_in_use_count, long &alloc_on_full_count)
  {
    ACE_MT (ACE_GUARD(ACE_LOCK, ace_mon, this->m_mutex));
    alloc_count = m_alloc_count;
    free_count = m_free_count;
    max_in_use_count = m_max_in_use_count;
    alloc_on_full_count = m_alloc_on_full_count;
  }

  size_t chunk_size() CONST
  {
    return m_chunk_size;
  }

  ni chunks() CONST
  {
    return m_chunks;
  }

private:
  ACE_LOCK m_mutex;
  size_t m_chunk_size;
  ni  m_chunks;
  long m_alloc_count;
  long m_free_count;
  long m_max_in_use_count;
  long m_alloc_on_full_count;
  DVOID * m_begin;
  DVOID * m_end;
};

#define DECLARE_MEMORY_POOL(Cls, Mutex) \
  public: \
    typedef CCachedAllocator<Mutex> Mem_Pool; \
    SF void* operator new(size_t _size, std::new_handler p = 0) \
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
    SF DVOID * operator new (size_t _size, CONST std::nothrow_t &) \
    { \
      return operator new(_size, 0); \
    } \
    SF DVOID operator delete(void* _ptr) \
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
    SF DVOID init_mem_pool(ni pool_size) \
    { \
      if (g_use_mem_pool) \
        m_mem_pool = new Mem_Pool(pool_size, sizeof(Cls)); \
    } \
    SF DVOID fini_mem_pool() \
    { \
      if (m_mem_pool) \
      { \
        delete m_mem_pool; \
        m_mem_pool = NULL; \
      } \
    } \
    SF Mem_Pool * mem_pool() \
    { \
      return m_mem_pool; \
    } \
  private: \
    SF Mem_Pool * m_mem_pool

#define DECLARE_MEMORY_POOL__NOTHROW(Cls, Mutex) \
  public: \
    typedef CCachedAllocator<Mutex> Mem_Pool; \
    SF void* operator new(size_t _size, std::new_handler p = 0) throw() \
    { \
      ACE_UNUSED_ARG(p); \
      if (_size != sizeof(Cls) || !g_use_mem_pool) \
        return ::operator new(_size); \
      return m_mem_pool->malloc(); \
    } \
    SF DVOID operator delete(void* _ptr) \
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
    SF DVOID init_mem_pool(ni pool_size) \
    { \
      if (g_use_mem_pool) \
        m_mem_pool = new Mem_Pool(pool_size, sizeof(Cls)); \
    } \
    SF DVOID fini_mem_pool() \
    { \
      if (m_mem_pool) \
      { \
        delete m_mem_pool; \
        m_mem_pool = NULL; \
      } \
    } \
    SF Mem_Pool * mem_pool() \
    { \
      return m_mem_pool; \
    } \
  private: \
    SF Mem_Pool * m_mem_pool

#define PREPARE_MEMORY_POOL(Cls) \
  Cls::Mem_Pool * Cls::m_mem_pool = NULL

class CClientIDS;

class CClientPathGenerator
{
public:
  SF DVOID make_paths(CONST text * app_data_path, int64_t _start, ni _count);
  SF truefalse client_id_to_path(CONST text * id, text * result, ni result_len);
  SF DVOID make_paths_from_id_table(CONST text * app_data_path, CClientIDS * id_table);
};

class CCachedMB: public CMB
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
  DVOID init(CCfg * config);
  CMB * get_mb_bs(ni data_len, CONST text * cmd);
  CMB * get_mb_ack(CMB * src);
  CMB * get_mb_cmd(ni extra, ni command, truefalse b_no_uuid = true);
  CMB * get_mb(ni capacity);
  CMB * get_mb_cmd_direct(ni capacity, ni command, truefalse b_no_uuid = true);
  DVOID release_mem_x(DVOID * ptr); //use _x to avoid ambiguous of NULL pointer as parameter
  DVOID release_mem(CMemGuard * guard);
  truefalse alloc_mem(ni size, CMemGuard * guard);
  DVOID * alloc_mem_x(ni size);
  DVOID print_info();

private:
  enum { INVALID_INDEX = 9999 };
  typedef ACE_Atomic_Op<ACE_Thread_Mutex, long> COUNTER;
  typedef std::vector<int> CPoolSizes;
  typedef CCachedAllocator<ACE_Thread_Mutex> CCachedPool;
  typedef std::vector<CCachedPool *> CCachedPools;

  ni get_first_index(ni capacity);
  ni get_pool(DVOID * ptr);
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

  text * data() CONST
  {
    return (char*)m_buff;
  }

  DVOID free()
  {
    if (m_buff)
    {
      CMemPoolX::instance()->release_mem(this);
      m_buff = NULL;
    }
  }

  DVOID from_string(CONST text * src);
  DVOID from_string(CONST text * src1, CONST text * src2);
  DVOID from_string(CONST text * src1, CONST text * src2, CONST text * src3);
  DVOID from_string(CONST text * src1, CONST text * src2, CONST text * src3, CONST text * src4);
  DVOID from_strings(CONST text * arr[], ni len);

protected:
  friend class CMemPool;

  DVOID data(DVOID * _buff, ni index, ni size)
  {
    if (unlikely(m_buff != NULL))
      C_ERROR("mem leak @MyPooledMemGuard index=%d\n", m_index);
    m_buff = (char*)_buff;
    m_index = index;
    m_size = size;
  }
  ni index() CONST
  {
    return m_index;
  }

private:
  CMemGuard(CONST CMemGuard &);
  CMemGuard & operator = (CONST CMemGuard &);
  text * m_buff;
  ni m_index;
  ni m_size;
};

template<typename T> class CCppAllocator
{
public:
  typedef std::size_t size_type;
  typedef std::ptrdiff_t difference_type;
  typedef T *pointer;
  typedef CONST T *const_pointer;
  typedef T& reference;
  typedef CONST T& const_reference;
  typedef T value_type;

  pointer address(reference val) CONST { return &val; }
  const_pointer address(const_reference val) CONST { return &val; }

  template<class Other> struct rebind
  {
    typedef CCppAllocator<Other> other;
  };

  CCppAllocator() throw() {}

  template<class Other>
  CCppAllocator(CONST CCppAllocator<Other>&) throw() {}

  template<class Other>
  CCppAllocator& operator=(CONST CCppAllocator<Other>&) { return *this; }

  pointer allocate(size_type count, CONST DVOID * = 0)
  {
    return static_cast<pointer> (CMemPoolX::instance()->alloc_mem_x(count * sizeof(T)));
  }

  DVOID deallocate(pointer ptr, size_type)
  {
    CMemPoolX::instance()->release_mem_x(ptr);
  }

  DVOID construct(pointer ptr, CONST T& val)
  {
    new ((DVOID *)ptr) T(val);
  }

  DVOID destroy(pointer ptr)
  {
    ptr->T::~T();
  }

  size_type max_size() CONST throw()
  {
    return UINT_MAX / sizeof(T);
  }
};

class CPoolObjectDeletor
{
public:
  template <typename T> DVOID operator()(CONST T * ptr)
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
  SF truefalse exist(CONST text * path);
  SF truefalse make_path(CONST char* path, truefalse self_only);
  SF truefalse make_path(char* path, ni prefix_len, truefalse is_file, truefalse self_only);
  SF truefalse make_path_const(CONST char* path, ni prefix_len, truefalse is_file, truefalse self_only);
  SF truefalse make_path(CONST text * path, CONST text * subpath, truefalse is_file, truefalse self_only);
  SF truefalse copy_path(CONST text * srcdir, CONST text * destdir, truefalse self_only, truefalse syn);
  SF truefalse copy_path_zap(CONST text * srcdir, CONST text * destdir, truefalse self_only, truefalse zap, truefalse syn);
  SF truefalse remove_path(CONST text * path, truefalse ignore_eror);
  SF truefalse remove_old_files(CONST text * path, time_t deadline);
  SF truefalse copy_file_by_fd(ni src_fd, ni dest_fd);
  SF truefalse copy_file(CONST text * src, CONST text * dest, truefalse self_only, truefalse syn);
  SF ni  cat_path(CONST text * path, CONST text * subpath, CMemGuard & result);
  SF truefalse get_correlate_path(CMemGuard & pathfile, ni skip);
  SF truefalse remove(CONST text *pathfile, truefalse ignore_error = false);
  SF truefalse zap(CONST text *pathfile, truefalse ignore_error);
  SF truefalse rename(CONST text *old_path, CONST text * new_path, truefalse ignore_eror);
  SF truefalse stat(CONST text *pathfile, struct stat * _stat);
  SF ni  filesize(CONST text *pathfile);
  SF truefalse zap_path_except_mfile(CONST CMemGuard & path, CONST CMemGuard & mfile, truefalse ignore_error);
  SF DVOID zap_empty_paths(CONST CMemGuard & parent_path);
};

class CStringTokenizer
{
public:
  CStringTokenizer(text * str, CONST text * separator);
  text * get();

private:
  text * m_str;
  text * m_savedptr;
  CONST text * m_separator;
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

truefalse c_util_mb_putq(ACE_Task<ACE_MT_SYNCH> * target, CMB * mb, CONST text * err_msg);
int  c_util_send_message_block_queue(ACE_Svc_Handler<ACE_SOCK_STREAM, ACE_NULL_SYNCH> * handler, CMB *mb, truefalse discard);
int  c_util_recv_message_block(ACE_Svc_Handler<ACE_SOCK_STREAM, ACE_NULL_SYNCH> * handler, CMB *mb);
int  c_util_translate_tcp_result(ssize_t transfer_return_value);
int  c_util_send_message_block(ACE_Svc_Handler<ACE_SOCK_STREAM, ACE_NULL_SYNCH> * handler, CMB *mb);

truefalse c_util_generate_time_string(text * result_buff, ni buff_len, truefalse full, time_t t = time(NULL));
truefalse c_util_find_tag_value(text * & ptr, CONST text * tag, text * & value, text terminator);
truefalse c_util_calculate_file_md5(CONST text * _file, CMemGuard & md5_result);
size_t c_util_string_hash(CONST text * str);
truefalse c_util_string_end_with(CONST text * src, CONST text * key);
DVOID c_util_gen_random_password(text * buff, CONST ni password_len);
DVOID c_util_string_replace_text(text * s, CONST text src, CONST text dest);
DVOID c_util_hex_dump(DVOID * ptr, ni len, text * result_buff, ni buff_len);

class CStrHasher
{
public:
  size_t operator()(CONST text * x) CONST
  {
    return c_util_string_hash(x);
  }
};

class CStrEqual
{
public:
  truefalse operator()(CONST text * x, CONST text * y) CONST
  {
    return strcmp(x, y) == 0;
  }
};

typedef struct
{
    u32 erk[64];
    u32 drk[64];
    ni nr;
} aes_context;

int  aes_set_key( aes_context *ctx, u8 *key, ni nbits );
DVOID aes_encrypt( aes_context *ctx, u8 input[16], u8 output[16] );
DVOID aes_decrypt( aes_context *ctx, u8 input[16], u8 output[16] );

#pragma pack(push, 1)

class MyClientID
{
public:
  union ClientID
  {
    text as_string[];
    i64 as_long[3];
  }client_id;

  enum
  {
    ID_LENGTH_AS_INT64 = sizeof(client_id)/sizeof(i64),
    ID_LENGTH_AS_STRING = sizeof(client_id)/sizeof(text)
  };

#define client_id_value_i client_id.as_long
#define client_id_value_s client_id.as_string

  MyClientID()
  {
    memset((void*)client_id_value_i, 0, ID_LENGTH_AS_STRING);
  }

  MyClientID(CONST text * s)
  {
    memset((void*)client_id_value_i, 0, ID_LENGTH_AS_STRING);

    if (!s || !*s)
      return;
    while(*s == ' ')
      ++s;
    ACE_OS::strsncpy(client_id_value_s, s, ID_LENGTH_AS_STRING);
  }

  DVOID fix_data()
  {
    client_id_value_s[ID_LENGTH_AS_STRING - 1] = 0;
  }

  MyClientID & operator = (CONST text * s)
  {
    memset((void*)client_id_value_i, 0, ID_LENGTH_AS_STRING);

    if (!s || !*s)
      return *this;
    while(*s == ' ')
      ++s;
    ACE_OS::strsncpy(client_id_value_s, s, ID_LENGTH_AS_STRING);
    return *this;
  }

  MyClientID & operator = (CONST MyClientID & rhs)
  {
    if (&rhs == this)
      return *this;
    memcpy(client_id.as_string, rhs.client_id.as_string, ID_LENGTH_AS_STRING);
    client_id_value_s[ID_LENGTH_AS_STRING - 1] = 0;
    return *this;
  }

  CONST text * as_string() CONST
  {
    return client_id_value_s;
  }

  truefalse is_null() CONST
  {
    return (client_id_value_s[0] == 0);
  }

  truefalse operator < (CONST MyClientID & rhs) CONST
  {
    for (ni i = 0; i < ID_LENGTH_AS_INT64; ++i)
    {
      if (client_id_value_i[i] < rhs.client_id_value_i[i])
        return true;
      if (client_id_value_i[i] > rhs.client_id_value_i[i])
        return false;
    }
    return false;
  }

  truefalse operator == (CONST MyClientID & rhs) CONST
  {
    for (ni i = 0; i < ID_LENGTH_AS_INT64; ++i)
    {
      if (client_id_value_i[i] != rhs.client_id_value_i[i])
        return false;
    }
    return true;
  }

  truefalse operator != (CONST MyClientID & rhs) CONST
  {
    return ! operator == (rhs);
  }

  DVOID trim_tail_space()
  {
    text * ptr = client_id_value_s;
    for (ni i = ID_LENGTH_AS_STRING - 1; i >= 0; --i)
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
  text data[0];

  truefalse guard();
};

class MyClientVersionCheckRequest: public MyDataPacketHeader
{
public:
  u8 client_version_major;
  u8 client_version_minor;
  u8 server_id;
  MyClientID client_id;
  text hw_ver[0];

  DVOID validate_data()
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
  text data[0]; //placeholder
};

truefalse my_dph_validate_base(CONST MyDataPacketHeader * header);
truefalse my_dph_validate_file_md5_list(CONST MyDataPacketHeader * header);
truefalse my_dph_validate_ftp_file(CONST MyDataPacketHeader * header);
truefalse my_dph_validate_plc_alarm(CONST MyDataPacketHeader * header);
truefalse my_dph_validate_load_balance_req(CONST MyDataPacketHeader * header);
truefalse my_dph_validate_client_version_check_reply(CONST MyDataPacketHeader * header);
truefalse my_dph_validate_client_version_check_req(CONST MyDataPacketHeader * header, CONST ni extra = 0);
truefalse my_dph_validate_vlc_empty(CONST MyDataPacketHeader * header);
#define my_dph_validate_have_dist_task my_dph_validate_base
#define my_dph_validate_heart_beat my_dph_validate_base

class MyLoadBalanceRequest: public MyDataPacketHeader
{
public:
  enum { IP_ADDR_LENGTH = INET_ADDRSTRLEN };
  text ip_addr[IP_ADDR_LENGTH];
  i32 clients_connected;

  DVOID set_ip_addr(CONST text * s)
  {
    if (unlikely(!s || !*s))
      ip_addr[0] = 0;
    else
    {
      memset(ip_addr, 0, MyLoadBalanceRequest::IP_ADDR_LENGTH); //noise muffler
      ACE_OS::strsncpy(ip_addr, s, MyLoadBalanceRequest::IP_ADDR_LENGTH);
    }
  }

};

class MyPLCAlarm: public MyDataPacketHeader
{
public:
  text x;
  text y;
};

class MyBSBasePacket
{
public:
  enum { LEN_SIZE = 8, MAGIC_SIZE = 4, CMD_SIZE = 2, DATA_OFFSET = LEN_SIZE + MAGIC_SIZE + CMD_SIZE };
  enum { BS_PARAMETER_SEPARATOR = '#', BS_PACKET_END_MARK = '$' };

  DVOID packet_len(ni _len);
  ni  packet_len() CONST;
  DVOID packet_magic();
  truefalse check_header() CONST;
  DVOID packet_cmd(CONST text * _cmd);
  truefalse is_cmd(CONST text * _cmd);
  truefalse guard();

  text len[LEN_SIZE];
  text magic[4];
  text cmd[2];
  text data[0];
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
