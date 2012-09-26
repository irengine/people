#ifndef tools_h_akjd81pajkjf5
#define tools_h_akjd81pajkjf5

#include <sys/types.h>
#include <stddef.h>
#include <uuid/uuid.h>

#include <ace/Log_Msg.h>
#include <ace/Message_Block.h>
#include <ace/SOCK_Stream.h>
#include <ace/Svc_Handler.h>
#include <ace/Malloc_T.h>
#include <ace/FILE_IO.h>
#include <ace/OS_NS_string.h>
#include <ace/INET_Addr.h>

#include <new>
#include <vector>
#include <algorithm>

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

EXTERN truefalse g_cache;

#define INFO_PREFIX        "(%D %P|%t %N/%l)\n  INFO %I"
#define C_INFO(FMT, ...)     \
        ACE_DEBUG(( LM_INFO,  \
                    INFO_PREFIX FMT, \
                    ## __VA_ARGS__))

#define DEBUG_PREFIX       "(%D %P|%t %N/%l)\n  DEBUG  %I"
#define C_DEBUG(FMT, ...)     \
        ACE_DEBUG(( LM_DEBUG,  \
                    DEBUG_PREFIX FMT, \
                    ## __VA_ARGS__))

#define WARNING_PREFIX       "(%D %P|%t %N/%l)\n  WARN  %I"
#define C_WARNING(FMT, ...)     \
        ACE_DEBUG(( LM_WARNING,  \
                    WARNING_PREFIX FMT, \
                    ## __VA_ARGS__))

#define ERROR_PREFIX       "(%D %P|%t %N/%l)\n  ERROR  %I"
#define C_ERROR(FMT, ...)     \
        ACE_DEBUG(( LM_ERROR,  \
                    ERROR_PREFIX  FMT, \
                    ## __VA_ARGS__))

#define FATAL_PREFIX       "(%D %P|%t %N.%l)\n  FATAL  %I"
#define C_FATAL(FMT, ...)     \
        ACE_DEBUG(( LM_ERROR,  \
                    FATAL_PREFIX  FMT, \
                    ## __VA_ARGS__))

#define ASSERT_PREFIX       "(%D %P|%t %N.%l)\n  ASSERT failed %I"
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

class CSysError
{
public:
  CSysError(ni x = ACE_OS::last_error())
  {
    get_text(x);
  }
  operator CONST text *()
  {
    return m_data;
  }

private:
  DVOID get_text(ni error)
  {
    snprintf(m_data, DATA_LEN, "error = %d msg = ", error);
    ni len = strlen(m_data);
    text temp[DATA_LEN];
    CONST text * i = strerror_r(error, temp, DATA_LEN);
    ACE_OS::strsncpy(m_data + len, (i ? i: "NULL"), DATA_LEN - len);
  }

  enum { DATA_LEN = 256 };
  text m_data[DATA_LEN];
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

class CFileGuard
{
public:
  enum { BAD_FD = -1 };
  CFileGuard(): m_fd(BAD_FD)
  { m_print_failure = true; }
  CFileGuard(ni fd): m_fd(fd), m_print_failure(true)
  {}
  ~CFileGuard()
  {
    if (m_fd >= 0)
      close(m_fd);
  }

  truefalse open_nowrite(CONST text * fn)
  {
    return open_i(fn, true, false, false, false, false);
  }

  truefalse open_write(CONST text * fn, truefalse newf, truefalse zap_content, truefalse add_only, truefalse owned_by_me)
  {
    return open_i(fn, false, newf, zap_content, add_only, owned_by_me);
  }

  ni get_fd() CONST
  {
    return m_fd;
  }
  DVOID bind_fd(ni h)
  {
    if (unlikely(m_fd == h))
      return;
    if (m_fd >= 0)
      close(m_fd);
    m_fd = h;
  }
  ni unbind()
  {
    ni h = m_fd;
    m_fd = BAD_FD;
    return h;
  }
  truefalse ok() CONST
  {
    return m_fd >= 0;
  }

  DVOID set_print_failure(truefalse b)
  {
    m_print_failure = b;
  }

private:
  truefalse open_i(CONST text *, truefalse, truefalse, truefalse, truefalse, truefalse);
  ni  m_fd;
  truefalse m_print_failure;
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
  typedef ACE_Dynamic_Cached_Allocator<ACE_LOCK> baseclass;

  CCachedAllocator (size_t _blocks, size_t _block_len): baseclass(_blocks, _block_len)
  {
    m_start = NULL;
    m_end = NULL;
    m_get = 0;
    m_put = 0;
    m_peak = 0;
    m_block_len = _block_len;
    m_fail = 0;
    m_blocks = _blocks;
  }

  DVOID prepare()
  {
    m_end = baseclass::malloc();
    baseclass::free(m_end);
    m_start = (void*)((char*)m_end - m_block_len * (m_blocks - 1));
  }

  truefalse belong_to(DVOID * ptr) CONST
  {
    return (ptr >= m_start && ptr <= m_end);
  }

  virtual ~CCachedAllocator() {}

  virtual DVOID *malloc (size_t size = 0)
  {
    DVOID * p = baseclass::malloc(size);

    {
      ACE_MT (ACE_GUARD_RETURN(ACE_LOCK, ace_mon, this->m_mutex, p));
      if (p)
      {
        ++m_get;
        if (m_get - m_put > m_peak)
          m_peak = m_get - m_put;
      } else
        ++m_fail;
    }

    return p;
  }

  virtual DVOID *calloc (size_t size, text fill = '\0')
  {
    DVOID * p = baseclass::calloc(size, fill);
    {
      ACE_MT (ACE_GUARD_RETURN(ACE_LOCK, ace_mon, this->m_mutex, p));
      if (p)
      {
        ++m_get;
        if (m_get - m_put > m_peak)
          m_peak = m_get - m_put;
      } else
        ++m_fail;
    }

    return p;
  }
  DVOID free (DVOID * p)
  {
    {
      ACE_MT (ACE_GUARD(ACE_LOCK, ace_mon, this->m_mutex));
      if (p != NULL)
        ++m_put;
    }
    baseclass::free(p);
  }

  DVOID query_stats(long & nGet, long & nPut, long & nPeak, long & nFail)
  {
    ACE_MT (ACE_GUARD(ACE_LOCK, ace_mon, this->m_mutex));
    nGet = m_get;
    nPut = m_put;
    nPeak = m_peak;
    nFail = m_fail;
  }

  size_t block_len() CONST
  {
    return m_block_len;
  }

  ni blocks() CONST
  {
    return m_blocks;
  }

private:
  ACE_LOCK m_mutex;
  size_t m_block_len;
  ni  m_blocks;
  long m_get;
  long m_put;
  long m_peak;
  long m_fail;
  DVOID * m_start;
  DVOID * m_end;
};

#define DECLARE_MEMORY_POOL(Cls, Mutex) \
  public: \
    typedef CCachedAllocator<Mutex> Mem_Pool; \
    SF void* operator new(size_t _size, std::new_handler p = 0) \
    { \
      ACE_UNUSED_ARG(p); \
      if (_size != sizeof(Cls) || !g_cache) \
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
        if (!g_cache) \
        { \
          ::operator delete(_ptr); \
          return; \
        } \
        m_mem_pool->free(_ptr); \
      } \
    } \
    SF DVOID init_mem_pool(ni pool_size) \
    { \
      if (g_cache) \
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
      if (_size != sizeof(Cls) || !g_cache) \
        return ::operator new(_size); \
      return m_mem_pool->malloc(); \
    } \
    SF DVOID operator delete(void* _ptr) \
    { \
      if (_ptr != NULL) \
      { \
        if (!g_cache) \
        { \
          ::operator delete(_ptr); \
          return; \
        } \
        m_mem_pool->free(_ptr); \
      } \
    } \
    SF DVOID init_mem_pool(ni pool_size) \
    { \
      if (g_cache) \
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

class CTermSNs;

class CTerminalDirCreator
{
public:
  SF DVOID create_dirs(CONST text * app_data_path, int64_t _start, ni _count);
  SF truefalse term_sn_to_dir(CONST text * id, text * result, ni result_len);
  SF DVOID create_dirs_from_TermSNs(CONST text * app_data_path, CTermSNs * id_table);
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
  enum { BAD_IDX = 9999 };
  typedef ACE_Atomic_Op<ACE_Thread_Mutex, long> COUNTER;
  typedef std::vector<int> CPoolSizes;
  typedef CCachedAllocator<ACE_Thread_Mutex> CCachedPool;
  typedef std::vector<CCachedPool *> CCachedPools;

  ni find_best_index(ni capacity);
  ni find_index_by_ptr(DVOID * ptr);
  CCachedAllocator<ACE_Thread_Mutex> *m_mb_pool;
  CCachedAllocator<ACE_Thread_Mutex> *m_data_block_pool;
  CPoolSizes m_pool_sizes;
  CCachedPools m_pools;
  COUNTER m_total_count;
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
      C_ERROR("mem leak @CMemGuard index=%d\n", m_index);
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
    FILE_FLAG_ME = S_IRUSR | S_IWUSR,
    FILE_FLAG_ALL = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH,
    DIR_FLAG_ME = S_IRWXU,
    DIR_FLAG_ALL = S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH
  };
  SF truefalse exist(CONST text * path);
  SF truefalse create_dir(CONST char* path, truefalse owned_by_me);
  SF truefalse create_dir(char* path, ni prefix_len, truefalse is_file, truefalse owned_by_me);
  SF truefalse create_dir_const(CONST char* path, ni prefix_len, truefalse is_file, truefalse owned_by_me);
  SF truefalse create_dir(CONST text * path, CONST text * subpath, truefalse is_file, truefalse owned_by_me);
  SF truefalse copy_dir(CONST text * src, CONST text * dest, truefalse owned_by_me, truefalse syn);
  SF truefalse copy_dir_zap(CONST text * src, CONST text * dest, truefalse owned_by_me, truefalse zap, truefalse syn);
  SF truefalse delete_dir(CONST text * path, truefalse ignore_eror);
  SF truefalse remove_old_files(CONST text * path, time_t deadline);
  SF truefalse copy_file_by_fd(ni src_fd, ni dest_fd);
  SF truefalse copy_file(CONST text * src, CONST text * dest, truefalse owned_by_me, truefalse syn);
  SF ni        cat_path(CONST text * path, CONST text * subpath, CMemGuard & result);
  SF truefalse get_correlate_path(CMemGuard & pathfile, ni skip);
  SF truefalse remove(CONST text *pathfile, truefalse no_report_failure = false);
  SF truefalse zap(CONST text *pathfile, truefalse no_report_failure);
  SF truefalse rename(CONST text *old_path, CONST text * new_path, truefalse ignore_eror);
  SF truefalse stat(CONST text *pathfile, struct stat * _stat);
  SF ni        filesize(CONST text *pathfile);
  SF truefalse clean_dir_keep_mfile(CONST CMemGuard & path, CONST CMemGuard & mfile, truefalse no_report_failure);
  SF DVOID     clean_empty_dir(CONST CMemGuard & parent_path);
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

truefalse c_tools_mb_putq(ACE_Task<ACE_MT_SYNCH> *, CMB *, CONST text * fail_info);
int  c_tools_post_mbq(ACE_Svc_Handler<ACE_SOCK_STREAM, ACE_NULL_SYNCH> * , CMB *, truefalse autofree);
int  c_tools_read_mb(ACE_Svc_Handler<ACE_SOCK_STREAM, ACE_NULL_SYNCH> * , CMB *);
int  c_tools_socket_outcome(ssize_t o);
int  c_tools_post_mb(ACE_Svc_Handler<ACE_SOCK_STREAM, ACE_NULL_SYNCH> * , CMB *);
truefalse c_tools_convert_time_to_text(text * ret, ni ret_size, truefalse full, time_t t = time(NULL));
truefalse c_tools_locate_key_result(text * & p, CONST text * key, text * & , text mark);
truefalse c_tools_tally_md5(CONST text * fn, CMemGuard & g);
size_t c_tools_text_hash(CONST text * s);
truefalse c_tools_text_tail_is(CONST text * p, CONST text * tail);
DVOID c_tools_create_rnd_text(text * ret, CONST ni size);
DVOID c_tools_text_replace(text * s, CONST text src, CONST text dest);
DVOID c_tools_dump_hex(DVOID * ptr, ni len, text * ret, ni ret_size);

class CStrHasher
{
public:
  size_t operator()(CONST text * x) CONST
  {
    return c_tools_text_hash(x);
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

class CNumber
{
public:
  union NUMBER
  {
    text char_array[];
    i64 i64_array[3];
  }number;

  enum
  {
    NUMBER_LENGTH_I64 = sizeof(number)/sizeof(i64),
    NUMBER_LENGTH_S = sizeof(number)/sizeof(text)
  };

#define number_i number.i64_array
#define number_s number.char_array

  CNumber()
  {
    memset((void*)number_i, 0, NUMBER_LENGTH_S);
  }

  CNumber(CONST text * s)
  {
    memset((void*)number_i, 0, NUMBER_LENGTH_S);

    if (!s || !*s)
      return;
    while(*s == ' ')
      ++s;
    ACE_OS::strsncpy(number_s, s, NUMBER_LENGTH_S);
  }

  DVOID zero_ending()
  {
    number_s[NUMBER_LENGTH_S - 1] = 0;
  }

  CNumber & operator = (CONST text * s)
  {
    memset((void*)number_i, 0, NUMBER_LENGTH_S);

    if (!s || !*s)
      return *this;
    while(*s == ' ')
      ++s;
    ACE_OS::strsncpy(number_s, s, NUMBER_LENGTH_S);
    return *this;
  }

  CNumber & operator = (CONST CNumber & c)
  {
    if (&c == this)
      return *this;
    memcpy(number.char_array, c.number.char_array, NUMBER_LENGTH_S);
    number_s[NUMBER_LENGTH_S - 1] = 0;
    return *this;
  }

  CONST text * to_str() CONST
  {
    return number_s;
  }

  truefalse empty() CONST
  {
    return (number_s[0] == 0);
  }

  truefalse operator < (CONST CNumber & c) CONST
  {
    for (ni i = 0; i < NUMBER_LENGTH_I64; ++i)
    {
      if (number_i[i] < c.number_i[i])
        return true;
      if (number_i[i] > c.number_i[i])
        return false;
    }
    return false;
  }

  truefalse operator == (CONST CNumber & c) CONST
  {
    for (ni i = 0; i < NUMBER_LENGTH_I64; ++i)
    {
      if (number_i[i] != c.number_i[i])
        return false;
    }
    return true;
  }

  truefalse operator != (CONST CNumber & r) CONST
  {
    return ! operator == (r);
  }

  DVOID rtrim()
  {
    text * p = number_s;
    for (ni i = NUMBER_LENGTH_S - 1; i >= 0; --i)
    {
      if (p[i] == 0)
        continue;
      else if (p[i] == ' ')
        p[i] = 0;
      else
        break;
    }
  }

};


#ifndef Item_NULL
  #define Item_NULL "!"
#endif

class CCmdHeader
{
public:
  enum { SIGNATURE = 0x80089397 };
  enum { ITEM_SEPARATOR = '*', MIDDLE_SEPARATOR = '?', FINISH_SEPARATOR = ':' };
  enum { ITEM_NULL_SIZE = 1 };

  enum PacketType
  {
    PT_NULL = 0,
    PT_PING,
    PT_VER_REQ,
    PT_VER_REPLY,
    PT_LOAD_BALANCE_REQ,
    PT_FILE_MD5_LIST,
    PT_HAVE_DIST_TASK,
    PT_FTP_FILE,
    PT_IP_VER_REQ,
    PT_ADV_CLICK,
    PT_PC_ON_OFF,
    PT_HARDWARE_ALARM,
    PT_VLC,
    PT_REMOTE_CMD,
    PT_ACK,
    PT_VLC_EMPTY,
    PT_TEST,
    PT_PSP,
    PT_TQ,
    PT_END,
    PT_DISCONNECT_INTERNAL
  };
  i32 size;
  u32 signature;
  uuid_t  uuid;
  i16 cmd;
};

class CCmdExt: public CCmdHeader
{
public:
  text data[0];

  truefalse validate();
};

class CTerminalVerReq: public CCmdHeader
{
public:
  u8 term_ver_major;
  u8 term_ver_minor;
  u8 server_id;
  CNumber term_sn;
  text hw_ver[0];

  DVOID fix_data()
  { term_sn.zero_ending(); }

};

class CIpVerReq: public CCmdHeader
{
public:
  u8 term_ver_major;
  u8 term_ver_minor;
};

class CTermVerReply: public CCmdHeader
{
public:
  enum SUBCMD
  {
    SC_OK = 1,
    SC_OK_UP,
    SC_NOT_MATCH,
    SC_ACCESS_DENIED,
    SC_SERVER_BUSY,
    SC_SERVER_LIST
  };
  enum { DATA_LENGTH_MAX = 4096 };
  i8 ret_subcmd;
  text data[0];
};

truefalse c_packet_check_base(CONST CCmdHeader *);
truefalse c_packet_check_file_md5_list(CONST CCmdHeader *);
truefalse c_packet_check_ftp_file(CONST CCmdHeader *);
truefalse c_packet_check_plc_alarm(CONST CCmdHeader *);
truefalse c_packet_check_load_balance_req(CONST CCmdHeader *);
truefalse c_packet_check_term_ver_reply(CONST CCmdHeader *);
truefalse c_packet_check_term_ver_req(CONST CCmdHeader *, CONST ni extra = 0);
truefalse c_packet_check_vlc_empty(CONST CCmdHeader *);
#define c_packet_check_have_dist_task c_packet_check_base
#define c_packet_check_ping c_packet_check_base

class CLoadBalanceReq: public CCmdHeader
{
public:
  enum { IP_SIZE = INET_ADDRSTRLEN };
  text ip[IP_SIZE];
  i32 load;

  DVOID set_ip(CONST text * s)
  {
    if (unlikely(!s || !*s))
      ip[0] = 0;
    else
    {
      memset(ip, 0, CLoadBalanceReq::IP_SIZE); //make compiler happy
      ACE_OS::strsncpy(ip, s, CLoadBalanceReq::IP_SIZE);
    }
  }
};

class CPLCWarning: public CCmdHeader
{
public:
  text x;
  text y;
};

class CBSData
{
public:
  enum { LEN = 8, SIGNATURE_LEN = 4, CMD_LEN = 2, DATA_OFFSET = LEN + SIGNATURE_LEN + CMD_LEN };
  enum { PARAM_SEPARATOR = '#', END_MARK = '$' };

  DVOID data_len(ni _len);
  ni  data_len() CONST;
  DVOID data_signature();
  truefalse validate_header() CONST;
  DVOID set_cmd(CONST text * _cmd);
  truefalse is_cmd(CONST text * _cmd);
  truefalse fix_data();

  text length[LEN];
  text signature[4];
  text command[2];
  text data[0];
};

#define CONST_BS_IP_VER_CMD        "01"
#define CONST_BS_DIST_FEEDBACK_CMD "02"
#define CONST_BS_HARD_MON_CMD      "03"
#define CONST_BS_PING_CMD          "04"
#define CONST_BS_ADV_CLICK_CMD     "05"
#define CONST_BS_PATCH_FILE_CMD    "06"
#define CONST_BS_POWERON_LINK_CMD  "07"
#define CONST_BS_VLC_CMD           "10"
#define CONST_BS_DIST_FBDETAIL_CMD "12"
#define CONST_BS_VLC_EMPTY_CMD     "13"

#pragma pack(pop)


#endif
