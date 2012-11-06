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
typedef ACE_Time_Value CTV;

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

class CMBProt
{
public:
  CMBProt(): m_mb(NULL)
  {}
  CMBProt(CMB * mb): m_mb(mb)
  {}
  ~CMBProt()
  {
    if (m_mb)
      m_mb->release();
  }
  DVOID bind_mb(CMB * mb)
  {
    if (unlikely(m_mb == mb))
      return;
    if (m_mb)
      m_mb->release();
    m_mb = mb;
  }
  CMB * unbind()
  {
    CMB * result = m_mb;
    m_mb = NULL;
    return result;
  }
  CMB * get_mb() CONST
  {
    return m_mb;
  }

private:
  CMB * m_mb;
};

class CFileProt
{
public:
  enum { BAD_FD = -1 };
  CFileProt(): m_fd(BAD_FD)
  { m_print_failure = true; }
  CFileProt(ni fd): m_fd(fd), m_print_failure(true)
  {}
  ~CFileProt()
  {
    if (m_fd >= 0)
      close(m_fd);
  }

  truefalse open_nowrite(CONST text * fn)
  {
    return open_i(fn, true, false, false, false, false);
  }

  truefalse open_write(CONST text * fn, truefalse newf, truefalse clear_content, truefalse add_only, truefalse owned_by_me)
  {
    return open_i(fn, false, newf, clear_content, add_only, owned_by_me);
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


class CSStreamProt
{
public:
  CSStreamProt(ACE_SOCK_Stream & s): m_ss(s)
  {}
  ~CSStreamProt()
  {
    m_ss.close();
  }
private:
  ACE_SOCK_Stream & m_ss;
};


class CFIOProt
{
public:
  CFIOProt(ACE_FILE_IO & f): m_f(f)
  {}
  ~CFIOProt()
  {
    m_f.close();
  }
private:
  ACE_FILE_IO & m_f;
};

template <class ACE_LOCK> class CMemBlock: public ACE_Dynamic_Cached_Allocator<ACE_LOCK>
{
public:
  typedef ACE_Dynamic_Cached_Allocator<ACE_LOCK> baseclass;

  CMemBlock (size_t _blocks, size_t _block_len): baseclass(_blocks, _block_len)
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

  virtual ~CMemBlock() {}

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
  DVOID free(DVOID * p)
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

#define xx_enable_cache(v_type, v_lock) \
  public: \
    typedef CMemBlock<v_lock> MemBlock; \
    SF void* operator new(size_t _size, std::new_handler p = 0) \
    { \
      ACE_UNUSED_ARG(p); \
      if (_size != sizeof(v_type) || !g_cache) \
        return ::operator new(_size); \
      void* _ptr = _m_mem_block->malloc(); \
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
        _m_mem_block->free(_ptr); \
      } \
    } \
    SF DVOID mem_block_start(ni pool_size) \
    { \
      if (g_cache) \
        _m_mem_block = new MemBlock(pool_size, sizeof(v_type)); \
    } \
    SF DVOID mem_block_end() \
    { \
      if (_m_mem_block) \
      { \
        delete _m_mem_block; \
        _m_mem_block = NULL; \
      } \
    } \
    SF MemBlock * mem_block() \
    { \
      return _m_mem_block; \
    } \
  private: \
    SF MemBlock * _m_mem_block

#define xx_enable_cache_easy(v_type, v_lock) \
  public: \
    typedef CMemBlock<v_lock> MemBlock; \
    SF void* operator new(size_t _size, std::new_handler p = 0) throw() \
    { \
      ACE_UNUSED_ARG(p); \
      if (_size != sizeof(v_type) || !g_cache) \
        return ::operator new(_size); \
      return _m_mem_block->malloc(); \
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
        _m_mem_block->free(_ptr); \
      } \
    } \
    SF DVOID mem_block_start(ni pool_size) \
    { \
      if (g_cache) \
        _m_mem_block = new MemBlock(pool_size, sizeof(v_type)); \
    } \
    SF DVOID mem_block_end() \
    { \
      if (_m_mem_block) \
      { \
        delete _m_mem_block; \
        _m_mem_block = NULL; \
      } \
    } \
    SF MemBlock * mem_block() \
    { \
      return _m_mem_block; \
    } \
  private: \
    SF MemBlock * _m_mem_block

#define yy_enable_cache(v_type) \
  v_type::MemBlock * v_type::_m_mem_block = NULL

class CTermSNs;

class CTerminalDirCreator
{
public:
  SF DVOID create_dirs(CONST text * data_dir, int64_t _from, ni _count);
  SF truefalse term_sn_to_dir(CONST text * sn, text * ret, ni ret_len);
  SF DVOID create_dirs_from_TermSNs(CONST text * data_dir, CTermSNs *);
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
class CMemProt;

class CCache
{
public:
  CCache();
  ~CCache();
  DVOID prepare(CCfg * config);
  truefalse get(ni size, CMemProt *);
  DVOID * get_raw(ni size);
  CMB * get_mb_bs(ni data_len, CONST text * cmd);
  CMB * get_mb_ack(CMB * src);
  CMB * get_mb_cmd(ni extra, ni command, truefalse no_gen = true);
  CMB * get_mb(ni size);
  CMB * get_mb_cmd_direct(ni size, ni cmd, truefalse no_gen = true);
  DVOID put_raw(DVOID * ptr);
  DVOID put(CMemProt *);
  DVOID print_info();

private:
  enum { BAD_IDX = 9999 };
  typedef ACE_Atomic_Op<ACE_Thread_Mutex, long> SYNCDATA;
  typedef std::vector<int> CBlockSizes;
  typedef CMemBlock<ACE_Thread_Mutex> MemBlock;
  typedef std::vector<MemBlock *> MemBlocks;

  ni find_best(ni size);
  ni find_by_ptr(DVOID * ptr);
  CMemBlock<ACE_Thread_Mutex> *m_mbs;
  CMemBlock<ACE_Thread_Mutex> *m_dbs;
  CBlockSizes m_block_sizes;
  MemBlocks m_blocks;
  SYNCDATA m_all_outside;
};
typedef ACE_Unmanaged_Singleton<CCache, ACE_Null_Mutex> CCacheX;

class CMemProt
{
public:
  CMemProt(): m_ptr(NULL), m_idx(-1), m_size(0)
  {}

  ~CMemProt()
  {
    free();
  }

  text * get_ptr() CONST
  {
    return (char*)m_ptr;
  }

  DVOID free()
  {
    if (m_ptr)
    {
      CCacheX::instance()->put(this);
      m_ptr = NULL;
    }
  }

  DVOID init(CONST text *);
  DVOID init(CONST text *, CONST text *);
  DVOID init(CONST text *, CONST text *, CONST text *);
  DVOID init(CONST text *, CONST text *, CONST text *, CONST text *);
  DVOID inits(CONST text * p[], ni);

protected:
  friend class CCache;

  DVOID data(DVOID * p, ni i, ni size)
  {
    if (unlikely(m_ptr != NULL))
      C_ERROR("bad idx(%d)\n", m_idx);
    m_ptr = (char*)p;
    m_idx = i;
    m_size = size;
  }
  ni index() CONST
  {
    return m_idx;
  }

private:
  CMemProt(CONST CMemProt &);
  CMemProt & operator = (CONST CMemProt &);
  text * m_ptr;
  ni m_idx;
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
    return static_cast<pointer> (CCacheX::instance()->get_raw(count * sizeof(T)));
  }

  DVOID deallocate(pointer ptr, size_type)
  {
    CCacheX::instance()->put_raw(ptr);
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
    CCacheX::instance()->put_raw((void*)ptr);
  }
};

class CSysFS
{
public:
  enum
  {
    FPROT_ME = S_IRUSR | S_IWUSR,
    FPROT_NONE = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH,
    DPROT_ME = S_IRWXU,
    DPROT_NONE = S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH
  };
  SF truefalse exist(CONST text * path);
  SF truefalse create_dir(CONST char* path, truefalse owned_by_me);
  SF truefalse create_dir(char* path, ni prefix_len, truefalse is_file, truefalse owned_by_me);
  SF truefalse create_dir_const(CONST char* path, ni prefix_len, truefalse is_file, truefalse owned_by_me);
  SF truefalse create_dir(CONST text * path, CONST text * subpath, truefalse is_file, truefalse owned_by_me);
  SF truefalse copy_dir(CONST text * src, CONST text * dest, truefalse owned_by_me, truefalse syn);
  SF truefalse copy_dir_clear(CONST text * src, CONST text * dest, truefalse owned_by_me, truefalse clear, truefalse syn);
  SF truefalse delete_dir(CONST text * path, truefalse ignore_eror);
  SF truefalse delete_obsolete_files(CONST text * dir, time_t checkpoint);
  SF truefalse copy_file_by_fd(ni src_fd, ni dest_fd);
  SF truefalse copy_file(CONST text * v_from, CONST text * v_to, truefalse owned_by_me, truefalse syn);
  SF ni        dir_add(CONST text * parent_dir, CONST text * child_dir, CMemProt &);
  SF truefalse dir_from_mfile(CMemProt & mfn, ni ignore_lead_n);
  SF truefalse remove(CONST text * pfn, truefalse no_report_failure = false);
  SF truefalse ensure_delete(CONST text * pfn, truefalse no_report_failure);
  SF truefalse rename(CONST text * v_from, CONST text * v_to, truefalse ignore_eror);
  SF truefalse stat(CONST text *, struct stat *);
  SF ni        get_fsize(CONST text *);
  SF truefalse clean_dir_keep_mfile(CONST CMemProt & path, CONST CMemProt & mfile, truefalse no_report_failure);
  SF DVOID     clean_empty_dir(CONST CMemProt & parent_dir);
};

class CTextDelimiter
{
public:
  CTextDelimiter(text *, CONST text * mark);
  text * get();

private:
  text * m_txt;
  text * m_tmp;
  CONST text * m_marks;
};

#define c_tell_ftype_led(ftype) ((ftype) == '7' || (ftype) == '9')
#define c_tell_ftype_adv(ftype) ((ftype) == '3' || (ftype) == '5' || (ftype) == '6')
#define c_tell_ftype_adv_list(ftype) ((ftype) == '6')
#define c_tell_ftype_chn(ftype) ((ftype) == '1' || (ftype) == '2' || (ftype) == '4')
#define c_tell_ftype_frame(ftype) ((ftype) == '0')
#define c_tell_ftype_backgnd(ftype) ((ftype) == '8')
#define c_tell_ftype_vd(ftype) ((ftype) == '3' || (ftype) == '5' || (ftype) == '6' || (ftype) == '8')
#define c_tell_ftype_valid(ftype) ((ftype) >= '0' && (ftype) <= '9')

#define c_tell_type_valid(type) ((type) == '0' || (type) == '1' || (type) == '3')
#define c_tell_type_single(type) ((type) == '0')
#define c_tell_type_multi(type) ((type) == '1')
#define c_tell_type_all(type) ((type) == '3')

truefalse c_tools_mb_putq(ACE_Task<ACE_MT_SYNCH> *, CMB *, CONST text * fail_info);
int  c_tools_post_mbq(ACE_Svc_Handler<ACE_SOCK_STREAM, ACE_NULL_SYNCH> * , CMB *, truefalse autofree);
int  c_tools_read_mb(ACE_Svc_Handler<ACE_SOCK_STREAM, ACE_NULL_SYNCH> * , CMB *);
int  c_tools_socket_outcome(ssize_t o);
int  c_tools_post_mb(ACE_Svc_Handler<ACE_SOCK_STREAM, ACE_NULL_SYNCH> * , CMB *);
truefalse c_tools_convert_time_to_text(text * ret, ni ret_size, truefalse full, time_t t = time(NULL));
truefalse c_tools_locate_key_result(text * & p, CONST text * key, text * & , text mark);
truefalse c_tools_tally_md5(CONST text * fn, CMemProt & g);
size_t c_tools_text_hash(CONST text * s);
truefalse c_tools_text_tail_is(CONST text * p, CONST text * tail);
DVOID c_tools_create_rnd_text(text * ret, CONST ni size);
DVOID c_tools_text_replace(text * s, CONST text src, CONST text dest);
DVOID c_tools_dump_hex(DVOID * ptr, ni len, text * ret, ni ret_size);

class CTextHashGenerator
{
public:
  size_t operator()(CONST text * x) CONST
  {
    return c_tools_text_hash(x);
  }
};

class CTextEqual
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
    PT_HEART_BEAT,
    PT_LOGIN,
    PT_LOGIN_BACK,
    PT_LOAD_BALANCE_REQ,
    PT_CHECKSUMS,
    PT_HAS_JOB,
    PT_DOWNLOAD,
    PT_LOC_REPORT,
    PT_ADV_CLICK,
    PT_POWER_TIME,
    PT_HW_WARN,
    PT_VIDEO,
    PT_REMOTE_CMD,
    PT_ANSWER,
    PT_NO_VIDEO,
    PT_QUIZ,
    PT_PAUSE_STOP,
    PT_TQ,
    PT_LAST,
    PT_TERMINATE_CONNECTION_I
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
  u8 term_edition_x;
  u8 term_edition_y;
  u8 handleout_id;
  CNumber term_sn;
  text driver_edition[0];

  DVOID fix_data()
  { term_sn.zero_ending(); }

};

class CLocationReq: public CCmdHeader
{
public:
  u8 term_edition_x;
  u8 term_edition_y;
};

class CTermVerReply: public CCmdHeader
{
public:
  enum SUBCMD
  {
    SC_OK = 1,
    SC_OK_UP,
    SC_NOT_MATCH,
    SC_NO_RIGHTS,
    SC_NOT_FREE,
    SC_GET_ALL
  };
  enum { DATA_LENGTH_MAX = 4096 };
  i8 ret_subcmd;
  text data[0];
};

truefalse c_packet_check_common(CONST CCmdHeader *);
truefalse c_packet_check_checksums_all(CONST CCmdHeader *);
truefalse c_packet_check_download_cmd(CONST CCmdHeader *);
truefalse c_packet_check_hw_warn(CONST CCmdHeader *);
truefalse c_packet_check_load_balance_req(CONST CCmdHeader *);
truefalse c_packet_check_term_ver_back(CONST CCmdHeader *);
truefalse c_packet_check_term_ver_req(CONST CCmdHeader *, CONST ni extra = 0);
truefalse c_packet_check_no_video(CONST CCmdHeader *);
#define c_packet_check_has_job c_packet_check_common
#define c_packet_check_ping c_packet_check_common

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
      memset(ip, 0, CLoadBalanceReq::IP_SIZE);
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
  DVOID set_cmd(CONST text *);
  truefalse is_cmd(CONST text *);
  truefalse fix_data();

  text length[LEN];
  text signature[4];
  text command[2];
  text data[0];
};

#define CCMD_PATCH_FILE    "06"
#define CCMD_POWERON_LINK  "07"
#define CCMD_VIDEO           "10"
#define CCMD_HANDOUT_MORE_INFO "12"
#define CCMD_NO_VIDEO     "13"
#define CCMD_LOC_REPORT        "01"
#define CCMD_HANDOUT_RESULT "02"
#define CCMD_HARD_MON      "03"
#define CCMD_HEART_BEAT          "04"
#define CCMD_ADV_CLICK     "05"

#pragma pack(pop)


#endif
