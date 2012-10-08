#ifndef component_h_ijma834va
#define component_h_ijma834va

#include <ace/Log_Msg.h>
#include <ace/INET_Addr.h>
#include <ace/SOCK_Acceptor.h>
#include <ace/Reactor.h>
#include <ace/Acceptor.h>
#include <ace/Message_Block.h>
#include <ace/SOCK_Stream.h>
#include <ace/Svc_Handler.h>
#include <ace/Dev_Poll_Reactor.h>
#include <ace/Thread_Mutex.h>
#include <ace/Signal.h>
#include <ace/Connector.h>
#include <ace/SOCK_Connector.h>

#include <bzlib.h>
#include <vector>
#include <map>
#include <list>
#include <string>
#include <algorithm>
#include <tr1/unordered_map>

#include "tools.h"

class CMod;
class CParentHandler;
class CAcceptorBase;
class CHandlerDirector;
class CApp;
class CDispatchBase;
class CConnectorBase;
class CProc;

class CDirConverter
{
public:
  CDirConverter();
  truefalse prepare(CONST text * fn);
  CONST text * dir() CONST;
  CONST text * value() CONST;
  CONST text * convert(CONST text * fn);

private:
  CMemProt m_value;
  CMemProt m_dir;
  CMemProt m_value_converted;
};

class CTermVer
{
public:
  CTermVer();
  CTermVer(u8, u8);
  DVOID init(u8, u8);
  truefalse init(CONST text * s);
  CONST text * to_text() CONST;
  truefalse operator < (CONST CTermVer &);

private:
  DVOID prepare_buff();

  enum { DATA_LEN = 8 };
  u8 m_v1;
  u8 m_v2;
  text m_data[DATA_LEN];
};

class CTermData
{
public:
  enum { AUTH_SIZE = 24 };
  CTermData();
  CTermData(CONST CNumber & id, CONST text * download_auth = NULL, truefalse v_invalid = false);
  DVOID set_download_auth(CONST text * download_auth);

  text download_auth[AUTH_SIZE];
  ni   download_auth_len;
  truefalse server_changed;
  CNumber   term_sn;
  truefalse connected;
  truefalse invalid;
};

class CTermSNs
{
public:
  CTermSNs();
  ~CTermSNs();

  DVOID prepare_space(ni);
  truefalse have(CONST CNumber &);
  DVOID append(CONST CNumber &);
  DVOID append(CONST text *, CONST text * auth = NULL, truefalse binvalid = false);
  DVOID append_lot(text *); //"34;100;111;..."
  ni  find_location(CONST CNumber &);
  ni  number();
  truefalse get_sn(ni loc, CNumber *);
  truefalse get_termData(ni loc, CTermData & );
  DVOID server_changed(ni loc, truefalse);
  DVOID set_invalid(ni loc, truefalse);
  truefalse mark_valid(CONST CNumber &, truefalse valid, ni & loc);
  truefalse connected(CONST CNumber &, ni & loc, truefalse & server_changed);
  truefalse connected(ni loc);
  DVOID set_connected(ni loc, truefalse);
  ni  prev_no() CONST;
  DVOID set_prev_no(ni);

private:
  typedef std::vector<CTermData > CTermSNs_vec;
  typedef std::map<CNumber, ni> CTermSNs_map;

  ni do_locate(CONST CNumber &, CTermSNs_map::iterator * = NULL);
  DVOID append_new(CONST CNumber &, CONST text * auth, truefalse binvalid);

  ni m_prev_no;
  CTermSNs_vec   m_SNs;
  CTermSNs_map   m_fast_locater;
  ACE_RW_Thread_Mutex m_mutex;
};

EXTERN CTermSNs * g_term_sns;

class CCheckSum
{
public:
  enum { CHECK_SUM_SIZE = 32 };
  CCheckSum(CONST text * fn, CONST text * checksum, ni ignore_lead_n, CONST text * _replace = NULL);
  CONST text * value() CONST
  {
    return m_checksum;
  }
  ni size(truefalse full) CONST
  {
    return full? (m_size + CHECK_SUM_SIZE + 1) : m_size;
  }
  truefalse check() CONST
  {
    return (m_checksum[0] != 0);
  }
  CONST text * fn() CONST
  {
    return m_fn.get_ptr();
  }
  truefalse operator == (CONST CCheckSum & o) CONST
  {
    return (strcmp(m_fn.get_ptr(), o.m_fn.get_ptr()) == 0);
  }
  truefalse operator < (CONST CCheckSum & o) CONST
  {
    return (strcmp(m_fn.get_ptr(), o.m_fn.get_ptr()) < 0);
  }
  truefalse checksum_equal(CONST CCheckSum & o) CONST
  {
    return memcmp(m_checksum, o.m_checksum, CHECK_SUM_SIZE) == 0;
  }

private:
  text m_checksum[CHECK_SUM_SIZE];
  ni m_size;
  CMemProt m_fn;
};


class CCheckSums
{
public:
  typedef std::vector<CCheckSum *, CCppAllocator<CCheckSum *> > CCheckSumVec;

  CCheckSums();
  ~CCheckSums();
  DVOID init_locator();
  truefalse contains(CONST text * fn);
  truefalse root_path(CONST text *);
  DVOID make_ordered();
  ni  number() CONST
  { return m_checksums.size(); }
  truefalse compute(CONST text * fn, CONST text * mfile, truefalse only_one);
  truefalse compute_diverse(CONST text * fn, CDirConverter * p = NULL);
  DVOID substract(CCheckSums &, CDirConverter *, truefalse remove_file);
  DVOID delete_unused(CONST text * pn);
  truefalse append_checksum(CONST text * fn, CONST text * val, ni ignore_lead_n);
  truefalse append_checksum(CONST text * pn, CONST text * fn, ni ignore_lead_n, CONST text * _replace);
  truefalse save_text(text *, ni, truefalse full);
  truefalse load_text(text *, CDirConverter * p = NULL);
  ni  text_len(truefalse full);

private:
  typedef std::tr1::unordered_map<const text *, CCheckSum *, CTextHashGenerator, CTextEqual,
                    CCppAllocator <std::pair<const text *, CCheckSum *> > > CheckSumLocator;

  truefalse i_tally_path(CONST text *, ni);
  DVOID i_delete_unused(CONST text * pn, ni);
  CCheckSum * do_search(CONST text * fn);

  CheckSumLocator * m_locator;
  CCheckSumVec m_checksums;
  CMemProt m_root_path;
  ni m_root_path_len;
};

class CBaseFileReader
{
public:
  CBaseFileReader();
  virtual ~CBaseFileReader()
  {}
  virtual truefalse open(CONST text * fn);
  virtual ni read(text *, ni);
  DVOID close();

protected:
  ni read_i(text *, ni);

  CFileProt m_f;
  CMemProt m_fn;
  ni m_size;
};

#pragma pack(push, 1)

class CCompBegining
{
public:
  enum { SIGNATURE = 0x96809685 };

  i32  begining_size;
  u32  signature;
  i32  data_size; //exclude header
  i32  processed_size;
  text fn[0];
};

#pragma pack(pop)

class CCompFileReader: public CBaseFileReader
{
public:
  typedef CBaseFileReader baseclass;

  virtual truefalse open(CONST text *);
  virtual ni read(text *, ni);
  CONST text * fn() CONST;
  truefalse get_more();
  truefalse finished() CONST;
  DVOID password(CONST text *);

private:
  truefalse load_begining();

  aes_context m_x;
  CMemProt m_begining;
  ni  m_more_size;
  ni  m_more_comp_size;
};


class CBaseFileWriter
{
public:
  virtual ~CBaseFileWriter()
  {}
  truefalse open(CONST text *);
  truefalse open(CONST text * dir, CONST text * filename);
  virtual truefalse write(text *, ni);
  DVOID close();

protected:
  truefalse open_i();
  truefalse write_i(text *, ni);

  CFileProt m_f;
  CMemProt m_fn;
};

class CCompFileWriter: public CBaseFileWriter
{
public:
  typedef CBaseFileWriter baseclass;
  enum { BUFFER_SIZE = 4096 };
  virtual truefalse write(text *, ni);
  truefalse begin(CONST text * fn, ni skip_n = 0);
  truefalse end();
  DVOID password(CONST text *);

private:
  truefalse save_begining(CONST text * filename);
  truefalse comp_save();

  aes_context m_x;
  CCompBegining m_begining;
  ni  m_size;
  ni  m_comp_size;
  ni  m_more_comp_size;
  CMemProt m_comp_cache;
};

class CBZMemBridge
{
public:
  SF DVOID * intf_alloc(DVOID *,ni, ni );
  SF DVOID intf_free(DVOID *, DVOID *);
};

class CDataComp
{
public:
  enum { AGGRESSIVE = 3 };
  enum { BUFF_SIZE = 4096 };

  CDataComp();
  truefalse reduce(CONST text * fn, ni skip_n, CONST text * to_fn, CONST text * password);
  truefalse bloat(CONST text * fn, CONST text * to_path, CONST text * password, CONST text * new_name = NULL);

private:
  truefalse init();
  truefalse reduce_i(CBaseFileReader *, CBaseFileWriter *);
  truefalse bloat_i(CBaseFileReader *, CBaseFileWriter *);

  bz_stream m_s;
  CMemProt  m_in;
  CMemProt  m_out;
};

class CCompUniter
{
public:
  truefalse begin(CONST text *);
  truefalse append(CONST text *);
  truefalse append_batch(text * fn, CONST text * dir, CONST text mark = '*', CONST text * ext = NULL);
  DVOID finish();

private:
  CFileProt m_f;
};

class CParentHandler: public ACE_Svc_Handler<ACE_SOCK_STREAM, ACE_NULL_SYNCH>
{
public:
  typedef ACE_Svc_Handler<ACE_SOCK_STREAM, ACE_NULL_SYNCH> baseclass;

  virtual ~CParentHandler();
  CParentHandler(CHandlerDirector * p = NULL);
  virtual ni handle_output(ACE_HANDLE fd = ACE_INVALID_HANDLE);
  virtual ni handle_close(ACE_HANDLE = ACE_INVALID_HANDLE, ACE_Reactor_Mask = ACE_Event_Handler::ALL_EVENTS_MASK);
  virtual ni open (DVOID * p = 0);
  virtual ni handle_input(ACE_HANDLE fd = ACE_INVALID_HANDLE);
  virtual CTermSNs * term_SNs() CONST;
  CHandlerDirector * handler_director();
  CProc * get_proc() CONST;
  ni post_packet(CMB * mb);
  DVOID prepare_close();
  DVOID container(DVOID * p)
  { m_container = p; }
  CAcceptorBase * acceptor() CONST
  { return (CAcceptorBase *)m_container; }
  CConnectorBase * connector() CONST
  { return (CConnectorBase *)m_container; }

protected:
  virtual DVOID at_finish();
  virtual ni  at_start();

  truefalse m_marked_for_close;
  CHandlerDirector * m_handler_director;
  CProc * m_proc;
  DVOID * m_container;
};

class CHandlerDirector
{
public:
  enum CHow { HWaiting = 1, HConnected = 2 };

  virtual ~CHandlerDirector();
  CHandlerDirector();
  i64 data_get() CONST;
  i64 data_post() CONST;
  truefalse is_down() CONST;
  DVOID print_all();
  DVOID post_all(CMB * mb);
  DVOID post_one(CMB * mb);
  DVOID on_data_get(ni);
  DVOID on_data_post(ni);
  DVOID add(CParentHandler *, CHow);
  DVOID sn_at_location(CParentHandler *, ni, CTermSNs *);
  CParentHandler * locate(ni index);
  DVOID change_how(CParentHandler *, CHow);
  DVOID remove_x(CParentHandler *, CTermSNs *);
  DVOID delete_broken(ni);
  DVOID down();
  DVOID up();
  ni  active_count() CONST;
  ni  total_count() CONST;
  ni  forced_count() CONST;
  ni  waiting_count() CONST;

protected:
  virtual DVOID i_print();

private:
  typedef std::map<CParentHandler *, long, std::less<CParentHandler *>, CCppAllocator<std::pair<const CParentHandler *, long> > > CHandlersAll;
  typedef CHandlersAll::iterator CHandlersAllIt;
  typedef std::map<ni, CParentHandler *, std::less<ni>, CCppAllocator<std::pair<const ni, CParentHandler *> > > CHandlersMap;
  typedef std::map<ni, CParentHandler *>::iterator CHandlersMapIt;

  DVOID delete_at_container(CParentHandler *);
  DVOID delete_at_map(CParentHandler *, CTermSNs *);
  CHandlersAllIt do_search(CParentHandler *);
  CHandlersMapIt do_locate(ni);
  DVOID i_post(CMB * mb, truefalse to_all);

  CHandlersAll m_handlers;
  CHandlersMap m_map;
  i64 m_data_get;
  i64 m_data_post;
  truefalse m_down;
  ni  m_count;
  ni  m_all_count;
  ni  m_waiting_count;
  ni  m_forced_count;
};


class CHandlerDirectorDownProt
{
public:
  ~CHandlerDirectorDownProt()
  {
    if (m_p)
      m_p->up();
  }

  CHandlerDirectorDownProt(CHandlerDirector * p): m_p(p)
  {
    if (m_p)
      m_p->down();
  }

private:
  CHandlerDirector * m_p;
};

class CProc
{
public:
  enum OUTPUT  { OP_FAIL = -1, OP_OK = 0, OP_GO_ON, OP_DONE };

  CProc(CParentHandler *);
  virtual ~CProc();

  virtual DVOID get_sinfo(CMemProt &) CONST;
  virtual ni at_start();
  virtual DVOID at_finish();
  virtual ni handle_input();
  virtual truefalse ok_to_post(CMB *) CONST;
  virtual CONST text * name() CONST;
  DVOID set_lastest_action();
  long get_lastest_action() CONST;
  CONST CNumber & term_sn() CONST;
  DVOID set_term_sn(CONST text *id);
  virtual truefalse term_sn_check_done() CONST;
  i32 term_sn_loc() CONST;
  truefalse get_mark_down() CONST;
  DVOID set_mark_down();
  truefalse broken() CONST;

protected:
  ni on_read_data_at_down();

  truefalse m_mark_down;
  CNumber m_term_sn;
  i32     m_term_loc;
  ni      m_term_sn_len;
  CParentHandler * m_handler;
  long m_lastest_action;
};


template <typename T> class CParentFormattedProc: public CProc
{
public:
  typedef CProc baseclass;

  CParentFormattedProc (CParentHandler * handler): CProc(handler)
  {
    m_subsequent_data_pos = 0;
    m_mb = NULL;
  }

  virtual ~CParentFormattedProc()
  {
    if (m_mb)
      m_mb->release();
  }

  virtual CONST text * name() CONST
  {
    return "CParentFormattedProc";
  }

  virtual ni handle_input()
  {
    if (m_mark_down)
      return on_read_data_at_down();

    ni l_x = 0;
  ll_cont:
    ++l_x;

    if (l_x >= 4)
      return 0;
    if (m_subsequent_data_pos < (ni)sizeof( m_data_head))
    {
      ni l_tmp = read_data_head();
      if (l_tmp < 0)
        return -1;
      else if (l_tmp > 0)
        return 0;
    }

    if (m_subsequent_data_pos < (ni)sizeof( m_data_head))
      return 0;

    ni l_y = read_data_remain();
    if (l_y < 0)
      return -1;
    else if (l_y > 0)
      return 0;

    if (process_data() < 0)
      return -1;

    goto ll_cont;

    return 0;
  }

protected:

  ni read_data_head()
  {
    set_lastest_action();
    ssize_t l_x = m_handler->peer().recv((char*)& m_data_head + m_subsequent_data_pos,
        sizeof( m_data_head) - m_subsequent_data_pos);
    ni ret = c_tools_socket_outcome(l_x);
    if (ret <= 0)
      return ret;
    m_subsequent_data_pos += l_x;

    if (m_subsequent_data_pos < (ni)sizeof( m_data_head))
      return 0;

    CProc::OUTPUT l_o = at_head_arrival();
    switch(l_o)
    {
    case CProc::OP_FAIL:
    case CProc::OP_GO_ON:
      return -1;
    case CProc::OP_DONE:
      if (data_len() != sizeof( m_data_head))
      {
        C_FATAL("OP_DONE data\n");
        return -1;
      }
      if (m_handler->handler_director())
        m_handler->handler_director()->on_data_get(sizeof(m_data_head));
      m_subsequent_data_pos = 0;
      return 1;
    case CProc::OP_OK:
      return 0;
    default:
      C_FATAL("unknown CPROC::OP_XXX = %d.\n", l_o);
      return -1;
    }
  }

  ni read_data_remain()
  {
    if (!m_mb)
    {
      m_mb = CCacheX::instance()->get_mb(data_len());
      if (!m_mb)
        return -1;
      if (move_data_head_to(m_mb,  m_data_head) < 0)
      {
        C_ERROR("mb copy head failed\n");
        return -1;
      }
    }
    set_lastest_action();
    return c_tools_read_mb(m_handler, m_mb);
  }

  ni process_data()
  {
    if (m_handler->handler_director())
       m_handler->handler_director()->on_data_get(m_mb->size());

    ni ret = 0;
    if (read_data(m_mb) != CProc::OP_OK)
      ret = -1;

    m_mb = 0;
    m_subsequent_data_pos = 0;
    return ret;
  }

  ni move_data_head_to(CMB * mb, CONST T & h)
  {
    return mb->copy((CONST char*)&h, sizeof(T));
  }

  virtual ni data_len() = 0;

  virtual CProc::OUTPUT at_head_arrival()
  {
    return OP_GO_ON;
  }

  CProc::OUTPUT read_data(CMB * mb)
  {
    if (mb->size() < sizeof(T))
    {
      C_ERROR(ACE_TEXT("mb len too short ( = %d)"), mb->size());
      mb->release();
      return OP_FAIL;
    }
    mb->rd_ptr(mb->base());

    return do_read_data(mb);
  }

  virtual CProc::OUTPUT do_read_data(CMB *)
  {
    return OP_OK;
  }

  ni m_subsequent_data_pos;
  T  m_data_head;
  CMB * m_mb;
};

class CFormatProcBase: public CParentFormattedProc<CCmdHeader>
{
public:
  typedef CParentFormattedProc<CCmdHeader> baseclass;

  CFormatProcBase(CParentHandler * handler);
  virtual DVOID get_sinfo(CMemProt & info) CONST;
  virtual ni at_start();
  virtual CONST text * name() CONST;

protected:
  virtual ni data_len();
  virtual CProc::OUTPUT at_head_arrival();
  virtual CProc::OUTPUT do_read_data(CMB * mb);
  CMB * create_login_mb(CONST ni x = 0);

  enum { IP_LEN = INET_ADDRSTRLEN };
  text m_remote_ip[IP_LEN];
};

class CBSProceBase: public CParentFormattedProc<CBSData>
{
public:
  typedef CParentFormattedProc<CBSData> baseclass;
  CBSProceBase(CParentHandler * h);

protected:
  virtual ni data_len();

  virtual CProc::OUTPUT at_head_arrival();
  virtual CProc::OUTPUT do_read_data(CMB * mb);
};

class CParentServerProc: public CFormatProcBase
{
public:
  typedef CFormatProcBase baseclass;
  CParentServerProc(CParentHandler * h);
  virtual ~CParentServerProc();
  virtual CONST text * name() CONST;
  virtual truefalse ok_to_post(CMB * mb) CONST;
  virtual truefalse term_sn_check_done() CONST;

protected:
  virtual CProc::OUTPUT at_head_arrival();
  CProc::OUTPUT i_is_ver_ok(CMB * mb, CTermSNs & term_SNs);
  CMB * i_create_mb_ver_reply(CTermVerReply::SUBCMD x, ni = 0);

  CTermVer m_term_ver;
};

class CParentClientProc: public CFormatProcBase
{
public:
  typedef CFormatProcBase baseclass;

  CParentClientProc(CParentHandler * h);
  virtual ~CParentClientProc();
  virtual CONST text * name() CONST;
  virtual truefalse term_sn_check_done() CONST;
  virtual ni at_start();
  virtual DVOID at_finish();
  virtual truefalse ok_to_post(CMB * mb) CONST;

protected:
  virtual CProc::OUTPUT at_head_arrival();
  DVOID sn_check_ok(truefalse _is_ok);

private:
  truefalse m_sn_check_ok;
};

class CSockBridge: public ACE_SOCK_ACCEPTOR
{
public:
  typedef ACE_SOCK_ACCEPTOR baseclass;
  ni open (CONST ACE_Addr & l, ni r = 0, ni f = PF_UNSPEC, ni b = 128, ni p = 0)
  {
    return baseclass::open(l, r, f, b, p);
  }
};

class CAcceptorBase: public ACE_Acceptor<CParentHandler, CSockBridge>
{
public:
  typedef ACE_Acceptor<CParentHandler, CSockBridge>  baseclass;
  CAcceptorBase(CDispatchBase *, CHandlerDirector *);
  virtual ~CAcceptorBase();
  virtual ni handle_timeout (CONST ACE_Time_Value &, CONST DVOID * = 0);
  CMod * container() CONST;
  CHandlerDirector * director() CONST;
  CDispatchBase * dispatcher() CONST;

  ni start();
  ni stop();
  DVOID print_info();
  virtual CONST text * name() CONST;

protected:
  enum { TID_reap_broken = 1, TID1, TID2, TID3 };
  virtual DVOID i_print();
  virtual truefalse before_begin();
  virtual DVOID before_finish();

  CDispatchBase * m_dispatcher;
  CMod * m_container;
  CHandlerDirector * m_director;
  ni m_tcp_port;
  ni m_reap_interval; //min
  ni m_reaper_id;
};


class CConnectorBase: public ACE_Connector<CParentHandler, ACE_SOCK_CONNECTOR>
{
public:
  typedef ACE_Connector<CParentHandler, ACE_SOCK_CONNECTOR> baseclass;
  enum { ONCE_COUNT = 100 };

  CConnectorBase(CDispatchBase * _dispatcher, CHandlerDirector * _manager);
  virtual ~CConnectorBase();

  virtual ni handle_timeout (CONST ACE_Time_Value &current_time, CONST DVOID *act = 0);

  CMod * container() CONST;
  CHandlerDirector * director() CONST;
  CDispatchBase * dispatcher() CONST;
  DVOID tcp_addr(CONST text *);
  ni start();
  ni stop();
  DVOID print_data();
  virtual CONST text * name() CONST;
  ni connect_ready();
  DVOID reset_retry_count();

protected:
  enum
  {
    TIMER_ID_check_dead_connection = 1,
    TIMER_ID_reconnect = 2,
    TIMER_ID_multi_connect,
    TIMER_ID_reserved_1,
    TIMER_ID_reserved_2,
    TIMER_ID_reserved_3,
  };
  ni do_connect(ni count = 1, truefalse bNew = false);
  virtual truefalse before_begin();
  virtual DVOID before_finish();
  virtual DVOID i_print();
  virtual truefalse before_reconnect();

  CDispatchBase * m_dispatcher;
  CMod * m_module;
  CHandlerDirector * m_connection_manager;
  ni m_tcp_port;
  std::string m_tcp_addr;
  ni m_num_connection;
  ni m_reconnect_interval; //minutes
  ni m_reconnect_retry_count;
  long m_reconnect_timer_id;
  ni m_idle_time_as_dead; //minutes
  ni m_idle_connection_timer_id;
  ni m_remain_to_connect;
};


class CTaskBase: public ACE_Task<ACE_MT_SYNCH>
{
public:
  CTaskBase(CMod * mod, ni num_threads);
  CMod * module_x() CONST;
  ni start();
  ni stop();
  DVOID print_all();
  virtual CONST text * name() CONST;

protected:
  virtual DVOID i_print();
  truefalse do_add_task(DVOID * p, ni task_type);
  DVOID * get_task(CMB * mb, ni & task_type) CONST;

private:
  CMod * m_mod;
  ni m_threads_count;
};


class CDispatchBase: public ACE_Task<ACE_MT_SYNCH>
{
public:
  CDispatchBase(CMod * pModule, ni numThreads = 1);

  virtual ~CDispatchBase();
  virtual ni open (DVOID * p= 0);
  virtual ni svc();
  ni start();
  ni stop();
  CMod * container() CONST;
  DVOID dump_info();
  virtual CONST text * name() CONST;

protected:
  typedef std::vector<CConnectorBase *> CConnectors;
  typedef std::vector<CAcceptorBase *> CAcceptors;
  enum { TIMER_ID_BASE = 1 };

  virtual DVOID before_finish();
  virtual DVOID before_finish_stage_1();
  virtual truefalse before_begin();
  virtual truefalse do_schedule_work();
  DVOID add_connector(CConnectorBase * _connector);
  DVOID add_acceptor(CAcceptorBase * _acceptor);
  virtual DVOID i_print();

  CMod * m_container;
  ni m_clock_interval;
  CConnectors m_connectors;
  CAcceptors m_acceptors;

private:
  truefalse do_start_i();
  DVOID do_stop_i();

  ACE_Reactor *m_reactor;
  ni m_numThreads;
  ni m_numBatchSend;
  ACE_Thread_Mutex m_mutex;
  truefalse m_init_done;
};


class CMod
{
public:
  CMod(CApp * app);
  virtual ~CMod();
  //module specific
  truefalse running() CONST;
  //both module and app
  truefalse running_with_app() CONST;
  CApp * app() CONST;
  ni start();
  ni stop();
  DVOID print_all();
  virtual CONST text * name() CONST;

protected:
  typedef std::vector<CTaskBase *> CTasks;
  typedef std::vector<CDispatchBase *> CDispatchBases;

  virtual truefalse before_begin();
  virtual DVOID before_finish();
  DVOID add_task(CTaskBase * _service);
  DVOID add_dispatch(CDispatchBase * _dispatcher);
  virtual DVOID i_print();

  CApp * m_app;
  truefalse m_running;

  CTasks m_tasks;
  CDispatchBases m_dispatchs;
};


#endif
