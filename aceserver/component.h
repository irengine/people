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
class CHandlerBase;
class CAcceptorBase;
class CConnectionManagerBase;
class CApp;
class CDispatchBase;
class CConnectorBase;
class CProcBase;

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

class CCompCombiner
{
public:
  truefalse open(CONST text *);
  truefalse add(CONST text *);
  truefalse add_multi(text * filenames, CONST text * path, CONST text seperator = '*', CONST text * ext = NULL);
  DVOID close();

private:
  CFileProt m_f;
};

class CHandlerBase: public ACE_Svc_Handler<ACE_SOCK_STREAM, ACE_NULL_SYNCH>
{
public:
  typedef ACE_Svc_Handler<ACE_SOCK_STREAM, ACE_NULL_SYNCH> baseclass;
  CHandlerBase(CConnectionManagerBase * xptr = NULL);
  virtual ~CHandlerBase();
  DVOID parent(DVOID * p)
    { m_parent = p; }
  CAcceptorBase * acceptor() CONST
    { return (CAcceptorBase *)m_parent; }
  CConnectorBase * connector() CONST
    { return (CConnectorBase *)m_parent; }
  virtual ni open (DVOID * p = 0);
  virtual ni handle_input(ACE_HANDLE fd = ACE_INVALID_HANDLE);
  virtual ni handle_output(ACE_HANDLE fd = ACE_INVALID_HANDLE);
  virtual ni handle_close(ACE_HANDLE = ACE_INVALID_HANDLE, ACE_Reactor_Mask = ACE_Event_Handler::ALL_EVENTS_MASK);
  virtual CTermSNs * client_id_table() CONST;

  CConnectionManagerBase * connection_manager();
  CProcBase * processor() CONST;
  ni send_data(CMB * mb);
  DVOID mark_as_reap();

protected:
  virtual DVOID on_close();
  virtual ni  on_open();

  truefalse m_reaped;
  CConnectionManagerBase * m_connection_manager;
  CProcBase * m_proc;
  DVOID * m_parent;
};

class CConnectionManagerBase
{
public:
  enum CState
  {
    CS_Pending = 1,
    CS_Connected = 2
  };
  CConnectionManagerBase();
  virtual ~CConnectionManagerBase();
  ni  active_count() CONST;
  ni  total_count() CONST;
  ni  reaped_count() CONST;
  ni  pending_count() CONST;
  i64 bytes_received() CONST;
  i64 bytes_sent() CONST;

  DVOID on_data_received(ni data_size);
  DVOID on_data_send(ni data_size);

  DVOID add_connection(CHandlerBase * handler, CState state);
  DVOID set_connection_client_id_index(CHandlerBase * handler, ni index, CTermSNs * id_table);
  CHandlerBase * find_handler_by_index(ni index);
  DVOID set_connection_state(CHandlerBase * handler, CState state);
  DVOID remove_connection(CHandlerBase * handler, CTermSNs * id_table);

  DVOID detect_dead_connections(ni timeout);
  DVOID lock();
  DVOID unlock();
  truefalse locked() CONST;
  DVOID print_all();
  DVOID broadcast(CMB * mb);
  DVOID send_single(CMB * mb);

protected:
  virtual DVOID i_print();

private:
  typedef std::map<CHandlerBase *, long, std::less<CHandlerBase *>, CCppAllocator<std::pair<const CHandlerBase *, long> > > MyConnections;
  typedef MyConnections::iterator MyConnectionsPtr;

  typedef std::map<ni, CHandlerBase *, std::less<ni>, CCppAllocator<std::pair<const ni, CHandlerBase *> > > MyIndexHandlerMap;
  typedef std::map<ni, CHandlerBase *>::iterator MyIndexHandlerMapPtr;

  MyConnectionsPtr find(CHandlerBase * handler);
  MyIndexHandlerMapPtr find_handler_by_index_i(ni index);
  DVOID do_send(CMB * mb, truefalse broadcast);
  DVOID remove_from_active_table(CHandlerBase * handler);
  DVOID remove_from_handler_map(CHandlerBase * handler, CTermSNs * id_table);

  ni  m_num_connections;
  ni  m_total_connections;
  ni  m_pending;
  ni  m_reaped_connections;
  i64 m_bytes_received;
  i64 m_bytes_sent;
  truefalse m_locked;
  MyConnections m_active_connections;
  MyIndexHandlerMap m_index_handler_map;
};


class MyConnectionManagerLockProt
{
public:
  MyConnectionManagerLockProt(CConnectionManagerBase * p): m_p(p)
  {
    if (m_p)
      m_p->lock();
  }

  ~MyConnectionManagerLockProt()
  {
    if (m_p)
      m_p->unlock();
  }

private:
  CConnectionManagerBase * m_p;
};

class CProcBase
{
public:
  enum OUTPUT
  {
    OP_FAIL = -1,
    OP_OK = 0,
    OP_CONTINUE,
    OP_DONE
  };
  CProcBase(CHandlerBase *);
  virtual ~CProcBase();

  virtual DVOID get_sinfo(CMemProt &) CONST;
  virtual ni on_open();
  virtual DVOID on_close();
  virtual ni handle_input();
  virtual truefalse ok_to_send(CMB *) CONST;
  virtual CONST text * name() CONST;
  truefalse wait_for_close() CONST;
  DVOID prepare_to_close();

  truefalse broken() CONST;
  DVOID update_last_activity();
  long last_activity() CONST;

  CONST CNumber & client_id() CONST;
  DVOID client_id(CONST text *id);
  virtual truefalse client_id_verified() CONST;
  i32 client_id_index() CONST;

protected:
  ni handle_input_wait_for_close();
  CHandlerBase * m_handler;
  long m_last_activity;
  truefalse m_wait_for_close;

  CNumber m_client_id;
  i32    m_client_id_index;
  ni     m_client_id_length;
};


template <typename T> class CFormattedProcBase: public CProcBase
{
public:
  typedef CProcBase baseclass;

  CFormattedProcBase (CHandlerBase * handler): CProcBase(handler)
  {
    m_read_next_offset = 0;
    m_current_block = NULL;
  }

  virtual ~CFormattedProcBase()
  {
    if (m_current_block)
      m_current_block->release();
  }

  virtual CONST text * name() CONST
  {
    return "MyVeryBasePacketProcessor";
  }

  virtual ni handle_input()
  {
    if (m_wait_for_close)
      return handle_input_wait_for_close();

    ni loop_count = 0;
  __loop:
    ++loop_count;

    if (loop_count >= 4) //do not bias too much toward this connection, this can starve other clients
      return 0;          //just in case of the malicious/ill-behaved clients
    if (m_read_next_offset < (ni)sizeof(m_packet_header))
    {
      ni ret = read_req_header();
      //MY_DEBUG("read_req_header() returns %d, m_read_next_offset = %d\n", ret, m_read_next_offset);
      if (ret < 0)
        return -1;
      else if (ret > 0)
        return 0;
    }

    if (m_read_next_offset < (ni)sizeof(m_packet_header))
      return 0;

    ni ret = read_req_body();
    if (ret < 0)
      return -1;
    else if (ret > 0)
      return 0;

    if (handle_req() < 0)
      return -1;

    goto __loop;

    return 0;
  }

protected:

  ni read_req_header()
  {
    update_last_activity();
    ssize_t recv_cnt = m_handler->peer().recv((char*)&m_packet_header + m_read_next_offset,
        sizeof(m_packet_header) - m_read_next_offset);
  //      TEMP_FAILURE_RETRY(m_handler->peer().recv((char*)&m_packet_header + m_read_next_offset,
  //      sizeof(m_packet_header) - m_read_next_offset));
    ni ret = c_tools_socket_outcome(recv_cnt);
    if (ret <= 0)
      return ret;
    m_read_next_offset += recv_cnt;

    if (m_read_next_offset < (ni)sizeof(m_packet_header))
      return 0;

    CProcBase::OUTPUT er = on_recv_header();
    switch(er)
    {
    case CProcBase::OP_FAIL:
    case CProcBase::OP_CONTINUE:
      return -1;
    case CProcBase::OP_DONE:
      if (packet_length() != sizeof(m_packet_header))
      {
        C_FATAL("got ER_OK_FINISHED for packet header with more data remain to process.\n");
        return -1;
      }
      if (m_handler->connection_manager())
        m_handler->connection_manager()->on_data_received(sizeof(m_packet_header));
      m_read_next_offset = 0;
      return 1;
    case CProcBase::OP_OK:
      return 0;
    default:
      C_FATAL("unexpected MyVeryBasePacketProcessor::EVENT_RESULT value = %d.\n", er);
      return -1;
    }
  }

  ni read_req_body()
  {
    if (!m_current_block)
    {
      m_current_block = CCacheX::instance()->get_mb(packet_length());
      if (!m_current_block)
        return -1;
      if (copy_header_to_mb(m_current_block, m_packet_header) < 0)
      {
        C_ERROR(ACE_TEXT("Message block copy header: m_current_block.copy() failed\n"));
        return -1;
      }
    }
    update_last_activity();
    return c_tools_read_mb(m_handler, m_current_block);
  }

  ni handle_req()
  {
    if (m_handler->connection_manager())
       m_handler->connection_manager()->on_data_received(m_current_block->size());

    ni ret = 0;
    if (on_recv_packet(m_current_block) != CProcBase::OP_OK)
      ret = -1;

    m_current_block = 0;
    m_read_next_offset = 0;
    return ret;
  }

  ni copy_header_to_mb(CMB * mb, CONST T & header)
  {
    return mb->copy((CONST char*)&header, sizeof(T));
  }

  virtual ni packet_length() = 0;

  virtual CProcBase::OUTPUT on_recv_header()
  {
    return OP_CONTINUE;
  }

  CProcBase::OUTPUT on_recv_packet(CMB * mb)
  {
    if (mb->size() < sizeof(T))
    {
      C_ERROR(ACE_TEXT("message block size too little ( = %d)"), mb->size());
      mb->release();
      return OP_FAIL;
    }
    mb->rd_ptr(mb->base());

    return on_recv_packet_i(mb);
  }

  virtual CProcBase::OUTPUT on_recv_packet_i(CMB * mb)
  {
    ACE_UNUSED_ARG(mb);
    return OP_OK;
  }

  T m_packet_header;
  CMB * m_current_block;
  ni m_read_next_offset;
};

class CFormatProcBase: public CFormattedProcBase<CCmdHeader>
{
public:
  typedef CFormattedProcBase<CCmdHeader> baseclass;

  CFormatProcBase(CHandlerBase * handler);
  virtual DVOID get_sinfo(CMemProt & info) CONST;
  virtual ni on_open();
  virtual CONST text * name() CONST;

protected:
  virtual ni packet_length();
  virtual CProcBase::OUTPUT on_recv_header();
  virtual CProcBase::OUTPUT on_recv_packet_i(CMB * mb);
  CMB * make_version_check_request_mb(CONST ni extra = 0);

  enum { PEER_ADDR_LEN = INET_ADDRSTRLEN };
  text m_peer_addr[PEER_ADDR_LEN];
};

class CBSProceBase: public CFormattedProcBase<CBSData>
{
public:
  typedef CFormattedProcBase<CBSData> baseclass;
  CBSProceBase(CHandlerBase * handler);

protected:
  virtual ni packet_length();

  virtual CProcBase::OUTPUT on_recv_header();
  virtual CProcBase::OUTPUT on_recv_packet_i(CMB * mb);
};

class CServerProcBase: public CFormatProcBase
{
public:
  typedef CFormatProcBase baseclass;
  CServerProcBase(CHandlerBase * handler);
  virtual ~CServerProcBase();
  virtual CONST text * name() CONST;
  virtual truefalse ok_to_send(CMB * mb) CONST;
  virtual truefalse client_id_verified() CONST;

protected:
  virtual CProcBase::OUTPUT on_recv_header();
  CProcBase::OUTPUT do_version_check_common(CMB * mb, CTermSNs & client_id_table);
  CMB * make_version_check_reply_mb(CTermVerReply::SUBCMD code, ni extra_len = 0);

  CTermVer m_client_version;
};

class CClientProcBase: public CFormatProcBase
{
public:
  typedef CFormatProcBase baseclass;

  CClientProcBase(CHandlerBase * handler);
  virtual ~CClientProcBase();
  virtual CONST text * name() CONST;
  virtual truefalse client_id_verified() CONST;
  virtual ni on_open();
  virtual DVOID on_close();
  virtual truefalse ok_to_send(CMB * mb) CONST;

protected:
  virtual CProcBase::OUTPUT on_recv_header();
  DVOID client_verified(truefalse _verified);

private:
  truefalse m_client_verified;
};

class CSockBridge: public ACE_SOCK_ACCEPTOR
{
public:
  typedef ACE_SOCK_ACCEPTOR baseclass;
  ni open (CONST ACE_Addr &local_sap, ni reuse_addr=0, ni protocol_family=PF_UNSPEC, ni backlog= 128, ni protocol=0)
  {
    return baseclass::open(local_sap, reuse_addr, protocol_family, backlog, protocol);
  }
};

class CAcceptorBase: public ACE_Acceptor<CHandlerBase, CSockBridge>
{
public:
  typedef ACE_Acceptor<CHandlerBase, CSockBridge>  baseclass;
  CAcceptorBase(CDispatchBase * _dispatcher, CConnectionManagerBase * _manager);
  virtual ~CAcceptorBase();
  virtual ni handle_timeout (CONST ACE_Time_Value &current_time, CONST DVOID *act = 0);
  CMod * module_x() CONST;
  CConnectionManagerBase * connection_manager() CONST;
  CDispatchBase * dispatcher() CONST;

  ni start();
  ni stop();
  DVOID print_info();
  virtual CONST text * name() CONST;

protected:
  enum
  {
    TIMER_ID_check_dead_connection = 1,
    TIMER_ID_reserved_1,
    TIMER_ID_reserved_2,
    TIMER_ID_reserved_3,
  };
  virtual DVOID i_print();
  virtual truefalse before_begin();
  virtual DVOID before_finish();

  CDispatchBase * m_dispatcher;
  CMod * m_module;
  CConnectionManagerBase * m_connection_manager;
  ni m_tcp_port;
  ni m_idle_time_as_dead; //in minutes
  ni m_idle_connection_timer_id;
};


class CConnectorBase: public ACE_Connector<CHandlerBase, ACE_SOCK_CONNECTOR>
{
public:
  typedef ACE_Connector<CHandlerBase, ACE_SOCK_CONNECTOR> baseclass;
  enum { BATCH_CONNECT_NUM = 100 };

  CConnectorBase(CDispatchBase * _dispatcher, CConnectionManagerBase * _manager);
  virtual ~CConnectorBase();

  virtual ni handle_timeout (CONST ACE_Time_Value &current_time, CONST DVOID *act = 0);

  CMod * module_x() CONST;
  CConnectionManagerBase * connection_manager() CONST;
  CDispatchBase * dispatcher() CONST;
  DVOID tcp_addr(CONST text * addr);
  ni start();
  ni stop();
  DVOID dump_info();
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
  CConnectionManagerBase * m_connection_manager;
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
  CMod * module_x() CONST;
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

  CMod * m_mod;
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
