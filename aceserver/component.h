#ifndef BASESERVER_H_
#define BASESERVER_H_

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

class CClientVer
{
public:
  CClientVer();
  CClientVer(u_int8_t major, u_int8_t minor);
  DVOID init(u_int8_t major, u_int8_t minor);
  truefalse from_string(CONST text * s);
  CONST text * to_string() CONST;
  truefalse operator < (CONST CClientVer & rhs);

private:
  enum { DATA_BUFF_SIZE = 8 };
  DVOID prepare_buff();

  u8 m_major;
  u8 m_minor;
  text m_data[DATA_BUFF_SIZE];
};

class CMfileSplit
{
public:
  CMfileSplit();
  truefalse init(CONST text * mfile);
  CONST text * path() CONST;
  CONST text * mfile() CONST;
  CONST text * translate(CONST text * src);

private:
  CMemGuard m_mfile;
  CMemGuard m_path;
  CMemGuard m_translated_name;
};

class CClientInfo
{
public:
  CClientInfo();
  CClientInfo(CONST MyClientID & id, CONST text * _ftp_password = NULL, truefalse _expired = false);
  DVOID set_password(CONST text * _ftp_password);

  enum { FTP_PASSWORD_LEN = 24 };

  truefalse active;
  truefalse expired;
  truefalse switched;
  MyClientID client_id;
  text ftp_password[FTP_PASSWORD_LEN];
  ni  password_len;
};

class CClientIDS
{
public:
  CClientIDS();
  ~CClientIDS();
  truefalse have(CONST MyClientID & id);
  DVOID add(CONST MyClientID & id);
  DVOID add(CONST text * str_id, CONST text *ftp_password = NULL, truefalse expired = false);
  DVOID add_batch(text * idlist); //in the format of "12334434;33222334;34343111;..."
  ni  index_of(CONST MyClientID & id);
  ni  count();
  truefalse value(ni index, MyClientID * id);
  truefalse value_all(ni index, CClientInfo & client_info);
  truefalse active(CONST MyClientID & id, ni & index, truefalse & switched);
//  DVOID active(CONST MyClientID & id, truefalse _active);
  truefalse active(ni index);
  DVOID active(ni index, truefalse _active);
  DVOID switched(ni index, truefalse _switched);
  DVOID expired(ni index, truefalse _expired);
  truefalse mark_valid(CONST MyClientID & id, truefalse valid, ni & idx);

  //APIs used only by db-layer
  ni  last_sequence() CONST;
  DVOID last_sequence(ni _seq);
  DVOID prepare_space(ni _count);

private:
  typedef std::vector<CClientInfo > ClientIDTable_type;
  typedef std::map<MyClientID, ni> ClientIDTable_map;

//  typedef std::vector<MyClientID, MyAllocator<MyClientID> > ClientIDTable_type;
//  typedef std::map<MyClientID, ni, std::less<MyClientID>, MyAllocator<std::pair<const MyClientID,ni> > > ClientIDTable_map;
  ni index_of_i(CONST MyClientID & id, ClientIDTable_map::iterator * pIt = NULL);
  DVOID add_i(CONST MyClientID & id, CONST text *ftp_password, truefalse expired);
  ClientIDTable_type  m_table;
  ClientIDTable_map   m_map;
  ACE_RW_Thread_Mutex m_mutex;
  ni m_last_sequence;
};

EXTERN CClientIDS * g_client_ids; //the side effect of sharing the source codes...

class CFileMD5
{
public:
  enum { MD5_STRING_LENGTH = 32 };
  //  /root/mydir/a.txt  prefix=/root/mydir/
  CFileMD5(CONST text * _filename, CONST text * md5, ni prefix_len, CONST text * alias = NULL);
  truefalse ok() CONST
  {
    return (m_md5[0] != 0);
  }
  CONST text * filename() CONST
  {
    return m_file_name.data();
  }
  CONST text * md5() CONST
  {
    return m_md5;
  }
  ni size(truefalse include_md5_value) CONST
  {
    return include_md5_value? (m_size + MD5_STRING_LENGTH + 1) : m_size;
  }
  truefalse operator == (CONST CFileMD5 & rhs) CONST
  {
    return (strcmp(m_file_name.data(), rhs.m_file_name.data()) == 0);
  }
  truefalse operator < (CONST CFileMD5 & rhs) CONST
  {
    return (strcmp(m_file_name.data(), rhs.m_file_name.data()) < 0);
  }
  truefalse same_md5(CONST CFileMD5 & rhs) CONST
  {
    return memcmp(m_md5, rhs.m_md5, MD5_STRING_LENGTH) == 0;
  }

private:

  CMemGuard m_file_name;
  text m_md5[MD5_STRING_LENGTH];
  ni m_size;
};

class CFileMD5s
{
public:
  typedef std::vector<CFileMD5 *, CCppAllocator<CFileMD5 *> > MyFileMD5List;

  CFileMD5s();
  ~CFileMD5s();
  DVOID enable_map();
  truefalse has_file(CONST text * fn);
  truefalse base_dir(CONST text *);
  DVOID minus(CFileMD5s & , CMfileSplit * spl, truefalse do_delete);
  DVOID trim_garbage(CONST text * pathname);
  truefalse add_file(CONST text * filename, CONST text * md5, ni prefix_len);
  truefalse add_file(CONST text * pathname, CONST text * filename, ni prefix_len, CONST text * alias);
  DVOID sort();
  ni  count() CONST
  {
    return m_file_md5_list.size();
  }
  truefalse to_buffer(text * buff, ni buff_len, truefalse include_md5_value);
  truefalse from_buffer(text * buff, CMfileSplit * spl = NULL);

  ni  total_size(truefalse include_md5_value);
  truefalse calculate(CONST text * dirname, CONST text * mfile, truefalse single);
  truefalse calculate_diff(CONST text * dirname, CMfileSplit * spl = NULL);

private:
  typedef std::tr1::unordered_map<const text *,
                                  CFileMD5 *,
                                  CStrHasher,
                                  CStrEqual,
                                  CCppAllocator <std::pair<const text *, CFileMD5 *> >
                                > MyMD5map;

  truefalse do_scan_directory(CONST text * dirname, ni start_len);
  DVOID do_trim_garbage(CONST text * pathname, ni start_len);

  CFileMD5 * find(CONST text * fn);

  MyFileMD5List m_file_md5_list;
  CMemGuard m_base_dir; //todo: remove m_base_dir
  ni m_base_dir_len;
  MyMD5map * m_md5_map;
};

class CArchiveloaderBase
{
public:
  CArchiveloaderBase();
  virtual ~CArchiveloaderBase()
  {}
  virtual truefalse open(CONST text * filename);
  virtual ni read(text * buff, ni buff_len);
  DVOID close();

protected:
  ni do_read(text * buff, ni buff_len);

  CUnixFileGuard m_file;
  CMemGuard m_file_name;
  ni m_file_length;
};

#pragma pack(push, 1)

class CPackHead
{
public:
  enum { HEADER_MAGIC = 0x96809685 };
  int32_t header_length;
  u_int32_t magic;
  int32_t data_length; //not including the header
  int32_t encrypted_data_length;
  text    file_name[0];
};

#pragma pack(pop)

class CArchiveLoader: public CArchiveloaderBase
{
public:
  typedef CArchiveloaderBase super;

  virtual truefalse open(CONST text * filename);
  virtual ni read(text * buff, ni buff_len);
  CONST text * file_name() CONST;
  truefalse next();
  truefalse eof() CONST;
  DVOID set_key(CONST text * skey);

private:
  truefalse read_header();
  CMemGuard m_wrapped_header;
  ni  m_remain_length;
  ni  m_remain_encrypted_length;
  aes_context m_aes_context;
};


class CArchiveSaverBase
{
public:
  virtual ~CArchiveSaverBase()
  {}
  truefalse open(CONST text * filename);
  truefalse open(CONST text * dir, CONST text * filename);
  virtual truefalse write(text * buff, ni buff_len);
  DVOID close();

protected:
  truefalse do_open();
  truefalse do_write(text * buff, ni buff_len);

  CUnixFileGuard m_file;
  CMemGuard m_file_name;
};

class CArchiveSaver: public CArchiveSaverBase
{
public:
  enum { ENCRYPT_DATA_LENGTH = 4096 };
  typedef CArchiveSaverBase super;

  virtual truefalse write(text * buff, ni buff_len);
  truefalse start(CONST text * filename, ni prefix_len = 0);
  truefalse finish();

  DVOID set_key(CONST text * skey);

private:
  truefalse write_header(CONST text * filename);
  truefalse encrypt_and_write();
  CPackHead m_pack_header;
  ni  m_data_length;
  ni  m_encrypted_length;
  aes_context m_aes_context;
  ni m_remain_encrypted_length;
  CMemGuard m_encrypt_buffer;
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
  CDataComp();
  enum { COMPRESS_100k = 3 };
  enum { BUFFER_LEN = 4096 };
  truefalse compress(CONST text * filename, ni prefix_len, CONST text * destfn, CONST text * key);
  truefalse decompress(CONST text * filename, CONST text * destdir, CONST text * key, CONST text * _rename = NULL);

private:
  truefalse prepare_buffers();
  truefalse do_compress(CArchiveloaderBase * _reader, CArchiveSaverBase * _writer);
  truefalse do_decompress(CArchiveloaderBase * _reader, CArchiveSaverBase * _writer);

  CMemGuard m_buff_in;
  CMemGuard m_buff_out;
  bz_stream m_bz_stream;
};

class CCompCombiner
{
public:
  truefalse open(CONST text * filename);
  truefalse add(CONST text * filename);
  truefalse add_multi(text * filenames, CONST text * path, CONST text seperator = '*', CONST text * ext = NULL);
  DVOID close();

private:
  CUnixFileGuard m_file;
};

class CHandlerBase: public ACE_Svc_Handler<ACE_SOCK_STREAM, ACE_NULL_SYNCH>
{
public:
  typedef ACE_Svc_Handler<ACE_SOCK_STREAM, ACE_NULL_SYNCH> super;
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
  virtual CClientIDS * client_id_table() CONST;

  CConnectionManagerBase * connection_manager();
  CProcBase * processor() CONST;
  ni send_data(CMB * mb);
  DVOID mark_as_reap();

protected:
  virtual DVOID on_close();
  virtual ni  on_open();

  truefalse m_reaped;
  CConnectionManagerBase * m_connection_manager;
  CProcBase * m_processor;
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
  DVOID set_connection_client_id_index(CHandlerBase * handler, ni index, CClientIDS * id_table);
  CHandlerBase * find_handler_by_index(ni index);
  DVOID set_connection_state(CHandlerBase * handler, CState state);
  DVOID remove_connection(CHandlerBase * handler, CClientIDS * id_table);

  DVOID detect_dead_connections(ni timeout);
  DVOID lock();
  DVOID unlock();
  truefalse locked() CONST;
  DVOID dump_info();
  DVOID broadcast(CMB * mb);
  DVOID send_single(CMB * mb);

protected:
  virtual DVOID do_dump_info();

private:
  typedef std::map<CHandlerBase *, long, std::less<CHandlerBase *>, CCppAllocator<std::pair<const CHandlerBase *, long> > > MyConnections;
  typedef MyConnections::iterator MyConnectionsPtr;

  typedef std::map<ni, CHandlerBase *, std::less<ni>, CCppAllocator<std::pair<const ni, CHandlerBase *> > > MyIndexHandlerMap;
  typedef std::map<ni, CHandlerBase *>::iterator MyIndexHandlerMapPtr;

  MyConnectionsPtr find(CHandlerBase * handler);
  MyIndexHandlerMapPtr find_handler_by_index_i(ni index);
  DVOID do_send(CMB * mb, truefalse broadcast);
  DVOID remove_from_active_table(CHandlerBase * handler);
  DVOID remove_from_handler_map(CHandlerBase * handler, CClientIDS * id_table);

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


class MyConnectionManagerLockGuard
{
public:
  MyConnectionManagerLockGuard(CConnectionManagerBase * p): m_p(p)
  {
    if (m_p)
      m_p->lock();
  }

  ~MyConnectionManagerLockGuard()
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
  enum EVENT_RESULT
  {
    ER_ERROR = -1,
    ER_OK = 0,
    ER_CONTINUE,
    ER_OK_FINISHED
  };
  CProcBase(CHandlerBase * handler);
  virtual ~CProcBase();

  virtual DVOID info_string(CMemGuard & info) CONST;
  virtual ni on_open();
  virtual DVOID on_close();
  virtual ni handle_input();
  virtual truefalse can_send_data(CMB * mb) CONST;
  virtual CONST text * name() CONST;
  truefalse wait_for_close() CONST;
  DVOID prepare_to_close();

  truefalse dead() CONST;
  DVOID update_last_activity();
  long last_activity() CONST;

  CONST MyClientID & client_id() CONST;
  DVOID client_id(CONST text *id);
  virtual truefalse client_id_verified() CONST;
  int32_t client_id_index() CONST;

protected:
  ni handle_input_wait_for_close();
  CHandlerBase * m_handler;
  long m_last_activity;
  truefalse m_wait_for_close;

  MyClientID m_client_id;
  int32_t    m_client_id_index;
  ni        m_client_id_length;
};

class CProcRemoteAccessBase: public CProcBase
{
public:
  typedef CProcBase super;
  enum { MAX_COMMAND_LINE_LENGTH = 4096 };

  CProcRemoteAccessBase(CHandlerBase * handler);
  virtual ~CProcRemoteAccessBase();

  virtual ni handle_input();
  virtual ni on_open();

protected:
  virtual ni say_hello();
  virtual ni on_command(CONST text * cmd, text * parameter);
  virtual ni on_command_help();
  ni send_string(CONST text * s);
  ni on_unsupported_command(CONST text * cmd);

private:
  ni do_command(CONST text * cmd, text * parameter);
  ni process_command_line(text * cmdline);
  ni on_command_quit();

  CMB * m_mb;
};

template <typename T> class CFormattedProcBase: public CProcBase
{
public:
  typedef CProcBase super;

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

    goto __loop; //burst transfer, in the hope that more are ready in the buffer

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
    ni ret = c_util_translate_tcp_result(recv_cnt);
    if (ret <= 0)
      return ret;
    m_read_next_offset += recv_cnt;

    if (m_read_next_offset < (ni)sizeof(m_packet_header))
      return 0;

    CProcBase::EVENT_RESULT er = on_recv_header();
    switch(er)
    {
    case CProcBase::ER_ERROR:
    case CProcBase::ER_CONTINUE:
      return -1;
    case CProcBase::ER_OK_FINISHED:
      if (packet_length() != sizeof(m_packet_header))
      {
        C_FATAL("got ER_OK_FINISHED for packet header with more data remain to process.\n");
        return -1;
      }
      if (m_handler->connection_manager())
        m_handler->connection_manager()->on_data_received(sizeof(m_packet_header));
      m_read_next_offset = 0;
      return 1;
    case CProcBase::ER_OK:
      return 0;
    default:
      C_FATAL(ACE_TEXT("unexpected MyVeryBasePacketProcessor::EVENT_RESULT value = %d.\n"), er);
      return -1;
    }
  }

  ni read_req_body()
  {
    if (!m_current_block)
    {
      m_current_block = CMemPoolX::instance()->get_mb(packet_length());
      if (!m_current_block)
        return -1;
      if (copy_header_to_mb(m_current_block, m_packet_header) < 0)
      {
        C_ERROR(ACE_TEXT("Message block copy header: m_current_block.copy() failed\n"));
        return -1;
      }
    }
    update_last_activity();
    return c_util_recv_message_block(m_handler, m_current_block);
  }

  ni handle_req()
  {
    if (m_handler->connection_manager())
       m_handler->connection_manager()->on_data_received(m_current_block->size());

    ni ret = 0;
    if (on_recv_packet(m_current_block) != CProcBase::ER_OK)
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

  virtual CProcBase::EVENT_RESULT on_recv_header()
  {
    return ER_CONTINUE;
  }

  CProcBase::EVENT_RESULT on_recv_packet(CMB * mb)
  {
    if (mb->size() < sizeof(T))
    {
      C_ERROR(ACE_TEXT("message block size too little ( = %d)"), mb->size());
      mb->release();
      return ER_ERROR;
    }
    mb->rd_ptr(mb->base());

    return on_recv_packet_i(mb);
  }

  virtual CProcBase::EVENT_RESULT on_recv_packet_i(CMB * mb)
  {
    ACE_UNUSED_ARG(mb);
    return ER_OK;
  }

  T m_packet_header;
  CMB * m_current_block;
  ni m_read_next_offset;
};

class CFormatProcBase: public CFormattedProcBase<MyDataPacketHeader>
{
public:
  typedef CFormattedProcBase<MyDataPacketHeader> super;

  CFormatProcBase(CHandlerBase * handler);
  virtual DVOID info_string(CMemGuard & info) CONST;
  virtual ni on_open();
  virtual CONST text * name() CONST;

protected:
  virtual ni packet_length();
  virtual CProcBase::EVENT_RESULT on_recv_header();
  virtual CProcBase::EVENT_RESULT on_recv_packet_i(CMB * mb);
  CMB * make_version_check_request_mb(CONST ni extra = 0);

  enum { PEER_ADDR_LEN = INET_ADDRSTRLEN };
  text m_peer_addr[PEER_ADDR_LEN];
};

class CBSProceBase: public CFormattedProcBase<MyBSBasePacket>
{
public:
  typedef CFormattedProcBase<MyBSBasePacket> super;
  CBSProceBase(CHandlerBase * handler);

protected:
  virtual ni packet_length();

  virtual CProcBase::EVENT_RESULT on_recv_header();
  virtual CProcBase::EVENT_RESULT on_recv_packet_i(CMB * mb);
};

class CServerProcBase: public CFormatProcBase
{
public:
  typedef CFormatProcBase super;
  CServerProcBase(CHandlerBase * handler);
  virtual ~CServerProcBase();
  virtual CONST text * name() CONST;
  virtual truefalse can_send_data(CMB * mb) CONST;
  virtual truefalse client_id_verified() CONST;

protected:
  virtual CProcBase::EVENT_RESULT on_recv_header();
  CProcBase::EVENT_RESULT do_version_check_common(CMB * mb, CClientIDS & client_id_table);
  CMB * make_version_check_reply_mb(MyClientVersionCheckReply::REPLY_CODE code, ni extra_len = 0);

  CClientVer m_client_version;
};

class CClientProcBase: public CFormatProcBase
{
public:
  typedef CFormatProcBase super;

  CClientProcBase(CHandlerBase * handler);
  virtual ~CClientProcBase();
  virtual CONST text * name() CONST;
  virtual truefalse client_id_verified() CONST;
  virtual ni on_open();
  virtual DVOID on_close();
  virtual truefalse can_send_data(CMB * mb) CONST;

protected:
  virtual CProcBase::EVENT_RESULT on_recv_header();
  DVOID client_verified(truefalse _verified);

private:
  truefalse m_client_verified;
};

class CSockBridge: public ACE_SOCK_ACCEPTOR
{
public:
  typedef ACE_SOCK_ACCEPTOR super;
  ni open (CONST ACE_Addr &local_sap, ni reuse_addr=0, ni protocol_family=PF_UNSPEC, ni backlog= 128, ni protocol=0)
  {
    return super::open(local_sap, reuse_addr, protocol_family, backlog, protocol);
  }
};

class CAcceptorBase: public ACE_Acceptor<CHandlerBase, CSockBridge>
{
public:
  typedef ACE_Acceptor<CHandlerBase, CSockBridge>  super;
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
  virtual DVOID do_dump_info();
  virtual truefalse on_start();
  virtual DVOID on_stop();

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
  typedef ACE_Connector<CHandlerBase, ACE_SOCK_CONNECTOR> super;
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
  virtual truefalse on_start();
  virtual DVOID on_stop();
  virtual DVOID do_dump_info();
  virtual truefalse before_reconnect();

  CDispatchBase * m_dispatcher;
  CMod * m_module;
  CConnectionManagerBase * m_connection_manager;
  ni m_tcp_port;
  std::string m_tcp_addr;
  ni m_num_connection;
  ni m_reconnect_interval; //in minutes
  ni m_reconnect_retry_count;
  long m_reconnect_timer_id;
  ni m_idle_time_as_dead; //in minutes
  ni m_idle_connection_timer_id;
  ni m_remain_to_connect;
};


class CTaskBase: public ACE_Task<ACE_MT_SYNCH>
{
public:
  CTaskBase(CMod * mod, ni num_threads);
  CMod * module_x() CONST; //name collision with parent class
  ni start();
  ni stop();
  DVOID dump_info();
  virtual CONST text * name() CONST;

protected:
  virtual DVOID do_dump_info();
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

  virtual DVOID on_stop();
  virtual DVOID on_stop_stage_1();
  virtual truefalse on_start();
  virtual truefalse on_event_loop();
  DVOID add_connector(CConnectorBase * _connector);
  DVOID add_acceptor(CAcceptorBase * _acceptor);
  virtual DVOID do_dump_info();

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
  DVOID dump_info();
  virtual CONST text * name() CONST;

protected:
  typedef std::vector<CTaskBase *> CTasks;
  typedef std::vector<CDispatchBase *> CDispatchBases;

  virtual truefalse on_start();
  virtual DVOID on_stop();
  DVOID add_task(CTaskBase * _service);
  DVOID add_dispatch(CDispatchBase * _dispatcher);
  virtual DVOID do_dump_info();

  CApp * m_app;
  truefalse m_running;

  CTasks m_tasks;
  CDispatchBases m_dispatchs;
};


#endif /* BASESERVER_H_ */
