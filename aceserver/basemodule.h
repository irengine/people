/*
 * baseserver.h
 *
 *  Created on: Dec 26, 2011
 *      Author: root
 */

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

#include "mycomutil.h"
#include "datapacket.h"

class CMod;
class MyBaseHandler;
class MyBaseAcceptor;
class MyBaseConnectionManager;
class CApp;
class MyBaseDispatcher;
class MyBaseConnector;
class MyBaseProcessor;

class MyClientVerson
{
public:
  MyClientVerson();
  MyClientVerson(u_int8_t major, u_int8_t minor);
  void init(u_int8_t major, u_int8_t minor);
  bool from_string(const char * s);
  const char * to_string() const;
  bool operator < (const MyClientVerson & rhs);

private:
  enum { DATA_BUFF_SIZE = 8 };
  void prepare_buff();

  u_int8_t m_major;
  u_int8_t m_minor;
  char m_data[DATA_BUFF_SIZE];
};

class MyMfileSplitter
{
public:
  MyMfileSplitter();
  bool init(const char * mfile);
  const char * path() const;
  const char * mfile() const;
  const char * translate(const char * src);

private:
  CMemGuard m_mfile;
  CMemGuard m_path;
  CMemGuard m_translated_name;
};

class MyClientInfo
{
public:
  MyClientInfo();
  MyClientInfo(const MyClientID & id, const char * _ftp_password = NULL, bool _expired = false);
  void set_password(const char * _ftp_password);

  enum { FTP_PASSWORD_LEN = 24 };

  bool active;
  bool expired;
  bool switched;
  MyClientID client_id;
  char ftp_password[FTP_PASSWORD_LEN];
  int  password_len;
};

class MyClientIDTable
{
public:
  MyClientIDTable();
  ~MyClientIDTable();
  bool contains(const MyClientID & id);
  void add(const MyClientID & id);
  void add(const char * str_id, const char *ftp_password = NULL, bool expired = false);
  void add_batch(char * idlist); //in the format of "12334434;33222334;34343111;..."
  int  index_of(const MyClientID & id);
  int  count();
  bool value(int index, MyClientID * id);
  bool value_all(int index, MyClientInfo & client_info);
  bool active(const MyClientID & id, int & index, bool & switched);
//  void active(const MyClientID & id, bool _active);
  bool active(int index);
  void active(int index, bool _active);
  void switched(int index, bool _switched);
  void expired(int index, bool _expired);
  bool mark_valid(const MyClientID & id, bool valid, int & idx);

  //APIs used only by db-layer
  int  last_sequence() const;
  void last_sequence(int _seq);
  void prepare_space(int _count);

private:
  typedef std::vector<MyClientInfo > ClientIDTable_type;
  typedef std::map<MyClientID, int> ClientIDTable_map;

//  typedef std::vector<MyClientID, MyAllocator<MyClientID> > ClientIDTable_type;
//  typedef std::map<MyClientID, int, std::less<MyClientID>, MyAllocator<std::pair<const MyClientID,int> > > ClientIDTable_map;
  int index_of_i(const MyClientID & id, ClientIDTable_map::iterator * pIt = NULL);
  void add_i(const MyClientID & id, const char *ftp_password, bool expired);
  ClientIDTable_type  m_table;
  ClientIDTable_map   m_map;
  ACE_RW_Thread_Mutex m_mutex;
  int m_last_sequence;
};

extern MyClientIDTable * g_client_id_table; //the side effect of sharing the source codes...

class MyFileMD5
{
public:
  enum { MD5_STRING_LENGTH = 32 };
  //  /root/mydir/a.txt  prefix=/root/mydir/
  MyFileMD5(const char * _filename, const char * md5, int prefix_len, const char * alias = NULL);
  bool ok() const
  {
    return (m_md5[0] != 0);
  }
  const char * filename() const
  {
    return m_file_name.data();
  }
  const char * md5() const
  {
    return m_md5;
  }
  int size(bool include_md5_value) const
  {
    return include_md5_value? (m_size + MD5_STRING_LENGTH + 1) : m_size;
  }
  bool operator == (const MyFileMD5 & rhs) const
  {
    return (strcmp(m_file_name.data(), rhs.m_file_name.data()) == 0);
  }
  bool operator < (const MyFileMD5 & rhs) const
  {
    return (strcmp(m_file_name.data(), rhs.m_file_name.data()) < 0);
  }
  bool same_md5(const MyFileMD5 & rhs) const
  {
    return memcmp(m_md5, rhs.m_md5, MD5_STRING_LENGTH) == 0;
  }

private:

  CMemGuard m_file_name;
  char m_md5[MD5_STRING_LENGTH];
  int m_size;
};

class MyFileMD5s
{
public:
  typedef std::vector<MyFileMD5 *, MyAllocator<MyFileMD5 *> > MyFileMD5List;

  MyFileMD5s();
  ~MyFileMD5s();
  void enable_map();
  bool has_file(const char * fn);
  bool base_dir(const char *);
  void minus(MyFileMD5s & , MyMfileSplitter * spl, bool do_delete);
  void trim_garbage(const char * pathname);
  bool add_file(const char * filename, const char * md5, int prefix_len);
  bool add_file(const char * pathname, const char * filename, int prefix_len, const char * alias);
  void sort();
  int  count() const
  {
    return m_file_md5_list.size();
  }
  bool to_buffer(char * buff, int buff_len, bool include_md5_value);
  bool from_buffer(char * buff, MyMfileSplitter * spl = NULL);

  int  total_size(bool include_md5_value);
  bool calculate(const char * dirname, const char * mfile, bool single);
  bool calculate_diff(const char * dirname, MyMfileSplitter * spl = NULL);

private:
  typedef std::tr1::unordered_map<const char *,
                                  MyFileMD5 *,
                                  CStrHasher,
                                  CStrEqual,
                                  MyAllocator <std::pair<const char *, MyFileMD5 *> >
                                > MyMD5map;

  bool do_scan_directory(const char * dirname, int start_len);
  void do_trim_garbage(const char * pathname, int start_len);

  MyFileMD5 * find(const char * fn);

  MyFileMD5List m_file_md5_list;
  CMemGuard m_base_dir; //todo: remove m_base_dir
  int m_base_dir_len;
  MyMD5map * m_md5_map;
};

class MyBaseArchiveReader
{
public:
  MyBaseArchiveReader();
  virtual ~MyBaseArchiveReader()
  {}
  virtual bool open(const char * filename);
  virtual int read(char * buff, int buff_len);
  void close();

protected:
  int do_read(char * buff, int buff_len);

  CUnixFileGuard m_file;
  CMemGuard m_file_name;
  int m_file_length;
};

#pragma pack(push, 1)

class MyWrappedHeader
{
public:
  enum { HEADER_MAGIC = 0x96809685 };
  int32_t header_length;
  u_int32_t magic;
  int32_t data_length; //not including the header
  int32_t encrypted_data_length;
  char    file_name[0];
};

#pragma pack(pop)

class MyWrappedArchiveReader: public MyBaseArchiveReader
{
public:
  typedef MyBaseArchiveReader super;

  virtual bool open(const char * filename);
  virtual int read(char * buff, int buff_len);
  const char * file_name() const;
  bool next();
  bool eof() const;
  void set_key(const char * skey);

private:
  bool read_header();
  CMemGuard m_wrapped_header;
  int  m_remain_length;
  int  m_remain_encrypted_length;
  aes_context m_aes_context;
};


class MyBaseArchiveWriter
{
public:
  virtual ~MyBaseArchiveWriter()
  {}
  bool open(const char * filename);
  bool open(const char * dir, const char * filename);
  virtual bool write(char * buff, int buff_len);
  void close();

protected:
  bool do_open();
  bool do_write(char * buff, int buff_len);

  CUnixFileGuard m_file;
  CMemGuard m_file_name;
};

class MyWrappedArchiveWriter: public MyBaseArchiveWriter
{
public:
  enum { ENCRYPT_DATA_LENGTH = 4096 };
  typedef MyBaseArchiveWriter super;

  virtual bool write(char * buff, int buff_len);
  bool start(const char * filename, int prefix_len = 0);
  bool finish();

  void set_key(const char * skey);

private:
  bool write_header(const char * filename);
  bool encrypt_and_write();
  MyWrappedHeader m_wrapped_header;
  int  m_data_length;
  int  m_encrypted_length;
  aes_context m_aes_context;
  int m_remain_encrypted_length;
  CMemGuard m_encrypt_buffer;
};

class MyBZMemPoolAdaptor
{
public:
  static void * my_alloc(void *,int, int );
  static void my_free(void *, void *);
};

class MyBZCompressor
{
public:
  MyBZCompressor();
  enum { COMPRESS_100k = 3 };
  enum { BUFFER_LEN = 4096 };
  bool compress(const char * filename, int prefix_len, const char * destfn, const char * key);
  bool decompress(const char * filename, const char * destdir, const char * key, const char * _rename = NULL);

private:
  bool prepare_buffers();
  bool do_compress(MyBaseArchiveReader * _reader, MyBaseArchiveWriter * _writer);
  bool do_decompress(MyBaseArchiveReader * _reader, MyBaseArchiveWriter * _writer);

  CMemGuard m_buff_in;
  CMemGuard m_buff_out;
  bz_stream m_bz_stream;
};

class MyBZCompositor
{
public:
  bool open(const char * filename);
  bool add(const char * filename);
  bool add_multi(char * filenames, const char * path, const char seperator = '*', const char * ext = NULL);
  void close();

private:
  CUnixFileGuard m_file;
};

class MyBaseHandler: public ACE_Svc_Handler<ACE_SOCK_STREAM, ACE_NULL_SYNCH>
{
public:
  typedef ACE_Svc_Handler<ACE_SOCK_STREAM, ACE_NULL_SYNCH> super;
  MyBaseHandler(MyBaseConnectionManager * xptr = NULL);
  virtual ~MyBaseHandler();
  void parent(void * p)
    { m_parent = p; }
  MyBaseAcceptor * acceptor() const
    { return (MyBaseAcceptor *)m_parent; }
  MyBaseConnector * connector() const
    { return (MyBaseConnector *)m_parent; }
  virtual int open (void * p = 0);
  virtual int handle_input(ACE_HANDLE fd = ACE_INVALID_HANDLE);
  virtual int handle_output(ACE_HANDLE fd = ACE_INVALID_HANDLE);
  virtual int handle_close(ACE_HANDLE = ACE_INVALID_HANDLE, ACE_Reactor_Mask = ACE_Event_Handler::ALL_EVENTS_MASK);
  virtual MyClientIDTable * client_id_table() const;

  MyBaseConnectionManager * connection_manager();
  MyBaseProcessor * processor() const;
  int send_data(ACE_Message_Block * mb);
  void mark_as_reap();

protected:
  virtual void on_close();
  virtual int  on_open();

  bool m_reaped;
  MyBaseConnectionManager * m_connection_manager;
  MyBaseProcessor * m_processor;
  void * m_parent;
};

class MyBaseConnectionManager
{
public:
  enum Connection_State
  {
    CS_Pending = 1,
    CS_Connected = 2
  };
  MyBaseConnectionManager();
  virtual ~MyBaseConnectionManager();
  int  active_connections() const;
  int  total_connections() const;
  int  reaped_connections() const;
  int  pending_count() const;
  long long int bytes_received() const;
  long long int bytes_sent() const;

  void on_data_received(int data_size);
  void on_data_send(int data_size);

  void add_connection(MyBaseHandler * handler, Connection_State state);
  void set_connection_client_id_index(MyBaseHandler * handler, int index, MyClientIDTable * id_table);
  MyBaseHandler * find_handler_by_index(int index);
  void set_connection_state(MyBaseHandler * handler, Connection_State state);
  void remove_connection(MyBaseHandler * handler, MyClientIDTable * id_table);

  void detect_dead_connections(int timeout);
  void lock();
  void unlock();
  bool locked() const;
  void dump_info();
  void broadcast(ACE_Message_Block * mb);
  void send_single(ACE_Message_Block * mb);

protected:
  virtual void do_dump_info();

private:
  typedef std::map<MyBaseHandler *, long, std::less<MyBaseHandler *>, MyAllocator<std::pair<const MyBaseHandler *, long> > > MyConnections;
  typedef MyConnections::iterator MyConnectionsPtr;

  typedef std::map<int, MyBaseHandler *, std::less<int>, MyAllocator<std::pair<const int, MyBaseHandler *> > > MyIndexHandlerMap;
  typedef std::map<int, MyBaseHandler *>::iterator MyIndexHandlerMapPtr;

  MyConnectionsPtr find(MyBaseHandler * handler);
  MyIndexHandlerMapPtr find_handler_by_index_i(int index);
  void do_send(ACE_Message_Block * mb, bool broadcast);
  void remove_from_active_table(MyBaseHandler * handler);
  void remove_from_handler_map(MyBaseHandler * handler, MyClientIDTable * id_table);

  int  m_num_connections;
  int  m_total_connections;
  int  m_pending;
  int  m_reaped_connections;
  long long int m_bytes_received;
  long long int m_bytes_sent;
  bool m_locked;
  MyConnections m_active_connections;
  MyIndexHandlerMap m_index_handler_map;
};


class MyConnectionManagerLockGuard
{
public:
  MyConnectionManagerLockGuard(MyBaseConnectionManager * p): m_p(p)
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
  MyBaseConnectionManager * m_p;
};

class MyBaseProcessor
{
public:
  enum EVENT_RESULT
  {
    ER_ERROR = -1,
    ER_OK = 0,
    ER_CONTINUE,
    ER_OK_FINISHED
  };
  MyBaseProcessor(MyBaseHandler * handler);
  virtual ~MyBaseProcessor();

  virtual void info_string(CMemGuard & info) const;
  virtual int on_open();
  virtual void on_close();
  virtual int handle_input();
  virtual bool can_send_data(ACE_Message_Block * mb) const;
  virtual const char * name() const;
  bool wait_for_close() const;
  void prepare_to_close();

  bool dead() const;
  void update_last_activity();
  long last_activity() const;

  const MyClientID & client_id() const;
  void client_id(const char *id);
  virtual bool client_id_verified() const;
  int32_t client_id_index() const;

protected:
  int handle_input_wait_for_close();
  MyBaseHandler * m_handler;
  long m_last_activity;
  bool m_wait_for_close;

  MyClientID m_client_id;
  int32_t    m_client_id_index;
  int        m_client_id_length;
};

class MyBaseRemoteAccessProcessor: public MyBaseProcessor
{
public:
  typedef MyBaseProcessor super;
  enum { MAX_COMMAND_LINE_LENGTH = 4096 };

  MyBaseRemoteAccessProcessor(MyBaseHandler * handler);
  virtual ~MyBaseRemoteAccessProcessor();

  virtual int handle_input();
  virtual int on_open();

protected:
  virtual int say_hello();
  virtual int on_command(const char * cmd, char * parameter);
  virtual int on_command_help();
  int send_string(const char * s);
  int on_unsupported_command(const char * cmd);

private:
  int do_command(const char * cmd, char * parameter);
  int process_command_line(char * cmdline);
  int on_command_quit();

  ACE_Message_Block * m_mb;
};

template <typename T> class MyVeryBasePacketProcessor: public MyBaseProcessor
{
public:
  typedef MyBaseProcessor super;

  MyVeryBasePacketProcessor (MyBaseHandler * handler): MyBaseProcessor(handler)
  {
    m_read_next_offset = 0;
    m_current_block = NULL;
  }

  virtual ~MyVeryBasePacketProcessor()
  {
    if (m_current_block)
      m_current_block->release();
  }

  virtual const char * name() const
  {
    return "MyVeryBasePacketProcessor";
  }

  virtual int handle_input()
  {
    if (m_wait_for_close)
      return handle_input_wait_for_close();

    int loop_count = 0;
  __loop:
    ++loop_count;

    if (loop_count >= 4) //do not bias too much toward this connection, this can starve other clients
      return 0;          //just in case of the malicious/ill-behaved clients
    if (m_read_next_offset < (int)sizeof(m_packet_header))
    {
      int ret = read_req_header();
      //MY_DEBUG("read_req_header() returns %d, m_read_next_offset = %d\n", ret, m_read_next_offset);
      if (ret < 0)
        return -1;
      else if (ret > 0)
        return 0;
    }

    if (m_read_next_offset < (int)sizeof(m_packet_header))
      return 0;

    int ret = read_req_body();
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

  int read_req_header()
  {
    update_last_activity();
    ssize_t recv_cnt = m_handler->peer().recv((char*)&m_packet_header + m_read_next_offset,
        sizeof(m_packet_header) - m_read_next_offset);
  //      TEMP_FAILURE_RETRY(m_handler->peer().recv((char*)&m_packet_header + m_read_next_offset,
  //      sizeof(m_packet_header) - m_read_next_offset));
    int ret = mycomutil_translate_tcp_result(recv_cnt);
    if (ret <= 0)
      return ret;
    m_read_next_offset += recv_cnt;

    if (m_read_next_offset < (int)sizeof(m_packet_header))
      return 0;

    MyBaseProcessor::EVENT_RESULT er = on_recv_header();
    switch(er)
    {
    case MyBaseProcessor::ER_ERROR:
    case MyBaseProcessor::ER_CONTINUE:
      return -1;
    case MyBaseProcessor::ER_OK_FINISHED:
      if (packet_length() != sizeof(m_packet_header))
      {
        C_FATAL("got ER_OK_FINISHED for packet header with more data remain to process.\n");
        return -1;
      }
      if (m_handler->connection_manager())
        m_handler->connection_manager()->on_data_received(sizeof(m_packet_header));
      m_read_next_offset = 0;
      return 1;
    case MyBaseProcessor::ER_OK:
      return 0;
    default:
      C_FATAL(ACE_TEXT("unexpected MyVeryBasePacketProcessor::EVENT_RESULT value = %d.\n"), er);
      return -1;
    }
  }

  int read_req_body()
  {
    if (!m_current_block)
    {
      m_current_block = MyMemPoolFactoryX::instance()->get_message_block(packet_length());
      if (!m_current_block)
        return -1;
      if (copy_header_to_mb(m_current_block, m_packet_header) < 0)
      {
        C_ERROR(ACE_TEXT("Message block copy header: m_current_block.copy() failed\n"));
        return -1;
      }
    }
    update_last_activity();
    return mycomutil_recv_message_block(m_handler, m_current_block);
  }

  int handle_req()
  {
    if (m_handler->connection_manager())
       m_handler->connection_manager()->on_data_received(m_current_block->size());

    int ret = 0;
    if (on_recv_packet(m_current_block) != MyBaseProcessor::ER_OK)
      ret = -1;

    m_current_block = 0;
    m_read_next_offset = 0;
    return ret;
  }

  int copy_header_to_mb(ACE_Message_Block * mb, const T & header)
  {
    return mb->copy((const char*)&header, sizeof(T));
  }

  virtual int packet_length() = 0;

  virtual MyBaseProcessor::EVENT_RESULT on_recv_header()
  {
    return ER_CONTINUE;
  }

  MyBaseProcessor::EVENT_RESULT on_recv_packet(ACE_Message_Block * mb)
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

  virtual MyBaseProcessor::EVENT_RESULT on_recv_packet_i(ACE_Message_Block * mb)
  {
    ACE_UNUSED_ARG(mb);
    return ER_OK;
  }

  T m_packet_header;
  ACE_Message_Block * m_current_block;
  int m_read_next_offset;
};

class MyBasePacketProcessor: public MyVeryBasePacketProcessor<MyDataPacketHeader>
{
public:
  typedef MyVeryBasePacketProcessor<MyDataPacketHeader> super;

  MyBasePacketProcessor(MyBaseHandler * handler);
  virtual void info_string(CMemGuard & info) const;
  virtual int on_open();
  virtual const char * name() const;

protected:
  virtual int packet_length();
  virtual MyBaseProcessor::EVENT_RESULT on_recv_header();
  virtual MyBaseProcessor::EVENT_RESULT on_recv_packet_i(ACE_Message_Block * mb);
  ACE_Message_Block * make_version_check_request_mb(const int extra = 0);

  enum { PEER_ADDR_LEN = INET_ADDRSTRLEN };
  char m_peer_addr[PEER_ADDR_LEN];
};

class MyBSBasePacketProcessor: public MyVeryBasePacketProcessor<MyBSBasePacket>
{
public:
  typedef MyVeryBasePacketProcessor<MyBSBasePacket> super;
  MyBSBasePacketProcessor(MyBaseHandler * handler);

protected:
  virtual int packet_length();

  virtual MyBaseProcessor::EVENT_RESULT on_recv_header();
  virtual MyBaseProcessor::EVENT_RESULT on_recv_packet_i(ACE_Message_Block * mb);
};

class MyBaseServerProcessor: public MyBasePacketProcessor
{
public:
  typedef MyBasePacketProcessor super;
  MyBaseServerProcessor(MyBaseHandler * handler);
  virtual ~MyBaseServerProcessor();
  virtual const char * name() const;
  virtual bool can_send_data(ACE_Message_Block * mb) const;
  virtual bool client_id_verified() const;

protected:
  virtual MyBaseProcessor::EVENT_RESULT on_recv_header();
  MyBaseProcessor::EVENT_RESULT do_version_check_common(ACE_Message_Block * mb, MyClientIDTable & client_id_table);
  ACE_Message_Block * make_version_check_reply_mb(MyClientVersionCheckReply::REPLY_CODE code, int extra_len = 0);

  MyClientVerson m_client_version;
};

class MyBaseClientProcessor: public MyBasePacketProcessor
{
public:
  typedef MyBasePacketProcessor super;

  MyBaseClientProcessor(MyBaseHandler * handler);
  virtual ~MyBaseClientProcessor();
  virtual const char * name() const;
  virtual bool client_id_verified() const;
  virtual int on_open();
  virtual void on_close();
  virtual bool can_send_data(ACE_Message_Block * mb) const;

protected:
  virtual MyBaseProcessor::EVENT_RESULT on_recv_header();
  void client_id_verified(bool _verified);

private:
  bool m_client_id_verified;
};

class MySockAcceptor: public ACE_SOCK_ACCEPTOR
{
public:
  typedef ACE_SOCK_ACCEPTOR super;
  int open (const ACE_Addr &local_sap, int reuse_addr=0, int protocol_family=PF_UNSPEC, int backlog= 128, int protocol=0)
  {
    return super::open(local_sap, reuse_addr, protocol_family, backlog, protocol);
  }
};

class MyBaseAcceptor: public ACE_Acceptor<MyBaseHandler, MySockAcceptor>
{
public:
  typedef ACE_Acceptor<MyBaseHandler, MySockAcceptor>  super;
  MyBaseAcceptor(MyBaseDispatcher * _dispatcher, MyBaseConnectionManager * _manager);
  virtual ~MyBaseAcceptor();
  virtual int handle_timeout (const ACE_Time_Value &current_time, const void *act = 0);
  CMod * module_x() const;
  MyBaseConnectionManager * connection_manager() const;
  MyBaseDispatcher * dispatcher() const;

  int start();
  int stop();
  void dump_info();
  virtual const char * name() const;

protected:
  enum
  {
    TIMER_ID_check_dead_connection = 1,
    TIMER_ID_reserved_1,
    TIMER_ID_reserved_2,
    TIMER_ID_reserved_3,
  };
  virtual void do_dump_info();
  virtual bool on_start();
  virtual void on_stop();

  MyBaseDispatcher * m_dispatcher;
  CMod * m_module;
  MyBaseConnectionManager * m_connection_manager;
  int m_tcp_port;
  int m_idle_time_as_dead; //in minutes
  int m_idle_connection_timer_id;
};


class MyBaseConnector: public ACE_Connector<MyBaseHandler, ACE_SOCK_CONNECTOR>
{
public:
  typedef ACE_Connector<MyBaseHandler, ACE_SOCK_CONNECTOR> super;
  enum { BATCH_CONNECT_NUM = 100 };

  MyBaseConnector(MyBaseDispatcher * _dispatcher, MyBaseConnectionManager * _manager);
  virtual ~MyBaseConnector();

  virtual int handle_timeout (const ACE_Time_Value &current_time, const void *act = 0);

  CMod * module_x() const;
  MyBaseConnectionManager * connection_manager() const;
  MyBaseDispatcher * dispatcher() const;
  void tcp_addr(const char * addr);
  int start();
  int stop();
  void dump_info();
  virtual const char * name() const;
  int connect_ready();
  void reset_retry_count();

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
  int do_connect(int count = 1, bool bNew = false);
  virtual bool on_start();
  virtual void on_stop();
  virtual void do_dump_info();
  virtual bool before_reconnect();

  MyBaseDispatcher * m_dispatcher;
  CMod * m_module;
  MyBaseConnectionManager * m_connection_manager;
  int m_tcp_port;
  std::string m_tcp_addr;
  int m_num_connection;
  int m_reconnect_interval; //in minutes
  int m_reconnect_retry_count;
  long m_reconnect_timer_id;
  int m_idle_time_as_dead; //in minutes
  int m_idle_connection_timer_id;
  int m_remain_to_connect;
};


class MyBaseService: public ACE_Task<ACE_MT_SYNCH>
{
public:
  MyBaseService(CMod * module, int numThreads);
  CMod * module_x() const; //name collision with parent class
  int start();
  int stop();
  void dump_info();
  virtual const char * name() const;

protected:
  virtual void do_dump_info();
  bool do_add_task(void * p, int task_type);
  void * get_task(ACE_Message_Block * mb, int & task_type) const;

private:
  CMod * m_module;
  int m_numThreads;
};


class MyBaseDispatcher: public ACE_Task<ACE_MT_SYNCH>
{
public:
  MyBaseDispatcher(CMod * pModule, int numThreads = 1);

  virtual ~MyBaseDispatcher();
  virtual int open (void * p= 0);
  virtual int svc();
  int start();
  int stop();
  CMod * module_x() const;
  void dump_info();
  virtual const char * name() const;

protected:
  typedef std::vector<MyBaseConnector *> MyConnectors;
  typedef std::vector<MyBaseAcceptor *> MyAcceptors;
  enum { TIMER_ID_BASE = 1 };

  virtual void on_stop();
  virtual void on_stop_stage_1();
  virtual bool on_start();
  virtual bool on_event_loop();
  void add_connector(MyBaseConnector * _connector);
  void add_acceptor(MyBaseAcceptor * _acceptor);
  virtual void do_dump_info();

  CMod * m_module;
  int m_clock_interval;
  MyConnectors m_connectors;
  MyAcceptors m_acceptors;

private:
  bool do_start_i();
  void do_stop_i();

  ACE_Reactor *m_reactor;
  int m_numThreads;
  int m_numBatchSend;
  ACE_Thread_Mutex m_mutex;
  bool m_init_done;
};


class CMod
{
public:
  CMod(CApp * app);
  virtual ~CMod();
  //module specific
  bool running() const;
  //both module and app
  bool running_with_app() const;
  CApp * app() const;
  int start();
  int stop();
  void dump_info();
  virtual const char * name() const;

protected:
  typedef std::vector<MyBaseService *> MyServices;
  typedef std::vector<MyBaseDispatcher *> MyBaseDispatchers;

  virtual bool on_start();
  virtual void on_stop();
  void add_service(MyBaseService * _service);
  void add_dispatcher(MyBaseDispatcher * _dispatcher);
  virtual void do_dump_info();

  CApp * m_app;
  bool m_running;

  MyServices m_services;
  MyBaseDispatchers m_dispatchers;
};


#endif /* BASESERVER_H_ */
