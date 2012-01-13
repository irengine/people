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

#include <vector>
#include <map>
#include <list>
#include <string>
#include <algorithm>

#include "common.h"
#include "mycomutil.h"
#include "datapacket.h"

class MyBaseModule;
class MyBaseHandler;
class MyBaseAcceptor;
class MyBaseConnectionManager;
class MyBaseApp;
class MyBaseDispatcher;

class MyCached_Message_Block: public ACE_Message_Block
{
public:
  MyCached_Message_Block(size_t size,
                ACE_Allocator * allocator_strategy,
                ACE_Allocator * data_block_allocator,
                ACE_Allocator * message_block_allocator,
                ACE_Message_Type type = MB_DATA
      ):
      ACE_Message_Block(
        size,
        type,
        0, //ACE_Message_Block * cont
        0, //const char * data
        allocator_strategy,
        0, //ACE_Lock * locking_strategy
        ACE_DEFAULT_MESSAGE_BLOCK_PRIORITY, //unsigned long priority
        ACE_Time_Value::zero, //const ACE_Time_Value & execution_time
        ACE_Time_Value::max_time, //const ACE_Time_Value & deadline_time
        data_block_allocator,
        message_block_allocator)
  {}
};

class MyConfig;
class MyMemPoolFactory
{
public:
  MyMemPoolFactory();
  ~MyMemPoolFactory();
  void init(MyConfig * config);
  ACE_Message_Block * get_message_block(int capacity);
  void dump_info();

private:
  typedef My_Cached_Allocator<ACE_Thread_Mutex> MyMemPool;
  typedef std::vector<MyMemPool *> MyMemPools;

  My_Cached_Allocator<ACE_Thread_Mutex> *m_message_block_pool;
  My_Cached_Allocator<ACE_Thread_Mutex> *m_data_block_pool;
  MyMemPools m_pools;
  bool m_use_mem_pool; //local copy
};
typedef ACE_Unmanaged_Singleton<MyMemPoolFactory, ACE_Null_Mutex> MyMemPoolFactoryX;



class MyClientIDTable
{
public:
  MyClientIDTable();
  bool contains(const MyClientID & id);
  void add(const MyClientID & id);
  void add(const char * str_id);
  void add_batch(char * idlist); //in the format of "12334434;33222334;34343111;..."
  int index_of(const MyClientID & id);
  int count();

private:
  typedef std::vector<MyClientID> ClientIDTable_type;
  typedef std::map<MyClientID, int> ClientIDTable_map;

  int index_of_i(const MyClientID & id, ClientIDTable_map::iterator * pIt = NULL);
  void add_i(const MyClientID & id);
  ClientIDTable_type m_table;
  ClientIDTable_map  m_map;
  ACE_RW_Thread_Mutex m_mutex;
};

typedef std::list<MyBaseHandler *> MyActiveConnections;
typedef MyActiveConnections::iterator MyActiveConnectionPointer;

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

  virtual std::string info_string() const;
  virtual int on_open();
  virtual int handle_input();
  bool wait_for_close() const;

  bool dead() const;
  void update_last_activity();
  long last_activity() const;
  bool check_activity() const;
  void check_activity(bool bCheck);

protected:
  int handle_input_wait_for_close();
  MyBaseHandler * m_handler;
  long m_last_activity;
  bool m_wait_for_close;
  bool m_check_activity;
};

class MyBasePacketProcessor: public MyBaseProcessor
{
public:
  typedef MyBaseProcessor super;
  MyBasePacketProcessor(MyBaseHandler * handler);
  virtual ~MyBasePacketProcessor();
  virtual std::string info_string() const;
  virtual int on_open();
  virtual bool client_id_verified() const;
  const MyClientID & client_id() const;
  void client_id(const char *id);
  virtual int handle_input();

protected:
  virtual MyBaseProcessor::EVENT_RESULT on_recv_header(const MyDataPacketHeader & header);
  MyBaseProcessor::EVENT_RESULT on_recv_packet(ACE_Message_Block * mb);
  int copy_header_to_mb(ACE_Message_Block * mb, const MyDataPacketHeader & header);
  virtual MyBaseProcessor::EVENT_RESULT on_recv_packet_i(ACE_Message_Block * mb);
  ACE_Message_Block * make_version_check_request_mb();
  int read_req_header();
  int read_req_body();
  int handle_req();

  MyClientID m_client_id;
  int32_t    m_client_id_index;
  int        m_client_id_length;
  enum
  {
    PEER_ADDR_LEN = 16 //"xxx.xxx.xxx.xxx"
  };
  char m_peer_addr[PEER_ADDR_LEN];
  ACE_Message_Block * m_current_block;
  MyDataPacketHeader m_packet_header;
  int m_read_next_offset;
};

class MyBaseServerProcessor: public MyBasePacketProcessor
{
public:
  typedef MyBasePacketProcessor super;
  MyBaseServerProcessor(MyBaseHandler * handler);
  virtual ~MyBaseServerProcessor();
  virtual bool client_id_verified() const;

protected:
  virtual MyBaseProcessor::EVENT_RESULT on_recv_header(const MyDataPacketHeader & header);
  MyBaseProcessor::EVENT_RESULT do_version_check_common(ACE_Message_Block * mb, MyClientIDTable & client_id_table);
  ACE_Message_Block * make_version_check_reply_mb(MyClientVersionCheckReply::REPLY_CODE code, int extra_len = 0);
};

class MyBaseClientProcessor: public MyBasePacketProcessor
{
public:
  typedef MyBasePacketProcessor super;

  MyBaseClientProcessor(MyBaseHandler * handler);
  virtual ~MyBaseClientProcessor();
  virtual bool client_id_verified() const;

protected:
  virtual MyBaseProcessor::EVENT_RESULT on_recv_header(const MyDataPacketHeader & header);

private:
  bool m_client_id_verified;
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
  int  num_connections() const;
  long long int bytes_received() const;
  long long int bytes_sent() const;

  void on_data_received(int data_size);
  void on_data_send(int data_size);
//  virtual void on_new_connection(MyBaseHandler *);
//  virtual void on_close_connection(MyBaseHandler *);
  void add_connection(MyBaseHandler * handler, Connection_State state);
  void set_connection_state(MyBaseHandler * handler, Connection_State state);
  void remove_connection(MyBaseHandler * handler);
  void detect_dead_connections();

private:
  typedef std::map<MyBaseHandler *, long> MyConnections;
  typedef MyConnections::iterator MyConnectionsPtr;

  MyConnectionsPtr find(MyBaseHandler * handler);

  int  m_num_connections;
  long long int m_bytes_received;
  long long int m_bytes_sent;
  MyConnections m_active_connections;
};


class MyBaseHandler: public ACE_Svc_Handler<ACE_SOCK_STREAM, ACE_NULL_SYNCH>
{
public:
  typedef ACE_Svc_Handler<ACE_SOCK_STREAM, ACE_NULL_SYNCH> super;
  MyBaseHandler(MyBaseConnectionManager * xptr = NULL);

  virtual int open (void * p = 0);
  virtual int handle_input(ACE_HANDLE fd = ACE_INVALID_HANDLE);
  virtual int handle_output(ACE_HANDLE fd = ACE_INVALID_HANDLE);
  virtual int handle_close(ACE_HANDLE handle, ACE_Reactor_Mask close_mask);
  virtual ~MyBaseHandler();

  MyBaseConnectionManager * connection_manager();
  MyBaseProcessor * processor() const;
  int send_data(ACE_Message_Block * mb);

protected:
  virtual void on_close();
  virtual int  on_open();

  MyBaseConnectionManager * m_connection_manager;
  MyBaseProcessor * m_processor;
};

class MyBaseAcceptor: public ACE_Acceptor<MyBaseHandler, ACE_SOCK_ACCEPTOR>
{
public:
  typedef ACE_Acceptor<MyBaseHandler, ACE_SOCK_ACCEPTOR>  super;
  MyBaseAcceptor(MyBaseDispatcher * _dispatcher, MyBaseConnectionManager * _manager);
  virtual ~MyBaseAcceptor();

  MyBaseModule * module_x() const;
  MyBaseConnectionManager * connection_manager() const;
  MyBaseDispatcher * dispatcher() const;

  int start();
  int stop();
  void dump_info();
  virtual const char * name() const;

protected:
  virtual void do_dump_info();

//  bool next_pointer();

//  MyActiveConnectionPointer m_scan_pointer;
  MyBaseDispatcher * m_dispatcher;
  MyBaseModule * m_module;
  MyBaseConnectionManager * m_connection_manager;
  int m_tcp_port;
};


class MyBaseConnector: public ACE_Connector<MyBaseHandler, ACE_SOCK_CONNECTOR>
{
public:
  typedef ACE_Connector<MyBaseHandler, ACE_SOCK_CONNECTOR> super;
  MyBaseConnector(MyBaseDispatcher * _dispatcher, MyBaseConnectionManager * _manager);
  virtual ~MyBaseConnector();

  virtual int handle_timeout (const ACE_Time_Value &current_time, const void *act = 0);
  virtual int handle_output(ACE_HANDLE fd = ACE_INVALID_HANDLE);
  MyBaseModule * module_x() const;
  MyBaseConnectionManager * connection_manager() const;
  MyBaseDispatcher * dispatcher() const;
  MyBaseHandler * unique_handler() const;
  void tcp_addr(const char * addr);
  int start();
  int stop();
  void dump_info();
  virtual const char * name() const;

protected:
  enum
  {
    RECONNECT_TIMER = 1,
    UNUSED_TIMER_1,
    UNUSED_TIMER_2
  };
  int do_connect(int count = 1);
  virtual void do_dump_info();
  virtual bool before_reconnect();

  MyBaseDispatcher * m_dispatcher;
  MyBaseModule * m_module;
  MyBaseConnectionManager * m_connection_manager;
  int m_tcp_port;
  std::string m_tcp_addr;
  int m_num_connection;
  int m_reconnect_interval;
  int m_reconnect_retry_count;
  long m_reconnect_timer_id;
};


class MyBaseService: public ACE_Task<ACE_MT_SYNCH>
{
public:
  MyBaseService(MyBaseModule * module, int numThreads);
  MyBaseModule * module_x() const; //name collision with parent class
  int start();
  int stop();
  void dump_info();
  virtual const char * name() const;

protected:
  virtual void do_dump_info();

private:
  MyBaseModule * m_module;
  int m_numThreads;
};


class MyBaseDispatcher: public ACE_Task<ACE_MT_SYNCH>
{
public:
  MyBaseDispatcher(MyBaseModule * pModule, int numThreads = 1);

  virtual ~MyBaseDispatcher();
  virtual int open (void * p= 0);
  virtual int svc();
  virtual int handle_timeout (const ACE_Time_Value &tv,
                              const void *act);
  int start();
  int stop();
  MyBaseModule * module_x() const;
  void dump_info();
  virtual const char * name() const;

protected:
  typedef std::vector<MyBaseConnector *> MyConnectors;
  typedef std::vector<MyBaseAcceptor *> MyAcceptors;

  virtual void on_stop();
  virtual bool on_start();
  void add_connector(MyBaseConnector * _connector);
  void add_acceptor(MyBaseAcceptor * _acceptor);
  virtual void do_dump_info();

  MyBaseModule * m_module;
  int m_clock_interval;
  MyConnectors m_connectors;;
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


class MyBaseModule
{
public:
  MyBaseModule(MyBaseApp * app);
  virtual ~MyBaseModule();
  //module specific
  bool running() const;
  //both module and app
  bool running_with_app() const;
  MyBaseApp * app() const;
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

  MyBaseApp * m_app;
  bool m_running;

  MyServices m_services;
  MyBaseDispatchers m_dispatchers;
};


#endif /* BASESERVER_H_ */
