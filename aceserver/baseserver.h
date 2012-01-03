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

#include <vector>
#include <map>
#include <list>

#include "myutil.h"
#include "datapacket.h"

class MyBaseModule;
class MyBaseHandler;
class MyBaseAcceptor;

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

class MyClientInfo
{
public:
  union
  {
    char as_string[8];
    long as_long;
  }client_id;
  MyBaseHandler * handler;

#define client_id_long   client_id.as_long
#define client_id_string client_id.as_string

  enum
  {
    INVALID_CLIENT_ID = 0
  };

  MyClientInfo()
  {
    client_id_long = INVALID_CLIENT_ID;
    handler = NULL;
  }

  bool operator == (const MyClientInfo & rhs) const
  {
    return (client_id_long == rhs.client_id_long);
  }
  bool operator != (const MyClientInfo & rhs) const
  {
    return ! (operator ==(rhs));
  }
};

class MyClientInfos
{
public:
  MyClientInfos();
  bool contains(long id);
//  bool contains(const char* id) const;
  MyBaseHandler * find_handler(long id);
  void set_handler(long id, MyBaseHandler * handler);
  void add(MyClientInfo aInfo);

private:
  typedef std::vector<MyClientInfo> ClientInfos_type;
  typedef std::map<long, int> ClientInfos_map;

  int index_of(long id);
  int index_of_i(long id, ClientInfos_map::iterator * pIt = NULL);

  ClientInfos_type m_infos;
  ClientInfos_map  m_map;
  ACE_Thread_Mutex m_mutex;
};

typedef std::list<MyBaseHandler *> MyActiveConnections;
typedef MyActiveConnections::iterator MyActiveConnectionPointer;


class MyBaseHandler: public ACE_Svc_Handler<ACE_SOCK_STREAM, ACE_NULL_SYNCH>
{
public:
  typedef ACE_Svc_Handler<ACE_SOCK_STREAM, ACE_NULL_SYNCH> super;
  MyBaseHandler(MyBaseAcceptor * xptr = NULL);

  virtual int open (void * = 0);
  virtual int handle_input(ACE_HANDLE fd = ACE_INVALID_HANDLE);
  virtual int handle_output(ACE_HANDLE fd = ACE_INVALID_HANDLE);
  virtual int handle_close(ACE_HANDLE handle, ACE_Reactor_Mask close_mask);
  virtual ~MyBaseHandler();

  MyBaseModule * module_x() const; //name collision with parent class
  MyBaseAcceptor * acceptor() const;
  void active_pointer(MyActiveConnectionPointer ptr);
  MyActiveConnectionPointer active_pointer();
  bool client_id_verified() const;
  long client_id() const;

protected:
  virtual bool sumbit_received_data();

  MyBaseAcceptor * m_acceptor; //trade space for speed, although we can get acceptor pointer
                               //by the module_x()->dispatcher()->acceptor() method
                               //but this is much faster
  int m_client_id;
  ACE_Message_Block * m_current_block;
  enum
  {
    PEER_ADDR_LEN = 16 //"xxx.xxx.xxx.xxx"
  };
  char m_peer_addr[PEER_ADDR_LEN];
private:
  ACE_Message_Block * make_message_block();
  MyActiveConnectionPointer m_active_pointer;
  MyDataPacketHeader m_packet_header;
  int m_read_next_offset;

};

class MyBaseAcceptor: public ACE_Acceptor<MyBaseHandler, ACE_SOCK_ACCEPTOR>
{
public:
  typedef ACE_Acceptor<MyBaseHandler, ACE_SOCK_ACCEPTOR>  super;
  MyBaseAcceptor(MyBaseModule * _module);
  virtual ~MyBaseAcceptor();

  MyBaseModule * module_x() const;
  int  num_connections() const;
  long bytes_received() const;
  long bytes_processed() const;

  void on_data_received(MyBaseHandler *, long data_size);
  void on_data_processed(MyBaseHandler *, long data_size);
  void on_client_id_verified(MyBaseHandler *);
  void on_new_connection(MyBaseHandler *);
  void on_close_connection(MyBaseHandler *);

protected:
  friend class MyBaseHandler;


  bool next_pointer();

  My_Cached_Allocator<MyDataPacketHeader, ACE_Thread_Mutex> *m_header_pool;
  My_Cached_Allocator<ACE_Message_Block, ACE_Thread_Mutex> *m_message_block_pool;
  My_Cached_Allocator<ACE_Data_Block, ACE_Thread_Mutex> *m_data_block_pool;
//  MyCached_Message_Block Header_Message_Block;

  int  m_num_connections;
  long m_bytes_received;
  long m_bytes_processed;
  MyActiveConnections m_active_connections;
  MyActiveConnectionPointer m_scan_pointer;
  MyClientInfos m_client_infos;
  MyBaseModule * m_module;
};


class MyBaseService: public ACE_Task<ACE_MT_SYNCH>
{
public:
  MyBaseService(MyBaseModule * module, int numThreads);
  MyBaseModule * module_x() const; //name collision with parent class
  int start();
  int stop();


private:
  MyBaseModule * m_module;
  int m_numThreads;
};


class MyBaseDispatcher: public ACE_Task<ACE_MT_SYNCH>
{
public:
  MyBaseDispatcher(MyBaseModule * pModule, int tcp_port, int numThreads = 1);

  virtual ~MyBaseDispatcher();
  virtual int open (void * = 0);
  virtual int svc();
  virtual int handle_timeout (const ACE_Time_Value &tv,
                              const void *act);
  MyBaseAcceptor * acceptor() const;

  int start();
  int stop();

protected:
  virtual MyBaseAcceptor * make_acceptor();
  MyBaseModule * m_module;

private:
  MyBaseAcceptor * m_acceptor;
  ACE_Dev_Poll_Reactor * m_dev_reactor;
  ACE_Reactor *m_reactor;
  int m_numThreads;
  int m_numBatchSend;
  int m_tcp_port;
};


class MyBaseModule
{
public:
  MyBaseModule();
  virtual ~MyBaseModule();
  //module specific
  bool is_running() const;
  //both module and app
  bool is_running_app() const;
  MyBaseDispatcher * dispatcher() const;
  MyBaseService * service() const;
  int start();
  int stop();

protected:
  MyBaseService * m_service;
  MyBaseDispatcher * m_dispatcher;
  bool m_running;
};


#endif /* BASESERVER_H_ */
