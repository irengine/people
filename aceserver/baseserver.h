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

#include <vector>
#include <map>
#include <list>

#include "myutil.h"

class MyBaseModule;
class MyBaseHandler;
class MyBaseAcceptor;

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

  virtual MyBaseModule * module_x() const; //name collision with parent class
  MyBaseAcceptor * acceptor() const;
  void active_pointer(MyActiveConnectionPointer ptr);
  MyActiveConnectionPointer active_pointer();
  bool client_id_verified() const;
  long client_id() const;

private:
  MyActiveConnectionPointer m_active_pointer;
  int m_client_id;
};

class MyBaseAcceptor: public ACE_Acceptor<MyBaseHandler, ACE_SOCK_ACCEPTOR>
{
public:
  typedef ACE_Acceptor<MyBaseHandler, ACE_SOCK_ACCEPTOR>  super;

  int  num_connections() const;
  long bytes_received() const;
  long bytes_processed() const;

  void on_data_received(MyBaseHandler *, long data_size);
  void on_data_processed(MyBaseHandler *, long data_size);
  void on_new_connection(MyBaseHandler *);
  void on_close_connection(MyBaseHandler *);

protected:
  friend class MyBaseHandler;

  bool next_pointer();
  int  m_num_connections;
  long m_bytes_received;
  long m_bytes_processed;
  MyActiveConnections m_active_connections;
  MyActiveConnectionPointer m_scan_pointer;
  MyClientInfos m_client_infos;
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

private:
  MyBaseAcceptor * m_acceptor;
  ACE_Dev_Poll_Reactor * m_dev_reactor;
  ACE_Reactor *m_reactor;
  MyBaseModule * m_module;
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
