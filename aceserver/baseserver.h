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

#include "myutil.h"

#define MY_USE_MEM_POOL

class MyBaseModule;
class MyBaseHandler;
class MyBaseAcceptor;


class MyBaseHandler: public ACE_Svc_Handler<ACE_SOCK_STREAM, ACE_NULL_SYNCH>
{
public:
  typedef ACE_Svc_Handler<ACE_SOCK_STREAM, ACE_NULL_SYNCH> super;

  virtual MyBaseModule * module_x() const; //name collision with parent class
  MyBaseAcceptor * acceptor() const;

  int open (void * = 0);
  virtual int handle_input(ACE_HANDLE fd = ACE_INVALID_HANDLE);
  virtual int handle_output(ACE_HANDLE fd = ACE_INVALID_HANDLE);
  virtual int handle_close(ACE_HANDLE handle,
                           ACE_Reactor_Mask close_mask);
  virtual ~MyBaseHandler();

private:

};


class MyBaseAcceptor: public ACE_Acceptor<MyBaseHandler, ACE_SOCK_ACCEPTOR>
{
public:
  typedef ACE_Acceptor<MyBaseHandler, ACE_SOCK_ACCEPTOR>  super;

  int num_connections() const;
  long bytes_received() const;
  long bytes_processed() const;

  void OnDataReceived(MyBaseHandler *, long data_size);
  void OnDataProcessed(MyBaseHandler *, long data_size);
  void OnNewConnection(MyBaseHandler *);
  void OnCloseConnection(MyBaseHandler *);

private:
  int m_num_connections;
  long m_bytes_received;
  long m_bytes_processed;
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
  virtual MyBaseAcceptor * makeAcceptor();

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
  bool isRunning() const;
  //both module and app
  bool isRunning_app() const;
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
