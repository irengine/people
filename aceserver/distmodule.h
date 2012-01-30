/*
 * heartbeatmodule.h
 *
 *  Created on: Dec 26, 2011
 *      Author: root
 */

#ifndef HEARTBEATMODULE_H_
#define HEARTBEATMODULE_H_

#include <ace/Malloc_T.h>
#include <new>

#include "common.h"
#include "baseapp.h"
#include "basemodule.h"

class MyHeartBeatModule;
class MyPingSubmitter;
class MyHeartBeatAcceptor;

class MyHeartBeatProcessor: public MyBaseServerProcessor
{
public:
  typedef MyBaseServerProcessor super;

  MyHeartBeatProcessor(MyBaseHandler * handler);
  virtual MyBaseProcessor::EVENT_RESULT on_recv_header();

  static MyPingSubmitter * m_sumbitter;

protected:
  virtual MyBaseProcessor::EVENT_RESULT on_recv_packet_i(ACE_Message_Block * mb);

private:
  void do_ping();
  MyBaseProcessor::EVENT_RESULT do_version_check(ACE_Message_Block * mb);
};

class MyPingSubmitter
{
public:
  enum {ID_SEPERATOR = ';' };
  MyPingSubmitter();
  ~MyPingSubmitter();
  void add_ping(const char * client_id, const int len);
  void check_time_out();

private:
  void do_submit();
  void reset();
  enum { BLOCK_SIZE = 4096 };
  ACE_Message_Block * m_current_block;
  long m_last_add;
  char * m_current_ptr;
  int  m_current_length;

#ifdef MY_server_test
  int m_fd;
#endif

  //todo: add target
};

class MyHeartBeatHandler: public MyBaseHandler
{
public:
  MyHeartBeatHandler(MyBaseConnectionManager * xptr = NULL);

  DECLARE_MEMORY_POOL__NOTHROW(MyHeartBeatHandler, ACE_Thread_Mutex);
};

class MyHeartBeatService: public MyBaseService
{
public:
  MyHeartBeatService(MyBaseModule * module, int numThreads = 1);
  virtual int svc();

protected:
  enum { MSG_QUEUE_MAX_SIZE = 5 * 1024 * 1024 };

  void calc_server_file_md5_list(ACE_Message_Block * mb);
  void calc_server_file_md5_list_one(const char * client_id);
  ACE_Message_Block * make_server_file_md5_list_mb(int list_len, int client_id_index);
};

class MyHeartBeatDispatcher: public MyBaseDispatcher
{
public:
  MyHeartBeatDispatcher(MyBaseModule * pModule, int numThreads = 1);
  virtual const char * name() const;
  virtual int handle_timeout (const ACE_Time_Value &tv,
                              const void *act);
protected:
  virtual void on_stop();
  virtual bool on_start();

private:
  enum { CLOCK_INTERVAL = 3 }; //in seconds, the interval of picking send out packages
  enum { MSG_QUEUE_MAX_SIZE = 20 * 1024 * 1024 };
  MyHeartBeatAcceptor * m_acceptor;
};

class MyHeartBeatAcceptor: public MyBaseAcceptor
{
public:
  enum { IDLE_TIME_AS_DEAD = 5 }; //in minutes
  MyHeartBeatAcceptor(MyBaseDispatcher * _dispatcher, MyBaseConnectionManager * manager);
  virtual int make_svc_handler(MyBaseHandler *& sh);
  virtual const char * name() const;
};


class MyHeartBeatModule: public MyBaseModule
{
public:
  MyHeartBeatModule(MyBaseApp * app);
  virtual ~MyHeartBeatModule();
  MyHeartBeatDispatcher * dispatcher() const;
  virtual const char * name() const;
  MyHeartBeatService * service() const;

protected:
  virtual bool on_start();
  virtual void on_stop();

private:
  MyPingSubmitter m_ping_sumbitter;
  MyHeartBeatService * m_service;
  MyHeartBeatDispatcher * m_dispatcher;

};

/////////////////////////////////////
//remote access module
/////////////////////////////////////

class MyDistRemoteAccessProcessor: public MyBaseRemoteAccessProcessor
{
public:
  typedef MyBaseRemoteAccessProcessor super;

  MyDistRemoteAccessProcessor(MyBaseHandler * handler);

protected:
  virtual int on_command(const char * cmd, char * parameter);
  virtual int on_command_help();

private:
  int on_command_dist_file_md5(char * parameter);
  int on_command_dist_batch_file_md5(char * parameter);
};

class MyDistRemoteAccessHandler: public MyBaseHandler
{
public:
  MyDistRemoteAccessHandler(MyBaseConnectionManager * xptr = NULL);
};

class MyDistRemoteAccessAcceptor: public MyBaseAcceptor
{
public:
  enum { IDLE_TIME_AS_DEAD = 10 }; //in minutes
  MyDistRemoteAccessAcceptor(MyBaseDispatcher * _dispatcher, MyBaseConnectionManager * manager);
  virtual int make_svc_handler(MyBaseHandler *& sh);
  virtual const char * name() const;
};

class MyDistRemoteAccessDispatcher: public MyBaseDispatcher
{
public:
  MyDistRemoteAccessDispatcher(MyBaseModule * pModule);
  virtual const char * name() const;

protected:
  virtual bool on_start();
};

class MyDistRemoteAccessModule: public MyBaseModule
{
public:
  MyDistRemoteAccessModule(MyBaseApp * app);
//  MyDistRemoteAccessDispatcher * dispatcher() const;
  virtual const char * name() const;

protected:
  virtual bool on_start();

//private:
//  MyDistRemoteAccessDispatcher * m_dispatcher;
};

#endif /* HEARTBEATMODULE_H_ */
