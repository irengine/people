/*
 * heartbeatmodule.h
 *
 *  Created on: Dec 26, 2011
 *      Author: root
 */

#ifndef HEARTBEATMODULE_H_
#define HEARTBEATMODULE_H_

#include "serverapp.h"
#include "baseserver.h"
#include <ace/Malloc_T.h>
#include <new>

class MyHeartBeatModule;
class MyPingSubmitter;

class MyHeartBeatProcessor: public MyBaseServerProcessor
{
public:
  MyHeartBeatProcessor(MyBaseHandler * handler);
  virtual MyBaseProcessor::EVENT_RESULT on_recv_header(const MyDataPacketHeader & header);

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
  MyPingSubmitter();
  void add_ping(const char * client_id, const int len);
  void check_time_out();

private:
  void do_submit();
  void reset();
  enum
  {
    BLOCK_SIZE = 4096
  };
  ACE_Message_Block * m_current_block;
  long m_last_add;
  char * m_current_ptr;
  int  m_current_length;

  //todo: add target
};

class MyHeartBeatHandler: public MyBaseHandler
{
public:
  MyHeartBeatHandler(MyBaseConnectionManager * xptr = NULL);
  DECLARE_MEMORY_POOL(MyHeartBeatHandler, ACE_Thread_Mutex);
};

class MyHeartBeatService: public MyBaseService
{
public:
  MyHeartBeatService(MyBaseModule * module, int numThreads);
  virtual int svc();
};

class MyHeartBeatDispatcher: public MyBaseDispatcher
{
public:
  MyHeartBeatDispatcher(MyBaseModule * pModule, int numThreads = 1);

protected:
  virtual MyBaseAcceptor * make_acceptor();

private:
//  typedef ACE_Cached_Allocator<MyHeartBeatDispatcher, ACE_Thread_Mutex> Mem_Pool;
//  static Mem_Pool * m_mem_pool;
};

class MyHeartBeatAcceptor: public MyBaseAcceptor
{
public:
  MyHeartBeatAcceptor(MyHeartBeatModule * _module, MyBaseConnectionManager * manager);
  virtual int make_svc_handler(MyBaseHandler *& sh);
};


class MyHeartBeatModule: public MyBaseModule
{
public:
  MyHeartBeatModule();
  virtual ~MyHeartBeatModule();
private:
  MyPingSubmitter m_ping_sumbitter;
};

#endif /* HEARTBEATMODULE_H_ */
