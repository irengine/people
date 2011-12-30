/*
 * heartbeatmodule.h
 *
 *  Created on: Dec 26, 2011
 *      Author: root
 */

#ifndef HEARTBEATMODULE_H_
#define HEARTBEATMODULE_H_

#include "baseserver.h"
#ifdef MY_USE_MEM_POOL
#include <ace/Malloc_T.h>
#include <new>
#endif

class MyHeartBeatHandler: public MyBaseHandler
{
public:
  virtual MyBaseModule * module_x() const;
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
  virtual MyBaseAcceptor * makeAcceptor();

private:
//  typedef ACE_Cached_Allocator<MyHeartBeatDispatcher, ACE_Thread_Mutex> Mem_Pool;
//  static Mem_Pool * m_mem_pool;
};

class MyHeartBeatAcceptor: public MyBaseAcceptor
{
public:
  virtual int make_svc_handler(MyBaseHandler *& sh);
};


class MyHeartBeatModule: public MyBaseModule
{
public:
  MyHeartBeatModule();
  virtual ~MyHeartBeatModule();
//  static MyHeartBeatModule *instance();

//private:
//  static MyHeartBeatModule * m_instance;
};

//typedef ACE_Unmanaged_Singleton<MyHeartBeatModule, ACE_Null_Mutex> MyHeartBeatModuleX;

#endif /* HEARTBEATMODULE_H_ */
