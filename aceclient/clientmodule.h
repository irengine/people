/*
 * clientmodule.h
 *
 *  Created on: Jan 8, 2012
 *      Author: root
 */

#ifndef CLIENTMODULE_H_
#define CLIENTMODULE_H_

#include <ace/Malloc_T.h>
#include <new>

#include "common.h"
#include "baseapp.h"
#include "basemodule.h"

class MyClientToDistModule;
class MyClientToDistConnector;

const int16_t const_client_version = 1;

class MyClientToDistProcessor: public MyBaseClientProcessor
{
public:
  typedef MyBaseClientProcessor super;

  MyClientToDistProcessor(MyBaseHandler * handler);
  virtual MyBaseProcessor::EVENT_RESULT on_recv_header(const MyDataPacketHeader & header);
  virtual int on_open();
  int send_heart_beat();

protected:
  virtual MyBaseProcessor::EVENT_RESULT on_recv_packet_i(ACE_Message_Block * mb);

private:
  int send_version_check_req();
  MyBaseProcessor::EVENT_RESULT do_version_check_reply(ACE_Message_Block * mb);

  bool m_version_check_reply_done;
};

class MyDistServerAddrList
{
public:
  MyDistServerAddrList();
  void addr_list(char *list);
  const char * begin();
  const char * next();
  bool empty() const;

private:
  std::vector<std::string> m_server_addrs;
  int m_index;
};

class MyClientToDistHandler: public MyBaseHandler
{
public:
  MyClientToDistHandler(MyBaseConnectionManager * xptr = NULL);
  virtual int handle_timeout (const ACE_Time_Value &current_time, const void *act = 0);
  void setup_timer();
  MyClientToDistModule * module_x() const;
  DECLARE_MEMORY_POOL__NOTHROW(MyClientToDistHandler, ACE_Thread_Mutex);

protected:
  virtual void on_close();
  virtual int  on_open();

private:
  enum { HEART_BEAT_PING_TIMER = 1 };
  long m_heat_beat_ping_timer_id;
};

class MyClientToDistService: public MyBaseService
{
public:
  MyClientToDistService(MyBaseModule * module, int numThreads = 1);
  virtual int svc();
  virtual const char * name() const;

protected:
  enum { MSG_QUEUE_MAX_SIZE = 5 * 1024 * 1024 };
  void do_server_file_md5_list(ACE_Message_Block * mb);
};

class MyClientToDistDispatcher: public MyBaseDispatcher
{
public:
  MyClientToDistDispatcher(MyBaseModule * pModule, int numThreads = 1);
  virtual const char * name() const;

protected:
  virtual void on_stop();
  virtual bool on_start();

private:
  MyClientToDistConnector * m_connector;
};


class MyClientToDistConnector: public MyBaseConnector
{
public:
  MyClientToDistConnector(MyBaseDispatcher * _dispatcher, MyBaseConnectionManager * _manager);
  virtual int make_svc_handler(MyBaseHandler *& sh);
  virtual const char * name() const;

protected:
  enum { RECONNECT_INTERVAL = 3 }; //time in minutes
  virtual bool before_reconnect();
};

class MyClientToDistModule: public MyBaseModule
{
public:
  MyClientToDistModule(MyBaseApp * app);
  virtual ~MyClientToDistModule();
  MyDistServerAddrList & server_addr_list();
  MyClientToDistService * service() const
  {
    return m_service;
  }
  virtual const char * name() const;

protected:
  virtual bool on_start();
  virtual void on_stop();

private:
  MyDistServerAddrList m_server_addr_list;
  MyClientToDistService * m_service;
  MyClientToDistDispatcher *m_dispatcher;

};


#endif /* CLIENTMODULE_H_ */
