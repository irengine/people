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
//class MyPingSubmitter;
class MyClientToDistConnector;

const int16_t const_client_version = 1;

class MyClientToDistProcessor: public MyBaseClientProcessor
{
public:
  MyClientToDistProcessor(MyBaseHandler * handler);
  virtual MyBaseProcessor::EVENT_RESULT on_recv_header(const MyDataPacketHeader & header);

//  static MyPingSubmitter * m_sumbitter;
  int send_heart_beat();

protected:
  virtual MyBaseProcessor::EVENT_RESULT on_recv_packet_i(ACE_Message_Block * mb);

private:
  MyBaseProcessor::EVENT_RESULT send_version_check_req();
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

/*
class MyPingSubmitter
{
public:
  MyPingSubmitter();
  ~MyPingSubmitter();
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
*/
class MyClientToDistHandler: public MyBaseHandler
{
public:
  MyClientToDistHandler(MyBaseConnectionManager * xptr = NULL);
  virtual int open (void * = 0);
  virtual int handle_timeout (const ACE_Time_Value &current_time, const void *act = 0);
  DECLARE_MEMORY_POOL(MyClientToDistHandler, ACE_Thread_Mutex);

protected:
  virtual void on_close();

private:
  enum
  {
    HEART_BEAT_PING_TIMER = 1
  };
  long m_heat_beat_ping_timer_id;
};

class MyClientToDistService: public MyBaseService
{
public:
  MyClientToDistService(MyBaseModule * module, int numThreads = 1);
  virtual int svc();
};

class MyClientToDistDispatcher: public MyBaseDispatcher
{
public:
  MyClientToDistDispatcher(MyBaseModule * pModule, int numThreads = 1);
//  virtual int open (void * = 0);

protected:
  virtual void on_stop();
  virtual int on_start();

private:
  MyClientToDistConnector * m_connector;
};


class MyClientToDistConnector: public MyBaseConnector
{
public:
  MyClientToDistConnector(MyClientToDistModule * _module, MyBaseConnectionManager * _manager);
  virtual int make_svc_handler(MyBaseHandler *& sh);

protected:
  virtual bool before_reconnect();
};

class MyClientToDistModule: public MyBaseModule
{
public:
  MyClientToDistModule(MyBaseApp * app);
  virtual ~MyClientToDistModule();
  MyDistServerAddrList & server_addr_list();

private:
  MyDistServerAddrList m_server_addr_list;
//  MyPingSubmitter m_ping_sumbitter;
};


#endif /* CLIENTMODULE_H_ */
