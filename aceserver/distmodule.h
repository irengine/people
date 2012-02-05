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
#include "servercommon.h"

class MyHeartBeatModule;
class MyPingSubmitter;
class MyHeartBeatAcceptor;
class MyDistClients;

class MyDistClient
{
public:
  MyDistClient(MyHttpDistInfo * _dist_info);
  bool check_valid() const;
  int  dist_file(MyDistClients & dist_clients);
  bool active();

  MyHttpDistInfo * dist_info;
  int status;
  MyClientID client_id;
  MyPooledMemGuard adir;
  MyPooledMemGuard md5;
  MyPooledMemGuard mbz_file;
  time_t last_update;

private:
  int do_stage_0(MyDistClients & dist_clients);
  int do_stage_1(MyDistClients & dist_clients);
  int do_stage_2(MyDistClients & dist_clients);
  int do_stage_3(MyDistClients & dist_clients);
  int do_stage_4(MyDistClients & dist_clients);
  int send_md5();
  int send_ftp();

  int dist_out_leading_length();
  void dist_out_leading_data(char * data);

  int m_client_id_index;
};

class MyDistClients
{
public:
  typedef std::vector<MyDistClient *, MyAllocator<MyDistClient *> > MyDistClientList;
  MyDistClients(MyHttpDistInfos * dist_infos);
  ~MyDistClients();

  MyHttpDistInfo * find(const char * dist_id);
  void clear();
  bool add(MyDistClient *);
  void dist_files();


  MyDistClientList dist_clients;
  time_t db_time;

private:
  MyHttpDistInfos * m_dist_infos;
};

class MyClientFileDistributor
{
public:
  MyClientFileDistributor();
  bool distribute();
  bool check_dist_info();
  bool check_dist_clients();

private:
  bool check_dist_info_one(MyHttpDistInfo * info);

  MyHttpDistInfos m_dist_infos;
  MyDistClients m_dist_clients;
};

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
  MyBaseProcessor::EVENT_RESULT do_md5_file_list(ACE_Message_Block * mb);
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

private:
  enum { MSG_QUEUE_MAX_SIZE = 5 * 1024 * 1024 };

  void do_have_dist_task();
  void calc_server_file_md5_list(ACE_Message_Block * mb);
  void calc_server_file_md5_list_one(const char * client_id);
  ACE_Message_Block * make_server_file_md5_list_mb(int list_len, int client_id_index);

  MyClientFileDistributor m_distributor;
};

class MyHeartBeatDispatcher: public MyBaseDispatcher
{
public:
  MyHeartBeatDispatcher(MyBaseModule * pModule, int numThreads = 1);
  virtual const char * name() const;
  virtual int handle_timeout (const ACE_Time_Value &tv,
                              const void *act);
  MyHeartBeatAcceptor * acceptor() const;

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
  int num_active_clients() const;

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
  virtual const char * name() const;

protected:
  virtual bool on_start();
};


/////////////////////////////////////
//dist to BS
/////////////////////////////////////

class MyDistToMiddleModule;

class MyDistToBSProcessor: public MyBSBasePacketProcessor
{
public:
  typedef MyBSBasePacketProcessor super;

  MyDistToBSProcessor(MyBaseHandler * handler);
};

class MyDistToBSHandler: public MyBaseHandler
{
public:
  MyDistToBSHandler(MyBaseConnectionManager * xptr = NULL);
  MyDistToMiddleModule * module_x() const;
  DECLARE_MEMORY_POOL__NOTHROW(MyDistToBSHandler, ACE_Thread_Mutex);

protected:
  virtual void on_close();
  virtual int  on_open();
};

class MyDistToBSConnector: public MyBaseConnector
{
public:
  MyDistToBSConnector(MyBaseDispatcher * _dispatcher, MyBaseConnectionManager * _manager);
  virtual int make_svc_handler(MyBaseHandler *& sh);
  virtual const char * name() const;

protected:
  enum { RECONNECT_INTERVAL = 3 }; //time in minutes
};


/////////////////////////////////////
//dist to middle module
/////////////////////////////////////

class MyDistToMiddleModule;
class MyDistToMiddleConnector;

class MyDistToMiddleProcessor: public MyBaseClientProcessor
{
public:
  typedef MyBaseClientProcessor super;

  MyDistToMiddleProcessor(MyBaseHandler * handler);
  virtual MyBaseProcessor::EVENT_RESULT on_recv_header();
  virtual int on_open();
  int send_server_load();

protected:
  virtual MyBaseProcessor::EVENT_RESULT on_recv_packet_i(ACE_Message_Block * mb);

private:
  enum { IP_ADDR_LENGTH = INET_ADDRSTRLEN };

  int send_version_check_req();
  MyBaseProcessor::EVENT_RESULT do_version_check_reply(ACE_Message_Block * mb);
  MyBaseProcessor::EVENT_RESULT do_have_dist_task(ACE_Message_Block * mb);

  bool m_version_check_reply_done;
  char m_local_addr[IP_ADDR_LENGTH];
};

class MyDistToMiddleHandler: public MyBaseHandler
{
public:
  MyDistToMiddleHandler(MyBaseConnectionManager * xptr = NULL);
  virtual int handle_timeout (const ACE_Time_Value &current_time, const void *act = 0);
  void setup_timer();
  MyDistToMiddleModule * module_x() const;
  DECLARE_MEMORY_POOL__NOTHROW(MyDistToMiddleHandler, ACE_Thread_Mutex);

protected:
  virtual void on_close();
  virtual int  on_open();

private:
  enum { LOAD_BALANCE_REQ_TIMER = 1 };
  enum { LOAD_BALANCE_REQ_INTERVAL = 3 }; //in minutes
  long m_load_balance_req_timer_id;
};

class MyDistToMiddleDispatcher: public MyBaseDispatcher
{
public:
  MyDistToMiddleDispatcher(MyBaseModule * pModule, int numThreads = 1);
  virtual const char * name() const;
  void send_to_bs(ACE_Message_Block * mb);
  void send_to_middle(ACE_Message_Block * mb);

protected:
  virtual void on_stop();
  virtual bool on_start();
  virtual bool on_event_loop();

private:
  MyDistToMiddleConnector * m_connector;
  MyDistToBSConnector * m_bs_connector;
  ACE_Message_Queue<ACE_MT_SYNCH> m_to_bs_queue;
};


class MyDistToMiddleConnector: public MyBaseConnector
{
public:
  MyDistToMiddleConnector(MyBaseDispatcher * _dispatcher, MyBaseConnectionManager * _manager);
  virtual int make_svc_handler(MyBaseHandler *& sh);
  virtual const char * name() const;

protected:
  enum { RECONNECT_INTERVAL = 3 }; //time in minutes
};

class MyDistToMiddleModule: public MyBaseModule
{
public:
  MyDistToMiddleModule(MyBaseApp * app);
  virtual ~MyDistToMiddleModule();
  virtual const char * name() const;
  void send_to_bs(ACE_Message_Block * mb);
  void send_to_middle(ACE_Message_Block * mb);

protected:
  virtual bool on_start();
  virtual void on_stop();

private:
  MyDistToMiddleDispatcher *m_dispatcher;
};


#endif /* HEARTBEATMODULE_H_ */
