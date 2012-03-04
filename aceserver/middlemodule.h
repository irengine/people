/*
 * distmodule.h
 *
 *  Created on: Jan 7, 2012
 *      Author: root
 */

#ifndef DISTMODULE_H_
#define DISTMODULE_H_

#include <ace/Malloc_T.h>
#include <new>
#include <tr1/unordered_set>

#include "common.h"
#include "baseapp.h"
#include "basemodule.h"
#include "servercommon.h"

class MyLocationAcceptor;
class MyLocationModule;

class MyDistLoad
{
public:
  MyDistLoad()
  {
    m_ip_addr[0] = 0;
    m_clients_connected = 0;
    m_last_access = g_clock_tick;
  }

  MyDistLoad(const char * _addr, int m)
  {
    ip_addr(_addr);
    clients_connected(m);
    m_last_access = g_clock_tick;
  }

  void ip_addr(const char * _addr)
  {
    if (_addr)
      ACE_OS::strsncpy(m_ip_addr, _addr, IP_ADDR_LEN);
    else
      m_ip_addr[0] = 0;
  }

  void clients_connected(int m)
  {
    if (m >= 0)
      m_clients_connected = m;
    else
      m_clients_connected = 0;
  }

  bool operator < (const MyDistLoad & rhs) const
  {
    return m_clients_connected < rhs.m_clients_connected;
  }

  enum
  {
    IP_ADDR_LEN = 40
  };

  char    m_ip_addr[IP_ADDR_LEN];
  int32_t m_clients_connected;
  long    m_last_access;
};


class MyDistLoads
{
public:
  typedef std::vector<MyDistLoad> MyDistLoadVec;
  typedef MyDistLoadVec::iterator MyDistLoadVecIt;
  enum { SERVER_LIST_LENGTH = 2048 };
  enum { DEAD_TIME = 10 }; //in minutes

  MyDistLoads();

  void update(const MyDistLoad & load);
  void remove(const char * addr);
  int  get_server_list(char * buffer, int buffer_len);
  void scan_for_dead();

private:
  void calc_server_list();
  MyDistLoads::MyDistLoadVecIt find_i(const char * addr);

  MyDistLoadVec m_loads;
  char m_server_list[SERVER_LIST_LENGTH];
  int  m_server_list_length;
  ACE_Thread_Mutex m_mutex;
};

class MyUnusedPathRemover
{
public:
  ~MyUnusedPathRemover();

  void add_dist_id(const char * dist_id);
  void check_path(const char * path);

private:
  typedef std::tr1::unordered_set<const char *, MyStringHash, MyStringEqual, MyAllocator<const char *> > MyPathSet;
  typedef std::list<MyPooledMemGuard *, MyAllocator<MyPooledMemGuard *> > MyPathList;

  bool path_ok(const char * _path);

  MyPathSet  m_path_set;
  MyPathList m_path_list;
};

class MyLocationProcessor: public MyBaseServerProcessor
{
public:
  MyLocationProcessor(MyBaseHandler * handler);
  virtual MyBaseProcessor::EVENT_RESULT on_recv_header();

  static MyDistLoads * m_dist_loads;

  DECLARE_MEMORY_POOL__NOTHROW(MyLocationProcessor, ACE_Thread_Mutex);

protected:
  virtual MyBaseProcessor::EVENT_RESULT on_recv_packet_i(ACE_Message_Block * mb);

private:
  MyBaseProcessor::EVENT_RESULT do_version_check(ACE_Message_Block * mb);
};


class MyLocationHandler: public MyBaseHandler
{
public:
  MyLocationHandler(MyBaseConnectionManager * xptr = NULL);
  DECLARE_MEMORY_POOL__NOTHROW(MyLocationHandler, ACE_Thread_Mutex);
};

class MyLocationService: public MyBaseService
{
public:
  MyLocationService(MyBaseModule * module, int numThreads = 1);
  virtual int svc();
};

class MyLocationDispatcher: public MyBaseDispatcher
{
public:
  MyLocationDispatcher(MyBaseModule * _module, int numThreads = 1);

protected:
  virtual bool on_start();
  virtual void on_stop();
  virtual const char * name() const;

private:
  enum { MSG_QUEUE_MAX_SIZE = 5 * 1024 * 1024 };

  MyLocationAcceptor * m_acceptor;
};

class MyLocationAcceptor: public MyBaseAcceptor
{
public:
  enum { IDLE_TIME_AS_DEAD = 5 }; //in minutes
  MyLocationAcceptor(MyBaseDispatcher * _dispatcher, MyBaseConnectionManager * manager);

  virtual int make_svc_handler(MyBaseHandler *& sh);
  virtual const char * name() const;
};


class MyLocationModule: public MyBaseModule
{
public:
  MyLocationModule(MyBaseApp * app);
  virtual ~MyLocationModule();
  MyDistLoads * dist_loads();

protected:
  virtual bool on_start();
  virtual void on_stop();
  virtual const char * name() const;

private:
  MyDistLoads m_dist_loads;
  MyLocationService * m_service;
  MyLocationDispatcher *m_dispatcher;
};

//============================//
//http module stuff begins here
//============================//

class MyHttpModule;
class MyHttpAcceptor;

class MyHttpProcessor: public MyVeryBasePacketProcessor<int>
{
public:
  typedef MyVeryBasePacketProcessor<int> super;

  MyHttpProcessor(MyBaseHandler * handler);
  virtual ~MyHttpProcessor();
  DECLARE_MEMORY_POOL__NOTHROW(MyHttpProcessor, ACE_Thread_Mutex);

protected:
  virtual int packet_length();
  virtual MyBaseProcessor::EVENT_RESULT on_recv_header();
  virtual MyBaseProcessor::EVENT_RESULT on_recv_packet_i(ACE_Message_Block * mb);

private:
  bool do_process_input_data();
};


class MyHttpHandler: public MyBaseHandler
{
public:
  MyHttpHandler(MyBaseConnectionManager * xptr = NULL);

  DECLARE_MEMORY_POOL__NOTHROW(MyHttpHandler, ACE_Thread_Mutex);
};

class MyHttpService: public MyBaseService
{
public:
  MyHttpService(MyBaseModule * module, int numThreads = 1);

  virtual int svc();
  virtual const char * name() const;

private:
  enum { MSG_QUEUE_MAX_SIZE = 5 * 1024 * 1024 };

  bool handle_packet(ACE_Message_Block * mb);
  bool parse_request(ACE_Message_Block * mb, MyHttpDistRequest & http_dist_request);
  bool do_compress(MyHttpDistRequest & http_dist_request);
  bool do_calc_md5(MyHttpDistRequest & http_dist_request);
  bool notify_dist_servers();
};

class MyHttpDispatcher: public MyBaseDispatcher
{
public:
  MyHttpDispatcher(MyBaseModule * pModule, int numThreads = 1);
  virtual const char * name() const;

protected:
  virtual void on_stop();
  virtual bool on_start();

private:
  MyHttpAcceptor * m_acceptor;
};

class MyHttpAcceptor: public MyBaseAcceptor
{
public:
  enum { IDLE_TIME_AS_DEAD = 5 }; //in minutes

  MyHttpAcceptor(MyBaseDispatcher * _dispatcher, MyBaseConnectionManager * manager);
  virtual int make_svc_handler(MyBaseHandler *& sh);
  virtual const char * name() const;
};


class MyHttpModule: public MyBaseModule
{
public:
  MyHttpModule(MyBaseApp * app);
  virtual ~MyHttpModule();
  virtual const char * name() const;
  MyHttpService * http_service();

protected:
  virtual bool on_start();
  virtual void on_stop();

private:
  MyHttpService *m_service;
  MyHttpDispatcher * m_dispatcher;
};


//============================//
//DistLoad module stuff begins here
//============================//

class MyDistLoadModule;
class MyDistLoadAcceptor;
class MyMiddleToBSConnector;

class MyDistLoadProcessor: public MyBaseServerProcessor
{
public:
  typedef MyBaseServerProcessor super;

  MyDistLoadProcessor(MyBaseHandler * handler);
  virtual ~MyDistLoadProcessor();
  virtual bool client_id_verified() const;
  virtual MyBaseProcessor::EVENT_RESULT on_recv_header();
  void dist_loads(MyDistLoads * dist_loads);

protected:
  virtual MyBaseProcessor::EVENT_RESULT on_recv_packet_i(ACE_Message_Block * mb);

private:
  enum { MSG_QUEUE_MAX_SIZE = 512 * 1024 };

  MyBaseProcessor::EVENT_RESULT do_version_check(ACE_Message_Block * mb);
  MyBaseProcessor::EVENT_RESULT do_load_balance(ACE_Message_Block * mb);

  bool m_client_id_verified;
  MyDistLoads * m_dist_loads;
};


class MyDistLoadHandler: public MyBaseHandler
{
public:
  MyDistLoadHandler(MyBaseConnectionManager * xptr = NULL);
  void dist_loads(MyDistLoads * dist_loads);

  DECLARE_MEMORY_POOL__NOTHROW(MyDistLoadHandler, ACE_Thread_Mutex);
};

class MyDistLoadDispatcher: public MyBaseDispatcher
{
public:
  MyDistLoadDispatcher(MyBaseModule * pModule, int numThreads = 1);
  virtual const char * name() const;
  virtual int handle_timeout(const ACE_Time_Value &current_time, const void *act = 0);

protected:
  virtual void on_stop();
  virtual bool on_start();
  virtual bool on_event_loop();

private:
  enum { MSG_QUEUE_MAX_SIZE = 1024 * 1024 };

  MyDistLoadAcceptor * m_acceptor;
  MyMiddleToBSConnector * m_bs_connector;
};

class MyDistLoadAcceptor: public MyBaseAcceptor
{
public:
  enum { IDLE_TIME_AS_DEAD = 10 }; //in minutes
  MyDistLoadAcceptor(MyBaseDispatcher * _dispatcher, MyBaseConnectionManager * manager);

  virtual int make_svc_handler(MyBaseHandler *& sh);
  virtual const char * name() const;
};


class MyDistLoadModule: public MyBaseModule
{
public:
  MyDistLoadModule(MyBaseApp * app);
  virtual ~MyDistLoadModule();
  virtual const char * name() const;
  MyDistLoadDispatcher * dispatcher() const;

protected:
  virtual bool on_start();
  virtual void on_stop();

private:
  MyDistLoadDispatcher * m_dispatcher;
};



/////////////////////////////////////
//middle to BS
/////////////////////////////////////

class MyMiddleToBSProcessor: public MyBSBasePacketProcessor
{
public:
  typedef MyBSBasePacketProcessor super;

  MyMiddleToBSProcessor(MyBaseHandler * handler);

  DECLARE_MEMORY_POOL__NOTHROW(MyMiddleToBSProcessor, ACE_Thread_Mutex);
};

class MyMiddleToBSHandler: public MyBaseHandler
{
public:
  MyMiddleToBSHandler(MyBaseConnectionManager * xptr = NULL);
  MyDistLoadModule * module_x() const;
  DECLARE_MEMORY_POOL__NOTHROW(MyMiddleToBSHandler, ACE_Thread_Mutex);

protected:
  virtual void on_close();
  virtual int  on_open();
};

class MyMiddleToBSConnector: public MyBaseConnector
{
public:
  MyMiddleToBSConnector(MyBaseDispatcher * _dispatcher, MyBaseConnectionManager * _manager);
  virtual int make_svc_handler(MyBaseHandler *& sh);
  virtual const char * name() const;

protected:
  enum { RECONNECT_INTERVAL = 3 }; //time in minutes
};



#endif /* DISTMODULE_H_ */
