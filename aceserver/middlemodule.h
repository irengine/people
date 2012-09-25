#ifndef DISTMODULE_H_
#define DISTMODULE_H_

#include <ace/Malloc_T.h>
#include <new>
#include <tr1/unordered_set>

#include "tools.h"
#include "app.h"
#include "component.h"
#include "sall.h"

class MyLocationAcceptor;
class MyLocationModule;

class MyDistLoad
{
public:
  MyDistLoad()
  {
    m_ip_addr[0] = 0;
    m_clients_connected = 0;
    m_last_access = g_clock_counter;
  }

  MyDistLoad(const char * _addr, int m)
  {
    ip_addr(_addr);
    clients_connected(m);
    m_last_access = g_clock_counter;
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
  typedef std::tr1::unordered_set<const char *, CStrHasher, CStrEqual, CCppAllocator<const char *> > MyPathSet;
  typedef std::list<CMemGuard *, CCppAllocator<CMemGuard *> > MyPathList;

  bool path_ok(const char * _path);

  MyPathSet  m_path_set;
  MyPathList m_path_list;
};

class MyLocationProcessor: public CServerProcBase
{
public:
  MyLocationProcessor(CHandlerBase * handler);
  virtual CProcBase::EVENT_RESULT on_recv_header();
  virtual const char * name() const;

  static MyDistLoads * m_dist_loads;

  DECLARE_MEMORY_POOL__NOTHROW(MyLocationProcessor, ACE_Thread_Mutex);

protected:
  virtual CProcBase::EVENT_RESULT on_recv_packet_i(ACE_Message_Block * mb);

private:
  CProcBase::EVENT_RESULT do_version_check(ACE_Message_Block * mb);
};


class MyLocationHandler: public CHandlerBase
{
public:
  MyLocationHandler(CConnectionManagerBase * xptr = NULL);
  DECLARE_MEMORY_POOL__NOTHROW(MyLocationHandler, ACE_Thread_Mutex);
};

class MyLocationService: public CTaskBase
{
public:
  MyLocationService(CMod * module, int numThreads = 1);
  virtual int svc();
};

class MyLocationDispatcher: public CDispatchBase
{
public:
  MyLocationDispatcher(CMod * _module, int numThreads = 1);

protected:
  virtual bool on_start();
  virtual void on_stop();
  virtual const char * name() const;

private:
  enum { MSG_QUEUE_MAX_SIZE = 5 * 1024 * 1024 };

  MyLocationAcceptor * m_acceptor;
};

class MyLocationAcceptor: public CAcceptorBase
{
public:
  enum { IDLE_TIME_AS_DEAD = 5 }; //in minutes
  MyLocationAcceptor(CDispatchBase * _dispatcher, CConnectionManagerBase * manager);

  virtual int make_svc_handler(CHandlerBase *& sh);
  virtual const char * name() const;
};


class MyLocationModule: public CMod
{
public:
  MyLocationModule(CApp * app);
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

class MyHttpProcessor: public CFormattedProcBase<int>
{
public:
  typedef CFormattedProcBase<int> super;

  MyHttpProcessor(CHandlerBase * handler);
  virtual ~MyHttpProcessor();
  virtual const char * name() const;
  DECLARE_MEMORY_POOL__NOTHROW(MyHttpProcessor, ACE_Thread_Mutex);

protected:
  virtual int packet_length();
  virtual CProcBase::EVENT_RESULT on_recv_header();
  virtual CProcBase::EVENT_RESULT on_recv_packet_i(ACE_Message_Block * mb);

private:
  bool do_process_input_data();
  bool do_prio(ACE_Message_Block * mb);
};


class MyHttpHandler: public CHandlerBase
{
public:
  MyHttpHandler(CConnectionManagerBase * xptr = NULL);

  DECLARE_MEMORY_POOL__NOTHROW(MyHttpHandler, ACE_Thread_Mutex);
};

class MyHttpService: public CTaskBase
{
public:
  MyHttpService(CMod * module, int numThreads = 1);

  virtual int svc();
  virtual const char * name() const;

private:
  enum { MSG_QUEUE_MAX_SIZE = 5 * 1024 * 1024 };

  bool handle_packet(ACE_Message_Block * mb);
  bool do_handle_packet(ACE_Message_Block * mb, MyHttpDistRequest & http_dist_request);
  bool do_handle_packet2(ACE_Message_Block * mb);
  bool parse_request(ACE_Message_Block * mb, MyHttpDistRequest & http_dist_request);
  bool do_compress(MyHttpDistRequest & http_dist_request);
  bool do_calc_md5(MyHttpDistRequest & http_dist_request);
  bool notify_dist_servers();
};

class MyHttpDispatcher: public CDispatchBase
{
public:
  MyHttpDispatcher(CMod * pModule, int numThreads = 1);
  virtual const char * name() const;

protected:
  virtual void on_stop();
  virtual bool on_start();

private:
  MyHttpAcceptor * m_acceptor;
};

class MyHttpAcceptor: public CAcceptorBase
{
public:
  enum { IDLE_TIME_AS_DEAD = 5 }; //in minutes

  MyHttpAcceptor(CDispatchBase * _dispatcher, CConnectionManagerBase * manager);
  virtual int make_svc_handler(CHandlerBase *& sh);
  virtual const char * name() const;
};


class MyHttpModule: public CMod
{
public:
  MyHttpModule(CApp * app);
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

class MyDistLoadProcessor: public CServerProcBase
{
public:
  typedef CServerProcBase super;

  MyDistLoadProcessor(CHandlerBase * handler);
  virtual ~MyDistLoadProcessor();
  virtual const char * name() const;
  virtual bool client_id_verified() const;
  virtual CProcBase::EVENT_RESULT on_recv_header();
  void dist_loads(MyDistLoads * dist_loads);

protected:
  virtual CProcBase::EVENT_RESULT on_recv_packet_i(ACE_Message_Block * mb);

private:
  enum { MSG_QUEUE_MAX_SIZE = 1024 * 1024 };

  CProcBase::EVENT_RESULT do_version_check(ACE_Message_Block * mb);
  CProcBase::EVENT_RESULT do_load_balance(ACE_Message_Block * mb);

  bool m_client_id_verified;
  MyDistLoads * m_dist_loads;
};


class MyDistLoadHandler: public CHandlerBase
{
public:
  MyDistLoadHandler(CConnectionManagerBase * xptr = NULL);
  void dist_loads(MyDistLoads * dist_loads);

  DECLARE_MEMORY_POOL__NOTHROW(MyDistLoadHandler, ACE_Thread_Mutex);
};

class MyDistLoadDispatcher: public CDispatchBase
{
public:
  MyDistLoadDispatcher(CMod * pModule, int numThreads = 1);
  ~MyDistLoadDispatcher();
  virtual const char * name() const;
  virtual int handle_timeout(const ACE_Time_Value &current_time, const void *act = 0);
  void send_to_bs(ACE_Message_Block * mb);

protected:
  virtual void on_stop();
  virtual bool on_start();
  virtual bool on_event_loop();

private:
  enum { MSG_QUEUE_MAX_SIZE = 1024 * 1024 };

  MyDistLoadAcceptor * m_acceptor;
  MyMiddleToBSConnector * m_bs_connector;
  ACE_Message_Queue<ACE_MT_SYNCH> m_to_bs_queue;
};

class MyDistLoadAcceptor: public CAcceptorBase
{
public:
  enum { IDLE_TIME_AS_DEAD = 15 }; //in minutes
  MyDistLoadAcceptor(CDispatchBase * _dispatcher, CConnectionManagerBase * manager);

  virtual int make_svc_handler(CHandlerBase *& sh);
  virtual const char * name() const;
};


class MyDistLoadModule: public CMod
{
public:
  MyDistLoadModule(CApp * app);
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

class MyMiddleToBSProcessor: public CBSProceBase
{
public:
  typedef CBSProceBase super;

  MyMiddleToBSProcessor(CHandlerBase * handler);
  virtual const char * name() const;

  DECLARE_MEMORY_POOL__NOTHROW(MyMiddleToBSProcessor, ACE_Thread_Mutex);

protected:
  virtual CProcBase::EVENT_RESULT on_recv_packet_i(ACE_Message_Block * mb);
};

class MyMiddleToBSHandler: public CHandlerBase
{
public:
  MyMiddleToBSHandler(CConnectionManagerBase * xptr = NULL);
  virtual int handle_timeout (const ACE_Time_Value &current_time, const void *act = 0);
  void checker_update();
  MyDistLoadModule * module_x() const;
  DECLARE_MEMORY_POOL__NOTHROW(MyMiddleToBSHandler, ACE_Thread_Mutex);

protected:
  virtual void on_close();
  virtual int  on_open();

private:
  MyActChecker m_checker;
};

class MyMiddleToBSConnector: public CConnectorBase
{
public:
  MyMiddleToBSConnector(CDispatchBase * _dispatcher, CConnectionManagerBase * _manager);
  virtual int make_svc_handler(CHandlerBase *& sh);
  virtual const char * name() const;

protected:
  enum { RECONNECT_INTERVAL = 1 }; //time in minutes
};



#endif /* DISTMODULE_H_ */
