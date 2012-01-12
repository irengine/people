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

#include "common.h"
#include "baseapp.h"
#include "basemodule.h"

class MyLocationAcceptor;
class MyLocationModule;

class MyDistLoad
{
public:
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
};



class MyDistLoads
{
public:
  typedef std::vector<MyDistLoad> MyDistLoadVec;
  typedef MyDistLoadVec::iterator MyDistLoadVecIt;
  enum { SERVER_LIST_LENGTH = 1024};

  MyDistLoads();

  void update(const MyDistLoad & load);
  void remove(const char * addr);
  int  get_server_list(char * buffer, int buffer_len);

private:
  void calc_server_list();
  MyDistLoads::MyDistLoadVecIt find_i(const char * addr);
  MyDistLoadVec m_loads;
  char m_server_list[SERVER_LIST_LENGTH];
  int  m_server_list_length;
  ACE_Thread_Mutex m_mutex;
};

class MyLocationProcessor: public MyBaseServerProcessor
{
public:
  MyLocationProcessor(MyBaseHandler * handler);
  virtual MyBaseProcessor::EVENT_RESULT on_recv_header(const MyDataPacketHeader & header);

  static MyDistLoads * m_dist_loads;

protected:
  virtual MyBaseProcessor::EVENT_RESULT on_recv_packet_i(ACE_Message_Block * mb);

private:
  MyBaseProcessor::EVENT_RESULT do_version_check(ACE_Message_Block * mb);
};


class MyLocationHandler: public MyBaseHandler
{
public:
  MyLocationHandler(MyBaseConnectionManager * xptr = NULL);
  DECLARE_MEMORY_POOL(MyLocationHandler, ACE_Thread_Mutex);
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

private:
  MyLocationAcceptor * m_acceptor;
};

class MyLocationAcceptor: public MyBaseAcceptor
{
public:
  MyLocationAcceptor(MyBaseDispatcher * _dispatcher, MyBaseConnectionManager * manager);
  virtual int make_svc_handler(MyBaseHandler *& sh);
};


class MyLocationModule: public MyBaseModule
{
public:
  MyLocationModule(MyBaseApp * app);
  virtual ~MyLocationModule();

protected:
  virtual bool on_start();
  virtual void on_stop();

private:
  MyDistLoads m_dist_loads;
  MyLocationService * m_service;
  MyLocationDispatcher *m_dispatcher;

};

//============================//
//http module stuff begins here
//============================//

class MyHttpModule;
//class MyPingSubmitter;
class MyHttpAcceptor;

class MyHttpProcessor: public MyBaseProcessor
{
public:
  MyHttpProcessor(MyBaseHandler * handler);
  virtual ~MyHttpProcessor();

  virtual int handle_input();

//  static MyPingSubmitter * m_sumbitter;

private:
  bool do_process_input_data();
  ACE_Message_Block * m_current_block;

};


class MyHttpHandler: public MyBaseHandler
{
public:
  MyHttpHandler(MyBaseConnectionManager * xptr = NULL);
  DECLARE_MEMORY_POOL(MyHttpHandler, ACE_Thread_Mutex);
};

class MyHttpService: public MyBaseService
{
public:
  MyHttpService(MyBaseModule * module, int numThreads = 1);
  virtual int svc();
};

class MyHttpDispatcher: public MyBaseDispatcher
{
public:
  MyHttpDispatcher(MyBaseModule * pModule, int numThreads = 1);

protected:
  virtual void on_stop();
  virtual bool on_start();

private:
  MyHttpAcceptor * m_acceptor;
};

class MyHttpAcceptor: public MyBaseAcceptor
{
public:
  MyHttpAcceptor(MyBaseDispatcher * _dispatcher, MyBaseConnectionManager * manager);
  virtual int make_svc_handler(MyBaseHandler *& sh);
};


class MyHttpModule: public MyBaseModule
{
public:
  MyHttpModule(MyBaseApp * app);
  virtual ~MyHttpModule();

protected:
  virtual bool on_start();
  virtual void on_stop();

private:
  MyHttpService *m_service;
  MyHttpDispatcher * m_dispatcher;

};


#endif /* DISTMODULE_H_ */
