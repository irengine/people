/*
 * distmodule.h
 *
 *  Created on: Jan 7, 2012
 *      Author: root
 */

#ifndef DISTMODULE_H_
#define DISTMODULE_H_

#include "serverapp.h"
#include "basemodule.h"
#include <ace/Malloc_T.h>
#include <new>

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

  void update(const MyDistLoad & load);
  void remove(const char * addr);
  void get_server_list(char * buffer, int buffer_len);
private:
  void calc_server_list();

  MyDistLoads::MyDistLoadVecIt find_i(const char * addr);
  MyDistLoadVec m_loads;
  char m_server_list[MyClientVersionCheckReply::REPLY_DATA_LENGTH];
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
  MyLocationDispatcher(MyBaseModule * pModule, int numThreads = 1);
  virtual int open (void * = 0);

protected:
  virtual void on_stop();

private:
  MyLocationAcceptor * m_acceptor;
};

class MyLocationAcceptor: public MyBaseAcceptor
{
public:
  MyLocationAcceptor(MyLocationModule * _module, MyBaseConnectionManager * manager);
  virtual int make_svc_handler(MyBaseHandler *& sh);
};


class MyLocationModule: public MyBaseModule
{
public:
  MyLocationModule();
  virtual ~MyLocationModule();

private:
  //MyPingSubmitter m_ping_sumbitter;
  MyDistLoads m_dist_loads;
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
  virtual int open (void * = 0);

protected:
  virtual void on_stop();

private:
  MyHttpAcceptor * m_acceptor;
};

class MyHttpAcceptor: public MyBaseAcceptor
{
public:
  MyHttpAcceptor(MyHttpModule * _module, MyBaseConnectionManager * manager);
  virtual int make_svc_handler(MyBaseHandler *& sh);
};


class MyHttpModule: public MyBaseModule
{
public:
  MyHttpModule();
  virtual ~MyHttpModule();

private:
//  MyPingSubmitter m_ping_sumbitter;
};


#endif /* DISTMODULE_H_ */
