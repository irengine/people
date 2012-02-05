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

class MyFTPClient
{
public:
  MyFTPClient(const std::string &remote_ip, const u_short remote_port,
            const std::string &user_name, const std::string &pass_word);
  virtual ~MyFTPClient();

  bool login();
  bool logout();
  bool change_remote_dir(const char * dirname);
  bool get_file(const char *filename, const char * localfile);

  static bool download(const char * client_id, const char *remote_ip, const char *filename, const char * localfile);


private:
  enum { TIME_OUT_SECONDS = 30, MAX_BUFSIZE = 2048 };
  bool recv();
  bool send(const char * command);
  bool is_response(const char * res_code);

  std::string        m_user_name;
  std::string        m_password;
  MyPooledMemGuard   m_ftp_server_addr;
  ACE_INET_Addr      m_remote_addr;
  ACE_SOCK_Connector m_connector;
  ACE_SOCK_Stream    m_peer;
  MyPooledMemGuard   m_response;
};


class MyDistInfoHeader
{
public:
  int load_from_string(char * src);

  MyPooledMemGuard dist_id;
  MyPooledMemGuard findex;
  MyPooledMemGuard adir;
  MyPooledMemGuard aindex;
};

class MyClientToDistProcessor: public MyBaseClientProcessor
{
public:
  typedef MyBaseClientProcessor super;

  MyClientToDistProcessor(MyBaseHandler * handler);
  virtual MyBaseProcessor::EVENT_RESULT on_recv_header();
  virtual int on_open();
  int send_heart_beat();

protected:
  virtual MyBaseProcessor::EVENT_RESULT on_recv_packet_i(ACE_Message_Block * mb);

private:
  int send_version_check_req();

  MyBaseProcessor::EVENT_RESULT do_ftp_file_request(ACE_Message_Block * mb);
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

  const char * begin_ftp();
  const char * next_ftp();
  bool empty_ftp() const;

  void save();
  void load();

private:
  void get_file_name(MyPooledMemGuard & file_name);
  bool valid_addr(const char * addr) const;

  std::vector<std::string> m_server_addrs;
  std::vector<std::string> m_ftp_addrs;
  MyPooledMemGuard m_addr_list;
  int m_addr_list_len;
  int m_index;
  int m_ftp_index;
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

class MyClientToMiddleConnector;

class MyClientToDistDispatcher: public MyBaseDispatcher
{
public:
  MyClientToDistDispatcher(MyBaseModule * pModule, int numThreads = 1);
  virtual const char * name() const;
  void ask_for_server_addr_list_done(bool success);

protected:
  virtual void on_stop();
  virtual bool on_start();
  virtual bool on_event_loop();

private:
  MyClientToDistConnector * m_connector;
  MyClientToMiddleConnector * m_middle_connector;
};


class MyClientToDistConnector: public MyBaseConnector
{
public:
  MyClientToDistConnector(MyBaseDispatcher * _dispatcher, MyBaseConnectionManager * _manager);
  virtual int make_svc_handler(MyBaseHandler *& sh);
  virtual const char * name() const;
  void dist_server_addr(const char * addr);

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
  MyClientToDistDispatcher * dispatcher() const
  {
    return m_dispatcher;
  }
  virtual const char * name() const;
  void ask_for_server_addr_list_done(bool success);
#ifdef MY_client_test
  MyTestClientIDGenerator & id_generator()
  {
    return m_id_generator;
  }
#endif

protected:
  virtual bool on_start();
  virtual void on_stop();

private:
  MyDistServerAddrList m_server_addr_list;
  MyClientToDistService * m_service;
  MyClientToDistDispatcher *m_dispatcher;

#ifdef MY_client_test
  MyTestClientIDGenerator m_id_generator;
#endif
};

/////////////////////////////////////
//client to middle
/////////////////////////////////////

class MyClientToMiddleProcessor: public MyBaseClientProcessor
{
public:
  typedef MyBaseClientProcessor super;

  MyClientToMiddleProcessor(MyBaseHandler * handler);
  virtual MyBaseProcessor::EVENT_RESULT on_recv_header();
  virtual int on_open();

protected:
  virtual MyBaseProcessor::EVENT_RESULT on_recv_packet_i(ACE_Message_Block * mb);

private:
  int send_version_check_req();
  void do_version_check_reply(ACE_Message_Block * mb);
  void do_handle_server_list(ACE_Message_Block * mb);
};

class MyClientToMiddleHandler: public MyBaseHandler
{
public:
  MyClientToMiddleHandler(MyBaseConnectionManager * xptr = NULL);
  MyClientToDistModule * module_x() const;
  int handle_timeout(const ACE_Time_Value &current_time, const void *act);
  DECLARE_MEMORY_POOL__NOTHROW(MyClientToMiddleHandler, ACE_Thread_Mutex);

protected:
  virtual void on_close();
  virtual int  on_open();

private:
  enum { TIMER_OUT_TIMER = 1 };
  void setup_timer();

  long m_timer_out_timer_id;
};

class MyClientToMiddleConnector: public MyBaseConnector
{
public:
  MyClientToMiddleConnector(MyBaseDispatcher * _dispatcher, MyBaseConnectionManager * _manager);
  virtual int make_svc_handler(MyBaseHandler *& sh);
  virtual const char * name() const;
  void finish();

protected:
  virtual bool before_reconnect();

private:
  enum { RECONNECT_INTERVAL = 3 }; //time in minutes
  enum { MAX_CONNECT_RETRY_COUNT = 3 };
  int m_retried_count;
};

#endif /* CLIENTMODULE_H_ */
