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

#include <sqlite3.h>

class MyClientToDistModule;
class MyClientToDistConnector;
class MyDistInfoFtps;

const u_int8_t const_client_version_major = 1;
const u_int8_t const_client_version_minor = 0;

#if defined(MY_client_test)

//simple implementation, not thread safe, multiple calls to put on the same id will generate duplicate
//IDs for later gets. but it works for our test. that is enough
class MyTestClientIDGenerator
{
public:
  MyTestClientIDGenerator()
  { }
  const char * get()
  {
    if (m_id_list.empty())
      return NULL;
    MyClientID client_id = m_id_list.back();
    ACE_OS::strsncpy(m_result, client_id.as_string(), BUFF_LEN);
    m_id_list.pop_back();
    return m_result;
  }
  void put(const char * id)
  {
    if (unlikely(!id || !*id))
      return;
    m_id_list.push_back(MyClientID(id));
  }
  bool empty() const
  {
    return m_id_list.empty();
  }
  int count() const
  {
    return m_id_list.size();
  }
private:
  typedef std::vector<MyClientID> MyClientIDList;
  enum { BUFF_LEN = 32 };
  char  m_result[BUFF_LEN];
  MyClientIDList m_id_list;
};
#endif

class MyClientDB
{
public:
  ~MyClientDB();

  bool open_db(const char * client_id);
  void close_db();
  bool save_ftp_command(const char * ftp_command);
  bool set_ftp_command_status(const char * dist_id, int status);
  bool get_ftp_command_status(const char * dist_id, int & status);
  void remove_outdated_ftp_command(time_t deadline);
  bool load_ftp_commands(MyDistInfoFtps * dist_ftps);

protected:
  friend class MyClientDBGuard;
  MyClientDB();
  static ACE_Thread_Mutex m_mutex;

private:
  static int load_ftp_commands_callback(void * p, int argc, char **argv, char **azColName);
  static int get_ftp_commands_status_callback(void * p, int argc, char **argv, char **azColName);

  bool do_exec(const char *sql, bool show_error = true);
  bool init_db();

  sqlite3 * m_db;
};

class MyClientDBGuard
{
public:
  MyClientDBGuard()
  {
    MyClientDB::m_mutex.acquire();
  }

  ~MyClientDBGuard()
  {
    m_db.close_db();
    MyClientDB::m_mutex.release();
  }

  MyClientDB & db()
  {
    return m_db;
  }

private:
  MyClientDB m_db;
};

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

  static bool download(const char * client_id, const char *remote_ip, const char * ftp_password, const char *filename, const char * localfile);

private:
  enum { TIME_OUT_SECONDS = 30, MAX_BUFSIZE = 4096 };
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
  MyDistInfoHeader();
  virtual ~MyDistInfoHeader();
  void calc_target_parent_path(MyPooledMemGuard & target_parent_path, bool extract_only);
  bool calc_target_path(const char * target_parent_path, MyPooledMemGuard & target_path);
  virtual bool validate();

  MyPooledMemGuard dist_id;
  MyPooledMemGuard findex;
  MyPooledMemGuard adir;
  MyPooledMemGuard aindex;
  char ftype;
  char type;
#ifdef MY_client_test
  MyClientID client_id;
  int client_id_index;
#endif

protected:
  int load_header_from_string(char * src);
};

class MyDistInfoMD5: public MyDistInfoHeader
{
public:
  typedef MyDistInfoHeader super;

  MyDistInfoMD5();

  bool load_from_string(char * src);
  virtual bool validate();
  bool compare_done() const;
  void compare_done(bool done);
  MyFileMD5s & md5list();
  void post_md5_message();

private:
  MyFileMD5s m_md5list;
  bool m_compare_done;
};

class MyDistInfoMD5s
{
public:
  typedef std::list<MyDistInfoMD5 * > MyDistInfoMD5List;
  typedef MyDistInfoMD5List::iterator MyDistInfoMD5ListPtr;

  ~MyDistInfoMD5s();
  void add(MyDistInfoMD5 * p);
  MyDistInfoMD5 * get();
  MyDistInfoMD5 * get_finished(const MyDistInfoMD5 & rhs);

private:
  ACE_Thread_Mutex  m_mutex;
  MyDistInfoMD5List m_dist_info_md5s;
  MyDistInfoMD5List m_dist_info_md5s_finished;
};

class MyDistInfoMD5Comparer
{
public:
  static bool compute(MyDistInfoHeader * dist_info_header, MyFileMD5s & md5list);
  static void compare(MyDistInfoHeader * dist_info_header, MyFileMD5s & server_md5, MyFileMD5s & client_md5);
};

class MyDistInfoFtp: public MyDistInfoHeader
{
public:
  typedef MyDistInfoHeader super;
  MyDistInfoFtp();

  virtual bool validate();
  bool load_from_string(char * src);
  time_t get_delay_penalty() const;
  bool should_ftp(time_t now) const;
  bool should_extract() const;
  void touch();
  void inc_failed();
  void calc_local_file_name();
  void post_status_message() const;
  bool update_db_status() const;

  MyPooledMemGuard file_name;
  MyPooledMemGuard file_password;
  MyPooledMemGuard ftp_password;
  int  status;
  time_t recv_time;
  MyPooledMemGuard local_file_name;

private:
  enum { FAILED_PENALTY = 4, MAX_FAILED_COUNT = 20 };
  time_t last_update;
  int  failed_count;
};

class MyDistInfoFtps
{
public:
  typedef std::list<MyDistInfoFtp * > MyDistInfoFtpList;
  typedef MyDistInfoFtpList::iterator MyDistInfoFtpListPtr;

  ~MyDistInfoFtps();
  void begin();
  void add(MyDistInfoFtp * p);
  int status(const char * dist_id, const char * client_id);
  MyDistInfoFtp * get(bool is_ftp, time_t now = time(NULL));

  ACE_Thread_Mutex m_mutex; //for performance reasons...somewhat ugly
private:

  MyDistInfoFtpList m_dist_info_ftps;
  MyDistInfoFtpListPtr m_current_ptr;
};

class MyDistFtpFileExtractor
{
public:
  MyDistFtpFileExtractor();

  bool extract(MyDistInfoFtp * dist_info);

private:

  MyDistInfoFtp * m_dist_info;
};

class MyClientToDistProcessor: public MyBaseClientProcessor
{
public:
  typedef MyBaseClientProcessor super;

  MyClientToDistProcessor(MyBaseHandler * handler);
  virtual MyBaseProcessor::EVENT_RESULT on_recv_header();
  virtual int on_open();
  int send_heart_beat();
  int send_ip_ver_req();

protected:
  virtual MyBaseProcessor::EVENT_RESULT on_recv_packet_i(ACE_Message_Block * mb);

private:
  int send_version_check_req();
  MyBaseProcessor::EVENT_RESULT do_ftp_file_request(ACE_Message_Block * mb);
  MyBaseProcessor::EVENT_RESULT do_md5_list_request(ACE_Message_Block * mb);
  MyBaseProcessor::EVENT_RESULT do_version_check_reply(ACE_Message_Block * mb);

  bool m_version_check_reply_done;
  MyPooledMemGuard m_ftp_password;
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
  bool empty_ftp();

  void save();
  void load();

private:
  void get_file_name(MyPooledMemGuard & file_name);
  bool valid_addr(const char * addr) const;

  std::vector<std::string> m_server_addrs;
  std::vector<std::string> m_ftp_addrs;
  ACE_Thread_Mutex m_mutex;
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
  bool setup_timer(int heart_beat_interval);
  MyClientToDistModule * module_x() const;
  DECLARE_MEMORY_POOL__NOTHROW(MyClientToDistHandler, ACE_Thread_Mutex);

protected:
  virtual void on_close();
  virtual int  on_open();

private:
  enum { HEART_BEAT_PING_TIMER = 1, IP_VER_TIMER };
  enum { IP_VER_INTERVAL = 1 }; //in minutes
};

class MyClientToDistService: public MyBaseService
{
public:
  MyClientToDistService(MyBaseModule * module, int numThreads = 1);
  virtual int svc();
  virtual const char * name() const;
  bool add_md5_task(MyDistInfoMD5 * p);
  bool add_extract_task(MyDistInfoFtp * p);

private:
  enum { TASK_MD5, TASK_EXTRACT };
  enum { MSG_QUEUE_MAX_SIZE = 5 * 1024 * 1024 };

  void return_back(MyDistInfoFtp * dist_info);
  void return_back_md5(MyDistInfoMD5 * p);
  void do_server_file_md5_list(ACE_Message_Block * mb);
  void do_md5_task(MyDistInfoMD5 * p);
  void do_extract_task(MyDistInfoFtp * p);
};

class MyClientFtpService: public MyBaseService
{
public:
  MyClientFtpService(MyBaseModule * module, int numThreads = 1);
  virtual int svc();
  virtual const char * name() const;
  bool add_ftp_task(MyDistInfoFtp * p);

private:
  enum { TASK_FTP = 1 };

  void do_ftp_task(MyDistInfoFtp * dist_info, std::string & server_addr, int & failed_count);
  bool do_ftp_download(MyDistInfoFtp * dist_info, const char * server_ip);

  void return_back(MyDistInfoFtp * dist_info);
  MyDistInfoFtp * get_dist_info_ftp(ACE_Message_Block * mb) const;
};


class MyClientToMiddleConnector;

class MyClientToDistDispatcher: public MyBaseDispatcher
{
public:
  MyClientToDistDispatcher(MyBaseModule * pModule, int numThreads = 1);
  ~MyClientToDistDispatcher();
  virtual int handle_timeout (const ACE_Time_Value &current_time, const void *act = 0);
  virtual const char * name() const;
  void ask_for_server_addr_list_done(bool success);

protected:
  virtual void on_stop();
  virtual bool on_start();
  virtual bool on_event_loop();

private:
  enum { FTP_CHECK_INTERVAL = 1 }; //in minutes
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
  MyClientFtpService * client_ftp_service() const;
  virtual const char * name() const;
  void ask_for_server_addr_list_done(bool success);
  MyDistInfoFtps & dist_info_ftps();
  MyDistInfoMD5s & dist_info_md5s();
  void check_ftp_timed_task();
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
  MyDistInfoFtps m_dist_info_ftps;
  MyDistInfoMD5s m_dist_info_md5s;
  MyClientFtpService * m_client_ftp_service;

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
  int  send_version_check_req();
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
