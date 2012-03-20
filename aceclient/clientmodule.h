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
#include <ace/Process.h>

#include "common.h"
#include "baseapp.h"
#include "basemodule.h"

#include <sqlite3.h>

class MyClientToDistModule;
class MyClientToDistConnector;
class MyDistInfoFtp;
class MyDistInfoFtps;
class MyHttp1991Acceptor;

const u_int8_t const_client_version_major = 1;
const u_int8_t const_client_version_minor = 0;

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

class MyClickInfo
{
public:
  MyClickInfo();
  MyClickInfo(const char * chn, const char * pcode, const char * count);

  std::string channel;
  std::string point_code;
  std::string click_count;
  int len;
};

typedef std::list<MyClickInfo> MyClickInfos;

class MyServerID
{
public:
  static u_int8_t load(const char * client_id);
  static void save(const char * client_id, int server_id);
};

class MyClientDB
{
public:
  ~MyClientDB();

  bool open_db(const char * client_id, bool do_init = false);
  void close_db();
  bool save_ftp_command(const char * ftp_command, const MyDistInfoFtp & dist_ftp);
  bool save_md5_command(const char * dist_id, const char * md5_server, const char * md5_client);
  bool load_ftp_md5_for_diff(MyDistInfoFtp & dist_info);
  bool set_ftp_command_status(const char * dist_id, int status);
  bool get_ftp_command_status(const char * dist_id, int & status);
  bool get_click_infos(MyClickInfos & infos);
  bool clear_click_infos();
  bool save_click_info(const char * channel, const char * point_code);
  bool reset_ftp_command_status();
  void remove_outdated_ftp_command(time_t deadline);
  bool load_ftp_commands(MyDistInfoFtps * dist_ftps);
  bool load_ftp_command(MyDistInfoFtp & dist_ftp, const char * dist_id);
  bool ftp_obsoleted(MyDistInfoFtp & dist_ftp);
  bool update_adv_time(const char * filename, time_t t);
  bool delete_old_adv(time_t deadline);
  bool adv_has_file(const char * filename);
  bool adv_db_is_older(time_t deadline);

protected:
  friend class MyClientDBGuard;
  MyClientDB();
  static ACE_Thread_Mutex m_mutex;

private:
  bool ftp_command_existing(const char * dist_id);

  static int load_ftp_commands_callback(void * p, int argc, char **argv, char **azColName);
  static int load_ftp_command_callback(void * p, int argc, char **argv, char **azColName);
  static int get_one_integer_value_callback(void * p, int argc, char **argv, char **azColName);
  static int get_click_infos_callback(void * p, int argc, char **argv, char **azColName);
  static int get_ftp_md5_for_diff_callback(void * p, int argc, char **argv, char **azColName);

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

class MyAdvCleaner
{
public:
  void do_clean(const MyPooledMemGuard & path, const char * client_id, int expire_days);

private:
  void process_adv_txt(const MyPooledMemGuard & path, MyClientDB & db);
  void process_files(const MyPooledMemGuard & path, MyClientDB & db);
};

class MyConnectIni
{
public:
  enum CONNECT_STATUS {CS_DISCONNECTED = 0, CS_CONNECTING = 1, CS_ONLINE = 2 };
  static void update_connect_status(MyConnectIni::CONNECT_STATUS cs);
};

class MyFTPClient
{
public:
  MyFTPClient(const std::string &remote_ip, const u_short remote_port,
            const std::string &user_name, const std::string &pass_word, MyDistInfoFtp * ftp_info);
  virtual ~MyFTPClient();

  bool login();
  bool logout();
  bool change_remote_dir(const char * dirname);
  bool get_file(const char *filename, const char * localfile);

  static bool download(MyDistInfoFtp * dist_info, const char * server_ip);

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
  MyDistInfoFtp *    m_ftp_info;
};

class MyDistInfoHeader
{
public:
  MyDistInfoHeader();
  virtual ~MyDistInfoHeader();
  void calc_target_parent_path(MyPooledMemGuard & target_parent_path, bool extract_only);
  bool calc_target_path(const char * target_parent_path, MyPooledMemGuard & target_path);
  virtual bool validate();
  const char * index_file() const;

  MyPooledMemGuard dist_id;
  MyPooledMemGuard findex;
  MyPooledMemGuard adir;
  MyPooledMemGuard aindex;
  char ftype;
  char type;
  MyClientID client_id;
  int client_id_index;

protected:
  int load_header_from_string(char * src);
  bool calc_update_ini_value(MyPooledMemGuard & value);
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
  const char * md5_text() const;

private:
  MyPooledMemGuard m_md5_text;
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
//  MyDistInfoMD5List m_dist_info_md5s_finished;
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
  enum { FAILED_PENALTY = 2, MAX_FAILED_COUNT = 15 };

  MyDistInfoFtp();

  virtual bool validate();
  bool load_from_string(char * src);
  time_t get_delay_penalty() const;
  bool should_ftp(time_t now) const;
  bool should_extract() const;
  void touch();
  void inc_failed(int steps = 1);
  int  failed_count() const;
  void calc_local_file_name();
  void post_status_message(int _status = -1, bool result_ok = true) const;
  bool update_db_status() const;
  void generate_update_ini();
  void generate_url_ini();
  bool operator < (const MyDistInfoFtp & rhs) const;

  static ACE_Message_Block * make_ftp_dist_message(const char * dist_id, int status, bool ok = true, char ftype = 'x');

  MyPooledMemGuard file_name;
  MyPooledMemGuard file_password;
  MyPooledMemGuard ftp_password;
  MyPooledMemGuard ftp_md5;
  MyPooledMemGuard server_md5;
  MyPooledMemGuard client_md5;

  int  status;
  time_t recv_time;
  MyPooledMemGuard local_file_name;
  bool first_download;
  time_t last_update;

private:

  int  m_failed_count;
};

class MyDistInfoFtps
{
public:
  typedef std::list<MyDistInfoFtp * > MyDistInfoFtpList;
  typedef MyDistInfoFtpList::iterator MyDistInfoFtpListPtr;

  MyDistInfoFtps();
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
  bool get_true_dest_path(MyDistInfoFtp * dist_info, MyPooledMemGuard & target_path);

private:
  bool do_extract(MyDistInfoFtp * dist_info, const MyPooledMemGuard & target_parent_path);
  MyDistInfoFtp * m_dist_info;
};

class MyWatchDog
{
public:
  MyWatchDog();
  void touch();
  bool expired();
  void start();

private:
  enum { WATCH_DOG_TIME_OUT_VALUE = 5 * 60 }; //in seconds
  bool m_running;
  time_t m_time;
};

class MyIpVerReply
{
public:
  MyIpVerReply();
  void init(char * data);
  const char * pc();
  int heart_beat_interval();

private:
  enum { DEFAULT_HEART_BEAT_INTERVAL = 1};

  void do_init(MyPooledMemGuard & g, char * data, time_t t);
  void init_time_str(MyPooledMemGuard & g, const char * s, const char c);
  const char * search(char * src);
  static void get_filename(MyPooledMemGuard & fn);
  void save_to_file(const char * s);
  bool load_from_file();

  MyPooledMemGuard m_pc;
  MyPooledMemGuard m_pc_x;
  int m_heart_beat_interval;
  ACE_Thread_Mutex m_mutex;
  char m_tail;
  char m_now[24];
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
  enum { OFFLINE_THREASH_HOLD = 3 }; //in minutes

  int send_version_check_req();
  MyBaseProcessor::EVENT_RESULT do_ftp_file_request(ACE_Message_Block * mb);
  MyBaseProcessor::EVENT_RESULT do_md5_list_request(ACE_Message_Block * mb);
  MyBaseProcessor::EVENT_RESULT do_version_check_reply(ACE_Message_Block * mb);
  MyBaseProcessor::EVENT_RESULT do_ip_ver_reply(ACE_Message_Block * mb);
  void check_offline_report();

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

class MyVlcItem
{
public:
  MyVlcItem();
  int length() const;

  std::string filename;
  int duration;
};

class MyVlcItems
{
public:
  typedef std::list<MyVlcItem> MyVlcItemList;
  void add(const char * fn, int duration);
  int total_len();
  bool empty() const;
  ACE_Message_Block * make_mb();

private:
  MyVlcItem * find(const char * fn);
  MyVlcItemList m_vlcs;
};

class MyVlcHistory
{
public:
  void items(MyVlcItems * _items);
  void process();

private:
  MyVlcItems * m_items;
};

class MyClientToDistHandler: public MyBaseHandler
{
public:
  MyClientToDistHandler(MyBaseConnectionManager * xptr = NULL);
  virtual int handle_timeout (const ACE_Time_Value &current_time, const void *act = 0);
  bool setup_timer();
  bool setup_heart_beat_timer(int heart_beat_interval);
  bool setup_click_send_timer();
  MyClientToDistModule * module_x() const;
  DECLARE_MEMORY_POOL__NOTHROW(MyClientToDistHandler, ACE_Thread_Mutex);

protected:
  virtual void on_close();
  virtual int  on_open();

private:
  enum { HEART_BEAT_PING_TIMER = 1, IP_VER_TIMER, CLICK_SEND_TIMER };
  enum { IP_VER_INTERVAL = 10 }; //in minutes

  long m_heart_beat_timer;
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
  enum { MSG_QUEUE_MAX_SIZE = 1 * 1024 * 1024 };

  void return_back(MyDistInfoFtp * dist_info);
  void return_back_md5(MyDistInfoMD5 * p);
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
  virtual ~MyClientToDistDispatcher();

  virtual int handle_timeout (const ACE_Time_Value &current_time, const void *act = 0);
  virtual const char * name() const;
  void ask_for_server_addr_list_done(bool success);
  void start_watch_dog();

protected:
  virtual void on_stop();
  virtual bool on_start();
  virtual bool on_event_loop();

private:
  enum { MSG_QUEUE_MAX_SIZE = 5 * 1024 * 1024 };
  enum { FTP_CHECK_INTERVAL = 1, WATCH_DOG_INTERVAL = 5 }; //in minutes
  enum { TIMER_ID_WATCH_DOG = 2 };

  void check_watch_dog();

  MyClientToDistConnector * m_connector;
  MyClientToMiddleConnector * m_middle_connector;
  MyHttp1991Acceptor * m_http1991_acceptor;
};


class MyClientToDistConnector: public MyBaseConnector
{
public:
  MyClientToDistConnector(MyBaseDispatcher * _dispatcher, MyBaseConnectionManager * _manager);
  virtual int make_svc_handler(MyBaseHandler *& sh);
  virtual const char * name() const;
  void dist_server_addr(const char * addr);
  time_t reset_last_connect_time();

protected:
  enum { RECONNECT_INTERVAL = 3 }; //time in minutes
  virtual bool before_reconnect();

private:
  time_t m_last_connect_time;
};

class MyHwAlarm
{
public:
  MyHwAlarm();
  void x(char _x);
  void y(char _y);

private:
  ACE_Message_Block * make_hardware_alarm_mb();

  char m_x;
  char m_y;
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
  ACE_Message_Block * get_click_infos(const char * client_id) const;
  ACE_Message_Block * get_vlc_infos(const char * client_id) const;
  bool click_sent() const;
  void click_sent_done(const char * client_id);
  MyWatchDog & watch_dog();
  MyIpVerReply & ip_ver_reply();

  MyTestClientIDGenerator & id_generator()
  {
    return m_id_generator;
  }

  MyHwAlarm lcd_alarm;
  MyHwAlarm led_alarm;
  MyHwAlarm temperature_alarm;
  MyHwAlarm door_alarm;

protected:
  virtual bool on_start();
  virtual void on_stop();

private:
  void check_prev_download_task();

  MyDistServerAddrList m_server_addr_list;
  MyClientToDistService * m_service;
  MyClientToDistDispatcher *m_dispatcher;
  MyDistInfoFtps m_dist_info_ftps;
  MyDistInfoMD5s m_dist_info_md5s;
  MyClientFtpService * m_client_ftp_service;

  MyClickInfos m_click_infos;
  bool m_click_sent;
  MyWatchDog m_watch_dog;
  MyIpVerReply m_ip_ver_reply;

  MyTestClientIDGenerator m_id_generator;
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
  enum { TIMER_OUT_TIMER = 1, TIME_OUT_INTERVAL = 5 };
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
  enum { RECONNECT_INTERVAL = 4 }; //time in minutes
  enum { MAX_CONNECT_RETRY_COUNT = 3 };
  int m_retried_count;
};


/////////////////////////////////////
//http 1991
/////////////////////////////////////

class MyHttp1991Processor: public MyBaseProcessor
{
public:
  typedef MyBaseProcessor super;
  enum { MAX_COMMAND_LINE_LENGTH = 2048 };

  MyHttp1991Processor(MyBaseHandler * handler);
  virtual ~MyHttp1991Processor();

  virtual int handle_input();

private:
  enum { CMD_WATCH_DOG, CMD_ADV_CLICK, CMD_PLC };

  void do_command_adv_click(char * parameter);
  void do_command_plc(char * parameter);
  void do_command_watch_dog();
  void send_string(const char * s);
  ACE_Message_Block * make_pc_on_off_mb(bool on, const char * sdata);

  ACE_Message_Block * m_mb;
};

class MyHttp1991Handler: public MyBaseHandler
{
public:
  MyHttp1991Handler(MyBaseConnectionManager * xptr = NULL);
};

class MyHttp1991Acceptor: public MyBaseAcceptor
{
public:
  enum { IDLE_TIME_AS_DEAD = 5 }; //in minutes
  MyHttp1991Acceptor(MyBaseDispatcher * _dispatcher, MyBaseConnectionManager * manager);
  virtual int make_svc_handler(MyBaseHandler *& sh);
  virtual const char * name() const;
};


#endif /* CLIENTMODULE_H_ */
