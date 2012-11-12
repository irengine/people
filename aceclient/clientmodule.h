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
#include <sqlite3.h>

#include "tools.h"
#include "app.h"
#include "component.h"

class MyClientToDistModule;
class MyClientToDistConnector;
class MyDistInfoFtp;
class MyDistInfoFtps;
class MyHttp1991Acceptor;

const u_int8_t const_client_version_major = 1;
const u_int8_t const_client_version_minor = 2;

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
    CNumber client_id = m_id_list.back();
    ACE_OS::strsncpy(m_result, client_id.to_str(), BUFF_LEN);
    m_id_list.pop_back();
    return m_result;
  }
  void put(const char * id)
  {
    if (unlikely(!id || !*id))
      return;
    m_id_list.push_back(CNumber(id));
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
  typedef std::vector<CNumber> MyClientIDList;
  enum { BUFF_LEN = 32 };
  char  m_result[BUFF_LEN];
  MyClientIDList m_id_list;
};

class MyPL
{
public:
  MyPL();
  bool load(const char * client_id);
  bool save(const char * client_id, const char * s);
  int  value(int i);
  bool parse(char * s);
  static MyPL & instance();

private:
  ACE_Thread_Mutex m_mutex;
  int m_value[10];
};

class MyClickInfo
{
public:
  MyClickInfo();
  MyClickInfo(const char * chn, const char * pcode, const char * count, const char * _colname);

  std::string channel;
  std::string point_code;
  std::string click_count;
  std::string colname;
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
  bool save_click_info(const char * channel, const char * point_code, const char * col_name);
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
  friend class MyClientDBProt;
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

class MyClientDBProt
{
public:
  MyClientDBProt()
  {
    MyClientDB::m_mutex.acquire();
  }

  ~MyClientDBProt()
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
  enum { MAX_BUFSIZE = 4096 };
  bool recv();
  bool send(const char * command);
  bool is_response(const char * res_code);
  int  get_timeout_seconds() const;

  std::string        m_user_name;
  std::string        m_password;
  CMemProt   m_ftp_server_addr;
  ACE_INET_Addr      m_remote_addr;
  ACE_SOCK_Connector m_connector;
  ACE_SOCK_Stream    m_peer;
  CMemProt   m_response;
  MyDistInfoFtp *    m_ftp_info;
};

class MyDistInfoHeader
{
public:
  MyDistInfoHeader();
  virtual ~MyDistInfoHeader();
  void calc_target_parent_path(CMemProt & target_parent_path, bool extract_only, bool bv);
  bool calc_target_path(const char * target_parent_path, CMemProt & target_path);
  virtual bool validate();
  const char * index_file() const;
  bool need_spl() const;

  CMemProt dist_id;
  CMemProt findex;
  CMemProt adir;
  CMemProt aindex;
  char ftype;
  char type;
  CNumber client_id;
  int client_id_index;

protected:
  int load_header_init(char * src);
  bool calc_update_ini_value(CMemProt & value);
};

class MyDistInfoMD5: public MyDistInfoHeader
{
public:
  typedef MyDistInfoHeader super;

  MyDistInfoMD5();

  bool load_init(char * src);
  virtual bool validate();
  bool compare_done() const;
  void compare_done(bool done);
  CCheckSums & md5list();
  void post_md5_message();
  const char * md5_text() const;

private:
  CMemProt m_md5_text;
  CCheckSums m_md5list;
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
  static bool compute(MyDistInfoHeader * dist_info_header, CCheckSums & md5list);
  static void compare(MyDistInfoHeader * dist_info_header, CCheckSums & server_md5, CCheckSums & client_md5);
  static bool compute(MyDistInfoMD5 * dist_md5);
};

class MyDistInfoFtp: public MyDistInfoHeader
{
public:
  typedef MyDistInfoHeader super;
  enum { FAILED_PENALTY = 4, MAX_FAILED_COUNT = 40 };

  MyDistInfoFtp();

  virtual bool validate();
  bool load_init(char * src);
  time_t get_delay_penalty() const;
  bool should_ftp(time_t now) const;
  bool should_extract() const;
  void touch();
  void inc_failed(int steps = 1);
  int  failed_count() const;
  void calc_local_file_name();
  void post_status_message(int _status = -1) const;
  bool update_db_status() const;
  void generate_update_ini();
  void generate_url_ini();
  bool generate_dist_id_txt(const CMemProt & path);
  int  prio() const;
  bool operator < (const MyDistInfoFtp & rhs) const;

  static ACE_Message_Block * make_ftp_dist_message(const char * dist_id, int status, bool ok = true, char ftype = 'x');

  CMemProt file_name;
  CMemProt file_password;
  CMemProt ftp_password;
  CMemProt ftp_md5;
  CMemProt server_md5;
  CMemProt client_md5;

  int  status;
  time_t recv_time;
  CMemProt local_file_name;
  bool first_download;
  time_t last_update;

private:

  int  m_failed_count;
  int  m_prio;
};

class MyDistInfoFtps
{
public:
  typedef std::list<MyDistInfoFtp * > MyDistInfoFtpList;
  typedef MyDistInfoFtpList::iterator MyDistInfoFtpListPtr;

  MyDistInfoFtps();
  ~MyDistInfoFtps();

  void add(MyDistInfoFtp * p);
  int  status(const char * dist_id, const char * client_id);
  int  prio();
  MyDistInfoFtp * get();

private:
  ACE_Thread_Mutex m_mutex;
  MyDistInfoFtpList m_dist_info_ftps;
};

class MyDistFtpFileExtractor
{
public:
  MyDistFtpFileExtractor();

  bool extract(MyDistInfoFtp * dist_info);
  bool get_true_dest_path(MyDistInfoFtp * dist_info, CMemProt & target_path);
  static bool has_id(const CMemProt & target_parent_path);

private:
  bool do_extract(MyDistInfoFtp * dist_info, const CMemProt & target_parent_path);
  bool syn(MyDistInfoFtp * dist_info);
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

  void do_init(CMemProt & g, char * data, time_t t);
  void init_time_str(CMemProt & g, const char * s, const char c);
  const char * search(char * src);
  static void get_filename(CMemProt & fn);
  void save_to_file(const char * s);
  bool load_from_file();

  CMemProt m_pc;
  CMemProt m_pc_x;
  int m_heart_beat_interval;
  ACE_Thread_Mutex m_mutex;
  char m_tail;
  char m_now[24];
};

class MyClientToDistProcessor: public CParentClientProc
{
public:
  typedef CParentClientProc super;

  MyClientToDistProcessor(CParentHandler * handler);
  virtual const char * title() const;
  virtual CProc::OUTPUT at_head_arrival();
  virtual int at_start();
  int send_heart_beat();
  int send_ip_ver_req();

protected:
  virtual CProc::OUTPUT do_read_data(ACE_Message_Block * mb);

private:
  enum { OFFLINE_THREASH_HOLD = 20 }; //in seconds
  enum { MSG_QUEUE_MAX_SIZE = 2 * 1024 * 1024 };

  int send_version_check_req();
  CProc::OUTPUT do_ftp_file_request(ACE_Message_Block * mb);
  CProc::OUTPUT do_md5_list_request(ACE_Message_Block * mb);
  CProc::OUTPUT do_version_check_reply(ACE_Message_Block * mb);
  CProc::OUTPUT do_ip_ver_reply(ACE_Message_Block * mb);
  CProc::OUTPUT do_remote_cmd(ACE_Message_Block * mb);
  CProc::OUTPUT do_ack(ACE_Message_Block * mb);
  CProc::OUTPUT do_test(ACE_Message_Block * mb);
  CProc::OUTPUT do_psp(ACE_Message_Block * mb);
  CProc::OUTPUT do_pl(ACE_Message_Block * mb);
  void check_offline_report();
  bool check_vlc_empty();

  bool m_version_check_reply_done;
  CMemProt m_ftp_password;
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
  const char * rnd();
  bool empty_ftp();

  void save();
  void load();

  static bool has_cache();

private:
  static void get_file_name(CMemProt & file_name);
  bool valid_addr(const char * addr) const;

  std::vector<std::string> m_server_addrs;
  std::vector<std::string> m_ftp_addrs;
  ACE_Thread_Mutex m_mutex;
  CMemProt m_addr_list;
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
  int  total_len();
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

class MyClientToDistHandler: public CParentHandler
{
public:
  MyClientToDistHandler(CHandlerDirector * xptr = NULL);
  virtual int handle_timeout (const ACE_Time_Value &current_time, const void *act = 0);
  bool setup_timer();
  bool setup_heart_beat_timer(int heart_beat_interval);
  bool setup_click_send_timer();
  MyClientToDistModule * module_x() const;
  xx_enable_cache_easy(MyClientToDistHandler, ACE_Thread_Mutex);

protected:
  virtual void at_finish();
  virtual int  at_start();

private:
  enum { HEART_BEAT_PING_TIMER = 1, IP_VER_TIMER, CLICK_SEND_TIMER, HEART_BEAT_PING_TMP_TIMER };
  enum { IP_VER_INTERVAL = 10, HEART_BEAT_PING_TMP_INTERVAL = 3 }; //in minutes

  long m_heart_beat_timer;
  long m_heart_beat_tmp_timer;
};

class MyClientToDistService: public CTaskBase
{
public:
  MyClientToDistService(CContainer * module, int numThreads = 1);
  virtual int svc();
  virtual const char * title() const;
  bool add_md5_task(MyDistInfoMD5 * p);
  bool add_extract_task(MyDistInfoFtp * p);
  bool add_rev_task(const char * p);

private:
  enum { TASK_MD5, TASK_EXTRACT, TASK_REV };
  enum { MSG_QUEUE_MAX_SIZE = 1 * 1024 * 1024 };

  void return_back(MyDistInfoFtp * dist_info);
  void return_back_md5(MyDistInfoMD5 * p);
  void do_md5_task(MyDistInfoMD5 * p);
  void do_extract_task(MyDistInfoFtp * p);
  void do_rev_task(const char * p);
};

class MyClientFtpService: public CTaskBase
{
public:
  MyClientFtpService(CContainer * module, int numThreads = 1);
  virtual int svc();
  virtual const char * title() const;
  bool add_ftp_task(MyDistInfoFtp * p);

private:
  enum { TASK_FTP = 1 };

  void do_ftp_task(MyDistInfoFtp * dist_info, std::string & server_addr, int & failed_count);
  bool do_ftp_download(MyDistInfoFtp * dist_info, const char * server_ip);

  void return_back(MyDistInfoFtp * dist_info);
  MyDistInfoFtp * get_dist_info_ftp(ACE_Message_Block * mb) const;
};


class MyClientToMiddleConnector;

class MyBufferedMB
{
public:
  MyBufferedMB(ACE_Message_Block * mb);
  ~MyBufferedMB();
  ACE_Message_Block * mb();
  bool timeout(time_t t) const;
  void touch(time_t t);
  bool match(uuid_t uuid);

private:
  enum { TIME_OUT_VALUE = 10 * 60 };
  ACE_Message_Block * m_mb;
  time_t m_last;
};

class MyBufferedMBs
{
public:
  MyBufferedMBs();
  ~MyBufferedMBs();
  void connection_manager(CHandlerDirector * p);
  void add(ACE_Message_Block * mb);
  void check_timeout();
  void on_reply(uuid_t uuid);

private:
  typedef std::list<MyBufferedMB *> MyBufferedMBList;

  CHandlerDirector * m_con_manager;
  MyBufferedMBList m_mblist;
};

class MyClientToDistDispatcher: public CParentScheduler
{
public:
  MyClientToDistDispatcher(CContainer * pModule, int numThreads = 1);
  virtual ~MyClientToDistDispatcher();

  virtual int handle_timeout (const ACE_Time_Value &current_time, const void *act = 0);
  virtual const char * title() const;
  void ask_for_server_addr_list_done(bool success);
  void start_watch_dog();
  void on_ack(uuid_t uuid);
  void add_to_buffered_mbs(ACE_Message_Block * mb);

protected:
  virtual void before_finish();
  virtual bool before_begin();
  virtual bool do_schedule_work();

private:
  enum { MSG_QUEUE_MAX_SIZE = 5 * 1024 * 1024 };
  enum { FTP_CHECK_INTERVAL = 1, WATCH_DOG_INTERVAL = 5 }; //in minutes
  enum { TIMER_ID_WATCH_DOG = 2 };

  void check_watch_dog();

  MyClientToDistConnector * m_connector;
  MyClientToMiddleConnector * m_middle_connector;
  MyHttp1991Acceptor * m_http1991_acceptor;
  MyBufferedMBs m_buffered_mbs;
};


class MyClientToDistConnector: public CParentConn
{
public:
  MyClientToDistConnector(CParentScheduler * _dispatcher, CHandlerDirector * _manager);
  virtual int make_svc_handler(CParentHandler *& sh);
  virtual const char * title() const;
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

class MyClientToDistModule: public CContainer
{
public:
  MyClientToDistModule(CParentRunner * app);
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
  virtual const char * title() const;
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
  const char * hw_ver();

  MyTestClientIDGenerator & id_generator()
  {
    return m_id_generator;
  }

  MyHwAlarm lcd_alarm;
  MyHwAlarm led_alarm;
  MyHwAlarm temperature_alarm;
  MyHwAlarm door_alarm;

protected:
  virtual bool before_begin();
  virtual void before_finish();

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
  std::string m_hw_ver;

  MyTestClientIDGenerator m_id_generator;
};

/////////////////////////////////////
//client to middle
/////////////////////////////////////

class MyClientToMiddleProcessor: public CParentClientProc
{
public:
  typedef CParentClientProc super;

  MyClientToMiddleProcessor(CParentHandler * handler);
  virtual const char * title() const;
  virtual CProc::OUTPUT at_head_arrival();
  virtual int at_start();

protected:
  virtual CProc::OUTPUT do_read_data(ACE_Message_Block * mb);

private:
  int  send_version_check_req();
  void do_version_check_reply(ACE_Message_Block * mb);
  void do_handle_server_list(ACE_Message_Block * mb);
};

class MyClientToMiddleHandler: public CParentHandler
{
public:
  MyClientToMiddleHandler(CHandlerDirector * xptr = NULL);
  MyClientToDistModule * module_x() const;
  int handle_timeout(const ACE_Time_Value &current_time, const void *act);
  xx_enable_cache_easy(MyClientToMiddleHandler, ACE_Thread_Mutex);

protected:
  virtual void at_finish();
  virtual int  at_start();

private:
  enum { TIMER_OUT_TIMER = 1, TIME_OUT_INTERVAL = 5 };
  void setup_timer();

  long m_timer_out_timer_id;
};

class MyClientToMiddleConnector: public CParentConn
{
public:
  MyClientToMiddleConnector(CParentScheduler * _dispatcher, CHandlerDirector * _manager);
  virtual int make_svc_handler(CParentHandler *& sh);
  virtual const char * title() const;
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

class MyHttp1991Processor: public CProc
{
public:
  typedef CProc super;
  enum { MAX_COMMAND_LINE_LENGTH = 2048 };

  MyHttp1991Processor(CParentHandler * handler);
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

class MyHttp1991Handler: public CParentHandler
{
public:
  MyHttp1991Handler(CHandlerDirector * xptr = NULL);
};

class MyHttp1991Acceptor: public CParentAcc
{
public:
  enum { IDLE_TIME_AS_DEAD = 5 }; //in minutes
  MyHttp1991Acceptor(CParentScheduler * _dispatcher, CHandlerDirector * manager);
  virtual int make_svc_handler(CParentHandler *& sh);
  virtual const char * title() const;
};


#endif /* CLIENTMODULE_H_ */
