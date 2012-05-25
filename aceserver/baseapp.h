/*
 * serverapp.h
 *
 *  Created on: Dec 28, 2011
 *      Author: root
 */

#ifndef SERVERAPP_H_
#define SERVERAPP_H_

#include <ace/Singleton.h>
#include <string>
#include <ace/Configuration_Import_Export.h>
#include "common.h"
#include "basemodule.h"


extern const ACE_TCHAR * const_app_version;
extern long g_clock_tick;
extern bool g_test_mode;

class MyBaseApp;

class MyConfig
{
public:
  enum RUNNING_MODE
  {
    RM_UNKNOWN = 0,
    RM_DIST_SERVER = 1,
    RM_MIDDLE_SERVER = 2,
    RM_CLIENT = 3
  };

  MyConfig();
  bool load_config(const char * app_home_path, RUNNING_MODE mode);
  void dump_config_info();
  bool is_server() const;
  bool is_client() const;
  bool is_dist_server() const;
  bool is_middle_server() const;


  //common configuration
  RUNNING_MODE  running_mode;

  bool use_mem_pool;
  bool run_as_demon;
  int  mem_pool_dump_interval;
  int  status_file_check_interval;
  int  message_control_block_mem_pool_size;

  int  log_file_number;
  int  log_file_size_in_MB;
  bool log_debug_enabled;
  bool log_to_stderr;

  int remote_access_port;

  //dist and middle server
  int  max_clients;
  int  middle_server_dist_port;
  std::string middle_server_key;
  std::string db_server_addr;
  int db_server_port;
  std::string db_user_name;
  std::string db_password;
  std::string compressed_store_path;
  std::string bs_server_addr;
  int bs_server_port;

  //client an dist
  int dist_server_heart_beat_port;
  std::string middle_server_addr;

  //client and middle
  int middle_server_client_port;

  //client only
  int client_heart_beat_interval;
  int test_client_ftp_thread_number;
  int adv_expire_days;
  int client_ftp_timeout;
  int client_ftp_retry_count;
  int client_ftp_retry_interval;
  int client_enable_root;

  //dist only
  int module_heart_beat_mem_pool_size;
  MyClientVerson client_version_minimum;
  MyClientVerson client_version_current;
  u_int8_t server_id;

  //middle only
  int http_port;
  std::string ftp_addr_list;

  //common paths
  std::string exe_path;
  std::string status_file_name;
  std::string log_file_name;
  std::string config_file_name;
  std::string app_path;
  std::string app_data_path;

private:
  void init_path(const char * app_home_path);
  bool load_config_common(ACE_Configuration_Heap & cfgHeap, ACE_Configuration_Section_Key & section);
  bool load_config_client(ACE_Configuration_Heap & cfgHeap, ACE_Configuration_Section_Key & section);
  bool load_config_dist(ACE_Configuration_Heap & cfgHeap, ACE_Configuration_Section_Key & section);
  bool load_config_middle(ACE_Configuration_Heap & cfgHeap, ACE_Configuration_Section_Key & section);
  bool load_config_dist_middle(ACE_Configuration_Heap & cfgHeap, ACE_Configuration_Section_Key & section);
  bool load_config_client_middle(ACE_Configuration_Heap & cfgHeap, ACE_Configuration_Section_Key & section);
  bool load_config_client_dist(ACE_Configuration_Heap & cfgHeap, ACE_Configuration_Section_Key & section);
};

typedef ACE_Unmanaged_Singleton<MyConfig, ACE_Null_Mutex> MyConfigX;

class MySigHandler: public ACE_Event_Handler
{
public:
  MySigHandler(MyBaseApp * app);
  virtual int handle_signal (int signum,
                             siginfo_t * = 0,
                             ucontext_t * = 0);
private:
  MyBaseApp * m_app;
};

class MyStatusFileChecker: public ACE_Event_Handler
{
public:
  MyStatusFileChecker(MyBaseApp * app);
  virtual int handle_timeout (const ACE_Time_Value &current_time, const void *act = 0);

private:
  MyBaseApp * m_app;
};

class MyInfoDumper: public ACE_Event_Handler
{
public:
  MyInfoDumper(MyBaseApp * app);
  virtual int handle_timeout (const ACE_Time_Value &current_time, const void *act = 0);

private:
  MyBaseApp * m_app;
};

class MyClock: public ACE_Event_Handler
{
public:
  virtual int handle_timeout (const ACE_Time_Value &current_time, const void *act = 0);

private:
  MyBaseApp * m_app;
};


class MyBaseApp
{
public:
  enum { CLOCK_INTERVAL = 10 };
  MyBaseApp();
  virtual ~MyBaseApp();

  bool running() const;

  static void app_demonize();

  void init_log();

  void start();
  void stop();
  void dump_info();
  static void mem_pool_dump_one(const char * poolname, long nAlloc, long nFree, long nMaxUse, long nAllocFull, int block_size, int chunks);

protected:
  friend class MySigHandler;
  friend class MyStatusFileChecker;

  typedef std::vector<MyBaseModule *> MyModules;

  virtual void do_dump_info();
  virtual bool on_sigchild(pid_t pid);
  virtual bool on_event_loop();

  bool do_sigchild();
  void on_sig_event(int signum);
  void do_event_loop();
  bool do_sighup();
  void on_status_file_missing();
  bool do_constructor();
  void add_module(MyBaseModule * module);

  virtual bool on_start();
  virtual bool on_construct();
  virtual void on_stop();

  MyModules m_modules;
private:

  MySigHandler m_sig_handler;
  ACE_Sig_Handler m_ace_sig_handler;
  MyStatusFileChecker m_status_file_checker;
  MyInfoDumper m_info_dumper;
  MyClock m_clock;
  bool m_is_running;
  bool m_sighup;
  bool m_sigchld;
  bool m_sigterm;
  bool m_status_file_ok;
  bool m_status_file_checking;
};

#endif /* SERVERAPP_H_ */
