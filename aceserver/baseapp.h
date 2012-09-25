#ifndef SERVERAPP_H_
#define SERVERAPP_H_

#include <ace/Singleton.h>
#include <string>
#include <ace/Configuration_Import_Export.h>
#include "basemodule.h"


extern const char * g_const_app_ver;
extern long g_clock_counter;
extern bool g_is_test;
std::string current_ver();

class CApp;

class CCfg
{
public:
  enum RUNNING_MODE
  {
    RM_UNKNOWN = 0,
    RM_DIST_SERVER = 1,
    RM_MIDDLE_SERVER = 2,
    RM_CLIENT = 3
  };

  CCfg();
  bool readall(const char * home_dir, RUNNING_MODE mode);
  void print_all();
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
  bool read_base(ACE_Configuration_Heap & cfgHeap, ACE_Configuration_Section_Key & section);
  bool read_client(ACE_Configuration_Heap & cfgHeap, ACE_Configuration_Section_Key & section);
  bool read_dist(ACE_Configuration_Heap & cfgHeap, ACE_Configuration_Section_Key & section);
  bool read_middle(ACE_Configuration_Heap & cfgHeap, ACE_Configuration_Section_Key & section);
  bool read_dist_middle(ACE_Configuration_Heap & cfgHeap, ACE_Configuration_Section_Key & section);
  bool read_client_middle(ACE_Configuration_Heap & cfgHeap, ACE_Configuration_Section_Key & section);
  bool read_client_dist(ACE_Configuration_Heap & cfgHeap, ACE_Configuration_Section_Key & section);
};

typedef ACE_Unmanaged_Singleton<CCfg, ACE_Null_Mutex> CCfgX;

class CSignaller: public ACE_Event_Handler
{
public:
  CSignaller(CApp * app);
  virtual int handle_signal (int signum,
                             siginfo_t * = 0,
                             ucontext_t * = 0);
private:
  CApp * m_app;
};

class CNotificationFiler: public ACE_Event_Handler
{
public:
  CNotificationFiler(CApp * app);
  virtual int handle_timeout (const ACE_Time_Value &current_time, const void *act = 0);

private:
  CApp * m_app;
};

class CPrinter: public ACE_Event_Handler
{
public:
  CPrinter(CApp * app);
  virtual int handle_timeout (const ACE_Time_Value &current_time, const void *act = 0);

private:
  CApp * m_app;
};

class CClocker: public ACE_Event_Handler
{
public:
  virtual int handle_timeout (const ACE_Time_Value &current_time, const void *act = 0);

private:
  CApp * m_app;
};

class CApp
{
public:
  enum { CLOCK_INTERVAL = 10 };
  CApp();
  virtual ~CApp();

  bool running() const;
  void init_log();
  void start();
  void stop();
  void print_info();

  static void demon();
  static void print_pool_one(const char * poolname, long nAlloc, long nFree, long nMaxUse, long nAllocFull, int block_size, int chunks);

protected:
  friend class CSignaller;
  friend class CNotificationFiler;

  typedef std::vector<CMod *> CMods;

  virtual void do_dump_info();
  virtual bool on_sigchild(pid_t pid);
  virtual bool on_event_loop();
  virtual bool on_start();
  virtual bool on_construct();
  virtual void on_stop();

  bool do_sigchild();
  void on_sig_event(int signum);
  void do_event_loop();
  bool do_sighup();
  void on_status_file_missing();
  bool do_constructor();
  void add_module(CMod * module);

  CMods m_modules;
private:

  CSignaller m_sig_handler;
  ACE_Sig_Handler m_ace_sig_handler;
  CNotificationFiler m_status_file_checker;
  CPrinter m_info_dumper;
  CClocker m_clock;
  bool m_is_running;
  bool m_sighup;
  bool m_sigchld;
  bool m_sigterm;
  bool m_status_file_ok;
  bool m_status_file_checking;
};

#endif /* SERVERAPP_H_ */
