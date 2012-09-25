#ifndef APP_H_djkakifu33laf
#define APP_H_djkakifu33laf

#include <ace/Singleton.h>
#include <string>
#include <ace/Configuration_Import_Export.h>
#include "tools.h"
#include "component.h"


EXTERN truefalse g_is_test;
EXTERN long g_clock_counter;
EXTERN CONST text * g_CONST_app_ver;

typedef ACE_Configuration_Heap CCfgHeap;
typedef ACE_Configuration_Section_Key CCfgKey;

std::string current_ver();

class CApp;

class CCfg
{
public:
  enum CAppMode
  {
    AM_UNKNOWN = 0,
    AM_DIST_SERVER = 1,
    AM_MIDDLE_SERVER = 2,
    AM_CLIENT = 3
  };

  CCfg();
  truefalse readall(CONST text * home_dir, CAppMode mode);
  DVOID print_all();
  truefalse is_dist() CONST;
  truefalse is_middle() CONST;
  truefalse is_server() CONST;
  truefalse is_client() CONST;

  //common
  CAppMode  app_mode;

  truefalse use_mem_pool;
  truefalse as_demon;
  ni  mem_dump_interval;
  ni  file_check_interval;

  ni  log_file_count;
  ni  log_file_size; //megabytes
  truefalse log_debug;
  truefalse log_stderr;

  ni remote_port;

  //server
  ni  max_client_count;
  ni  middle_server_dist_port;
  std::string skey;
  std::string db_addr;
  ni db_port;
  std::string db_name;
  std::string db_password;
  std::string bz_files_path;
  std::string bs_addr;
  ni bs_port;

  //client dist
  ni ping_port;
  std::string middle_addr;

  //client middle
  ni middle_server_client_port;

  //client
  ni client_ping_interval;
  ni test_client_download_thread_count;
  ni client_adv_expire_days;
  ni client_download_timeout;
  ni client_download_retry_count;
  ni client_download_retry_interval;
  ni client_can_root;

  //dist
  ni module_heart_beat_mem_pool_size;
  CClientVer client_ver_min;
  CClientVer client_ver_now;
  u8 dist_server_id;

  //middle
  ni http_port;
  std::string ftp_addr_list;

  //all paths
  std::string data_path;
  std::string exe_path;
  std::string status_fn;
  std::string app_path;
  std::string log_fn;
  std::string cfg_fn;

private:
  truefalse read_dist(CCfgHeap & , CCfgKey & );
  truefalse read_middle(CCfgHeap & , CCfgKey & );
  DVOID do_init(CONST text * app_home_path);
  truefalse read_dist_middle(CCfgHeap &, CCfgKey &);
  truefalse read_client_middle(CCfgHeap &, CCfgKey &);
  truefalse read_client_dist(CCfgHeap &, CCfgKey &);
  truefalse read_base(CCfgHeap &, CCfgKey &);
  truefalse read_client(CCfgHeap &, CCfgKey &);
};

typedef ACE_Unmanaged_Singleton<CCfg, ACE_Null_Mutex> CCfgX;

class CSignaller: public ACE_Event_Handler
{
public:
  CSignaller(CApp *);
  virtual ni handle_signal (ni signum, siginfo_t * = 0, ucontext_t * = 0);

private:
  CApp * m_parent;
};

class CNotificationFiler: public ACE_Event_Handler
{
public:
  CNotificationFiler(CApp *);
  virtual ni handle_timeout (CONST ACE_Time_Value &, CONST DVOID * = 0);

private:
  CApp * m_parent;
};

class CPrinter: public ACE_Event_Handler
{
public:
  CPrinter(CApp *);
  virtual ni handle_timeout (CONST ACE_Time_Value &, CONST DVOID * = 0);

private:
  CApp * m_parent;
};

class CClocker: public ACE_Event_Handler
{
public:
  virtual ni handle_timeout (CONST ACE_Time_Value &, CONST DVOID * = 0);
};

class CApp
{
public:
  enum { CLOCK_INTERVAL = 10 };
  CApp();
  virtual ~CApp();
  truefalse running() CONST;
  DVOID start();
  DVOID stop();
  DVOID print_info();
  DVOID init_log();
  SF DVOID demon();
  SF DVOID print_pool(CONST text * name_of_pool, long nAlloc, long nFree, long nMaxUse, long nAllocFull, ni block_size, ni chunks);

protected:
  friend class CSignaller;
  friend class CNotificationFiler;

  typedef std::vector<CMod *> CMods;

  virtual DVOID do_dump_info();
  virtual truefalse on_sigchild(pid_t);
  virtual truefalse on_event_loop();
  virtual truefalse on_start();
  virtual truefalse on_construct();
  virtual DVOID on_stop();

  truefalse do_sigchild();
  DVOID on_sig_event(ni);
  DVOID schedule_works();
  truefalse do_sighup();
  DVOID on_status_file_missing();
  truefalse delayed_init();
  DVOID add_module(CMod *);

  CMods m_modules;
private:

  CSignaller m_sig_handler;
  ACE_Sig_Handler m_ace_sig_handler;
  CNotificationFiler m_status_file_checker;
  CPrinter m_printer;
  CClocker m_clock;
  truefalse m_running;
  truefalse m_sighup;
  truefalse m_sigchld;
  truefalse m_sigterm;
  truefalse m_status_file_ok;
  truefalse m_status_file_check;
};

#endif /* SERVERAPP_H_ */
