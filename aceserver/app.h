#ifndef APP_H_djkakifu33laf
#define APP_H_djkakifu33laf

#include <ace/Singleton.h>
#include <ace/Configuration_Import_Export.h>

#include <string>

#include "tools.h"
#include "component.h"


EXTERN truefalse g_is_test;
EXTERN long g_clock_counter;
EXTERN CONST text * g_CONST_ver;

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
    AM_DIST = 1,
    AM_MIDDLE = 2,
    AM_CLIENT = 3
  };

  CCfg();
  truefalse readall(CONST text *, CAppMode);
  DVOID print_all();
  truefalse dist() CONST;
  truefalse middle() CONST;
  truefalse server() CONST;
  truefalse client() CONST;

  //all
  CAppMode  mode;
  truefalse mem_pool;
  truefalse is_demon;
  ni  print_delay;
  ni  fcheck_delay;
  ni  log_file_count;
  ni  log_file_size; //megabytes
  truefalse log_debug;
  truefalse log_console;
  ni remote_port;
  std::string data_path;
  std::string exe_path;
  std::string status_fn;
  std::string app_path;
  std::string log_fn;
  std::string cfg_fn;

  //server
  ni  client_peak;
  ni  server_port;
  std::string skey;
  std::string db_addr;
  ni db_port;
  std::string db_name;
  std::string db_password;
  std::string bz_files_path;
  std::string bs_addr;
  ni bs_port;

  //cd
  ni ping_port;
  std::string middle_addr;

  //cm
  ni pre_client_port;

  //c
  ni client_ping_interval;
  ni download_threads;
  ni adv_keep_days;
  ni download_timeout;
  ni download_retry_count;
  ni download_retry_delay;
  ni can_root;

  //d
  CTermVer client_ver_min;
  CTermVer client_ver_now;
  u8 server_id;

  //m
  ni http_port;
  std::string ftp_servers;

private:
  truefalse read_dist(CCfgHeap & , CCfgKey & );
  truefalse read_middle(CCfgHeap & , CCfgKey & );
  truefalse read_dist_middle(CCfgHeap &, CCfgKey &);
  truefalse read_client_middle(CCfgHeap &, CCfgKey &);
  truefalse read_client_dist(CCfgHeap &, CCfgKey &);
  truefalse read_base(CCfgHeap &, CCfgKey &);
  truefalse read_client(CCfgHeap &, CCfgKey &);
  DVOID do_init(CONST text * app_home_path);
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
  enum { CLOCK_TIME = 10 };
  CApp();
  virtual ~CApp();
  truefalse running() CONST;
  DVOID begin();
  DVOID end();
  DVOID print_info();
  DVOID init_log();
  SF DVOID demon();
  SF DVOID print_pool(CONST text * name_of_pool, long, long, long, long, ni, ni);

protected:
  friend class CSignaller;
  friend class CNotificationFiler;

  typedef std::vector<CContainer *> CMods;

  virtual truefalse before_begin();
  virtual truefalse do_init();
  virtual DVOID before_finish();
  virtual DVOID i_print();
  virtual truefalse do_singal_child(pid_t);
  virtual truefalse do_schedule_work();

  truefalse handle_signal_child();
  DVOID handle_signal(ni);
  DVOID schedule_works();
  truefalse handle_signal_up();
  DVOID handle_no_sfile();
  truefalse delayed_init();
  DVOID add_component(CContainer *);

  CMods m_components;

private:
  truefalse m_chld;
  truefalse m_term;
  truefalse m_hup;
  CSignaller m_sig;
  CNotificationFiler m_sfile;
  CPrinter m_printer;
  truefalse m_sfile_ok;
  truefalse m_sfile_check;
  truefalse m_running;
  CClocker m_clock;
  ACE_Sig_Handler m_sgh;
};

#endif
