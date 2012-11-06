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

class CParentRunner;

class CCfg
{
public:
  enum CXYZStyle  { AM_BAD = 0, AM_HANDLEOUT = 1, AM_PRE = 2, AM_TERMINAL = 3 };

  CCfg();
  truefalse readall(CONST text *, CXYZStyle);
  DVOID print_all();
  truefalse handleout() CONST;
  truefalse pre() CONST;
  truefalse server() CONST;
  truefalse term_station() CONST;

  //all
  CXYZStyle  mode;
  truefalse enable_cache;
  truefalse run_at_back;
  ni  print_delay;
  ni  fcheck_delay;
  ni  num_log;
  ni  max_len_log; //mb
  truefalse verbose_log;
  truefalse window_also_log;
  ni rmt_hole;
  std::string data_dir;
  std::string execute_dir;
  std::string sfile_fn;
  std::string runner_dir;
  std::string log_fn;
  std::string cfg_fn;

  //s
  ni  term_peak;
  ni  server_hole;
  std::string skey;
  std::string db_ip;
  ni db_hole;
  std::string db_login;
  std::string db_key;
  std::string bz_files_path;
  std::string bs_ip;
  ni bs_hole;

  //cd
  ni ping_hole;
  std::string pre_ip;

  //cm
  ni pre_term_hole;

  //c
  ni term_ping_delay;
  ni download_concurrents;
  ni adv_keep_days;
  ni download_max_idle;
  ni download_again_num;
  ni download_again_sleep;
  ni can_su;

  //d
  CTermVer term_edition_min;
  CTermVer term_edition_now;
  u8 sid;

  //m
  ni web_hole;
  std::string download_servers;

private:
  truefalse read_handleout(CCfgHeap & , CCfgKey & );
  truefalse read_pre(CCfgHeap & , CCfgKey & );
  truefalse read_handleout_pre(CCfgHeap &, CCfgKey &);
  truefalse read_term_pre(CCfgHeap &, CCfgKey &);
  truefalse read_term_handleout(CCfgHeap &, CCfgKey &);
  truefalse read_base(CCfgHeap &, CCfgKey &);
  truefalse read_terminal(CCfgHeap &, CCfgKey &);
  DVOID do_init(CONST text *);
};

typedef ACE_Unmanaged_Singleton<CCfg, ACE_Null_Mutex> CCfgX;

class CSignaller: public ACE_Event_Handler
{
public:
  CSignaller(CParentRunner *);
  virtual ni handle_signal (ni signum, siginfo_t * = 0, ucontext_t * = 0);

private:
  CParentRunner * m_ptr;
};

class CNotificationFiler: public ACE_Event_Handler
{
public:
  CNotificationFiler(CParentRunner *);
  virtual ni handle_timeout (CONST CTV &, CONST DVOID * = 0);

private:
  CParentRunner * m_ptr;
};

class CPrinter: public ACE_Event_Handler
{
public:
  CPrinter(CParentRunner *);
  virtual ni handle_timeout (CONST CTV &, CONST DVOID * = 0);

private:
  CParentRunner * m_ptr;
};

class CClocker: public ACE_Event_Handler
{
public:
  virtual ni handle_timeout (CONST CTV &, CONST DVOID * = 0);
};

class CParentRunner
{
public:
  enum { CLOCK_TIME = 10 };
  CParentRunner();
  virtual ~CParentRunner();
  truefalse running() CONST;
  DVOID begin();
  DVOID end();
  DVOID print_info();
  DVOID init_log();
  SF DVOID put_to_back();
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
  truefalse m_working;
  CClocker m_clock;
  ACE_Sig_Handler m_sgh;
};

#endif
