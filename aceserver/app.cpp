#include <ace/streams.h>
#include <ace/Service_Config.h>
#include <ace/Logging_Strategy.h>
#include <cstdio>
#include "app.h"

CONST text * g_CONST_ver = "1.0";
long g_clock_counter = 0;
truefalse g_is_test = false;

CONST truefalse CONST_run_at_back = false;
CONST ni  CONST_term_peak = 9900;
CONST truefalse CONST_enable_cache = true;
CONST ni  CONST_print_delay = 30; //m
CONST ni  CONST_fcheck_delay = 3; //m
CONST ni  CONST_max_len_log = 20;
CONST ni  CONST_num_log = 3;
CONST truefalse CONST_window_also_log = true;
CONST truefalse CONST_verbose_log = true;

CONST ni  CONST_pre_term_hole = 2223;
CONST ni  CONST_server_hole = 2224;
CONST ni  CONST_download_concurrents = 50;
CONST ni  CONST_ping_delay = 60; //s
CONST ni  CONST_ping_hole = 2222;
CONST ni  CONST_db_hole = 5432;
CONST ni  CONST_bs_hole = 1921;
CONST ni  CONST_web_hole = 1922;
CONST ni  CONST_can_su = 0;
CONST ni  CONST_download_again_num = 30;
CONST ni  CONST_download_max_idle = 120;
CONST ni  CONST_download_again_sleep = 4;

//all
CONST text * TEXT_SDefault = "default";
CONST text * TEXT_style = "style";
CONST text * TEXT_fcheck_delay = "fcheck_delay";
CONST text * TEXT_enable_cache = "enable_cache";
CONST text * TEXT_print_delay = "print_delay";
CONST text * TEXT_test = "test_mode";
CONST text * TEXT_verbose_log = "verbose_log";
CONST text * TEXT_run_at_back = "run_at_back";
CONST text * TEXT_max_len_log = "max_len_log";
CONST text * TEXT_window_also_log = "window_also_log";
CONST text * TEXT_num_log = "num_log";
CONST text * TEXT_download_concurrents = "download_concurrents";

//s
CONST text * TEXT_term_peak = "term_peak";
CONST text * TEXT_skey = "skey";
CONST text * TEXT_server_hole = "pre.server_hole";
CONST text * TEXT_db_login = "db_login";
CONST text * TEXT_db_key = "db_key";
CONST text * TEXT_db_ip = "db_ip";
CONST text * TEXT_db_hole = "db_hole";
CONST text * TEXT_bz_files_path = "bz_files_dir";
CONST text * TEXT_bs_hole = "bs_hole";
CONST text * TEXT_bs_ip = "bs_ip";

//cd
CONST text *  TEXT_ping_hole = "ping_hole";
CONST text *  TEXT_pre_ip = "pre_ip";

//cm
CONST text *  TEXT_pre_term_hole = "pre_term_hole";

//m
CONST text *  TEXT_download_servers = "download_servers";
CONST text *  TEXT_web_hole = "web_hole";

//d
CONST text * TEXT_term_edition_min = "term_edition_min";
CONST text * TEXT_sid = "sid";
CONST text * TEXT_term_edition_now = "term_edition_now";

//c
CONST text * TEXT_can_su = "can_su";
CONST text * TEXT_term_ping_delay = "term_ping_delay";
CONST text * TEXT_download_again_num = "download_again_num";
CONST text * TEXT_download_again_sleep = "download_again_sleep";
CONST text * TEXT_download_max_idle = "download_max_idle";
CONST text * TEXT_adv_keep_days = "adv_keep_days";

CCfg::CCfg()
{
  verbose_log = CONST_verbose_log;
  num_log = CONST_num_log;
  max_len_log = CONST_max_len_log;
  window_also_log = CONST_window_also_log;

  print_delay = CONST_print_delay;
  fcheck_delay = CONST_fcheck_delay;
  rmt_hole = 0;
  mode = AM_BAD;
  enable_cache = CONST_enable_cache;
  run_at_back = CONST_run_at_back;

  //s
  db_hole = CONST_db_hole;
  bs_hole = CONST_bs_hole;
  term_peak = CONST_term_peak;
  server_hole = CONST_server_hole;

  //cd
  pre_term_hole = CONST_pre_term_hole;

  //d
  ping_hole = CONST_ping_hole;
  sid = 1;

  //c
  can_su = CONST_can_su;
  term_ping_delay = CONST_ping_delay;
  download_concurrents = CONST_download_concurrents;
  adv_keep_days = 0;
  download_again_num = CONST_download_again_num;
  download_again_sleep = CONST_download_again_sleep;
  download_max_idle = CONST_download_max_idle;

  //m
  web_hole = CONST_web_hole;
}

DVOID CCfg::do_init(CONST text * v_hdir)
{
  CONST size_t BUFF_SIZE = 4096;
  text l_dir[BUFF_SIZE];

  if (!v_hdir)
  {
    ssize_t l_m = readlink("/proc/self/exe", l_dir, BUFF_SIZE);
    if (l_m > 0 && l_m < ssize_t(BUFF_SIZE))
    {
      l_dir[l_m] = '\0';
      execute_dir = l_dir;
      size_t l_k = execute_dir.rfind('/');
      if (l_k == execute_dir.npos || l_k == 0)
      {
        std::printf("execute_dir (= %s) error\n", l_dir);
        exit(1);
      }
      execute_dir = execute_dir.substr(0, l_k);
      runner_dir = execute_dir;
      l_k = runner_dir.rfind('/', l_k);
      if (l_k == runner_dir.npos || l_k == 0)
      {
        std::printf("runner_dir (= %s) error\n", runner_dir.c_str());
        exit(2);
      }
      runner_dir = runner_dir.substr(0, l_k);
    } else
    {
      std::perror("readlink() failed\n");
      exit(3);
    }
  } else
  {
    runner_dir = v_hdir;
    execute_dir = runner_dir + "/bin";
  }

  sfile_fn = runner_dir + "/running/run.pid";
  log_fn = runner_dir + "/log/run.log";
  cfg_fn = runner_dir + "/config/run.conf";
  data_dir = runner_dir + "/data";
}

truefalse CCfg::server() CONST
{
  return mode != AM_TERMINAL;
}

truefalse CCfg::term_station() CONST
{
  return mode == AM_TERMINAL;
}

truefalse CCfg::handleout() CONST
{
  return mode == AM_HANDLEOUT;
}

truefalse CCfg::pre() CONST
{
  return mode == AM_PRE;
}

truefalse CCfg::readall(CONST text * h_path, CXYZStyle m)
{
  do_init(h_path);

  mode = m;
  CCfgHeap v_hp;
  if (v_hp.open () == -1)
  {
    C_FATAL("heap.open().\n");
    return false;
  }

  ACE_Registry_ImpExp bridge(v_hp);
  if (bridge.import_config (cfg_fn.c_str()) == -1)
  {
    C_FATAL("import_config() failed on %s\n", cfg_fn.c_str());
    return false;
  }

  CCfgKey akey;
  if (v_hp.open_section (v_hp.root_section (), TEXT_SDefault,
                           0, akey) == -1)
  {
    C_FATAL("config.open_key failed, key = %s\n", TEXT_SDefault);
    return false;
  }

  if (!read_base(v_hp, akey))
    return false;

  if (mode <= AM_BAD || mode > AM_TERMINAL)
  {
    C_FATAL("bad mode (= %d)", mode);
    return false;
  }

  if (!read_handleout_pre(v_hp, akey))
    return false;

  if (!read_term_pre(v_hp, akey))
    return false;

  if (!read_term_handleout(v_hp, akey))
    return false;

  if (!read_handleout(v_hp, akey))
    return false;

  if (!read_pre(v_hp, akey))
    return false;

  if (!read_terminal(v_hp, akey))
    return false;

  return true;
}

truefalse CCfg::read_base(CCfgHeap & v_h, CCfgKey & v_k)
{
  ui n;
  if (mode == AM_BAD)
  {
    if (v_h.get_integer_value (v_k,  TEXT_style, n) == 0)
    {
      if (n != AM_HANDLEOUT && n != AM_PRE)
      {
        C_FATAL("bad style = %d\n", n);
        return false;
      }
      mode = CXYZStyle(n);
    } else
    {
      C_FATAL("can not read style\n");
      return false;
    }
  }

  if (v_h.get_integer_value (v_k,  TEXT_test, n) == 0)
    g_is_test = (n != 0);

  if (v_h.get_integer_value (v_k,  TEXT_enable_cache, n) == 0)
  {
    enable_cache = (n != 0);
    g_cache = enable_cache;
  }

  if (v_h.get_integer_value (v_k,  TEXT_run_at_back, n) == 0)
    run_at_back = (n != 0);

  if (v_h.get_integer_value (v_k,  TEXT_fcheck_delay, n) == 0)
    fcheck_delay = n;

  if (v_h.get_integer_value (v_k,  TEXT_num_log, n) == 0)
  {
    if (n > 0 && n <= 1000)
      num_log = n;
  }

  if (v_h.get_integer_value (v_k,  TEXT_max_len_log, n) == 0)
  {
    if (n > 0 && n <= 10000)
      max_len_log = n;
  }

  if (v_h.get_integer_value (v_k,  TEXT_verbose_log, n) == 0)
    verbose_log = (n != 0);

  if (v_h.get_integer_value (v_k,  TEXT_window_also_log, n) == 0)
    window_also_log = (n != 0);

  if (v_h.get_integer_value (v_k,  TEXT_print_delay, n) == 0)
    print_delay = n;

  return true;
}

truefalse CCfg::read_handleout_pre(CCfgHeap & v_h, CCfgKey & v_k)
{
  if (!server())
    return true;

  ui n;
  if (v_h.get_integer_value (v_k,  TEXT_term_peak, n) == 0)
  {
    if (n > 0 && n <= 100000)
    {
      term_peak = n;
    }
  }

  ACE_TString s;
  if (v_h.get_string_value(v_k, TEXT_skey, s) == 0)
    skey = s.c_str();
  else
  {
    C_ERROR("fail to read cfg value %s\n", TEXT_skey);
    return false;
  }

  if (v_h.get_integer_value (v_k,  TEXT_server_hole, n) == 0)
  {
    if (n == 0 || n >= 65535)
    {
      C_ERROR("bad cfg value %s (= %d)\n", TEXT_server_hole, n);
      return false;
    }
    server_hole = n;
  }

  if (v_h.get_string_value(v_k, TEXT_db_ip, s) == 0)
    db_ip = s.c_str();
  else
  {
    C_ERROR("can not read cfg value %s\n", TEXT_db_ip);
    return false;
  }

  if (v_h.get_integer_value (v_k,  TEXT_db_hole, n) == 0)
  {
    if (n == 0 || n >= 65535)
    {
      C_ERROR("bad cfg value %s (= %d)\n", TEXT_db_hole, n);
      return false;
    }
    db_hole = n;
  }

  if (v_h.get_string_value(v_k, TEXT_db_login, s) == 0)
    db_login = s.c_str();
  else
  {
    C_ERROR("fail to read cfg value %s\n", TEXT_db_login);
    return false;
  }

  if (v_h.get_string_value(v_k, TEXT_db_key, s) == 0)
    db_key = s.c_str();
  else
  {
    C_ERROR("fail to read cfg value %s\n", TEXT_db_key);
    return false;
  }

  if (v_h.get_string_value(v_k, TEXT_bz_files_path, s) == 0)
    bz_files_path = s.c_str();
  else
  {
    C_ERROR("fail to read cfg value %s\n", TEXT_bz_files_path);
    return false;
  }

  if (v_h.get_string_value(v_k, TEXT_bs_ip, s) == 0)
    bs_ip = s.c_str();
  else
  {
    C_ERROR("fail to read cfg value %s\n", TEXT_bs_ip);
    return false;
  }

  if (v_h.get_integer_value(v_k, TEXT_bs_hole, n) == 0)
  {
    if (n == 0 || n >= 65535)
    {
      C_ERROR("bad config value %s (= %d)\n", TEXT_bs_hole, n);
      return false;
    }
    bs_hole = n;
  }

  return true;
}

truefalse CCfg::read_terminal(CCfgHeap & v_h, CCfgKey & v_k)
{
  if (server())
    return true;

  ui n;
  if (g_is_test)
  {
    if (v_h.get_integer_value(v_k, TEXT_term_ping_delay, n) == 0)
    {
      if (n == 0 || n > 0xFFFF)
      {
        C_WARNING("bad %s value (= %d), resort to default = %d\n",
            TEXT_term_ping_delay, n, CONST_ping_delay);
      }
      else
        term_ping_delay = n;
    }
  }

  if (g_is_test)
  {
    if (v_h.get_integer_value(v_k, TEXT_download_concurrents, n) == 0)
    {
      if (n == 0 || n > 500)
      {
        C_WARNING("bad %s value (= %d), resort to default = %d\n",
            TEXT_download_concurrents, n, CONST_download_concurrents);
      }
      else
        download_concurrents = n;
    }
  }

  if (v_h.get_integer_value(v_k, TEXT_adv_keep_days, n) == 0)
  {
    if (n > 365)
    {
      C_WARNING("bad %s value (%d), resort to default = %d\n",
          TEXT_adv_keep_days, n, 0);
    }
    else
      adv_keep_days = n;
  }

  if (v_h.get_integer_value(v_k, TEXT_download_max_idle, n) == 0)
  {
    if (n < 60)
    {
      C_WARNING("bad %s value (%d), resort to default = %d\n",
          TEXT_download_max_idle, n, CONST_download_max_idle);
    }
    else
      download_max_idle = n;
  }

  if (v_h.get_integer_value(v_k, TEXT_download_again_num, n) == 0)
  {
    if (n < 1 || n > 100000)
    {
      C_WARNING("bad %s value (%d), resort to default = %d\n",
          TEXT_download_again_num, n, CONST_download_again_num);
    }
    else
      download_again_num = n;
  }

  if (v_h.get_integer_value(v_k, TEXT_download_again_sleep, n) == 0)
  {
    if (n < 1 || n > 60)
    {
      C_WARNING("bad %s value (%d), resort to default = %d\n",
          TEXT_download_again_sleep, n, CONST_download_again_sleep);
    }
    else
      download_again_sleep = n;
  }

  if (v_h.get_integer_value(v_k, TEXT_can_su, n) == 0)
    can_su = n;

  return true;
}

truefalse CCfg::read_handleout(CCfgHeap & v_h, CCfgKey & v_k)
{
  if (!handleout())
    return true;

  ui n;
  if (v_h.get_integer_value(v_k, TEXT_sid, n) == 0)
  {
    if (n <= 1 || n >= 256)
    {
      C_ERROR("bad config value %s: %d\n", TEXT_sid, n);
      return false;
    }
    sid = (u_int8_t)n;
  }
  else
  {
    C_ERROR("fail to read cfg value %s\n", TEXT_sid);
    return false;
  }

  ACE_TString s;
  if (v_h.get_string_value(v_k, TEXT_term_edition_min, s) == 0)
  {
    if (!term_edition_min.init(s.c_str()))
    {
      C_ERROR("bad config value %s: %s\n", TEXT_term_edition_min, s.c_str());
      return false;
    }
  }
  else
  {
    C_ERROR("fail to read cfg value %s\n", TEXT_term_edition_min);
    return false;
  }

  if (v_h.get_string_value(v_k, TEXT_term_edition_now, s) == 0)
  {
    if (!term_edition_now.init(s.c_str()))
    {
      C_ERROR("bad config value %s: %s\n", TEXT_term_edition_now, s.c_str());
      return false;
    }
  }
  else
  {
    C_ERROR("fail to read cfg value %s\n", TEXT_term_edition_now);
    return false;
  }

  if (term_edition_now < term_edition_min)
  {
    C_ERROR("bad config value %s(%s) < %s(%s)\n",
        TEXT_term_edition_now, term_edition_now.to_text(),
        TEXT_term_edition_min, term_edition_min.to_text());
    return false;
  }

  return true;
}

truefalse CCfg::read_pre(CCfgHeap & v_h, CCfgKey & v_k)
{
  if (!pre())
    return true;

  ui n;
  if (v_h.get_integer_value (v_k,  TEXT_web_hole, n) == 0)
  {
    if (n == 0 || n >= 65535)
    {
      C_ERROR("bad config value %s (= %d)\n", TEXT_web_hole, n);
      return false;
    }
    web_hole = n;
  }

  ACE_TString s;
  if (v_h.get_string_value(v_k, TEXT_download_servers, s) == 0)
    download_servers = s.c_str();
  else
  {
    C_ERROR("fail to read cfg value %s\n", TEXT_download_servers);
    return false;
  }

  return true;
}

truefalse CCfg::read_term_pre(CCfgHeap & v_h, CCfgKey & v_k)
{
  if (handleout())
    return true;

  ui n;
  if (v_h.get_integer_value (v_k,  TEXT_pre_term_hole, n) == 0)
  {
    if (n == 0 || n >= 65535)
    {
      C_ERROR("bad config value %s (= %d)\n", TEXT_pre_term_hole, n);
      return false;
    }
    pre_term_hole = n;
  }

  return true;
}

truefalse CCfg::read_term_handleout(CCfgHeap & v_h, CCfgKey & v_k)
{
  if (pre())
    return true;

  ui n;
  if (v_h.get_integer_value (v_k, TEXT_ping_hole, n) == 0)
  {
    if (n == 0 || n >= 65535)
    {
      C_ERROR("bad config value %s (= %d)\n", TEXT_ping_hole, n);
      return false;
    }
    ping_hole = n;
  }

  ACE_TString s;
  if (v_h.get_string_value(v_k, TEXT_pre_ip, s) == 0)
    pre_ip = s.c_str();
  else
  {
    C_ERROR("fail to read cfg value %s\n", TEXT_pre_ip);
    return false;
  }

  return true;
}

DVOID CCfg::print_all()
{
  C_INFO("read cfg:\n");

  CONST text * smode;
  switch (mode)
  {
  case AM_HANDLEOUT:
    smode = "handleout";
    break;
  case AM_PRE:
    smode = "pre";
    break;
  case AM_TERMINAL:
    smode = "terminal";
    break;
  default:
    C_FATAL("bad mode (=%d).\n", mode);
    exit(10);
  }
  ACE_DEBUG ((LM_INFO, "\t%s = %s\n", TEXT_style, smode));

  ACE_DEBUG ((LM_INFO, "\t%s = %d\n", TEXT_run_at_back, run_at_back));
  ACE_DEBUG ((LM_INFO, "\t%s = %d\n", TEXT_enable_cache, enable_cache));
  ACE_DEBUG ((LM_INFO, "\t%s = %d\n", TEXT_print_delay, print_delay));
  ACE_DEBUG ((LM_INFO, "\t%s = %d\n", TEXT_fcheck_delay, fcheck_delay));

  ACE_DEBUG ((LM_INFO, "\t%s = %d\n", TEXT_num_log, num_log));
  ACE_DEBUG ((LM_INFO, "\t%s = %d\n", TEXT_max_len_log, max_len_log));
  ACE_DEBUG ((LM_INFO, "\t%s = %d\n", TEXT_verbose_log, verbose_log));
  ACE_DEBUG ((LM_INFO, "\t%s = %d\n", TEXT_window_also_log, window_also_log));

  if (g_is_test)
    ACE_DEBUG ((LM_INFO, "\ttest_mode = 1\n"));
  else
    ACE_DEBUG ((LM_INFO, "\ttest_mode = 0\n"));

  if (server())
  {
    ACE_DEBUG ((LM_INFO, "\t%s = %d\n", TEXT_term_peak, term_peak));
    ACE_DEBUG ((LM_INFO, "\t%s = %d\n", TEXT_server_hole, server_hole));
    ACE_DEBUG ((LM_INFO, "\t%s = %s\n", TEXT_skey, skey.c_str()));
    ACE_DEBUG ((LM_INFO, "\t%s = %s\n", TEXT_bz_files_path, bz_files_path.c_str()));
    ACE_DEBUG ((LM_INFO, "\t%s = %s\n", TEXT_bs_ip, bs_ip.c_str()));
    ACE_DEBUG ((LM_INFO, "\t%s = %d\n", TEXT_bs_hole, bs_hole));
    ACE_DEBUG ((LM_INFO, "\t%s = %s\n", TEXT_db_ip, db_ip.c_str()));
    ACE_DEBUG ((LM_INFO, "\t%s = %d\n", TEXT_db_hole, db_hole));
    ACE_DEBUG ((LM_INFO, "\t%s = %s\n", TEXT_db_login, db_login.c_str()));
  }

  if (term_station() || handleout())
  {
    ACE_DEBUG ((LM_INFO, "\t%s = %d\n", TEXT_ping_hole, ping_hole));
    ACE_DEBUG ((LM_INFO, "\t%s = %s\n", TEXT_pre_ip, pre_ip.c_str()));
  }

  if (term_station() || pre())
  {
    ACE_DEBUG ((LM_INFO, "\t%s = %d\n", TEXT_pre_term_hole, pre_term_hole));
  }

  if (term_station())
  {
    if (g_is_test)
      ACE_DEBUG ((LM_INFO, "\t%s = %d\n", TEXT_term_ping_delay, term_ping_delay));
//    ACE_DEBUG ((LM_INFO, "\t%s = %d\n", TEXT_adv_keep_days, adv_keep_days));
    ACE_DEBUG ((LM_INFO, "\t%s = %d\n", TEXT_download_max_idle, download_max_idle));
    ACE_DEBUG ((LM_INFO, "\t%s = %d\n", TEXT_download_again_num, download_again_num));
    ACE_DEBUG ((LM_INFO, "\t%s = %d\n", TEXT_download_again_sleep, download_again_sleep));
    ACE_DEBUG ((LM_INFO, "\t%s = %d\n", TEXT_can_su, can_su));
  }

  if (pre())
  {
    ACE_DEBUG ((LM_INFO, "\t%s = %d\n", TEXT_web_hole, web_hole));
    ACE_DEBUG ((LM_INFO, "\t%s = %s\n", TEXT_download_servers, download_servers.c_str()));
  }

  //
  ACE_DEBUG ((LM_INFO, "\tpid_fn = %s\n", sfile_fn.c_str()));
  ACE_DEBUG ((LM_INFO, "\tlog_fn = %s\n", log_fn.c_str()));
  ACE_DEBUG ((LM_INFO, "\tconfig_fn = %s\n", cfg_fn.c_str()));
  ACE_DEBUG ((LM_INFO, "\trunner_dir = %s\n", runner_dir.c_str()));
  ACE_DEBUG ((LM_INFO, "\texecute_dir = %s\n", execute_dir.c_str()));
}



CSignaller::CSignaller(CParentRunner * p)
{
  m_ptr = p;
}

ni CSignaller::handle_signal (ni signum, siginfo_t*, ucontext_t*)
{
  m_ptr->handle_signal(signum);
  return 0;
};



CNotificationFiler::CNotificationFiler(CParentRunner * p)
{
  m_ptr = p;
}

ni CNotificationFiler::handle_timeout(CONST CTV &, CONST DVOID *)
{
  struct stat st;
  if (::stat(CCfgX::instance()->sfile_fn.c_str(), &st) == -1 && errno == ENOENT)
    m_ptr->handle_no_sfile();
  return 0;
}



CPrinter::CPrinter(CParentRunner * p)
{
  m_ptr = p;
}

ni CPrinter::handle_timeout (CONST CTV &, CONST DVOID *)
{
  m_ptr->print_info();
  return 0;
}




ni CClocker::handle_timeout (CONST CTV &, CONST DVOID *)
{
  ++g_clock_counter;
  return 0;
}



CParentRunner::CParentRunner(): m_sig(this), m_sfile(this), m_printer(this)
{
  m_working = false;
  m_hup = false;
  m_term = false;
  m_chld = false;
  m_sfile_ok = true;
  m_sfile_check = false;
  srandom(time(NULL));
}

truefalse CParentRunner::do_init()
{
  return true;
}

DVOID CParentRunner::add_component(CContainer * p)
{
  if (!p)
  {
    C_ERROR("CApp::add_component(): null param\n");
    return;
  }
  m_components.push_back(p);
}

truefalse CParentRunner::delayed_init()
{
  CCfgX::instance()->print_all();
  C_INFO("loading containers...\n");

  m_sgh.register_handler(SIGTERM, &m_sig);
  m_sgh.register_handler(SIGCHLD, &m_sig);
  m_sgh.register_handler(SIGHUP, &m_sig);

  if (!do_init())
    return false;

  C_INFO("loading containers done!\n");

  if (CCfgX::instance()->fcheck_delay != 0)
  {
    ni l_i = open(CCfgX::instance()->sfile_fn.c_str(), O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR);
    if (l_i == -1)
    {
      C_WARNING("sfile needed, but fail create/open file %s\n", CCfgX::instance()->sfile_fn.c_str());
      return false;
    }
    close(l_i);
    m_sfile_check = true;

    CTV interval (CCfgX::instance()->fcheck_delay * 60);
    if (ACE_Reactor::instance()->schedule_timer (&m_sfile, 0, interval, interval) == -1)
      C_WARNING("fail init sfile timer\n");
  }

  if (CCfgX::instance()->print_delay > 0)
  {
    CTV interval(60 * CCfgX::instance()->print_delay);
    if (ACE_Reactor::instance()->schedule_timer (&m_printer,
                             0, interval, interval) == -1)
      C_WARNING("fail init stats timer\n");
  }

  CTV interval(CLOCK_TIME);
  if (ACE_Reactor::instance()->schedule_timer(&m_clock, 0, interval, interval) == -1)
  {
    C_FATAL("fail init clock timer\n");
    return false;
  }

  return true;
}

CParentRunner::~CParentRunner()
{
  m_sgh.remove_handler(SIGHUP);
  m_sgh.remove_handler(SIGTERM);
  if (m_sfile_check)
    ACE_Reactor::instance()->cancel_timer(&m_sfile);
  if (CCfgX::instance()->print_delay > 0)
    ACE_Reactor::instance()->cancel_timer(&m_printer);
  ACE_Reactor::instance()->cancel_timer(&m_clock);
  end();
  std::for_each(m_components.begin(), m_components.end(), CObjDeletor());
}

truefalse CParentRunner::running() CONST
{
  return m_working;
}

DVOID CParentRunner::put_to_back()
{
  pid_t l_x;

  if ((l_x = fork()) != 0)
    exit(0);

  setsid();
  signal(SIGHUP, SIG_IGN);

  if ((l_x = fork()) != 0)
    exit(0);

  umask(0);

  for (ni l_y = 0; l_y <= 1003; ++l_y)
    close(l_y);
}

DVOID CParentRunner::init_log()
{
  CONST text * l_xyz = "dynamic Logger Service_Object *ACE:_make_ACE_Logging_Strategy()"
   "\"-o -s %s -N %d -m %d000 -i 1 -f STDERR|OSTREAM \"";

  ni l_n = strlen(l_xyz) + CCfgX::instance()->log_fn.length() + 100;
  text * l_x = new text[l_n];
  std::snprintf(l_x, l_n, l_xyz, CCfgX::instance()->log_fn.c_str(),
      CCfgX::instance()->num_log, CCfgX::instance()->max_len_log);
  if (ACE_Service_Config::process_directive(l_x) == -1)
  {
    std::printf("ACE_Service_Config::process_directive failed, args = %s\n", l_x);
    exit(6);
  }
  delete []l_x;
  u_long log_mask = LM_INFO | LM_WARNING | LM_ERROR;
  if (CCfgX::instance()->verbose_log)
    log_mask |= LM_DEBUG;
  ACE_LOG_MSG->priority_mask (log_mask, ACE_Log_Msg::PROCESS);

  if (CCfgX::instance()->run_at_back || !CCfgX::instance()->window_also_log)
    ACE_LOG_MSG->clr_flags(ACE_Log_Msg::STDERR);
  if (CCfgX::instance()->server())
    C_INFO("Loading server Ver %s...\n", current_ver().c_str());
  else
    C_INFO("Loading client Ver %s...\n", current_ver().c_str());
}

DVOID CParentRunner::i_print()
{

}

DVOID CParentRunner::print_pool(CONST text * p, long v_get, long v_put, long v_peak, long v_fail, ni block_size, ni v_blocks)
{
  long l_use = v_get - v_put;
  ACE_DEBUG((LM_INFO, "    Obj[%s], Use=%d, Get=%d, "
      "Put=%d, Max=%d, Bad=%d, Size=%d, CNT=%d\n",
      p, l_use, v_get, v_put, v_peak, v_fail, block_size, v_blocks));
}

DVOID CParentRunner::print_info()
{
  C_INFO("##### Stats Start #####\n");
  std::for_each(m_components.begin(), m_components.end(), std::mem_fun(&CContainer::print_all));
  i_print();
  ACE_DEBUG((LM_INFO, "##### Finish #####\n"));
}

truefalse CParentRunner::before_begin()
{
  return true;
}

DVOID CParentRunner::begin()
{
  if (m_working)
    return;
  C_INFO("loading components...\n");
  m_working = true;
  before_begin();
  std::for_each(m_components.begin(), m_components.end(), std::mem_fun(&CContainer::begin));

  C_INFO("loading components finished!\n");
  handle_signal_child(); //quick handle
  schedule_works();
}

DVOID CParentRunner::before_finish()
{

}

DVOID CParentRunner::end()
{
  if (!m_working)
    return;
  C_INFO("ending components...\n");
  m_working = false;
  std::for_each(m_components.begin(), m_components.end(), std::mem_fun(&CContainer::end));
  before_finish();
  C_INFO("ending components finish!\n");
}

DVOID CParentRunner::handle_signal(ni signum)
{
  switch (signum)
  {
  case SIGTERM:
    m_term = true;
    break;
  case SIGHUP:
    m_hup = true;
    break;
  case SIGCHLD:
    m_chld = true;
    break;
  default:
    C_ERROR("bad signal (%d)\n", signum);
    break;
  }
}

DVOID CParentRunner::schedule_works()
{
  while(true)
  {
    CTV l_x(2);
    ACE_Reactor::instance()->run_reactor_event_loop(l_x);
    if (m_term)
    {
      C_INFO("sigterm, exiting...\n");
      return;
    }
    if (m_hup && !handle_signal_up())
    {
      C_INFO("sighup, exiting...\n");
      return;
    }
    if (m_chld && !handle_signal_child())
    {
      C_INFO("sigchild, exiting...\n");
      return;
    }
    if (!m_sfile_ok)
    {
      C_INFO("sfile check failed, exiting...\n");
      return;
    }
    if (!do_schedule_work())
      return;
  }
}

truefalse CParentRunner::handle_signal_up()
{
  m_hup = false;
  print_info();
  return true;
}

truefalse CParentRunner::handle_signal_child()
{
  ni st;
  pid_t x;
  m_chld = false;
  while ((x = ::waitpid(-1, &st, WNOHANG)) > 0)
  {
    C_INFO("child process (%d) ends...\n", (ni)x);
    if (!do_singal_child(x))
      return false;
  }
  return true;
}

truefalse CParentRunner::do_singal_child(pid_t)
{
  return true;
}

truefalse CParentRunner::do_schedule_work()
{
  return true;
}

DVOID CParentRunner::handle_no_sfile()
{
  m_sfile_ok = false;
}
