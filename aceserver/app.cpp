/*
 * serverapp.cpp
 *
 *  Created on: Dec 28, 2011
 *      Author: root
 */

#include <ace/streams.h>
#include <ace/Service_Config.h>
#include <ace/Logging_Strategy.h>
#include <cstdio>
#include "app.h"

CONST text * g_CONST_ver = "1.0";
long g_clock_counter = 0;
truefalse g_is_test = false;

//MyServerConfig//

CONST truefalse CONST_demon = false;
CONST ni  CONST_client_peak = 9900;
CONST truefalse CONST_mem_pool = true;
CONST ni  CONST_mem_print_delay = 30; //minutes
CONST ni  CONST_sfile_check_delay = 3; //minutes
CONST ni  CONST_log_fs = 20;
CONST ni  CONST_log_file_count = 3;
CONST truefalse CONST_log_console = true;
CONST truefalse CONST_log_debug = true;

CONST ni  CONST_pre_client_port = 2223;
CONST ni  CONST_server_port = 2224;
CONST ni  CONST_download_threads = 50;
CONST ni  CONST_ping_delay = 60; //seconds
CONST ni  CONST_ping_port = 2222;
CONST ni  CONST_db_port = 5432;
CONST ni  CONST_bs_port = 1921;
CONST ni  CONST_http_port = 1922;
CONST ni  CONST_can_root = 0;
CONST ni  CONST_download_retry_count = 30;
CONST ni  CONST_download_timeout = 120;
CONST ni  CONST_download_retry_delay = 4;

//all
CONST text * TEXT_Section_global = "global";
CONST text * TEXT_mode = "running_mode";
CONST text * TEXT_sfile_check_delay = "status_file_check_interval";
CONST text * TEXT_mem_pool = "use_mem_pool";
CONST text * TEXT_mem_print_delay = "mem_pool_dump_interval";
CONST text * TEXT_test = "test_mode";
CONST text * TEXT_log_debug = "log.debug_enabled";
CONST text * TEXT_as_demon = "run_as_demon";
CONST text * TEXT_log_file_size = "log.file_size";
CONST text * TEXT_log_console = "log.to_stderr";
CONST text * TEXT_log_file_number = "log.file_number";
CONST text * TEXT_download_threads = "module.test_client_ftp_thread_number";

//s
CONST text * TEXT_client_peak = "max_clients";
CONST text * TEXT_server_key = "middle_server.key";
CONST text * TEXT_server_port = "middle_server.dist_port";
CONST text * TEXT_db_user = "db_server.user_name";
CONST text * TEXT_db_password = "db_server.password";
CONST text * TEXT_db_addr = "db_server.addr";
CONST text * TEXT_db_port = "db_server.port";
CONST text * TEXT_bz_files_dir = "compressed_store_path";
CONST text * TEXT_bs_port = "bs_server_port";
CONST text * TEXT_bs_addr = "bs_server_addr";

//cd
CONST text *  TEXT_ping_port = "module.heart_beat.port";
CONST text *  TEXT_middle_addr = "middle_server.addr";

//cm
CONST text *  TEXT_pre_client_port = "middle_server.client_port";

//m
CONST text *  TEXT_ftp_servers = "ftp_addr_list";
CONST text *  TEXT_http_port = "middle_server.http_port";

//d
CONST text * TEXT_client_version_min = "client_version_minimum";
CONST text * TEXT_server_id = "server_id";
CONST text * TEXT_client_version_now = "client_version_current";

//c
CONST text * TEXT_can_root = "module.client_enable_root";
CONST text * TEXT_ping_delay = "module.client_heart_beat_interval";
CONST text * TEXT_download_retry_count = "module.client_ftp_retry_count";
CONST text * TEXT_download_retry_delay = "module.client_ftp_retry_interval";
CONST text * TEXT_download_timeout = "module.client_ftp_timeout";
CONST text * TEXT_adv_keep_days = "module.adv_expire_days";

CCfg::CCfg()
{
  //common configuration
  log_debug = CONST_log_debug;
  log_file_count = CONST_log_file_count;
  log_file_size = CONST_log_fs;
  log_console = CONST_log_console;

  print_delay = CONST_mem_print_delay;
  fcheck_delay = CONST_sfile_check_delay;
  remote_port = 0;
  mode = AM_UNKNOWN;
  mem_pool = CONST_mem_pool;
  is_demon = CONST_demon;

  //s
  db_port = CONST_db_port;
  bs_port = CONST_bs_port;
  client_peak = CONST_client_peak;
  server_port = CONST_server_port;

  //cd
  pre_client_port = CONST_pre_client_port;

  //d
  ping_port = CONST_ping_port;
  server_id = 1;

  //c
  can_root = CONST_can_root;
  client_ping_interval = CONST_ping_delay;
  download_threads = CONST_download_threads;
  adv_keep_days = 0;
  download_retry_count = CONST_download_retry_count;
  download_retry_delay = CONST_download_retry_delay;
  download_timeout = CONST_download_timeout;

  //m
  http_port = CONST_http_port;
}

DVOID CCfg::do_init(CONST text * app_home_path)
{
  CONST size_t BUFF_SIZE = 4096;
  text path[BUFF_SIZE];

  if (!app_home_path)
  {
    ssize_t n = readlink("/proc/self/exe", path, BUFF_SIZE);
    if (n > 0 && n < ssize_t(BUFF_SIZE))
    {
      path[n] = '\0';
      exe_path = path;
      size_t pos = exe_path.rfind('/');
      if (pos == exe_path.npos || pos == 0)
      {
        std::printf("exe_path (= %s) error\n", path);
        exit(1);
      }
      exe_path = exe_path.substr(0, pos);
      app_path = exe_path;
      pos = app_path.rfind('/', pos);
      if (pos == app_path.npos || pos == 0)
      {
        std::printf("app_path (= %s) error\n", app_path.c_str());
        exit(2);
      }
      app_path = app_path.substr(0, pos);
    } else
    {
      std::perror("readlink(\"/proc/self/exe\") failed\n");
      exit(3);
    }
  } else
  {
    app_path = app_home_path;
    exe_path = app_path + "/bin";
  }

  status_fn = app_path + "/running/app.pid";
  log_fn = app_path + "/log/app.log";
  cfg_fn = app_path + "/config/app.cfg";
  data_path = app_path + "/data";
}

truefalse CCfg::server() CONST
{
  return mode != AM_CLIENT;
}

truefalse CCfg::client() CONST
{
  return mode == AM_CLIENT;
}

truefalse CCfg::dist() CONST
{
  return mode == AM_DIST;
}

truefalse CCfg::middle() CONST
{
  return mode == AM_MIDDLE;
}

truefalse CCfg::readall(CONST text * h_path, CAppMode m)
{
  do_init(h_path);

  mode = m;
  CCfgHeap heap;
  if (heap.open () == -1)
  {
    C_FATAL("cfg.heap.open().\n");
    return false;
  }

  ACE_Registry_ImpExp bridge(heap);
  if (bridge.import_config (cfg_fn.c_str()) == -1)
  {
    C_FATAL("import_config() failed on %s\n", cfg_fn.c_str());
    return false;
  }

  CCfgKey akey;
  if (heap.open_section (heap.root_section (), TEXT_Section_global,
                           0, akey) == -1)
  {
    C_FATAL("config.open_key failed, key = %s\n", TEXT_Section_global);
    return false;
  }

  if (!read_base(heap, akey))
    return false;

  if (mode <= AM_UNKNOWN || mode > AM_CLIENT)
  {
    C_FATAL("unknown running mode (= %d)", mode);
    return false;
  }

  if (!read_dist_middle(heap, akey))
    return false;

  if (!read_client_middle(heap, akey))
    return false;

  if (!read_client_dist(heap, akey))
    return false;

  if (!read_dist(heap, akey))
    return false;

  if (!read_middle(heap, akey))
    return false;

  if (!read_client(heap, akey))
    return false;

  return true;
}

truefalse CCfg::read_base(CCfgHeap & heap, CCfgKey & key)
{
  ui n;
  if (mode == AM_UNKNOWN)
  {
    if (heap.get_integer_value (key,  TEXT_mode, n) == 0)
    {
      if (n != AM_DIST && n != AM_MIDDLE)
      {
        C_FATAL("invalid server running mode = %d\n", n);
        return false;
      }
      mode = CAppMode(n);
    } else
    {
      C_FATAL("can not read server running mode\n");
      return false;
    }
  }

  if (heap.get_integer_value (key,  TEXT_test, n) == 0)
    g_is_test = (n != 0);

  if (heap.get_integer_value (key,  TEXT_mem_pool, n) == 0)
  {
    mem_pool = (n != 0);
    g_cache = mem_pool;
  }

  if (heap.get_integer_value (key,  TEXT_as_demon, n) == 0)
    is_demon = (n != 0);

  if (heap.get_integer_value (key,  TEXT_sfile_check_delay, n) == 0)
    fcheck_delay = n;

  if (heap.get_integer_value (key,  TEXT_log_file_number, n) == 0)
  {
    if (n > 0 && n <= 1000)
      log_file_count = n;
  }

  if (heap.get_integer_value (key,  TEXT_log_file_size, n) == 0)
  {
    if (n > 0 && n <= 10000)
      log_file_size = n;
  }

  if (heap.get_integer_value (key,  TEXT_log_debug, n) == 0)
    log_debug = (n != 0);

  if (heap.get_integer_value (key,  TEXT_log_console, n) == 0)
    log_console = (n != 0);

  if (heap.get_integer_value (key,  TEXT_mem_print_delay, n) == 0)
    print_delay = n;

  return true;
}

truefalse CCfg::read_dist_middle(CCfgHeap & heap, CCfgKey & key)
{
  if (!server())
    return true;

  ui n;
  if (heap.get_integer_value (key,  TEXT_client_peak, n) == 0)
  {
    if (n > 0 && n <= 100000) //the upper limit of 100000 is more than enough?
    {
      client_peak = n;
    }
  }

  ACE_TString s;
  if (heap.get_string_value(key, TEXT_server_key, s) == 0)
    skey = s.c_str();
  else
  {
    C_ERROR("fail to read cfg value %s\n", TEXT_server_key);
    return false;
  }

  if (heap.get_integer_value (key,  TEXT_server_port, n) == 0)
  {
    if (n == 0 || n >= 65535)
    {
      C_ERROR("bad cfg value %s (= %d)\n", TEXT_server_port, n);
      return false;
    }
    server_port = n;
  }

  if (heap.get_string_value(key, TEXT_db_addr, s) == 0)
    db_addr = s.c_str();
  else
  {
    C_ERROR("can not read cfg value %s\n", TEXT_db_addr);
    return false;
  }

  if (heap.get_integer_value (key,  TEXT_db_port, n) == 0)
  {
    if (n == 0 || n >= 65535)
    {
      C_ERROR("bad cfg value %s (= %d)\n", TEXT_db_port, n);
      return false;
    }
    db_port = n;
  }

  if (heap.get_string_value(key, TEXT_db_user, s) == 0)
    db_name = s.c_str();
  else
  {
    C_ERROR("fail to read cfg value %s\n", TEXT_db_user);
    return false;
  }

  if (heap.get_string_value(key, TEXT_db_password, s) == 0)
    db_password = s.c_str();
  else
  {
    C_ERROR("fail to read cfg value %s\n", TEXT_db_password);
    return false;
  }

  if (heap.get_string_value(key, TEXT_bz_files_dir, s) == 0)
    bz_files_path = s.c_str();
  else
  {
    C_ERROR("fail to read cfg value %s\n", TEXT_bz_files_dir);
    return false;
  }

  if (heap.get_string_value(key, TEXT_bs_addr, s) == 0)
    bs_addr = s.c_str();
  else
  {
    C_ERROR("fail to read cfg value %s\n", TEXT_bs_addr);
    return false;
  }

  if (heap.get_integer_value(key, TEXT_bs_port, n) == 0)
  {
    if (n == 0 || n >= 65535)
    {
      C_ERROR("bad config value %s (= %d)\n", TEXT_bs_port, n);
      return false;
    }
    bs_port = n;
  }

  return true;
}

truefalse CCfg::read_client(CCfgHeap & heap, CCfgKey & key)
{
  if (server())
    return true;

  ui n;
  if (g_is_test)
  {
    if (heap.get_integer_value(key, TEXT_ping_delay, n) == 0)
    {
      if (n == 0 || n > 0xFFFF)
      {
        C_WARNING("bad %s value (= %d), resort to default = %d\n",
            TEXT_ping_delay, n, CONST_ping_delay);
      }
      else
        client_ping_interval = n;
    }
  }

  if (g_is_test)
  {
    if (heap.get_integer_value(key, TEXT_download_threads, n) == 0)
    {
      if (n == 0 || n > 500)
      {
        C_WARNING("bad %s value (= %d), resort to default = %d\n",
            TEXT_download_threads, n, CONST_download_threads);
      }
      else
        download_threads = n;
    }
  }

  if (heap.get_integer_value(key, TEXT_adv_keep_days, n) == 0)
  {
    if (n > 365)
    {
      C_WARNING("bad %s value (%d), resort to default = %d\n",
          TEXT_adv_keep_days, n, 0);
    }
    else
      adv_keep_days = n;
  }

  if (heap.get_integer_value(key, TEXT_download_timeout, n) == 0)
  {
    if (n < 60)
    {
      C_WARNING("bad %s value (%d), resort to default = %d\n",
          TEXT_download_timeout, n, CONST_download_timeout);
    }
    else
      download_timeout = n;
  }

  if (heap.get_integer_value(key, TEXT_download_retry_count, n) == 0)
  {
    if (n < 1 || n > 100000)
    {
      C_WARNING("bad %s value (%d), resort to default = %d\n",
          TEXT_download_retry_count, n, CONST_download_retry_count);
    }
    else
      download_retry_count = n;
  }

  if (heap.get_integer_value(key, TEXT_download_retry_delay, n) == 0)
  {
    if (n < 1 || n > 60)
    {
      C_WARNING("bad %s value (%d), resort to default = %d\n",
          TEXT_download_retry_delay, n, CONST_download_retry_delay);
    }
    else
      download_retry_delay = n;
  }

  if (heap.get_integer_value(key, TEXT_can_root, n) == 0)
    can_root = n;

  return true;
}

truefalse CCfg::read_dist(CCfgHeap & heap, CCfgKey & key)
{
  if (!dist())
    return true;

  ui n;
  if (heap.get_integer_value(key, TEXT_server_id, n) == 0)
  {
    if (n <= 1 || n >= 256)
    {
      C_ERROR("bad config value %s: %d\n", TEXT_server_id, n);
      return false;
    }
    server_id = (u_int8_t)n;
  }
  else
  {
    C_ERROR("fail to read cfg value %s\n", TEXT_server_id);
    return false;
  }

  ACE_TString s;
  if (heap.get_string_value(key, TEXT_client_version_min, s) == 0)
  {
    if (!client_ver_min.from_string(s.c_str()))
    {
      C_ERROR("bad config value %s: %s\n", TEXT_client_version_min, s.c_str());
      return false;
    }
  }
  else
  {
    C_ERROR("fail to read cfg value %s\n", TEXT_client_version_min);
    return false;
  }

  if (heap.get_string_value(key, TEXT_client_version_now, s) == 0)
  {
    if (!client_ver_now.from_string(s.c_str()))
    {
      C_ERROR("bad config value %s: %s\n", TEXT_client_version_now, s.c_str());
      return false;
    }
  }
  else
  {
    C_ERROR("fail to read cfg value %s\n", TEXT_client_version_now);
    return false;
  }

  if (client_ver_now < client_ver_min)
  {
    C_ERROR("bad config value %s(%s) < %s(%s)\n",
        TEXT_client_version_now, client_ver_now.to_string(),
        TEXT_client_version_min, client_ver_min.to_string());
    return false;
  }

  return true;
}

truefalse CCfg::read_middle(CCfgHeap & heap, CCfgKey & key)
{
  if (!middle())
    return true;

  ui n;
  if (heap.get_integer_value (key,  TEXT_http_port, n) == 0)
  {
    if (n == 0 || n >= 65535)
    {
      C_ERROR("bad config value %s (= %d)\n", TEXT_http_port, n);
      return false;
    }
    http_port = n;
  }

  ACE_TString s;
  if (heap.get_string_value(key, TEXT_ftp_servers, s) == 0)
    ftp_servers = s.c_str();
  else
  {
    C_ERROR("fail to read cfg value %s\n", TEXT_ftp_servers);
    return false;
  }

  return true;
}

truefalse CCfg::read_client_middle(CCfgHeap & heap, CCfgKey & key)
{
  if (dist())
    return true;

  ui n;
  if (heap.get_integer_value (key,  TEXT_pre_client_port, n) == 0)
  {
    if (n == 0 || n >= 65535)
    {
      C_ERROR("bad config value %s (= %d)\n", TEXT_pre_client_port, n);
      return false;
    }
    pre_client_port = n;
  }

  return true;
}

truefalse CCfg::read_client_dist(CCfgHeap & heap, CCfgKey & key)
{
  if (middle())
    return true;

  ui n;
  if (heap.get_integer_value (key, TEXT_ping_port, n) == 0)
  {
    if (n == 0 || n >= 65535)
    {
      C_ERROR("bad config value %s (= %d)\n", TEXT_ping_port, n);
      return false;
    }
    ping_port = n;
  }

  ACE_TString s;
  if (heap.get_string_value(key, TEXT_middle_addr, s) == 0)
    middle_addr = s.c_str();
  else
  {
    C_ERROR("fail to read cfg value %s\n", TEXT_middle_addr);
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
  case AM_DIST:
    smode = "dist server";
    break;
  case AM_MIDDLE:
    smode = "middle server";
    break;
  case AM_CLIENT:
    smode = "client";
    break;
  default:
    C_FATAL("bad mode (=%d).\n", mode);
    exit(10);
  }
  ACE_DEBUG ((LM_INFO, "\t%s = %s\n", TEXT_mode, smode));

  ACE_DEBUG ((LM_INFO, "\t%s = %d\n", TEXT_as_demon, is_demon));
  ACE_DEBUG ((LM_INFO, "\t%s = %d\n", TEXT_mem_pool, mem_pool));
  ACE_DEBUG ((LM_INFO, "\t%s = %d\n", TEXT_mem_print_delay, print_delay));
  ACE_DEBUG ((LM_INFO, "\t%s = %d\n", TEXT_sfile_check_delay, fcheck_delay));

  ACE_DEBUG ((LM_INFO, "\t%s = %d\n", TEXT_log_file_number, log_file_count));
  ACE_DEBUG ((LM_INFO, "\t%s = %d\n", TEXT_log_file_size, log_file_size));
  ACE_DEBUG ((LM_INFO, "\t%s = %d\n", TEXT_log_debug, log_debug));
  ACE_DEBUG ((LM_INFO, "\t%s = %d\n", TEXT_log_console, log_console));

  if (g_is_test)
    ACE_DEBUG ((LM_INFO, "\ttest_mode = 1\n"));
  else
    ACE_DEBUG ((LM_INFO, "\ttest_mode = 0\n"));

  if (server())
  {
    ACE_DEBUG ((LM_INFO, "\t%s = %d\n", TEXT_client_peak, client_peak));
    ACE_DEBUG ((LM_INFO, "\t%s = %d\n", TEXT_server_port, server_port));
    ACE_DEBUG ((LM_INFO, "\t%s = %s\n", TEXT_server_key, skey.c_str()));
    ACE_DEBUG ((LM_INFO, "\t%s = %s\n", TEXT_bz_files_dir, bz_files_path.c_str()));
    ACE_DEBUG ((LM_INFO, "\t%s = %s\n", TEXT_bs_addr, bs_addr.c_str()));
    ACE_DEBUG ((LM_INFO, "\t%s = %d\n", TEXT_bs_port, bs_port));
    ACE_DEBUG ((LM_INFO, "\t%s = %s\n", TEXT_db_addr, db_addr.c_str()));
    ACE_DEBUG ((LM_INFO, "\t%s = %d\n", TEXT_db_port, db_port));
    ACE_DEBUG ((LM_INFO, "\t%s = %s\n", TEXT_db_user, db_name.c_str()));
  }

  if (client() || dist())
  {
    ACE_DEBUG ((LM_INFO, "\t%s = %d\n", TEXT_ping_port, ping_port));
    ACE_DEBUG ((LM_INFO, "\t%s = %s\n", TEXT_middle_addr, middle_addr.c_str()));
  }

  if (client() || middle())
  {
    ACE_DEBUG ((LM_INFO, "\t%s = %d\n", TEXT_pre_client_port, pre_client_port));
  }

  if (client())
  {
    if (g_is_test)
      ACE_DEBUG ((LM_INFO, "\t%s = %d\n", TEXT_ping_delay, client_ping_interval));
//    ACE_DEBUG ((LM_INFO, "\t%s = %d\n", TEXT_adv_keep_days, adv_keep_days));
    ACE_DEBUG ((LM_INFO, "\t%s = %d\n", TEXT_download_timeout, download_timeout));
    ACE_DEBUG ((LM_INFO, "\t%s = %d\n", TEXT_download_retry_count, download_retry_count));
    ACE_DEBUG ((LM_INFO, "\t%s = %d\n", TEXT_download_retry_delay, download_retry_delay));
    ACE_DEBUG ((LM_INFO, "\t%s = %d\n", TEXT_can_root, can_root));
  }

  if (middle())
  {
    ACE_DEBUG ((LM_INFO, "\t%s = %d\n", TEXT_http_port, http_port));
    ACE_DEBUG ((LM_INFO, "\t%s = %s\n", TEXT_ftp_servers, ftp_servers.c_str()));
  }

  //common: file/path locations printout
  ACE_DEBUG ((LM_INFO, "\tstatus_file = %s\n", status_fn.c_str()));
  ACE_DEBUG ((LM_INFO, "\tlog_file = %s\n", log_fn.c_str()));
  ACE_DEBUG ((LM_INFO, "\tconfig_file = %s\n", cfg_fn.c_str()));
  ACE_DEBUG ((LM_INFO, "\tapp_path = %s\n", app_path.c_str()));
  ACE_DEBUG ((LM_INFO, "\texe_path = %s\n", exe_path.c_str()));
}


//MySigHandler//
CSignaller::CSignaller(CApp * p)
{
  m_parent = p;
}

ni CSignaller::handle_signal (ni signum, siginfo_t*, ucontext_t*)
{
  m_parent->handle_signal(signum);
  return 0;
};


//CNotificationFiler//
CNotificationFiler::CNotificationFiler(CApp * p)
{
  m_parent = p;
}

ni CNotificationFiler::handle_timeout(CONST ACE_Time_Value &, CONST DVOID *)
{
  struct stat st;
  if (::stat(CCfgX::instance()->status_fn.c_str(), &st) == -1 && errno == ENOENT)
    m_parent->handle_no_sfile();
  return 0;
}


//CPrinter//
CPrinter::CPrinter(CApp * p)
{
  m_parent = p;
}

ni CPrinter::handle_timeout (CONST ACE_Time_Value &, CONST DVOID *)
{
  m_parent->print_info();
  return 0;
}


//CClocker//

ni CClocker::handle_timeout (CONST ACE_Time_Value &, CONST DVOID *)
{
  ++g_clock_counter;
  return 0;
}


//CApp//
CApp::CApp(): m_sig(this), m_sfile(this), m_printer(this)
{
  m_running = false;
  //moved the initializations of modules to the SF app_init() func
  //Just can NOT do it in constructor simply because the singleton pattern
  //will make recursively calls to our constructor by the module constructor's ref
  //to MyServerApp's singleton.
  //This is Ugly, but works right now
  m_hup = false;
  m_term = false;
  m_chld = false;
  m_sfile_ok = true;
  m_sfile_check = false;
  srandom(time(NULL));
}

truefalse CApp::do_init()
{
  return true;
}

DVOID CApp::add_component(CMod * module)
{
  if (!module)
  {
    C_ERROR("MyBaseApp::add_module(): module is NULL\n");
    return;
  }
  m_components.push_back(module);
}

truefalse CApp::delayed_init()
{
  CCfgX::instance()->print_all();
  C_INFO("loading modules...\n");

  m_signal_handler.register_handler(SIGTERM, &m_sig);
  m_signal_handler.register_handler(SIGCHLD, &m_sig);
  m_signal_handler.register_handler(SIGHUP, &m_sig);

  if (!do_init())
    return false;

  C_INFO("loading modules done!\n");

  if (CCfgX::instance()->fcheck_delay != 0)
  {
    ni fd = open(CCfgX::instance()->status_fn.c_str(), O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR);
    if (fd == -1)
    {
      C_WARNING("status_file_check_interval enabled, but can not create/open file %s\n",
          CCfgX::instance()->status_fn.c_str());
      return false;
    }
    close(fd);
    m_sfile_check = true;

    ACE_Time_Value interval (CCfgX::instance()->fcheck_delay * 60);
    if (ACE_Reactor::instance()->schedule_timer (&m_sfile, 0, interval, interval) == -1)
      C_WARNING("can not setup status_file_check timer\n");
  }

  if (CCfgX::instance()->print_delay > 0)
  {
    ACE_Time_Value interval(60 * CCfgX::instance()->print_delay);
    if (ACE_Reactor::instance()->schedule_timer (&m_printer,
                             0, interval, interval) == -1)
      C_WARNING("can not setup info dump timer\n");
  }

  ACE_Time_Value interval(CLOCK_TIME);
  if (ACE_Reactor::instance()->schedule_timer(&m_clock, 0, interval, interval) == -1)
  {
    C_FATAL("can not setup clock timer\n");
    return false;
  }

  return true;
}

CApp::~CApp()
{
  m_signal_handler.remove_handler(SIGHUP);
  m_signal_handler.remove_handler(SIGTERM);
  if (m_sfile_check)
    ACE_Reactor::instance()->cancel_timer(&m_sfile);
  if (CCfgX::instance()->print_delay > 0)
    ACE_Reactor::instance()->cancel_timer(&m_printer);
  ACE_Reactor::instance()->cancel_timer(&m_clock);
  end();
  std::for_each(m_components.begin(), m_components.end(), CObjDeletor());
}

truefalse CApp::running() CONST
{
  return m_running;
}

DVOID CApp::demon()
{
  pid_t pid;

  if ((pid = fork()) != 0)
    exit(0);

  setsid();
  signal(SIGHUP, SIG_IGN);

  if ((pid = fork()) != 0)
    exit(0);

  umask(0);

  for (ni i = 0; i <= 1024; ++i)
    close(i);
}

DVOID CApp::init_log()
{
  CONST text * cmd = "dynamic Logger Service_Object *ACE:_make_ACE_Logging_Strategy()"
   "\"-o -s %s -N %d -m %d000 -i 1 -f STDERR|OSTREAM \"";

  ni m = strlen(cmd) + CCfgX::instance()->log_fn.length() + 100;
  text * buff = new text[m];
  std::snprintf(buff, m, cmd, CCfgX::instance()->log_fn.c_str(),
      CCfgX::instance()->log_file_count,
      CCfgX::instance()->log_file_size);
  if (ACE_Service_Config::process_directive(buff) == -1)
  {
    std::printf("ACE_Service_Config::process_directive failed, args = %s\n", buff);
    exit(6);
  }
  delete []buff;
  u_long log_mask = LM_INFO | LM_WARNING | LM_ERROR;
  if (CCfgX::instance()->log_debug)
    log_mask |= LM_DEBUG;
  ACE_LOG_MSG->priority_mask (log_mask, ACE_Log_Msg::PROCESS);

  if (CCfgX::instance()->is_demon || !CCfgX::instance()->log_console)
    ACE_LOG_MSG->clr_flags(ACE_Log_Msg::STDERR);
  if (CCfgX::instance()->server())
    C_INFO("Loading server Ver %s...\n", current_ver().c_str());
  else
    C_INFO("Loading client Ver %s...\n", current_ver().c_str());
}

DVOID CApp::i_print()
{

}

DVOID CApp::print_pool(CONST text * poolname, long nAlloc, long nFree, long nMaxUse, long nAllocFull, ni block_size, ni chunks)
{
  long nInUse = nAlloc - nFree;
  ACE_DEBUG((LM_INFO, "    Obj[%s], Use=%d, Get=%d, "
      "Rel=%d, Max=%d, Bad=%d, Size=%d, CNT=%d\n",
      poolname, nInUse, nAlloc, nFree, nMaxUse, nAllocFull, block_size, chunks));
}

DVOID CApp::print_info()
{
  C_INFO("##### Running Information Dump #####\n");
  std::for_each(m_components.begin(), m_components.end(), std::mem_fun(&CMod::print_all));
  i_print();
  ACE_DEBUG((LM_INFO, "##### Dump End #####\n"));
}

truefalse CApp::before_begin()
{
  return true;
}

DVOID CApp::begin()
{
  if (m_running)
    return;
  C_INFO("loading components...\n");
  m_running = true;
  before_begin();
  std::for_each(m_components.begin(), m_components.end(), std::mem_fun(&CMod::start));

  C_INFO("loading components finished!\n");
  handle_signal_child(); //fast delivery
  schedule_works();
}

DVOID CApp::before_finish()
{

}

DVOID CApp::end()
{
  if (!m_running)
    return;
  C_INFO("ending components...\n");
  m_running = false;
  std::for_each(m_components.begin(), m_components.end(), std::mem_fun(&CMod::stop));
  before_finish();
  C_INFO("ending components finish!\n");
}

DVOID CApp::handle_signal(ni signum)
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

DVOID CApp::schedule_works()
{
  while(true)
  {
    ACE_Time_Value timeout(2);
    ACE_Reactor::instance()->run_reactor_event_loop(timeout);
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

truefalse CApp::handle_signal_up()
{
  m_hup = false;
  print_info();
  return true;
}

truefalse CApp::handle_signal_child()
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

truefalse CApp::do_singal_child(pid_t)
{
  return true;
}

truefalse CApp::do_schedule_work()
{
  return true;
}

DVOID CApp::handle_no_sfile()
{
  m_sfile_ok = false;
}
