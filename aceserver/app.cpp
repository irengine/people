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

CONST text * g_CONST_app_ver = "1.0";
long g_clock_counter = 0;
truefalse g_is_test = false;

//MyServerConfig//

CONST ni  DEFAULT_max_clients = 10000;
CONST truefalse DEFAULT_use_mem_pool = true;
CONST truefalse DEFAULT_run_as_demon = false;
CONST ni  DEFAULT_status_file_check_interval = 3; //in minutes
CONST ni  DEFAULT_mem_pool_dump_interval = 30; //in minutes

CONST ni  DEFAULT_log_file_number = 3;
CONST ni  DEFAULT_log_file_size_in_MB = 20;
CONST truefalse DEFAULT_log_debug_enabled = true;
CONST truefalse DEFAULT_log_to_stderr = true;

CONST ni  DEFAULT_dist_server_heart_beat_port = 2222;
CONST ni  DEFAULT_MODULE_HEART_BEAT_MPOOL_SIZE = DEFAULT_max_clients * 4;

CONST ni  DEFAULT_middle_server_client_port = 2223;
CONST ni  DEFAULT_middle_server_dist_port = 2224;
CONST ni  DEFAULT_client_heart_beat_interval = 60; //in seconds
CONST ni  DEFAULT_test_client_ftp_thread_number = 50;
CONST ni  DEFAULT_db_server_port = 5432;
CONST ni  DEFAULT_http_port = 1922;
CONST ni  DEFAULT_bs_server_port = 1921;
CONST ni  DEFAULT_client_ftp_timeout = 120;
CONST ni  DEFAULT_client_ftp_retry_count = 30;
CONST ni  DEFAULT_client_ftp_retry_interval = 4;
CONST ni  DEFAULT_client_enable_root = 0;

//common for all
CONST text * CONFIG_Section_global = "global";

CONST text * CONFIG_test_mode = "test_mode";

CONST text * CONFIG_running_mode = "running_mode";
CONST text * CONFIG_use_mem_pool = "use_mem_pool";
CONST text * CONFIG_mem_pool_dump_interval = "mem_pool_dump_interval";
CONST text * CONFIG_run_as_demon = "run_as_demon";
CONST text * CONFIG_status_file_check_interval = "status_file_check_interval";

CONST text * CONFIG_log_debug_enabled = "log.debug_enabled";
CONST text * CONFIG_log_to_stderr = "log.to_stderr";
CONST text * CONFIG_log_file_number = "log.file_number";
CONST text * CONFIG_log_file_size_in_MB = "log.file_size";

CONST text * CONFIG_test_client_ftp_thread_number = "module.test_client_ftp_thread_number";

//dist and middle servers
CONST text * CONFIG_max_clients = "max_clients";
CONST text * CONFIG_middle_server_dist_port = "middle_server.dist_port";
CONST text * CONFIG_middle_server_key = "middle_server.key";
CONST text * CONFIG_db_server_addr = "db_server.addr";
CONST text * CONFIG_db_server_port = "db_server.port";
CONST text * CONFIG_db_user_name = "db_server.user_name";
CONST text * CONFIG_db_password = "db_server.password";
CONST text * CONFIG_compressed_store_path = "compressed_store_path";
CONST text * CONFIG_bs_server_addr = "bs_server_addr";
CONST text * CONFIG_bs_server_port = "bs_server_port";



//client and dist
CONST text *  CONFIG_middle_server_addr = "middle_server.addr";
CONST text *  CONFIG_dist_server_heart_beat_port = "module.heart_beat.port";

//client and middle
CONST text *  CONFIG_middle_server_client_port = "middle_server.client_port";

//middle specific
CONST text *  CONFIG_http_port = "middle_server.http_port";
CONST text *  CONFIG_ftp_addr_list = "ftp_addr_list";

//dist specific
CONST text * CONFIG_module_heart_beat_mem_pool_size = "module.heart_beat.mempool_size";
CONST text * CONFIG_client_version_minimum = "client_version_minimum";
CONST text * CONFIG_client_version_current = "client_version_current";
CONST text * CONFIG_server_id = "server_id";

//client specific
CONST text * CONFIG_client_heart_beat_interval = "module.client_heart_beat_interval";
CONST text * CONFIG_adv_expire_days = "module.adv_expire_days";
CONST text * CONFIG_client_ftp_timeout = "module.client_ftp_timeout";
CONST text * CONFIG_client_ftp_retry_count = "module.client_ftp_retry_count";
CONST text * CONFIG_client_ftp_retry_interval = "module.client_ftp_retry_interval";
CONST text * CONFIG_client_enable_root = "module.client_enable_root";


CCfg::CCfg()
{
  //common configuration
  app_mode = AM_UNKNOWN;
  use_mem_pool = DEFAULT_use_mem_pool;
  as_demon = DEFAULT_run_as_demon;
  mem_dump_interval = DEFAULT_mem_pool_dump_interval;
  file_check_interval = DEFAULT_status_file_check_interval;
  remote_port = 0;

  log_debug = DEFAULT_log_debug_enabled;
  log_file_count = DEFAULT_log_file_number;
  log_file_size = DEFAULT_log_file_size_in_MB;
  log_stderr = DEFAULT_log_to_stderr;

  //dist and middle server
  max_client_count = DEFAULT_max_clients;
  middle_server_dist_port = DEFAULT_middle_server_dist_port;
  db_port = DEFAULT_db_server_port;
  bs_port = DEFAULT_bs_server_port;

  //client and dist
  middle_server_client_port = DEFAULT_middle_server_client_port;

  //dist server only
  ping_port = DEFAULT_dist_server_heart_beat_port;
  module_heart_beat_mem_pool_size = DEFAULT_MODULE_HEART_BEAT_MPOOL_SIZE;
  dist_server_id = 1;

  //client only
  client_ping_interval = DEFAULT_client_heart_beat_interval;
  test_client_download_thread_count = DEFAULT_test_client_ftp_thread_number;
  client_adv_expire_days = 0;
  client_download_timeout = DEFAULT_client_ftp_timeout;
  client_download_retry_count = DEFAULT_client_ftp_retry_count;
  client_download_retry_interval = DEFAULT_client_ftp_retry_interval;
  client_can_root = DEFAULT_client_enable_root;

  //middle only
  http_port = DEFAULT_http_port;
}

DVOID CCfg::do_init(CONST text * app_home_path)
{
  CONST size_t BUFF_SIZE = 4096;
  text path[BUFF_SIZE];

  if (!app_home_path)
  {
    ssize_t ret = readlink("/proc/self/exe", path, BUFF_SIZE);
    if (ret > 0 && ret < ssize_t(BUFF_SIZE))
    {
      path[ret] = '\0';
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

truefalse CCfg::is_server() CONST
{
  return app_mode != AM_CLIENT;
}

truefalse CCfg::is_client() CONST
{
  return app_mode == AM_CLIENT;
}

truefalse CCfg::is_dist() CONST
{
  return app_mode == AM_DIST_SERVER;
}

truefalse CCfg::is_middle() CONST
{
  return app_mode == AM_MIDDLE_SERVER;
}

truefalse CCfg::readall(CONST text * home_dir, CAppMode mode)
{
  do_init(home_dir);

  app_mode = mode;

  CCfgHeap heap;
  if (heap.open () == -1)
  {
    C_FATAL("config.open().\n");
    return false;
  }

  ACE_Registry_ImpExp bridge(heap);
  if (bridge.import_config (cfg_fn.c_str()) == -1)
  {
    C_FATAL("import_config() failed on %s\n", cfg_fn.c_str());
    return false;
  }

  CCfgKey sect;
  if (heap.open_section (heap.root_section (), CONFIG_Section_global,
                           0, sect) == -1)
  {
    C_FATAL("config.open_key failed, key = %s\n", CONFIG_Section_global);
    return false;
  }

  if (!read_base(heap, sect))
    return false;

  if (app_mode <= AM_UNKNOWN || app_mode > AM_CLIENT)
  {
    C_FATAL("unknown running mode (= %d)", app_mode);
    return false;
  }

  if (!read_dist_middle(heap, sect))
    return false;

  if (!read_client_middle(heap, sect))
    return false;

  if (!read_client_dist(heap, sect))
    return false;

  if (!read_dist(heap, sect))
    return false;

  if (!read_middle(heap, sect))
    return false;

  if (!read_client(heap, sect))
    return false;

  return true;
}

truefalse CCfg::read_base(CCfgHeap & heap, CCfgKey & key)
{
  u_int ival;
  if (app_mode == AM_UNKNOWN)
  {
    if (heap.get_integer_value (key,  CONFIG_running_mode, ival) == 0)
    {
      if (ival != AM_DIST_SERVER && ival != AM_MIDDLE_SERVER)
      {
        C_FATAL("invalid server running mode = %d\n", ival);
        return false;
      }
      app_mode = CAppMode(ival);
    } else
    {
      C_FATAL("can not read server running mode\n");
      return false;
    }
  }

  if (heap.get_integer_value (key,  CONFIG_test_mode, ival) == 0)
    g_is_test = (ival != 0);

  if (heap.get_integer_value (key,  CONFIG_use_mem_pool, ival) == 0)
  {
    use_mem_pool = (ival != 0);
    g_use_mem_pool = use_mem_pool;
  }

  if (heap.get_integer_value (key,  CONFIG_run_as_demon, ival) == 0)
    as_demon = (ival != 0);

  if (heap.get_integer_value (key,  CONFIG_status_file_check_interval, ival) == 0)
    file_check_interval = ival;

  if (heap.get_integer_value (key,  CONFIG_log_file_number, ival) == 0)
  {
    if (ival > 0 && ival <= 1000)
      log_file_count = ival;
  }

  if (heap.get_integer_value (key,  CONFIG_log_file_size_in_MB, ival) == 0)
  {
    if (ival > 0 && ival <= 10000)
      log_file_size = ival;
  }

  if (heap.get_integer_value (key,  CONFIG_log_debug_enabled, ival) == 0)
    log_debug = (ival != 0);

  if (heap.get_integer_value (key,  CONFIG_log_to_stderr, ival) == 0)
    log_stderr = (ival != 0);

  if (heap.get_integer_value (key,  CONFIG_mem_pool_dump_interval, ival) == 0)
    mem_dump_interval = ival;

  return true;
}

truefalse CCfg::read_dist_middle(CCfgHeap & heap, CCfgKey & key)
{
  if (!is_server())
    return true;

  u_int ival;
  if (heap.get_integer_value (key,  CONFIG_max_clients, ival) == 0)
  {
    if (ival > 0 && ival <= 100000) //the upper limit of 100000 is more than enough?
    {
      max_client_count = ival;
    }
  }

  ACE_TString sval;
  if (heap.get_string_value(key, CONFIG_middle_server_key, sval) == 0)
    skey = sval.c_str();
  else
  {
    C_ERROR("can not read config value %s\n", CONFIG_middle_server_key);
    return false;
  }

  if (heap.get_integer_value (key,  CONFIG_middle_server_dist_port, ival) == 0)
  {
    if (ival == 0 || ival >= 65535)
    {
      C_ERROR("Invalid config value %s (= %d)\n", CONFIG_middle_server_dist_port, ival);
      return false;
    }
    middle_server_dist_port = ival;
  }

  if (heap.get_string_value(key, CONFIG_db_server_addr, sval) == 0)
    db_addr = sval.c_str();
  else
  {
    C_ERROR("can not read config value %s\n", CONFIG_db_server_addr);
    return false;
  }

  if (heap.get_integer_value (key,  CONFIG_db_server_port, ival) == 0)
  {
    if (ival == 0 || ival >= 65535)
    {
      C_ERROR("Invalid config value %s (= %d)\n", CONFIG_db_server_port, ival);
      return false;
    }
    db_port = ival;
  }

  if (heap.get_string_value(key, CONFIG_db_user_name, sval) == 0)
    db_name = sval.c_str();
  else
  {
    C_ERROR("can not read config value %s\n", CONFIG_db_user_name);
    return false;
  }

  if (heap.get_string_value(key, CONFIG_db_password, sval) == 0)
    db_password = sval.c_str();
  else
  {
    C_ERROR("can not read config value %s\n", CONFIG_db_password);
    return false;
  }

  if (heap.get_string_value(key, CONFIG_compressed_store_path, sval) == 0)
    bz_files_path = sval.c_str();
  else
  {
    C_ERROR("can not read config value %s\n", CONFIG_compressed_store_path);
    return false;
  }

  if (heap.get_string_value(key, CONFIG_bs_server_addr, sval) == 0)
    bs_addr = sval.c_str();
  else
  {
    C_ERROR("can not read config value %s\n", CONFIG_bs_server_addr);
    return false;
  }

  if (heap.get_integer_value(key, CONFIG_bs_server_port, ival) == 0)
  {
    if (ival == 0 || ival >= 65535)
    {
      C_ERROR("Invalid config value %s (= %d)\n", CONFIG_bs_server_port, ival);
      return false;
    }
    bs_port = ival;
  }

  return true;
}

truefalse CCfg::read_client(CCfgHeap & heap, CCfgKey & key)
{
  if (is_server())
    return true;

  u_int ival;

  if (g_is_test)
  {
    if (heap.get_integer_value(key, CONFIG_client_heart_beat_interval, ival) == 0)
    {
      if (ival == 0 || ival > 0xFFFF)
      {
        C_WARNING("Invalid %s value (= %d), using default value = %d\n",
            CONFIG_module_heart_beat_mem_pool_size, ival, DEFAULT_client_heart_beat_interval);
      }
      else
        client_ping_interval = ival;
    }
  }

  if (g_is_test)
  {
    if (heap.get_integer_value(key, CONFIG_test_client_ftp_thread_number, ival) == 0)
    {
      if (ival == 0 || ival > 500)
      {
        C_WARNING("Invalid %s value (= %d), using default value = %d\n",
            CONFIG_test_client_ftp_thread_number, ival, DEFAULT_test_client_ftp_thread_number);
      }
      else
        test_client_download_thread_count = ival;
    }
  }

  if (heap.get_integer_value(key, CONFIG_adv_expire_days, ival) == 0)
  {
    if (ival > 365)
    {
      C_WARNING("Invalid %s value (%d), using default value = %d\n",
          CONFIG_adv_expire_days, ival, 0);
    }
    else
      client_adv_expire_days = ival;
  }

  if (heap.get_integer_value(key, CONFIG_client_ftp_timeout, ival) == 0)
  {
    if (ival < 60)
    {
      C_WARNING("Invalid %s value (%d), using default value = %d\n",
          CONFIG_client_ftp_timeout, ival, DEFAULT_client_ftp_timeout);
    }
    else
      client_download_timeout = ival;
  }

  if (heap.get_integer_value(key, CONFIG_client_ftp_retry_count, ival) == 0)
  {
    if (ival < 1 || ival > 100000)
    {
      C_WARNING("Invalid %s value (%d), using default value = %d\n",
          CONFIG_client_ftp_retry_count, ival, DEFAULT_client_ftp_retry_count);
    }
    else
      client_download_retry_count = ival;
  }

  if (heap.get_integer_value(key, CONFIG_client_ftp_retry_interval, ival) == 0)
  {
    if (ival < 1 || ival > 60)
    {
      C_WARNING("Invalid %s value (%d), using default value = %d\n",
          CONFIG_client_ftp_retry_interval, ival, DEFAULT_client_ftp_retry_interval);
    }
    else
      client_download_retry_interval = ival;
  }

  if (heap.get_integer_value(key, CONFIG_client_enable_root, ival) == 0)
    client_can_root = ival;

  return true;
}

truefalse CCfg::read_dist(CCfgHeap & heap, CCfgKey & key)
{
  if (!is_dist())
    return true;

  u_int ival;

  if (heap.get_integer_value(key, CONFIG_module_heart_beat_mem_pool_size, ival) == 0)
  {
    u_int itemp = std::max(2 * max_client_count, 1000);
    if (ival < itemp)
    {
      C_WARNING("Invalid %s value (= %d), should at least max(2 * %s, 1000) = %d, will adjust to %d\n",
          CONFIG_module_heart_beat_mem_pool_size, ival, CONFIG_max_clients, itemp, itemp);
    }
    else
      module_heart_beat_mem_pool_size = ival;
  }

  if (heap.get_integer_value(key, CONFIG_server_id, ival) == 0)
  {
    if (ival <= 1 || ival >= 256)
    {
      C_ERROR("Invalid config value %s: %d\n", CONFIG_server_id, ival);
      return false;
    }
    dist_server_id = (u_int8_t)ival;
  }
  else
  {
    C_ERROR("can not read config value %s\n", CONFIG_server_id);
    return false;
  }

  ACE_TString sval;
  if (heap.get_string_value(key, CONFIG_client_version_minimum, sval) == 0)
  {
    if (!client_ver_min.from_string(sval.c_str()))
    {
      C_ERROR("Invalid config value %s: %s\n", CONFIG_client_version_minimum, sval.c_str());
      return false;
    }
  }
  else
  {
    C_ERROR("can not read config value %s\n", CONFIG_client_version_minimum);
    return false;
  }

  if (heap.get_string_value(key, CONFIG_client_version_current, sval) == 0)
  {
    if (!client_ver_now.from_string(sval.c_str()))
    {
      C_ERROR("Invalid config value %s: %s\n", CONFIG_client_version_current, sval.c_str());
      return false;
    }
  }
  else
  {
    C_ERROR("can not read config value %s\n", CONFIG_client_version_current);
    return false;
  }

  if (client_ver_now < client_ver_min)
  {
    C_ERROR("Invalid config value %s(%s) < %s(%s)\n",
        CONFIG_client_version_current, client_ver_now.to_string(),
        CONFIG_client_version_minimum, client_ver_min.to_string());
    return false;
  }

  return true;
}

truefalse CCfg::read_middle(CCfgHeap & heap, CCfgKey & key)
{
  if (!is_middle())
    return true;

  u_int ival;
  if (heap.get_integer_value (key,  CONFIG_http_port, ival) == 0)
  {
    if (ival == 0 || ival >= 65535)
    {
      C_ERROR("Invalid config value %s (= %d)\n", CONFIG_http_port, ival);
      return false;
    }
    http_port = ival;
  }

  ACE_TString sval;
  if (heap.get_string_value(key, CONFIG_ftp_addr_list, sval) == 0)
    ftp_addr_list = sval.c_str();
  else
  {
    C_ERROR("can not read config value %s\n", CONFIG_ftp_addr_list);
    return false;
  }

  return true;
}

truefalse CCfg::read_client_middle(CCfgHeap & heap, CCfgKey & key)
{
  if (is_dist())
    return true;

  u_int ival;
  if (heap.get_integer_value (key,  CONFIG_middle_server_client_port, ival) == 0)
  {
    if (ival == 0 || ival >= 65535)
    {
      C_ERROR("Invalid config value %s (= %d)\n", CONFIG_middle_server_client_port, ival);
      return false;
    }
    middle_server_client_port = ival;
  }

  return true;
}

truefalse CCfg::read_client_dist(CCfgHeap & heap, CCfgKey & key)
{
  if (is_middle())
    return true;

  u_int ival;
  if (heap.get_integer_value (key, CONFIG_dist_server_heart_beat_port, ival) == 0)
  {
    if (ival == 0 || ival >= 65535)
    {
      C_ERROR("Invalid config value %s (= %d)\n", CONFIG_dist_server_heart_beat_port, ival);
      return false;
    }
    ping_port = ival;
  }

  ACE_TString sval;
  if (heap.get_string_value(key, CONFIG_middle_server_addr, sval) == 0)
    middle_addr = sval.c_str();
  else
  {
    C_ERROR("can not read config value %s\n", CONFIG_middle_server_addr);
    return false;
  }

  return true;
}

DVOID CCfg::print_all()
{
  C_INFO(ACE_TEXT ("read cfg:\n"));

  CONST text * smode;
  switch (app_mode)
  {
  case AM_DIST_SERVER:
    smode = "dist server";
    break;
  case AM_MIDDLE_SERVER:
    smode = "middle server";
    break;
  case AM_CLIENT:
    smode = "client";
    break;
  default:
    C_FATAL("bad mode (=%d).\n", app_mode);
    exit(10);
  }
  ACE_DEBUG ((LM_INFO, ACE_TEXT ("\t%s = %s\n"), CONFIG_running_mode, smode));

  ACE_DEBUG ((LM_INFO, ACE_TEXT ("\t%s = %d\n"), CONFIG_run_as_demon, as_demon));
  ACE_DEBUG ((LM_INFO, ACE_TEXT ("\t%s = %d\n"), CONFIG_use_mem_pool, use_mem_pool));
  ACE_DEBUG ((LM_INFO, ACE_TEXT ("\t%s = %d\n"), CONFIG_mem_pool_dump_interval, mem_dump_interval));
  ACE_DEBUG ((LM_INFO, ACE_TEXT ("\t%s = %d\n"), CONFIG_status_file_check_interval, file_check_interval));

  ACE_DEBUG ((LM_INFO, ACE_TEXT ("\t%s = %d\n"), CONFIG_log_file_number, log_file_count));
  ACE_DEBUG ((LM_INFO, ACE_TEXT ("\t%s = %d\n"), CONFIG_log_file_size_in_MB, log_file_size));
  ACE_DEBUG ((LM_INFO, ACE_TEXT ("\t%s = %d\n"), CONFIG_log_debug_enabled, log_debug));
  ACE_DEBUG ((LM_INFO, ACE_TEXT ("\t%s = %d\n"), CONFIG_log_to_stderr, log_stderr));

  if (g_is_test)
    ACE_DEBUG ((LM_INFO, ACE_TEXT ("\ttest_mode = 1\n")));
  else
    ACE_DEBUG ((LM_INFO, ACE_TEXT ("\ttest_mode = 0\n")));

  //dist and middle server
  if (is_server())
  {
    ACE_DEBUG ((LM_INFO, ACE_TEXT ("\t%s = %d\n"), CONFIG_max_clients, max_client_count));
    ACE_DEBUG ((LM_INFO, ACE_TEXT ("\t%s = %d\n"), CONFIG_middle_server_dist_port, middle_server_dist_port));
    ACE_DEBUG ((LM_INFO, ACE_TEXT ("\t%s = %s\n"), CONFIG_middle_server_key, skey.c_str()));
    ACE_DEBUG ((LM_INFO, ACE_TEXT ("\t%s = %s\n"), CONFIG_compressed_store_path, bz_files_path.c_str()));
    ACE_DEBUG ((LM_INFO, ACE_TEXT ("\t%s = %s\n"), CONFIG_bs_server_addr, bs_addr.c_str()));
    ACE_DEBUG ((LM_INFO, ACE_TEXT ("\t%s = %d\n"), CONFIG_bs_server_port, bs_port));
    ACE_DEBUG ((LM_INFO, ACE_TEXT ("\t%s = %s\n"), CONFIG_db_server_addr, db_addr.c_str()));
    ACE_DEBUG ((LM_INFO, ACE_TEXT ("\t%s = %d\n"), CONFIG_db_server_port, db_port));
    ACE_DEBUG ((LM_INFO, ACE_TEXT ("\t%s = %s\n"), CONFIG_db_user_name, db_name.c_str()));
  }

  //client an dist
  if (is_client() || is_dist())
  {
    ACE_DEBUG ((LM_INFO, ACE_TEXT ("\t%s = %d\n"), CONFIG_dist_server_heart_beat_port, ping_port));
    ACE_DEBUG ((LM_INFO, ACE_TEXT ("\t%s = %s\n"), CONFIG_middle_server_addr, middle_addr.c_str()));
  }

  //client and middle
  if (is_client() || is_middle())
  {
    ACE_DEBUG ((LM_INFO, ACE_TEXT ("\t%s = %d\n"), CONFIG_middle_server_client_port, middle_server_client_port));
  }

  //client only
  if (is_client())
  {
    if (g_is_test)
      ACE_DEBUG ((LM_INFO, ACE_TEXT ("\t%s = %d\n"), CONFIG_client_heart_beat_interval, client_ping_interval));
//    ACE_DEBUG ((LM_INFO, ACE_TEXT ("\t%s = %d\n"), CONFIG_adv_expire_days, adv_expire_days));
    ACE_DEBUG ((LM_INFO, ACE_TEXT ("\t%s = %d\n"), CONFIG_client_ftp_timeout, client_download_timeout));
    ACE_DEBUG ((LM_INFO, ACE_TEXT ("\t%s = %d\n"), CONFIG_client_ftp_retry_count, client_download_retry_count));
    ACE_DEBUG ((LM_INFO, ACE_TEXT ("\t%s = %d\n"), CONFIG_client_ftp_retry_interval, client_download_retry_interval));
    ACE_DEBUG ((LM_INFO, ACE_TEXT ("\t%s = %d\n"), CONFIG_client_enable_root, client_can_root));
  }

  //dist only
  if (is_dist())
  {
    ACE_DEBUG ((LM_INFO, ACE_TEXT ("\t%s = %d\n"), CONFIG_module_heart_beat_mem_pool_size, module_heart_beat_mem_pool_size));
  }

  //middle only
  if (is_middle())
  {
    ACE_DEBUG ((LM_INFO, ACE_TEXT ("\t%s = %d\n"), CONFIG_http_port, http_port));
    ACE_DEBUG ((LM_INFO, ACE_TEXT ("\t%s = %s\n"), CONFIG_ftp_addr_list, ftp_addr_list.c_str()));
  }

  //common: file/path locations printout
  ACE_DEBUG ((LM_INFO, ACE_TEXT ("\tstatus_file = %s\n"), status_fn.c_str()));
  ACE_DEBUG ((LM_INFO, ACE_TEXT ("\tlog_file = %s\n"), log_fn.c_str()));
  ACE_DEBUG ((LM_INFO, ACE_TEXT ("\tconfig_file = %s\n"), cfg_fn.c_str()));
  ACE_DEBUG ((LM_INFO, ACE_TEXT ("\tapp_path = %s\n"), app_path.c_str()));
  ACE_DEBUG ((LM_INFO, ACE_TEXT ("\texe_path = %s\n"), exe_path.c_str()));
}


//MySigHandler//
CSignaller::CSignaller(CApp * app)
{
  m_parent = app;
}

ni CSignaller::handle_signal (ni signum, siginfo_t*, ucontext_t*)
{
  m_parent->on_sig_event(signum);
  return 0;
};


//CNotificationFiler//
CNotificationFiler::CNotificationFiler(CApp * app)
{
  m_parent = app;
}

ni CNotificationFiler::handle_timeout(CONST ACE_Time_Value &, CONST DVOID *)
{
  struct stat st;
  if (::stat(CCfgX::instance()->status_fn.c_str(), &st) == -1 && errno == ENOENT)
    m_parent->on_status_file_missing();
  return 0;
}


//CPrinter//
CPrinter::CPrinter(CApp * app)
{
  m_parent = app;
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
CApp::CApp(): m_sig_handler(this), m_status_file_checker(this), m_printer(this)
{
  m_running = false;
  //moved the initializations of modules to the SF app_init() func
  //Just can NOT do it in constructor simply because the singleton pattern
  //will make recursively calls to our constructor by the module constructor's ref
  //to MyServerApp's singleton.
  //This is Ugly, but works right now
  m_sighup = false;
  m_sigterm = false;
  m_sigchld = false;
  m_status_file_ok = true;
  m_status_file_check = false;
  srandom(time(NULL));
}

truefalse CApp::on_construct()
{
  return true;
}

DVOID CApp::add_module(CMod * module)
{
  if (!module)
  {
    C_ERROR("MyBaseApp::add_module(): module is NULL\n");
    return;
  }
  m_modules.push_back(module);
}

truefalse CApp::delayed_init()
{
  CCfgX::instance()->print_all();
  C_INFO("loading modules...\n");

  m_ace_sig_handler.register_handler(SIGTERM, &m_sig_handler);
  m_ace_sig_handler.register_handler(SIGCHLD, &m_sig_handler);
  m_ace_sig_handler.register_handler(SIGHUP, &m_sig_handler);

  if (!on_construct())
    return false;

  C_INFO("loading modules done!\n");

  if (CCfgX::instance()->file_check_interval != 0)
  {
    ni fd = open(CCfgX::instance()->status_fn.c_str(), O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR);
    if (fd == -1)
    {
      C_WARNING("status_file_check_interval enabled, but can not create/open file %s\n",
          CCfgX::instance()->status_fn.c_str());
      return false;
    }
    close(fd);
    m_status_file_check = true;

    ACE_Time_Value interval (CCfgX::instance()->file_check_interval * 60);
    if (ACE_Reactor::instance()->schedule_timer (&m_status_file_checker,
                             0, interval, interval) == -1)
      C_WARNING("can not setup status_file_check timer\n");
  }

  if (CCfgX::instance()->mem_dump_interval > 0)
  {
    ACE_Time_Value interval(60 * CCfgX::instance()->mem_dump_interval);
    if (ACE_Reactor::instance()->schedule_timer (&m_printer,
                             0, interval, interval) == -1)
      C_WARNING("can not setup info dump timer\n");
  }

  ACE_Time_Value interval(CLOCK_INTERVAL);
  if (ACE_Reactor::instance()->schedule_timer(&m_clock, 0, interval, interval) == -1)
  {
    C_FATAL("can not setup clock timer\n");
    return false;
  }

  return true;
}

CApp::~CApp()
{
  m_ace_sig_handler.remove_handler(SIGHUP);
  m_ace_sig_handler.remove_handler(SIGTERM);
  if (m_status_file_check)
    ACE_Reactor::instance()->cancel_timer(&m_status_file_checker);
  if (CCfgX::instance()->mem_dump_interval > 0)
    ACE_Reactor::instance()->cancel_timer(&m_printer);
  ACE_Reactor::instance()->cancel_timer(&m_clock);
  stop();
  std::for_each(m_modules.begin(), m_modules.end(), CObjDeletor());
}

truefalse CApp::running() CONST
{
  return m_running;
}

DVOID CApp::demon()
{
  ni i;
  pid_t pid;

  if ((pid = fork()) != 0)
    exit(0);

  setsid();
  signal(SIGHUP, SIG_IGN);

  if ((pid = fork()) != 0)
    exit(0);

  umask(0);

  for (i = 0; i <= 1024; ++i)
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
  if (ACE_Service_Config::process_directive (buff) == -1)
  {
    std::printf("ACE_Service_Config::process_directive failed, args = %s\n", buff);
    exit(6);
  }
  delete []buff;
  u_long log_mask = LM_INFO | LM_WARNING | LM_ERROR;
  if (CCfgX::instance()->log_debug)
    log_mask |= LM_DEBUG;
  ACE_LOG_MSG->priority_mask (log_mask, ACE_Log_Msg::PROCESS);

  if (CCfgX::instance()->as_demon || !CCfgX::instance()->log_stderr)
    ACE_LOG_MSG->clr_flags(ACE_Log_Msg::STDERR);
  if (CCfgX::instance()->is_server())
    C_INFO("Starting server (Ver: %s)...\n", current_ver().c_str());
  else
    C_INFO("Starting client (Ver: %s)...\n", current_ver().c_str());
}

DVOID CApp::do_dump_info()
{

}

DVOID CApp::print_pool(CONST text * poolname, long nAlloc, long nFree, long nMaxUse, long nAllocFull, ni block_size, ni chunks)
{
  long nInUse = nAlloc - nFree;
  ACE_DEBUG((LM_INFO, "    pool[%s], Use=%d, Alloc=%d, "
      "Free=%d, Max=%d, Fail=%d, Size=%d, chunks=%d\n",
      poolname, nInUse, nAlloc, nFree, nMaxUse, nAllocFull, block_size, chunks));
}

DVOID CApp::print_info()
{
  C_INFO("##### Running Information Dump #####\n");
  std::for_each(m_modules.begin(), m_modules.end(), std::mem_fun(&CMod::dump_info));
  do_dump_info();
  ACE_DEBUG((LM_INFO, "##### Dump End #####\n"));
}

truefalse CApp::on_start()
{
  return true;
}

DVOID CApp::start()
{
  if (m_running)
    return;
  C_INFO("loading components...\n");
  m_running = true;
  on_start();
  std::for_each(m_modules.begin(), m_modules.end(), std::mem_fun(&CMod::start));

  C_INFO("loading components finished!\n");
  do_sigchild(); //fast delivery
  schedule_works();
}

DVOID CApp::on_stop()
{

}

DVOID CApp::stop()
{
  if (!m_running)
    return;
  C_INFO("stopping modules...\n");
  m_running = false;
  std::for_each(m_modules.begin(), m_modules.end(), std::mem_fun(&CMod::stop));
  on_stop();
  C_INFO("stopping modules done!\n");
}

DVOID CApp::on_sig_event(ni signum)
{
  switch (signum)
  {
  case SIGTERM:
    m_sigterm = true;
    break;
  case SIGHUP:
    m_sighup = true;
    break;
  case SIGCHLD:
    m_sigchld = true;
    break;
  default:
    C_ERROR("unexpected signal caught %d\n", signum);
    break;
  }
}

DVOID CApp::schedule_works()
{
  while(true)
  {
    ACE_Time_Value timeout(2);
    ACE_Reactor::instance()->run_reactor_event_loop(timeout);
    if (m_sigterm)
    {
      C_INFO("signal sigterm caught, quitting...\n");
      return;
    }
    if (m_sighup && !do_sighup())
    {
      C_INFO("signal sighup caught, quitting...\n");
      return;
    }
    if (m_sigchld && !do_sigchild())
    {
      C_INFO("signal sigchild caught, quitting...\n");
      return;
    }
    if (!m_status_file_ok)
    {
      C_INFO("status file checking failed, quitting...\n");
      return;
    }
    if (!on_event_loop())
      return;
  }
}

truefalse CApp::do_sighup()
{
  m_sighup = false;
  print_info();
  return true;
}

truefalse CApp::do_sigchild()
{
  ni st;
  pid_t x;
  m_sigchld = false;
  while ((x = ::waitpid(-1, &st, WNOHANG)) > 0)
  {
    C_INFO("child process (%d) closes...\n", (ni)x);
    if (!on_sigchild(x))
      return false;
  }
  return true;
}

truefalse CApp::on_sigchild(pid_t pid)
{
  ACE_UNUSED_ARG(pid);
  return true;
}

truefalse CApp::on_event_loop()
{
  return true;
}

DVOID CApp::on_status_file_missing()
{
  m_status_file_ok = false;
}
