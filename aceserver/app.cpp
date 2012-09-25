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

const char * g_const_app_ver = "1.0";
long g_clock_counter = 0;
bool g_is_test = false;

//MyServerConfig//

const int  DEFAULT_max_clients = 10000;
const bool DEFAULT_use_mem_pool = true;
const bool DEFAULT_run_as_demon = false;
const int  DEFAULT_status_file_check_interval = 3; //in minutes
const int  DEFAULT_mem_pool_dump_interval = 30; //in minutes

const int  DEFAULT_log_file_number = 3;
const int  DEFAULT_log_file_size_in_MB = 20;
const bool DEFAULT_log_debug_enabled = true;
const bool DEFAULT_log_to_stderr = true;

const int  DEFAULT_dist_server_heart_beat_port = 2222;
const int  DEFAULT_MODULE_HEART_BEAT_MPOOL_SIZE = DEFAULT_max_clients * 4;

const int  DEFAULT_middle_server_client_port = 2223;
const int  DEFAULT_middle_server_dist_port = 2224;
const int  DEFAULT_client_heart_beat_interval = 60; //in seconds
const int  DEFAULT_test_client_ftp_thread_number = 50;
const int  DEFAULT_db_server_port = 5432;
const int  DEFAULT_http_port = 1922;
const int  DEFAULT_bs_server_port = 1921;
const int  DEFAULT_client_ftp_timeout = 120;
const int  DEFAULT_client_ftp_retry_count = 30;
const int  DEFAULT_client_ftp_retry_interval = 4;
const int  DEFAULT_client_enable_root = 0;

//common for all
const char * CONFIG_Section_global = "global";

const char * CONFIG_test_mode = "test_mode";

const char * CONFIG_running_mode = "running_mode";
const char * CONFIG_use_mem_pool = "use_mem_pool";
const char * CONFIG_mem_pool_dump_interval = "mem_pool_dump_interval";
const char * CONFIG_run_as_demon = "run_as_demon";
const char * CONFIG_status_file_check_interval = "status_file_check_interval";

const char * CONFIG_log_debug_enabled = "log.debug_enabled";
const char * CONFIG_log_to_stderr = "log.to_stderr";
const char * CONFIG_log_file_number = "log.file_number";
const char * CONFIG_log_file_size_in_MB = "log.file_size";

const char * CONFIG_test_client_ftp_thread_number = "module.test_client_ftp_thread_number";

//dist and middle servers
const char * CONFIG_max_clients = "max_clients";
const char * CONFIG_middle_server_dist_port = "middle_server.dist_port";
const char * CONFIG_middle_server_key = "middle_server.key";
const char * CONFIG_db_server_addr = "db_server.addr";
const char * CONFIG_db_server_port = "db_server.port";
const char * CONFIG_db_user_name = "db_server.user_name";
const char * CONFIG_db_password = "db_server.password";
const char * CONFIG_compressed_store_path = "compressed_store_path";
const char * CONFIG_bs_server_addr = "bs_server_addr";
const char * CONFIG_bs_server_port = "bs_server_port";



//client and dist
const char *  CONFIG_middle_server_addr = "middle_server.addr";
const char *  CONFIG_dist_server_heart_beat_port = "module.heart_beat.port";

//client and middle
const char *  CONFIG_middle_server_client_port = "middle_server.client_port";

//middle specific
const char *  CONFIG_http_port = "middle_server.http_port";
const char *  CONFIG_ftp_addr_list = "ftp_addr_list";

//dist specific
const char * CONFIG_module_heart_beat_mem_pool_size = "module.heart_beat.mempool_size";
const char * CONFIG_client_version_minimum = "client_version_minimum";
const char * CONFIG_client_version_current = "client_version_current";
const char * CONFIG_server_id = "server_id";

//client specific
const char * CONFIG_client_heart_beat_interval = "module.client_heart_beat_interval";
const char * CONFIG_adv_expire_days = "module.adv_expire_days";
const char * CONFIG_client_ftp_timeout = "module.client_ftp_timeout";
const char * CONFIG_client_ftp_retry_count = "module.client_ftp_retry_count";
const char * CONFIG_client_ftp_retry_interval = "module.client_ftp_retry_interval";
const char * CONFIG_client_enable_root = "module.client_enable_root";


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
  log_file_size_in_MB = DEFAULT_log_file_size_in_MB;
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

void CCfg::do_init(const char * app_home_path)
{
  const size_t BUFF_SIZE = 4096;
  char path[BUFF_SIZE];

  if (!app_home_path)
  {
    ssize_t ret = readlink("/proc/self/exe", path, BUFF_SIZE);
    if (ret > 0 && ret < ssize_t(BUFF_SIZE))
    {
      path[ret] = '\0';
      app_exe_path = path;
      size_t pos = app_exe_path.rfind('/');
      if (pos == app_exe_path.npos || pos == 0)
      {
        std::printf("exe_path (= %s) error\n", path);
        exit(1);
      }
      app_exe_path = app_exe_path.substr(0, pos);
      app_path = app_exe_path;
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
    app_exe_path = app_path + "/bin";
  }

  app_status_file_name = app_path + "/running/app.pid";
  app_log_file_name = app_path + "/log/app.log";
  app_config_file_name = app_path + "/config/app.cfg";
  app_data_path = app_path + "/data";
}

bool CCfg::is_server() const
{
  return app_mode != AM_CLIENT;
}

bool CCfg::is_client() const
{
  return app_mode == AM_CLIENT;
}

bool CCfg::is_dist() const
{
  return app_mode == AM_DIST_SERVER;
}

bool CCfg::is_middle() const
{
  return app_mode == AM_MIDDLE_SERVER;
}

bool CCfg::readall(const char * home_dir, CAppMode mode)
{
  do_init(home_dir);

  app_mode = mode;

  ACE_Configuration_Heap heap;
  if (heap.open () == -1)
  {
    C_FATAL("config.open().\n");
    return false;
  }

  ACE_Registry_ImpExp bridge(heap);
  if (bridge.import_config (app_config_file_name.c_str()) == -1)
  {
    C_FATAL("import_config() failed on %s\n", app_config_file_name.c_str());
    return false;
  }

  ACE_Configuration_Section_Key sect;
  if (heap.open_section (heap.root_section (), CONFIG_Section_global,
                           0, sect) == -1)
  {
    C_FATAL("config.open_section failed, section = %s\n", CONFIG_Section_global);
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

bool CCfg::read_base(ACE_Configuration_Heap & heap, ACE_Configuration_Section_Key & section)
{
  u_int ival;
  if (app_mode == AM_UNKNOWN)
  {
    if (heap.get_integer_value (section,  CONFIG_running_mode, ival) == 0)
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

  if (heap.get_integer_value (section,  CONFIG_test_mode, ival) == 0)
    g_is_test = (ival != 0);

  if (heap.get_integer_value (section,  CONFIG_use_mem_pool, ival) == 0)
  {
    use_mem_pool = (ival != 0);
    g_use_mem_pool = use_mem_pool;
  }

  if (heap.get_integer_value (section,  CONFIG_run_as_demon, ival) == 0)
    as_demon = (ival != 0);

  if (heap.get_integer_value (section,  CONFIG_status_file_check_interval, ival) == 0)
    file_check_interval = ival;

  if (heap.get_integer_value (section,  CONFIG_log_file_number, ival) == 0)
  {
    if (ival > 0 && ival <= 1000)
      log_file_count = ival;
  }

  if (heap.get_integer_value (section,  CONFIG_log_file_size_in_MB, ival) == 0)
  {
    if (ival > 0 && ival <= 10000)
      log_file_size_in_MB = ival;
  }

  if (heap.get_integer_value (section,  CONFIG_log_debug_enabled, ival) == 0)
    log_debug = (ival != 0);

  if (heap.get_integer_value (section,  CONFIG_log_to_stderr, ival) == 0)
    log_stderr = (ival != 0);

  if (heap.get_integer_value (section,  CONFIG_mem_pool_dump_interval, ival) == 0)
    mem_dump_interval = ival;

  return true;
}

bool CCfg::read_dist_middle(ACE_Configuration_Heap & heap, ACE_Configuration_Section_Key & section)
{
  if (!is_server())
    return true;

  u_int ival;
  if (heap.get_integer_value (section,  CONFIG_max_clients, ival) == 0)
  {
    if (ival > 0 && ival <= 100000) //the upper limit of 100000 is more than enough?
    {
      max_client_count = ival;
    }
  }

  ACE_TString sval;
  if (heap.get_string_value(section, CONFIG_middle_server_key, sval) == 0)
    middle_server_key = sval.c_str();
  else
  {
    C_ERROR("can not read config value %s\n", CONFIG_middle_server_key);
    return false;
  }

  if (heap.get_integer_value (section,  CONFIG_middle_server_dist_port, ival) == 0)
  {
    if (ival == 0 || ival >= 65535)
    {
      C_ERROR("Invalid config value %s (= %d)\n", CONFIG_middle_server_dist_port, ival);
      return false;
    }
    middle_server_dist_port = ival;
  }

  if (heap.get_string_value(section, CONFIG_db_server_addr, sval) == 0)
    db_addr = sval.c_str();
  else
  {
    C_ERROR("can not read config value %s\n", CONFIG_db_server_addr);
    return false;
  }

  if (heap.get_integer_value (section,  CONFIG_db_server_port, ival) == 0)
  {
    if (ival == 0 || ival >= 65535)
    {
      C_ERROR("Invalid config value %s (= %d)\n", CONFIG_db_server_port, ival);
      return false;
    }
    db_port = ival;
  }

  if (heap.get_string_value(section, CONFIG_db_user_name, sval) == 0)
    db_name = sval.c_str();
  else
  {
    C_ERROR("can not read config value %s\n", CONFIG_db_user_name);
    return false;
  }

  if (heap.get_string_value(section, CONFIG_db_password, sval) == 0)
    db_password = sval.c_str();
  else
  {
    C_ERROR("can not read config value %s\n", CONFIG_db_password);
    return false;
  }

  if (heap.get_string_value(section, CONFIG_compressed_store_path, sval) == 0)
    compressed_store_path = sval.c_str();
  else
  {
    C_ERROR("can not read config value %s\n", CONFIG_compressed_store_path);
    return false;
  }

  if (heap.get_string_value(section, CONFIG_bs_server_addr, sval) == 0)
    bs_addr = sval.c_str();
  else
  {
    C_ERROR("can not read config value %s\n", CONFIG_bs_server_addr);
    return false;
  }

  if (heap.get_integer_value(section, CONFIG_bs_server_port, ival) == 0)
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

bool CCfg::read_client(ACE_Configuration_Heap & heap, ACE_Configuration_Section_Key & section)
{
  if (is_server())
    return true;

  u_int ival;

  if (g_is_test)
  {
    if (heap.get_integer_value(section, CONFIG_client_heart_beat_interval, ival) == 0)
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
    if (heap.get_integer_value(section, CONFIG_test_client_ftp_thread_number, ival) == 0)
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

  if (heap.get_integer_value(section, CONFIG_adv_expire_days, ival) == 0)
  {
    if (ival > 365)
    {
      C_WARNING("Invalid %s value (%d), using default value = %d\n",
          CONFIG_adv_expire_days, ival, 0);
    }
    else
      client_adv_expire_days = ival;
  }

  if (heap.get_integer_value(section, CONFIG_client_ftp_timeout, ival) == 0)
  {
    if (ival < 60)
    {
      C_WARNING("Invalid %s value (%d), using default value = %d\n",
          CONFIG_client_ftp_timeout, ival, DEFAULT_client_ftp_timeout);
    }
    else
      client_download_timeout = ival;
  }

  if (heap.get_integer_value(section, CONFIG_client_ftp_retry_count, ival) == 0)
  {
    if (ival < 1 || ival > 100000)
    {
      C_WARNING("Invalid %s value (%d), using default value = %d\n",
          CONFIG_client_ftp_retry_count, ival, DEFAULT_client_ftp_retry_count);
    }
    else
      client_download_retry_count = ival;
  }

  if (heap.get_integer_value(section, CONFIG_client_ftp_retry_interval, ival) == 0)
  {
    if (ival < 1 || ival > 60)
    {
      C_WARNING("Invalid %s value (%d), using default value = %d\n",
          CONFIG_client_ftp_retry_interval, ival, DEFAULT_client_ftp_retry_interval);
    }
    else
      client_download_retry_interval = ival;
  }

  if (heap.get_integer_value(section, CONFIG_client_enable_root, ival) == 0)
    client_can_root = ival;

  return true;
}

bool CCfg::read_dist(ACE_Configuration_Heap & heap, ACE_Configuration_Section_Key & section)
{
  if (!is_dist())
    return true;

  u_int ival;

  if (heap.get_integer_value(section, CONFIG_module_heart_beat_mem_pool_size, ival) == 0)
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

  if (heap.get_integer_value(section, CONFIG_server_id, ival) == 0)
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
  if (heap.get_string_value(section, CONFIG_client_version_minimum, sval) == 0)
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

  if (heap.get_string_value(section, CONFIG_client_version_current, sval) == 0)
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

bool CCfg::read_middle(ACE_Configuration_Heap & heap, ACE_Configuration_Section_Key & section)
{
  if (!is_middle())
    return true;

  u_int ival;
  if (heap.get_integer_value (section,  CONFIG_http_port, ival) == 0)
  {
    if (ival == 0 || ival >= 65535)
    {
      C_ERROR("Invalid config value %s (= %d)\n", CONFIG_http_port, ival);
      return false;
    }
    http_port = ival;
  }

  ACE_TString sval;
  if (heap.get_string_value(section, CONFIG_ftp_addr_list, sval) == 0)
    ftp_addr_list = sval.c_str();
  else
  {
    C_ERROR("can not read config value %s\n", CONFIG_ftp_addr_list);
    return false;
  }

  return true;
}

bool CCfg::read_client_middle(ACE_Configuration_Heap & heap, ACE_Configuration_Section_Key & section)
{
  if (is_dist())
    return true;

  u_int ival;
  if (heap.get_integer_value (section,  CONFIG_middle_server_client_port, ival) == 0)
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

bool CCfg::read_client_dist(ACE_Configuration_Heap & heap, ACE_Configuration_Section_Key & section)
{
  if (is_middle())
    return true;

  u_int ival;
  if (heap.get_integer_value (section, CONFIG_dist_server_heart_beat_port, ival) == 0)
  {
    if (ival == 0 || ival >= 65535)
    {
      C_ERROR("Invalid config value %s (= %d)\n", CONFIG_dist_server_heart_beat_port, ival);
      return false;
    }
    ping_port = ival;
  }

  ACE_TString sval;
  if (heap.get_string_value(section, CONFIG_middle_server_addr, sval) == 0)
    middle_addr = sval.c_str();
  else
  {
    C_ERROR("can not read config value %s\n", CONFIG_middle_server_addr);
    return false;
  }

  return true;
}

void CCfg::print_all()
{
  C_INFO(ACE_TEXT ("read cfg:\n"));

  const char * smode;
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
  ACE_DEBUG ((LM_INFO, ACE_TEXT ("\t%s = %d\n"), CONFIG_log_file_size_in_MB, log_file_size_in_MB));
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
    ACE_DEBUG ((LM_INFO, ACE_TEXT ("\t%s = %s\n"), CONFIG_middle_server_key, middle_server_key.c_str()));
    ACE_DEBUG ((LM_INFO, ACE_TEXT ("\t%s = %s\n"), CONFIG_compressed_store_path, compressed_store_path.c_str()));
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
  ACE_DEBUG ((LM_INFO, ACE_TEXT ("\tstatus_file = %s\n"), app_status_file_name.c_str()));
  ACE_DEBUG ((LM_INFO, ACE_TEXT ("\tlog_file = %s\n"), app_log_file_name.c_str()));
  ACE_DEBUG ((LM_INFO, ACE_TEXT ("\tconfig_file = %s\n"), app_config_file_name.c_str()));
  ACE_DEBUG ((LM_INFO, ACE_TEXT ("\tapp_path = %s\n"), app_path.c_str()));
  ACE_DEBUG ((LM_INFO, ACE_TEXT ("\texe_path = %s\n"), app_exe_path.c_str()));
}


//MySigHandler//
CSignaller::CSignaller(CApp * app)
{
  m_app = app;
}

int CSignaller::handle_signal (int signum, siginfo_t*, ucontext_t*)
{
  m_app->on_sig_event(signum);
  return 0;
};


//CNotificationFiler//
CNotificationFiler::CNotificationFiler(CApp * app)
{
  m_app = app;
}

int CNotificationFiler::handle_timeout(const ACE_Time_Value &, const void *)
{
  struct stat st;
  if (::stat(CCfgX::instance()->app_status_file_name.c_str(), &st) == -1 && errno == ENOENT)
    m_app->on_status_file_missing();
  return 0;
}


//CPrinter//
CPrinter::CPrinter(CApp * app)
{
  m_app = app;
}

int CPrinter::handle_timeout (const ACE_Time_Value &, const void *)
{
  m_app->print_info();
  return 0;
}


//CClocker//

int CClocker::handle_timeout (const ACE_Time_Value &, const void *)
{
  ++g_clock_counter;
  return 0;
}


//CApp//
CApp::CApp(): m_sig_handler(this), m_status_file_checker(this), m_info_dumper(this)
{
  m_is_running = false;
  //moved the initializations of modules to the static app_init() func
  //Just can NOT do it in constructor simply because the singleton pattern
  //will make recursively calls to our constructor by the module constructor's ref
  //to MyServerApp's singleton.
  //This is Ugly, but works right now
  m_sighup = false;
  m_sigterm = false;
  m_sigchld = false;
  m_status_file_ok = true;
  m_status_file_checking = false;
  srandom(time(NULL));
}

bool CApp::on_construct()
{
  return true;
}

void CApp::add_module(CMod * module)
{
  if (!module)
  {
    C_ERROR("MyBaseApp::add_module(): module is NULL\n");
    return;
  }
  m_modules.push_back(module);
}

bool CApp::do_constructor()
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
    int fd = open(CCfgX::instance()->app_status_file_name.c_str(), O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR);
    if (fd == -1)
    {
      C_WARNING("status_file_check_interval enabled, but can not create/open file %s\n",
          CCfgX::instance()->app_status_file_name.c_str());
      return false;
    }
    close(fd);
    m_status_file_checking = true;

    ACE_Time_Value interval (CCfgX::instance()->file_check_interval * 60);
    if (ACE_Reactor::instance()->schedule_timer (&m_status_file_checker,
                             0, interval, interval) == -1)
      C_WARNING("can not setup status_file_check timer\n");
  }

  if (CCfgX::instance()->mem_dump_interval > 0)
  {
    ACE_Time_Value interval(60 * CCfgX::instance()->mem_dump_interval);
    if (ACE_Reactor::instance()->schedule_timer (&m_info_dumper,
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
  if (m_status_file_checking)
    ACE_Reactor::instance()->cancel_timer(&m_status_file_checker);
  if (CCfgX::instance()->mem_dump_interval > 0)
    ACE_Reactor::instance()->cancel_timer(&m_info_dumper);
  ACE_Reactor::instance()->cancel_timer(&m_clock);
  stop();
  std::for_each(m_modules.begin(), m_modules.end(), CObjDeletor());
}

bool CApp::running() const
{
  return m_is_running;
}

void CApp::demon()
{
  int i;
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

void CApp::init_log()
{
  const char * cmd = "dynamic Logger Service_Object *ACE:_make_ACE_Logging_Strategy()"
   "\"-o -s %s -N %d -m %d000 -i 1 -f STDERR|OSTREAM \"";

  int m = strlen(cmd) + CCfgX::instance()->app_log_file_name.length() + 100;
  char * buff = new char[m];
  std::snprintf(buff, m, cmd, CCfgX::instance()->app_log_file_name.c_str(),
      CCfgX::instance()->log_file_count,
      CCfgX::instance()->log_file_size_in_MB);
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

void CApp::do_dump_info()
{

}

void CApp::print_pool_one(const char * poolname, long nAlloc, long nFree, long nMaxUse, long nAllocFull, int block_size, int chunks)
{
  long nInUse = nAlloc - nFree;
  ACE_DEBUG((LM_INFO, "    pool[%s], Use=%d, Alloc=%d, "
      "Free=%d, Max=%d, Fail=%d, Size=%d, chunks=%d\n",
      poolname, nInUse, nAlloc, nFree, nMaxUse, nAllocFull, block_size, chunks));
}

void CApp::print_info()
{
  C_INFO("##### Running Information Dump #####\n");
  std::for_each(m_modules.begin(), m_modules.end(), std::mem_fun(&CMod::dump_info));
  do_dump_info();
  ACE_DEBUG((LM_INFO, "##### Dump End #####\n"));
}

bool CApp::on_start()
{
  return true;
}

void CApp::start()
{
  if (m_is_running)
    return;
  C_INFO("starting modules...\n");
  m_is_running = true;
  on_start();
  std::for_each(m_modules.begin(), m_modules.end(), std::mem_fun(&CMod::start));

  C_INFO("starting modules done!\n");
  do_sigchild(); //fast delivery
  do_event_loop();
}

void CApp::on_stop()
{

}

void CApp::stop()
{
  if (!m_is_running)
    return;
  C_INFO("stopping modules...\n");
  m_is_running = false;
  std::for_each(m_modules.begin(), m_modules.end(), std::mem_fun(&CMod::stop));
  on_stop();
  C_INFO("stopping modules done!\n");
}

void CApp::on_sig_event(int signum)
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

void CApp::do_event_loop()
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

bool CApp::do_sighup()
{
  m_sighup = false;
  print_info();
  return true;
}

bool CApp::do_sigchild()
{
  int status;
  pid_t pid;
  m_sigchld = false;
  while ((pid = ::waitpid(-1, &status, WNOHANG)) > 0)
  {
    C_INFO("child process (%d) closes...\n", (int)pid);
    if (!on_sigchild(pid))
      return false;
  }
  return true;
}

bool CApp::on_sigchild(pid_t pid)
{
  ACE_UNUSED_ARG(pid);
  return true;
}

bool CApp::on_event_loop()
{
  return true;
}

void CApp::on_status_file_missing()
{
  m_status_file_ok = false;
}
