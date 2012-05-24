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
#include "baseapp.h"

const ACE_TCHAR * const_app_version = ACE_TEXT("1.0");
long g_clock_tick = 0;
bool g_test_mode = false;

//MyServerConfig//

const int  DEFAULT_max_clients = 10000;
const bool DEFAULT_use_mem_pool = true;
const bool DEFAULT_run_as_demon = false;
const int  DEFAULT_status_file_check_interval = 3; //in minutes
const int  DEFAULT_message_control_block_mem_pool_size = DEFAULT_max_clients * 5;
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
const int  DEFAULT_client_ftp_retry_interval = 3;

//common for all
const ACE_TCHAR * CONFIG_Section_global = ACE_TEXT("global");

const ACE_TCHAR * CONFIG_test_mode = ACE_TEXT("test_mode");

const ACE_TCHAR * CONFIG_running_mode = ACE_TEXT("running_mode");
const ACE_TCHAR * CONFIG_use_mem_pool = ACE_TEXT("use_mem_pool");
const ACE_TCHAR * CONFIG_mem_pool_dump_interval = ACE_TEXT("mem_pool_dump_interval");
const ACE_TCHAR * CONFIG_message_control_block_mem_pool_size = ACE_TEXT("message_control_block_mempool_size");
const ACE_TCHAR * CONFIG_run_as_demon = ACE_TEXT("run_as_demon");
const ACE_TCHAR * CONFIG_status_file_check_interval = ACE_TEXT("status_file_check_interval");

const ACE_TCHAR * CONFIG_log_debug_enabled = ACE_TEXT("log.debug_enabled");
const ACE_TCHAR * CONFIG_log_to_stderr = ACE_TEXT("log.to_stderr");
const ACE_TCHAR * CONFIG_log_file_number = ACE_TEXT("log.file_number");
const ACE_TCHAR * CONFIG_log_file_size_in_MB = ACE_TEXT("log.file_size");

const ACE_TCHAR * CONFIG_test_client_ftp_thread_number = ACE_TEXT("module.test_client_ftp_thread_number");

//dist and middle servers
const ACE_TCHAR * CONFIG_max_clients = ACE_TEXT("max_clients");
const ACE_TCHAR * CONFIG_middle_server_dist_port = ACE_TEXT("middle_server.dist_port");
const ACE_TCHAR * CONFIG_middle_server_key = ACE_TEXT("middle_server.key");
const ACE_TCHAR * CONFIG_db_server_addr = ACE_TEXT("db_server.addr");
const ACE_TCHAR * CONFIG_db_server_port = ACE_TEXT("db_server.port");
const ACE_TCHAR * CONFIG_db_user_name = ACE_TEXT("db_server.user_name");
const ACE_TCHAR * CONFIG_db_password = ACE_TEXT("db_server.password");
const ACE_TCHAR * CONFIG_compressed_store_path = ACE_TEXT("compressed_store_path");
const ACE_TCHAR * CONFIG_bs_server_addr = ACE_TEXT("bs_server_addr");
const ACE_TCHAR * CONFIG_bs_server_port = ACE_TEXT("bs_server_port");



//client and dist
const ACE_TCHAR *  CONFIG_middle_server_addr = ACE_TEXT("middle_server.addr");
const ACE_TCHAR *  CONFIG_dist_server_heart_beat_port = ACE_TEXT("module.heart_beat.port");

//client and middle
const ACE_TCHAR *  CONFIG_middle_server_client_port = ACE_TEXT("middle_server.client_port");

//middle specific
const ACE_TCHAR *  CONFIG_http_port = ACE_TEXT("middle_server.http_port");
const ACE_TCHAR *  CONFIG_ftp_addr_list = ACE_TEXT("ftp_addr_list");

//dist specific
const ACE_TCHAR * CONFIG_module_heart_beat_mem_pool_size = ACE_TEXT("module.heart_beat.mempool_size");
const ACE_TCHAR * CONFIG_client_version_minimum = ACE_TEXT("client_version_minimum");
const ACE_TCHAR * CONFIG_client_version_current = ACE_TEXT("client_version_current");
const ACE_TCHAR * CONFIG_server_id = ACE_TEXT("server_id");

//client specific
const ACE_TCHAR * CONFIG_client_heart_beat_interval = ACE_TEXT("module.client_heart_beat_interval");
const ACE_TCHAR * CONFIG_adv_expire_days = ACE_TEXT("module.adv_expire_days");
const ACE_TCHAR * CONFIG_client_ftp_timeout = ACE_TEXT("module.client_ftp_timeout");
const ACE_TCHAR * CONFIG_client_ftp_retry_count = ACE_TEXT("module.client_ftp_retry_count");

MyConfig::MyConfig()
{
  //common configuration
  running_mode = RM_UNKNOWN;
  use_mem_pool = DEFAULT_use_mem_pool;
  run_as_demon = DEFAULT_run_as_demon;
  mem_pool_dump_interval = DEFAULT_mem_pool_dump_interval;
  status_file_check_interval = DEFAULT_status_file_check_interval;
  message_control_block_mem_pool_size = DEFAULT_message_control_block_mem_pool_size;

  log_debug_enabled = DEFAULT_log_debug_enabled;
  log_file_number = DEFAULT_log_file_number;
  log_file_size_in_MB = DEFAULT_log_file_size_in_MB;
  log_to_stderr = DEFAULT_log_to_stderr;

  //dist and middle server
  max_clients = DEFAULT_max_clients;
  middle_server_dist_port = DEFAULT_middle_server_dist_port;
  db_server_port = DEFAULT_db_server_port;
  bs_server_port = DEFAULT_bs_server_port;

  //client and dist
  middle_server_client_port = DEFAULT_middle_server_client_port;

  //dist server only
  dist_server_heart_beat_port = DEFAULT_dist_server_heart_beat_port;
  module_heart_beat_mem_pool_size = DEFAULT_MODULE_HEART_BEAT_MPOOL_SIZE;
  server_id = 1;

  //client only
  client_heart_beat_interval = DEFAULT_client_heart_beat_interval;
  test_client_ftp_thread_number = DEFAULT_test_client_ftp_thread_number;
  adv_expire_days = 0;
  client_ftp_timeout = DEFAULT_client_ftp_timeout;
  client_ftp_retry_count = DEFAULT_client_ftp_retry_count;
  client_ftp_retry_interval = DEFAULT_client_ftp_retry_interval;

  //middle only
  http_port = DEFAULT_http_port;
}

void MyConfig::init_path(const char * app_home_path)
{
  const size_t BUFF_SIZE = 4096;
  char path[BUFF_SIZE];

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

  status_file_name = app_path + "/running/app.pid";
  log_file_name = app_path + "/log/app.log";
  config_file_name = app_path + "/config/app.cfg";
  app_data_path = app_path + "/data";
}

bool MyConfig::is_server() const
{
  return running_mode != RM_CLIENT;
}

bool MyConfig::is_client() const
{
  return running_mode == RM_CLIENT;
}

bool MyConfig::is_dist_server() const
{
  return running_mode == RM_DIST_SERVER;
}

bool MyConfig::is_middle_server() const
{
  return running_mode == RM_MIDDLE_SERVER;
}

bool MyConfig::load_config(const char * app_home_path, RUNNING_MODE mode)
{
  init_path(app_home_path);

  running_mode = mode;

  ACE_Configuration_Heap cfgHeap;
  if (cfgHeap.open () == -1)
  {
    MY_FATAL("config.open().\n");
    return false;
  }

  ACE_Registry_ImpExp config_importer(cfgHeap);
  if (config_importer.import_config (config_file_name.c_str()) == -1)
  {
    MY_FATAL("import_config() failed on %s\n", config_file_name.c_str());
    return false;
  }

  ACE_Configuration_Section_Key section;
  if (cfgHeap.open_section (cfgHeap.root_section (), CONFIG_Section_global,
                           0, section) == -1)
  {
    MY_FATAL("config.open_section failed, section = %s\n", CONFIG_Section_global);
    return false;
  }

  if (!load_config_common(cfgHeap, section))
    return false;

  if (running_mode <= RM_UNKNOWN || running_mode > RM_CLIENT)
  {
    MY_FATAL("unknown running mode (= %d)", running_mode);
    return false;
  }

  if (!load_config_dist_middle(cfgHeap, section))
    return false;

  if (!load_config_client_middle(cfgHeap, section))
    return false;

  if (!load_config_client_dist(cfgHeap, section))
    return false;

  if (!load_config_dist(cfgHeap, section))
    return false;

  if (!load_config_middle(cfgHeap, section))
    return false;

  if (!load_config_client(cfgHeap, section))
    return false;

  return true;
}

bool MyConfig::load_config_common(ACE_Configuration_Heap & cfgHeap, ACE_Configuration_Section_Key & section)
{
  u_int ival;
  if (running_mode == RM_UNKNOWN)
  {
    if (cfgHeap.get_integer_value (section,  CONFIG_running_mode, ival) == 0)
    {
      if (ival != RM_DIST_SERVER && ival != RM_MIDDLE_SERVER)
      {
        MY_FATAL("invalid server running mode = %d\n", ival);
        return false;
      }
      running_mode = RUNNING_MODE(ival);
    } else
    {
      MY_FATAL("can not read server running mode\n");
      return false;
    }
  }

  if (cfgHeap.get_integer_value (section,  CONFIG_test_mode, ival) == 0)
    g_test_mode = (ival != 0);

  if (cfgHeap.get_integer_value (section,  CONFIG_use_mem_pool, ival) == 0)
  {
    use_mem_pool = (ival != 0);
    g_use_mem_pool = use_mem_pool;
  }

  if (cfgHeap.get_integer_value (section,  CONFIG_run_as_demon, ival) == 0)
    run_as_demon = (ival != 0);

  if (cfgHeap.get_integer_value (section,  CONFIG_status_file_check_interval, ival) == 0)
    status_file_check_interval = ival;

  if (cfgHeap.get_integer_value (section,  CONFIG_log_file_number, ival) == 0)
  {
    if (ival > 0 && ival <= 1000)
      log_file_number = ival;
  }

  if (cfgHeap.get_integer_value (section,  CONFIG_log_file_size_in_MB, ival) == 0)
  {
    if (ival > 0 && ival <= 10000)
      log_file_size_in_MB = ival;
  }

  if (cfgHeap.get_integer_value (section,  CONFIG_log_debug_enabled, ival) == 0)
    log_debug_enabled = (ival != 0);

  if (cfgHeap.get_integer_value (section,  CONFIG_log_to_stderr, ival) == 0)
    log_to_stderr = (ival != 0);

  if (cfgHeap.get_integer_value (section,  CONFIG_mem_pool_dump_interval, ival) == 0)
    mem_pool_dump_interval = ival;

//  if (cfgHeap.get_integer_value (section,  CONFIG_message_control_block_mem_pool_size, ival) == 0)
//  {
//    if (ival > 0 && ival < 1000000)
//      message_control_block_mem_pool_size = ival;
//  }
//  else if (is_client())
//    message_control_block_mem_pool_size = 1000;

  return true;
}

bool MyConfig::load_config_dist_middle(ACE_Configuration_Heap & cfgHeap, ACE_Configuration_Section_Key & section)
{
  if (!is_server())
    return true;

  u_int ival;
  if (cfgHeap.get_integer_value (section,  CONFIG_max_clients, ival) == 0)
  {
    if (ival > 0 && ival <= 100000) //the upper limit of 100000 is more than enough?
    {
      max_clients = ival;
    }
  }

  ACE_TString sval;
  if (cfgHeap.get_string_value(section, CONFIG_middle_server_key, sval) == 0)
    middle_server_key = sval.c_str();
  else
  {
    MY_ERROR("can not read config value %s\n", CONFIG_middle_server_key);
    return false;
  }

  if (cfgHeap.get_integer_value (section,  CONFIG_middle_server_dist_port, ival) == 0)
  {
    if (ival == 0 || ival >= 65535)
    {
      MY_ERROR(ACE_TEXT("Invalid config value %s (= %d)\n"), CONFIG_middle_server_dist_port, ival);
      return false;
    }
    middle_server_dist_port = ival;
  }

  if (cfgHeap.get_string_value(section, CONFIG_db_server_addr, sval) == 0)
    db_server_addr = sval.c_str();
  else
  {
    MY_ERROR("can not read config value %s\n", CONFIG_db_server_addr);
    return false;
  }

  if (cfgHeap.get_integer_value (section,  CONFIG_db_server_port, ival) == 0)
  {
    if (ival == 0 || ival >= 65535)
    {
      MY_ERROR(ACE_TEXT("Invalid config value %s (= %d)\n"), CONFIG_db_server_port, ival);
      return false;
    }
    db_server_port = ival;
  }

  if (cfgHeap.get_string_value(section, CONFIG_db_user_name, sval) == 0)
    db_user_name = sval.c_str();
  else
  {
    MY_ERROR("can not read config value %s\n", CONFIG_db_user_name);
    return false;
  }

  if (cfgHeap.get_string_value(section, CONFIG_db_password, sval) == 0)
    db_password = sval.c_str();
  else
  {
    MY_ERROR("can not read config value %s\n", CONFIG_db_password);
    return false;
  }

  if (cfgHeap.get_string_value(section, CONFIG_compressed_store_path, sval) == 0)
    compressed_store_path = sval.c_str();
  else
  {
    MY_ERROR("can not read config value %s\n", CONFIG_compressed_store_path);
    return false;
  }

  if (cfgHeap.get_string_value(section, CONFIG_bs_server_addr, sval) == 0)
    bs_server_addr = sval.c_str();
  else
  {
    MY_ERROR("can not read config value %s\n", CONFIG_bs_server_addr);
    return false;
  }

  if (cfgHeap.get_integer_value(section, CONFIG_bs_server_port, ival) == 0)
  {
    if (ival == 0 || ival >= 65535)
    {
      MY_ERROR(ACE_TEXT("Invalid config value %s (= %d)\n"), CONFIG_bs_server_port, ival);
      return false;
    }
    bs_server_port = ival;
  }

  return true;
}

bool MyConfig::load_config_client(ACE_Configuration_Heap & cfgHeap, ACE_Configuration_Section_Key & section)
{
  if (is_server())
    return true;

  u_int ival;

  if (g_test_mode)
  {
    if (cfgHeap.get_integer_value(section, CONFIG_client_heart_beat_interval, ival) == 0)
    {
      if (ival == 0 || ival > 0xFFFF)
      {
        MY_WARNING(ACE_TEXT("Invalid %s value (= %d), using default value = %d\n"),
            CONFIG_module_heart_beat_mem_pool_size, ival, DEFAULT_client_heart_beat_interval);
      }
      else
        client_heart_beat_interval = ival;
    }
  }

  if (g_test_mode)
  {
    if (cfgHeap.get_integer_value(section, CONFIG_test_client_ftp_thread_number, ival) == 0)
    {
      if (ival == 0 || ival > 500)
      {
        MY_WARNING(ACE_TEXT("Invalid %s value (= %d), using default value = %d\n"),
            CONFIG_test_client_ftp_thread_number, ival, DEFAULT_test_client_ftp_thread_number);
      }
      else
        test_client_ftp_thread_number = ival;
    }
  }

  if (cfgHeap.get_integer_value(section, CONFIG_adv_expire_days, ival) == 0)
  {
    if (ival > 365)
    {
      MY_WARNING(ACE_TEXT("Invalid %s value (%d), using default value = %d\n"),
          CONFIG_adv_expire_days, ival, 0);
    }
    else
      adv_expire_days = ival;
  }

  if (cfgHeap.get_integer_value(section, CONFIG_client_ftp_timeout, ival) == 0)
  {
    if (ival < 60)
    {
      MY_WARNING(ACE_TEXT("Invalid %s value (%d), using default value = %d\n"),
          CONFIG_client_ftp_timeout, ival, DEFAULT_client_ftp_timeout);
    }
    else
      client_ftp_timeout = ival;
  }

  if (cfgHeap.get_integer_value(section, CONFIG_client_ftp_retry_count, ival) == 0)
  {
    if (ival < 1 || ival > 100000)
    {
      MY_WARNING(ACE_TEXT("Invalid %s value (%d), using default value = %d\n"),
          CONFIG_client_ftp_retry_count, ival, DEFAULT_client_ftp_retry_count);
    }
    else
      client_ftp_timeout = ival;
  }

  return true;
}

bool MyConfig::load_config_dist(ACE_Configuration_Heap & cfgHeap, ACE_Configuration_Section_Key & section)
{
  if (!is_dist_server())
    return true;

  u_int ival;

  if (cfgHeap.get_integer_value(section, CONFIG_module_heart_beat_mem_pool_size, ival) == 0)
  {
    u_int itemp = std::max(2 * max_clients, 1000);
    if (ival < itemp)
    {
      MY_WARNING(ACE_TEXT("Invalid %s value (= %d), should at least max(2 * %s, 1000) = %d, will adjust to %d\n"),
          CONFIG_module_heart_beat_mem_pool_size, ival, CONFIG_max_clients, itemp, itemp);
    }
    else
      module_heart_beat_mem_pool_size = ival;
  }

  if (cfgHeap.get_integer_value(section, CONFIG_server_id, ival) == 0)
  {
    if (ival <= 1 || ival >= 256)
    {
      MY_ERROR(ACE_TEXT("Invalid config value %s: %d\n"), CONFIG_server_id, ival);
      return false;
    }
    server_id = (u_int8_t)ival;
  }
  else
  {
    MY_ERROR(ACE_TEXT("can not read config value %s\n"), CONFIG_server_id);
    return false;
  }

  ACE_TString sval;
  if (cfgHeap.get_string_value(section, CONFIG_client_version_minimum, sval) == 0)
  {
    if (!client_version_minimum.from_string(sval.c_str()))
    {
      MY_ERROR(ACE_TEXT("Invalid config value %s: %s\n"), CONFIG_client_version_minimum, sval.c_str());
      return false;
    }
  }
  else
  {
    MY_ERROR(ACE_TEXT("can not read config value %s\n"), CONFIG_client_version_minimum);
    return false;
  }

  if (cfgHeap.get_string_value(section, CONFIG_client_version_current, sval) == 0)
  {
    if (!client_version_current.from_string(sval.c_str()))
    {
      MY_ERROR(ACE_TEXT("Invalid config value %s: %s\n"), CONFIG_client_version_current, sval.c_str());
      return false;
    }
  }
  else
  {
    MY_ERROR(ACE_TEXT("can not read config value %s\n"), CONFIG_client_version_current);
    return false;
  }

  if (client_version_current < client_version_minimum)
  {
    MY_ERROR(ACE_TEXT("Invalid config value %s(%s) < %s(%s)\n"),
        CONFIG_client_version_current, client_version_current.to_string(),
        CONFIG_client_version_minimum, client_version_minimum.to_string());
    return false;
  }

  return true;
}

bool MyConfig::load_config_middle(ACE_Configuration_Heap & cfgHeap, ACE_Configuration_Section_Key & section)
{
  if (!is_middle_server())
    return true;

  u_int ival;
  if (cfgHeap.get_integer_value (section,  CONFIG_http_port, ival) == 0)
  {
    if (ival == 0 || ival >= 65535)
    {
      MY_ERROR(ACE_TEXT("Invalid config value %s (= %d)\n"), CONFIG_http_port, ival);
      return false;
    }
    http_port = ival;
  }

  ACE_TString sval;
  if (cfgHeap.get_string_value(section, CONFIG_ftp_addr_list, sval) == 0)
    ftp_addr_list = sval.c_str();
  else
  {
    MY_ERROR(ACE_TEXT("can not read config value %s\n"), CONFIG_ftp_addr_list);
    return false;
  }

  return true;
}

bool MyConfig::load_config_client_middle(ACE_Configuration_Heap & cfgHeap, ACE_Configuration_Section_Key & section)
{
  if (is_dist_server())
    return true;

  u_int ival;
  if (cfgHeap.get_integer_value (section,  CONFIG_middle_server_client_port, ival) == 0)
  {
    if (ival == 0 || ival >= 65535)
    {
      MY_ERROR(ACE_TEXT("Invalid config value %s (= %d)\n"), CONFIG_middle_server_client_port, ival);
      return false;
    }
    middle_server_client_port = ival;
  }

  return true;
}

bool MyConfig::load_config_client_dist(ACE_Configuration_Heap & cfgHeap, ACE_Configuration_Section_Key & section)
{
  if (is_middle_server())
    return true;

  u_int ival;
  if (cfgHeap.get_integer_value (section, CONFIG_dist_server_heart_beat_port, ival) == 0)
  {
    if (ival == 0 || ival >= 65535)
    {
      MY_ERROR(ACE_TEXT("Invalid config value %s (= %d)\n"), CONFIG_dist_server_heart_beat_port, ival);
      return false;
    }
    dist_server_heart_beat_port = ival;
  }

  ACE_TString sval;
  if (cfgHeap.get_string_value(section, CONFIG_middle_server_addr, sval) == 0)
    middle_server_addr = sval.c_str();
  else
  {
    MY_ERROR(ACE_TEXT("can not read config value %s\n"), CONFIG_middle_server_addr);
    return false;
  }

  return true;
}

void MyConfig::dump_config_info()
{
  MY_INFO(ACE_TEXT ("Loaded configuration:\n"));

  const char * smode;
  switch (running_mode)
  {
  case RM_DIST_SERVER:
    smode = "dist server";
    break;
  case RM_MIDDLE_SERVER:
    smode = "middle server";
    break;
  case RM_CLIENT:
    smode = "client";
    break;
  default:
    MY_FATAL("unexpected running mode (=%d).\n", running_mode);
    exit(10);
  }
  ACE_DEBUG ((LM_INFO, ACE_TEXT ("\t%s = %s\n"), CONFIG_running_mode, smode));

  ACE_DEBUG ((LM_INFO, ACE_TEXT ("\t%s = %d\n"), CONFIG_run_as_demon, run_as_demon));
  ACE_DEBUG ((LM_INFO, ACE_TEXT ("\t%s = %d\n"), CONFIG_use_mem_pool, use_mem_pool));
  ACE_DEBUG ((LM_INFO, ACE_TEXT ("\t%s = %d\n"), CONFIG_mem_pool_dump_interval, mem_pool_dump_interval));
//ACE_DEBUG ((LM_INFO, ACE_TEXT ("\t%s = %d\n"), CONFIG_message_control_block_mem_pool_size, message_control_block_mem_pool_size));
  ACE_DEBUG ((LM_INFO, ACE_TEXT ("\t%s = %d\n"), CONFIG_status_file_check_interval, status_file_check_interval));

  ACE_DEBUG ((LM_INFO, ACE_TEXT ("\t%s = %d\n"), CONFIG_log_file_number, log_file_number));
  ACE_DEBUG ((LM_INFO, ACE_TEXT ("\t%s = %d\n"), CONFIG_log_file_size_in_MB, log_file_size_in_MB));
  ACE_DEBUG ((LM_INFO, ACE_TEXT ("\t%s = %d\n"), CONFIG_log_debug_enabled, log_debug_enabled));
  ACE_DEBUG ((LM_INFO, ACE_TEXT ("\t%s = %d\n"), CONFIG_log_to_stderr, log_to_stderr));

  if (g_test_mode)
    ACE_DEBUG ((LM_INFO, ACE_TEXT ("\ttest_mode = 1\n")));
  else
    ACE_DEBUG ((LM_INFO, ACE_TEXT ("\ttest_mode = 0\n")));

  //dist and middle server
  if (is_server())
  {
    ACE_DEBUG ((LM_INFO, ACE_TEXT ("\t%s = %d\n"), CONFIG_max_clients, max_clients));
    ACE_DEBUG ((LM_INFO, ACE_TEXT ("\t%s = %d\n"), CONFIG_middle_server_dist_port, middle_server_dist_port));
    ACE_DEBUG ((LM_INFO, ACE_TEXT ("\t%s = %s\n"), CONFIG_middle_server_key, middle_server_key.c_str()));
    ACE_DEBUG ((LM_INFO, ACE_TEXT ("\t%s = %s\n"), CONFIG_compressed_store_path, compressed_store_path.c_str()));
    ACE_DEBUG ((LM_INFO, ACE_TEXT ("\t%s = %s\n"), CONFIG_bs_server_addr, bs_server_addr.c_str()));
    ACE_DEBUG ((LM_INFO, ACE_TEXT ("\t%s = %d\n"), CONFIG_bs_server_port, bs_server_port));
    ACE_DEBUG ((LM_INFO, ACE_TEXT ("\t%s = %s\n"), CONFIG_db_server_addr, db_server_addr.c_str()));
    ACE_DEBUG ((LM_INFO, ACE_TEXT ("\t%s = %d\n"), CONFIG_db_server_port, db_server_port));
    ACE_DEBUG ((LM_INFO, ACE_TEXT ("\t%s = %s\n"), CONFIG_db_user_name, db_user_name.c_str()));
  }

  //client an dist
  if (is_client() || is_dist_server())
  {
    ACE_DEBUG ((LM_INFO, ACE_TEXT ("\t%s = %d\n"), CONFIG_dist_server_heart_beat_port, dist_server_heart_beat_port));
    ACE_DEBUG ((LM_INFO, ACE_TEXT ("\t%s = %s\n"), CONFIG_middle_server_addr, middle_server_addr.c_str()));
  }

  //client and middle
  if (is_client() || is_middle_server())
  {
    ACE_DEBUG ((LM_INFO, ACE_TEXT ("\t%s = %d\n"), CONFIG_middle_server_client_port, middle_server_client_port));
  }

  //client only
  if (is_client())
  {
    if (g_test_mode)
      ACE_DEBUG ((LM_INFO, ACE_TEXT ("\t%s = %d\n"), CONFIG_client_heart_beat_interval, client_heart_beat_interval));
    ACE_DEBUG ((LM_INFO, ACE_TEXT ("\t%s = %d\n"), CONFIG_adv_expire_days, adv_expire_days));
    ACE_DEBUG ((LM_INFO, ACE_TEXT ("\t%s = %d\n"), CONFIG_client_ftp_timeout, client_ftp_timeout));
    ACE_DEBUG ((LM_INFO, ACE_TEXT ("\t%s = %d\n"), CONFIG_client_ftp_retry_count, client_ftp_retry_count));
  }

  //dist only
  if (is_dist_server())
  {
    ACE_DEBUG ((LM_INFO, ACE_TEXT ("\t%s = %d\n"), CONFIG_module_heart_beat_mem_pool_size, module_heart_beat_mem_pool_size));
  }

  //middle only
  if (is_middle_server())
  {
    ACE_DEBUG ((LM_INFO, ACE_TEXT ("\t%s = %d\n"), CONFIG_http_port, http_port));
    ACE_DEBUG ((LM_INFO, ACE_TEXT ("\t%s = %s\n"), CONFIG_ftp_addr_list, ftp_addr_list.c_str()));
  }

  //common: file/path locations printout
  ACE_DEBUG ((LM_INFO, ACE_TEXT ("\tstatus_file = %s\n"), status_file_name.c_str()));
  ACE_DEBUG ((LM_INFO, ACE_TEXT ("\tlog_file = %s\n"), log_file_name.c_str()));
  ACE_DEBUG ((LM_INFO, ACE_TEXT ("\tconfig_file = %s\n"), config_file_name.c_str()));
  ACE_DEBUG ((LM_INFO, ACE_TEXT ("\tapp_path = %s\n"), app_path.c_str()));
  ACE_DEBUG ((LM_INFO, ACE_TEXT ("\texe_path = %s\n"), exe_path.c_str()));
}


//MySigHandler//

MySigHandler::MySigHandler(MyBaseApp * app)
{
  m_app = app;
}

int MySigHandler::handle_signal (int signum, siginfo_t*, ucontext_t*)
{
  m_app->on_sig_event(signum);
  return 0;
};


//MyStatusFileChecker//

MyStatusFileChecker::MyStatusFileChecker(MyBaseApp * app)
{
  m_app = app;
}

int MyStatusFileChecker::handle_timeout(const ACE_Time_Value &, const void *)
{
  struct stat st;
  if (::stat(MyConfigX::instance()->status_file_name.c_str(), &st) == -1 && errno == ENOENT)
    m_app->on_status_file_missing();
  return 0;
}


//MyInfoDumper//
MyInfoDumper::MyInfoDumper(MyBaseApp * app)
{
  m_app = app;
}

int MyInfoDumper::handle_timeout (const ACE_Time_Value &, const void *)
{
  m_app->dump_info();
  return 0;
}


//MyClock//

int MyClock::handle_timeout (const ACE_Time_Value &, const void *)
{
  ++g_clock_tick;
  return 0;
}


//MyServerApp//

MyBaseApp::MyBaseApp(): m_sig_handler(this), m_status_file_checker(this), m_info_dumper(this)
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

bool MyBaseApp::on_construct()
{
  return true;
}

void MyBaseApp::add_module(MyBaseModule * module)
{
  if (!module)
  {
    MY_ERROR(ACE_TEXT("MyBaseApp::add_module(): module is NULL\n"));
    return;
  }
  m_modules.push_back(module);
}

bool MyBaseApp::do_constructor()
{
  MyConfigX::instance()->dump_config_info();
  MY_INFO(ACE_TEXT("loading modules...\n"));

  m_ace_sig_handler.register_handler(SIGTERM, &m_sig_handler);
  m_ace_sig_handler.register_handler(SIGCHLD, &m_sig_handler);
  m_ace_sig_handler.register_handler(SIGHUP, &m_sig_handler);

  if (!on_construct())
    return false;

  MY_INFO(ACE_TEXT("loading modules done!\n"));

  if (MyConfigX::instance()->status_file_check_interval != 0)
  {
    int fd = open(MyConfigX::instance()->status_file_name.c_str(), O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR);
    if (fd == -1)
    {
      MY_WARNING(ACE_TEXT("status_file_check_interval enabled, but can not create/open file %s\n"),
          MyConfigX::instance()->status_file_name.c_str());
      return false;
    }
    close(fd);
    m_status_file_checking = true;

    ACE_Time_Value interval (MyConfigX::instance()->status_file_check_interval * 60);
    if (ACE_Reactor::instance()->schedule_timer (&m_status_file_checker,
                             0, interval, interval) == -1)
      MY_WARNING("can not setup status_file_check timer\n");
  }

  if (MyConfigX::instance()->mem_pool_dump_interval > 0)
  {
    ACE_Time_Value interval(60 * MyConfigX::instance()->mem_pool_dump_interval);
    if (ACE_Reactor::instance()->schedule_timer (&m_info_dumper,
                             0, interval, interval) == -1)
      MY_WARNING("can not setup info dump timer\n");
  }

  ACE_Time_Value interval(CLOCK_INTERVAL);
  if (ACE_Reactor::instance()->schedule_timer(&m_clock, 0, interval, interval) == -1)
  {
    MY_FATAL("can not setup clock timer\n");
    return false;
  }

  return true;
}

MyBaseApp::~MyBaseApp()
{
  m_ace_sig_handler.remove_handler(SIGHUP);
  m_ace_sig_handler.remove_handler(SIGTERM);
  if (m_status_file_checking)
    ACE_Reactor::instance()->cancel_timer(&m_status_file_checker);
  if (MyConfigX::instance()->mem_pool_dump_interval > 0)
    ACE_Reactor::instance()->cancel_timer(&m_info_dumper);
  ACE_Reactor::instance()->cancel_timer(&m_clock);
  stop();
  std::for_each(m_modules.begin(), m_modules.end(), MyObjectDeletor());
}

bool MyBaseApp::running() const
{
  return m_is_running;
}

void MyBaseApp::app_demonize()
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

void MyBaseApp::init_log()
{
  const char * cmd = "dynamic Logger Service_Object *ACE:_make_ACE_Logging_Strategy()"
   "\"-o -s %s -N %d -m %d000 -i 1 -f STDERR|OSTREAM \"";

  int m = strlen(cmd) + MyConfigX::instance()->log_file_name.length() + 100;
  char * buff = new char[m];
  std::snprintf(buff, m, cmd, MyConfigX::instance()->log_file_name.c_str(),
      MyConfigX::instance()->log_file_number,
      MyConfigX::instance()->log_file_size_in_MB);
  if (ACE_Service_Config::process_directive (buff) == -1)
  {
    std::printf("ACE_Service_Config::process_directive failed, args = %s\n", buff);
    exit(6);
  }
  delete []buff;
  u_long log_mask = LM_INFO | LM_WARNING | LM_ERROR;
  if (MyConfigX::instance()->log_debug_enabled)
    log_mask |= LM_DEBUG;
  ACE_LOG_MSG->priority_mask (log_mask, ACE_Log_Msg::PROCESS);

//  ACE_LOG_MSG->open ("aceserver", ACE_Log_Msg::OSTREAM | ACE_Log_Msg::STDERR);
//  ACE_OSTREAM_TYPE *output = new ofstream (m_config.log_file_name.c_str(), ios::app | ios::out);
//  ACE_LOG_MSG->msg_ostream (output);

  if (MyConfigX::instance()->run_as_demon || !MyConfigX::instance()->log_to_stderr)
    ACE_LOG_MSG->clr_flags(ACE_Log_Msg::STDERR);
  if (MyConfigX::instance()->is_server())
    MY_INFO("Starting server (Ver: %s)...\n", const_app_version);
  else
    MY_INFO("Starting client (Ver: %s)...\n", const_app_version);
}

void MyBaseApp::do_dump_info()
{

}

void MyBaseApp::mem_pool_dump_one(const char * poolname, long nAlloc, long nFree, long nMaxUse, long nAllocFull, int block_size, int chunks)
{
  long nInUse = nAlloc - nFree;
  ACE_DEBUG((LM_INFO, ACE_TEXT("    mem pool[%s], InUse=%d, Alloc=%d, "
      "Free=%d, Peek=%d, Fail=%d, BlkSize=%d, chunks=%d\n"),
      poolname, nInUse, nAlloc, nFree, nMaxUse, nAllocFull, block_size, chunks));
}

void MyBaseApp::dump_info()
{
  MY_INFO("##### Running Information Dump #####\n");
  std::for_each(m_modules.begin(), m_modules.end(), std::mem_fun(&MyBaseModule::dump_info));
  do_dump_info();
  ACE_DEBUG((LM_INFO, "##### Dump End #####\n"));
}

bool MyBaseApp::on_start()
{
  return true;
}

void MyBaseApp::start()
{
  if (m_is_running)
    return;
  MY_INFO(ACE_TEXT("starting modules...\n"));
  m_is_running = true;
  on_start();
  std::for_each(m_modules.begin(), m_modules.end(), std::mem_fun(&MyBaseModule::start));

  MY_INFO(ACE_TEXT("starting modules done!\n"));
  do_sigchild(); //fast delivery
  do_event_loop();
}

void MyBaseApp::on_stop()
{

}

void MyBaseApp::stop()
{
  if (!m_is_running)
    return;
  MY_INFO(ACE_TEXT("stopping modules...\n"));
  m_is_running = false;
  std::for_each(m_modules.begin(), m_modules.end(), std::mem_fun(&MyBaseModule::stop));
  on_stop();
  MY_INFO(ACE_TEXT("stopping modules done!\n"));
}

void MyBaseApp::on_sig_event(int signum)
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
    MY_ERROR("unexpected signal caught %d\n", signum);
    break;
  }
}

void MyBaseApp::do_event_loop()
{
  while(true)
  {
    ACE_Time_Value timeout(2);
    ACE_Reactor::instance()->run_reactor_event_loop(timeout);
    if (m_sigterm)
    {
      MY_INFO("signal sigterm caught, quitting...\n");
      return;
    }
    if (m_sighup && !do_sighup())
    {
      MY_INFO("signal sighup caught, quitting...\n");
      return;
    }
    if (m_sigchld && !do_sigchild())
    {
      MY_INFO("signal sigchild caught, quitting...\n");
      return;
    }
    if (!m_status_file_ok)
    {
      MY_INFO("status file checking failed, quitting...\n");
      return;
    }
    if (!on_event_loop())
      return;
  }
}

bool MyBaseApp::do_sighup()
{
  m_sighup = false;
  dump_info();
  return true;
}

bool MyBaseApp::do_sigchild()
{
  int status;
  pid_t pid;
  m_sigchld = false;
  while ((pid = ::waitpid(-1, &status, WNOHANG)) > 0)
  {
    MY_INFO("child process (%d) closes...\n", (int)pid);
    if (!on_sigchild(pid))
      return false;
  }
  return true;
}

bool MyBaseApp::on_sigchild(pid_t pid)
{
  ACE_UNUSED_ARG(pid);
  return true;
}

bool MyBaseApp::on_event_loop()
{
  return true;
}

void MyBaseApp::on_status_file_missing()
{
  m_status_file_ok = false;
}
