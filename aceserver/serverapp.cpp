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
#include "serverapp.h"
#include "heartbeatmodule.h"

//MyServerConfig//

const int DEFAULT_MAX_CLIENTS = 10000;
const bool DEFAULT_USE_MEM_POOL = true;
const bool DEFAULT_RUN_AS_DEMON = false;

const int DEFAULT_LOG_FILE_NUMBER = 3;
const int DEFAULT_LOG_FILE_SIZE_IN_MB = 20;
const bool DEFAULT_LOG_DEBUG_ENABLED = true;
const bool DEFAULT_LOG_TO_STDERR = true;
const int DEFAULT_MODULE_HEART_BEAT_PORT = 2222;

const ACE_TCHAR * CONFIG_Section_Name = ACE_TEXT("global");

const ACE_TCHAR * CONFIG_Use_Mem_Pool = ACE_TEXT("use_mem_pool");
const ACE_TCHAR * CONFIG_Run_As_Demon = ACE_TEXT("run_as_demon");
const ACE_TCHAR * CONFIG_Max_Clients = ACE_TEXT("max_clients");

const ACE_TCHAR * CONFIG_Log_Debug_Enabled = ACE_TEXT("log.debug_enabled");
const ACE_TCHAR * CONFIG_Log_To_Stderr = ACE_TEXT("log.to_stderr");
const ACE_TCHAR * CONFIG_Log_File_Number = ACE_TEXT("log.file_number");
const ACE_TCHAR * CONFIG_Log_File_Size = ACE_TEXT("log.file_size");

const ACE_TCHAR * CONFIG_Heart_Beat_Port = ACE_TEXT("module.heart_beat.port");


MyServerConfig::MyServerConfig()
{
  use_mem_pool = DEFAULT_USE_MEM_POOL;
  run_as_demon = DEFAULT_RUN_AS_DEMON;
  max_clients = DEFAULT_MAX_CLIENTS;

  log_debug_enabled = DEFAULT_LOG_DEBUG_ENABLED;
  log_file_number = DEFAULT_LOG_FILE_NUMBER;
  log_file_size_in_MB = DEFAULT_LOG_FILE_SIZE_IN_MB;
  log_to_stderr = DEFAULT_LOG_TO_STDERR;

  module_heart_beat_port = DEFAULT_MODULE_HEART_BEAT_PORT;
}

void MyServerConfig::init_path()
{
  const size_t BUFF_SIZE = 4096;
  char path[BUFF_SIZE];
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
    status_file_name = app_path + "/running/aceserver.pid";
    log_file_name = app_path + "/log/aceserver.log";
    config_file_name = app_path + "/config/aceserver.cfg";
  } else
  {
    std::perror("readlink(\"/proc/self/exe\") failed\n");
    exit(3);
  }
}

bool MyServerConfig::loadConfig()
{
  init_path();

  ACE_Configuration_Heap cfgHeap;
  if (cfgHeap.open () == -1)
  {
    MY_ERROR("config.open()\n");
    return false;
  }

  ACE_Registry_ImpExp config_importer(cfgHeap);
  if (config_importer.import_config (config_file_name.c_str()) == -1)
  {
    MY_ERROR("import_config() failed on %s\n", config_file_name.c_str());
    return false;
  }

  ACE_Configuration_Section_Key section;
  if (cfgHeap.open_section (cfgHeap.root_section (), CONFIG_Section_Name,
                           0, section) == -1)
  {
    MY_ERROR("config.open_section failed, section = %s\n", CONFIG_Section_Name);
    return false;
  }

  u_int ival;
  if (cfgHeap.get_integer_value (section,  CONFIG_Use_Mem_Pool, ival) == 0)
    use_mem_pool = (ival != 0);

  if (cfgHeap.get_integer_value (section,  CONFIG_Run_As_Demon, ival) == 0)
    run_as_demon = (ival != 0);

  if (cfgHeap.get_integer_value (section,  CONFIG_Max_Clients, ival) == 0)
  {
    if (ival > 0 && ival <= 100000) //the upper limit of 100000 is more than enough?
      max_clients = ival;
  }

  if (cfgHeap.get_integer_value (section,  CONFIG_Log_File_Number, ival) == 0)
  {
    if (ival > 0 && ival <= 1000)
      log_file_number = ival;
  }

  if (cfgHeap.get_integer_value (section,  CONFIG_Log_File_Size, ival) == 0)
  {
    if (ival > 0 && ival <= 10000)
      log_file_size_in_MB = ival;
  }

  if (cfgHeap.get_integer_value (section,  CONFIG_Log_Debug_Enabled, ival) == 0)
  {
    log_debug_enabled = (ival != 0);
  }

  if (cfgHeap.get_integer_value (section,  CONFIG_Log_To_Stderr, ival) == 0)
  {
    log_to_stderr = (ival != 0);
  }

  if (cfgHeap.get_integer_value (section,  CONFIG_Log_To_Stderr, ival) == 0)
  {
    if (ival == 0 || ival >= 65535)
    {
      MY_ERROR(ACE_TEXT("Invalid heart beat tcp port number: %d!\n"), ival);
      return false;
    }
    module_heart_beat_port = ival;
  }

  return true;
}

void MyServerConfig::dump_config_info()
{
  MY_INFO(ACE_TEXT ("Loaded configuration:\n"));
  ACE_DEBUG ((LM_INFO, ACE_TEXT ("\t%s = %d\n"), CONFIG_Use_Mem_Pool, use_mem_pool));
  ACE_DEBUG ((LM_INFO, ACE_TEXT ("\t%s = %d\n"), CONFIG_Run_As_Demon, run_as_demon));
  ACE_DEBUG ((LM_INFO, ACE_TEXT ("\t%s = %d\n"), CONFIG_Max_Clients, max_clients));

  ACE_DEBUG ((LM_INFO, ACE_TEXT ("\t%s = %d\n"), CONFIG_Log_File_Number, log_file_number));
  ACE_DEBUG ((LM_INFO, ACE_TEXT ("\t%s = %d\n"), CONFIG_Log_File_Size, log_file_size_in_MB));
  ACE_DEBUG ((LM_INFO, ACE_TEXT ("\t%s = %d\n"), CONFIG_Log_Debug_Enabled, log_debug_enabled));
  ACE_DEBUG ((LM_INFO, ACE_TEXT ("\t%s = %d\n"), CONFIG_Log_To_Stderr, log_to_stderr));

  ACE_DEBUG ((LM_INFO, ACE_TEXT ("\t%s = %d\n"), CONFIG_Heart_Beat_Port, module_heart_beat_port));

  ACE_DEBUG ((LM_INFO, ACE_TEXT ("\tstatus_file = %s\n"), status_file_name.c_str()));
  ACE_DEBUG ((LM_INFO, ACE_TEXT ("\tlog_file = %s\n"), log_file_name.c_str()));
  ACE_DEBUG ((LM_INFO, ACE_TEXT ("\tconfig_file = %s\n"), config_file_name.c_str()));
  ACE_DEBUG ((LM_INFO, ACE_TEXT ("\tapp_path = %s\n"), app_path.c_str()));
  ACE_DEBUG ((LM_INFO, ACE_TEXT ("\texe_path = %s\n"), exe_path.c_str()));
}


//MyServerApp//

MyServerApp::MyServerApp()
{
  m_isRunning = false;
  //moved the initializations of modules to the static app_init() func
  //Just can NOT do it in constructor simply because the singleton pattern
  //will make recursively calls to our constructor by the module constructor's ref
  //to MyServerApp's singleton.
  //This is Ugly, but works right now
  m_heart_beat_module = NULL;
}

void MyServerApp::do_constructor()
{
  init_log();
  m_config.dump_config_info();
  m_heart_beat_module = new MyHeartBeatModule();
}

MyServerApp::~MyServerApp()
{
  stop();
  delete m_heart_beat_module;
}

const MyServerConfig & MyServerApp::ServerConfig() const
{
  return m_config;
}

bool MyServerApp::isRunning() const
{
  return m_isRunning;
}

void MyServerApp::app_init()
{
  if (!MyServerAppX::instance()->m_config.loadConfig())
  {
    MY_ERROR(ACE_TEXT("error loading config file, quitting\n"));
    exit(5);
  }
  if (MyServerAppX::instance()->m_config.run_as_demon)
    MyServerApp::app_demonize();
//  MyServerAppX::instance()->m_config.dump_config_info();
  MyHeartBeatHandler::init_mem_pool(1000);
  MyServerAppX::instance()->do_constructor();
}

void MyServerApp::app_fini()
{
  MyServerAppX::close();  //this comes before the releasing of memory pool
  MyHeartBeatHandler::fini_mem_pool();
}

void MyServerApp::app_demonize()
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

void MyServerApp::init_log()
{
  const char * cmd = "dynamic Logger Service_Object *ACE:_make_ACE_Logging_Strategy()"
   "\"-o -s %s -N %d -m %d000 -i 1 -f STDERR|OSTREAM \"";

  int m = strlen(cmd) + m_config.log_file_name.length() + 100;
  char * buff = new char[m];
  std::snprintf(buff, m, cmd, m_config.log_file_name.c_str(), m_config.log_file_number, m_config.log_file_size_in_MB);
//  std::printf("log_config=%s\n", buff);
  if (ACE_Service_Config::process_directive (buff) == -1)
  {
    MY_ERROR("init_log.config_log failed\n");
  }
  delete []buff;
  u_long log_mask = LM_INFO | LM_WARNING | LM_ERROR;
  if (m_config.log_debug_enabled)
    log_mask |= LM_DEBUG;
  ACE_LOG_MSG->priority_mask (log_mask, ACE_Log_Msg::PROCESS);

//  ACE_LOG_MSG->open ("aceserver", ACE_Log_Msg::OSTREAM | ACE_Log_Msg::STDERR);
//  ACE_OSTREAM_TYPE *output = new ofstream (m_config.log_file_name.c_str(), ios::app | ios::out);
//  ACE_LOG_MSG->msg_ostream (output);

  if (m_config.run_as_demon || !m_config.log_to_stderr)
    ACE_LOG_MSG->clr_flags(ACE_Log_Msg::STDERR);
}

void MyServerApp::dump_memory_pool_info()
{
  long nAlloc = 0, nFree = 0, nMaxUse = 0, nInUse = 0;
  if (MyHeartBeatHandler::mem_pool())
  {
    MyHeartBeatHandler::mem_pool()->get_usage(nAlloc, nFree, nMaxUse);
    nInUse = nAlloc - nFree;
    ACE_DEBUG ((LM_DEBUG,
               ACE_TEXT ("(%P|%t) memory info dump, inUse = %d, alloc = %d, free = %d, maxInUse = %d\n"),
               nInUse, nAlloc, nFree, nMaxUse));
  }
}

MyHeartBeatModule * MyServerApp::heart_beat_module() const
{
  return m_heart_beat_module;
}

void MyServerApp::start()
{
  if (m_isRunning)
    return;
  m_isRunning = true;
  m_heart_beat_module->start();
}

void MyServerApp::stop()
{
  if (!m_isRunning)
    return;
  m_isRunning = false;
  m_heart_beat_module->stop();
}
