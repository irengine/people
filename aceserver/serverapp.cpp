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

const int DEFAULT_LOG_FILE_NUMBER = 3;
const int DEFAULT_LOG_FILE_SIZE_IN_MB = 20;
const bool DEFAULT_USE_MEM_POOL = true;
const bool DEFAULT_RUN_AS_DEMON = false;
const bool DEFAULT_LOG_DEBUG_ENABLED = true;
const bool DEFAULT_LOG_TO_STDERR = true;

MyServerConfig::MyServerConfig()
{
  use_mem_pool = DEFAULT_USE_MEM_POOL;
  run_as_demon = DEFAULT_RUN_AS_DEMON;
  log_debug_enabled = DEFAULT_LOG_DEBUG_ENABLED;
  log_file_number = DEFAULT_LOG_FILE_NUMBER;
  log_file_size_in_MB = DEFAULT_LOG_FILE_SIZE_IN_MB;
  log_to_stderr = DEFAULT_LOG_TO_STDERR;
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

  return true;
}

void MyServerConfig::dump_config_info()
{
  MY_INFO(ACE_TEXT ("this is info\n"));

  ACE_DEBUG ((LM_INFO, ACE_TEXT ("(%D %P|%t %N.%l)\n")));
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
  MyServerAppX::instance()->m_config.loadConfig();
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
   "\"-o -s %s -N %d -m %d000 -i 1 -f STDERR|OSTREAM \""; //-p INFO -f STDERR|OSTREAM

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
