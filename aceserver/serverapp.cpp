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
#include "distmodule.h"
#include "middlemodule.h"

const ACE_TCHAR * const_server_version = ACE_TEXT("1.0");
long g_clock_tick = 0;

//MyServerConfig//

const int  DEFAULT_MAX_CLIENTS = 10000;
const bool DEFAULT_USE_MEM_POOL = true;
const bool DEFAULT_RUN_AS_DEMON = false;
const int  DEFAULT_STATUS_FILE_CHECK_INTERVAL = 3;
const int  DEFAULT_MESSAGE_CONTROL_BLOCK_MPOOL_SIZE = DEFAULT_MAX_CLIENTS * 5;
const int  DEFAULT_MEM_POOL_DUMP_INTERVAL = 30;

const int  DEFAULT_LOG_FILE_NUMBER = 3;
const int  DEFAULT_LOG_FILE_SIZE_IN_MB = 20;
const bool DEFAULT_LOG_DEBUG_ENABLED = true;
const bool DEFAULT_LOG_TO_STDERR = true;

const int  DEFAULT_MODULE_HEART_BEAT_PORT = 2222;
const int  DEFAULT_MODULE_HEART_BEAT_MPOOL_SIZE = DEFAULT_MAX_CLIENTS * 4;


const ACE_TCHAR * CONFIG_Section_Name = ACE_TEXT("global");

const ACE_TCHAR * CONFIG_Use_Mem_Pool = ACE_TEXT("use_mem_pool");
const ACE_TCHAR * CONFIG_Mem_Pool_Dump_Interval = ACE_TEXT("mem_pool_dump_interval");
const ACE_TCHAR * CONFIG_Message_Control_Block_Mem_Pool_Size = ACE_TEXT("message_control_block_mempool_size");
const ACE_TCHAR * CONFIG_Run_As_Demon = ACE_TEXT("run_as_demon");
const ACE_TCHAR * CONFIG_Max_Clients = ACE_TEXT("max_clients");
const ACE_TCHAR * CONFIG_Status_File_Check_Interval = ACE_TEXT("status_file_check_interval");

const ACE_TCHAR * CONFIG_Log_Debug_Enabled = ACE_TEXT("log.debug_enabled");
const ACE_TCHAR * CONFIG_Log_To_Stderr = ACE_TEXT("log.to_stderr");
const ACE_TCHAR * CONFIG_Log_File_Number = ACE_TEXT("log.file_number");
const ACE_TCHAR * CONFIG_Log_File_Size = ACE_TEXT("log.file_size");

const ACE_TCHAR * CONFIG_Heart_Beat_Port = ACE_TEXT("module.heart_beat.port");
const ACE_TCHAR * CONFIG_Heart_Beat_MPool_Size = ACE_TEXT("module.heart_beat.mempool_size");

MyServerConfig::MyServerConfig()
{
  use_mem_pool = DEFAULT_USE_MEM_POOL;
  run_as_demon = DEFAULT_RUN_AS_DEMON;
  max_clients = DEFAULT_MAX_CLIENTS;
  mem_pool_dump_interval = DEFAULT_MEM_POOL_DUMP_INTERVAL;
  status_file_check_interval = DEFAULT_STATUS_FILE_CHECK_INTERVAL;
  message_control_block_mem_pool_size = DEFAULT_MESSAGE_CONTROL_BLOCK_MPOOL_SIZE;

  log_debug_enabled = DEFAULT_LOG_DEBUG_ENABLED;
  log_file_number = DEFAULT_LOG_FILE_NUMBER;
  log_file_size_in_MB = DEFAULT_LOG_FILE_SIZE_IN_MB;
  log_to_stderr = DEFAULT_LOG_TO_STDERR;

  module_heart_beat_port = DEFAULT_MODULE_HEART_BEAT_PORT;
  module_heart_beat_mem_pool_size = DEFAULT_MODULE_HEART_BEAT_MPOOL_SIZE;
}

void MyServerConfig::init_path(const char * app_home_path)
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

  status_file_name = app_path + "/running/aceserver.pid";
  log_file_name = app_path + "/log/aceserver.log";
  config_file_name = app_path + "/config/aceserver.cfg";

}

bool MyServerConfig::loadConfig(const char * app_home_path)
{
  init_path(app_home_path);

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
    {
      max_clients = ival;
      module_heart_beat_mem_pool_size = std::max(2 * max_clients, 1000);
      message_control_block_mem_pool_size = std::max(2 * max_clients, 1000);
    }
  }

  if (cfgHeap.get_integer_value (section,  CONFIG_Status_File_Check_Interval, ival) == 0)
    status_file_check_interval = ival;

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
    log_debug_enabled = (ival != 0);

  if (cfgHeap.get_integer_value (section,  CONFIG_Log_To_Stderr, ival) == 0)
    log_to_stderr = (ival != 0);

  if (cfgHeap.get_integer_value (section,  CONFIG_Mem_Pool_Dump_Interval, ival) == 0)
    mem_pool_dump_interval = ival;

  if (cfgHeap.get_integer_value (section,  CONFIG_Heart_Beat_Port, ival) == 0)
  {
    if (ival == 0 || ival >= 65535)
    {
      MY_ERROR(ACE_TEXT("Invalid heart beat tcp port number: %d!\n"), ival);
      return false;
    }
    module_heart_beat_port = ival;
  }

  if (cfgHeap.get_integer_value (section,  CONFIG_Heart_Beat_MPool_Size, ival) == 0)
  {
    u_int itemp = std::max(2 * max_clients, 1000);
    if (ival < itemp)
    {
      MY_WARNING(ACE_TEXT("Invalid %s value (= %d), should at least max(2 * %s, 1000) = %d, will adjust to %d\n"),
          CONFIG_Heart_Beat_MPool_Size, ival, CONFIG_Max_Clients, itemp, itemp);
    }
    else
      module_heart_beat_mem_pool_size = ival;
  }

  if (cfgHeap.get_integer_value (section,  CONFIG_Message_Control_Block_Mem_Pool_Size, ival) == 0)
  {
    u_int itemp = std::max(3 * max_clients, 1000);
    if (ival < itemp)
    {
      MY_WARNING(ACE_TEXT("Invalid %s value (= %d), should at least max(3 * %s, 1000) = %d, will adjust to %d\n"),
          CONFIG_Message_Control_Block_Mem_Pool_Size, ival, CONFIG_Max_Clients, itemp, itemp);
    }
    else
      message_control_block_mem_pool_size = ival;
  }

  return true;
}

void MyServerConfig::dump_config_info()
{
  MY_INFO(ACE_TEXT ("Loaded configuration:\n"));
  ACE_DEBUG ((LM_INFO, ACE_TEXT ("\t%s = %d\n"), CONFIG_Max_Clients, max_clients));
  ACE_DEBUG ((LM_INFO, ACE_TEXT ("\t%s = %d\n"), CONFIG_Run_As_Demon, run_as_demon));
  ACE_DEBUG ((LM_INFO, ACE_TEXT ("\t%s = %d\n"), CONFIG_Use_Mem_Pool, use_mem_pool));
  ACE_DEBUG ((LM_INFO, ACE_TEXT ("\t%s = %d\n"), CONFIG_Mem_Pool_Dump_Interval, mem_pool_dump_interval));
  ACE_DEBUG ((LM_INFO, ACE_TEXT ("\t%s = %d\n"), CONFIG_Message_Control_Block_Mem_Pool_Size, message_control_block_mem_pool_size));

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


//MySigHandler//

MySigHandler::MySigHandler(MyServerApp * app)
{
  m_app = app;
}

int MySigHandler::handle_signal (int signum, siginfo_t*, ucontext_t*)
{
  m_app->on_sig_event(signum);
  return 0;
};


//MyStatusFileChecker//

MyStatusFileChecker::MyStatusFileChecker(MyServerApp * app)
{
  m_app = app;
}

int MyStatusFileChecker::handle_timeout(const ACE_Time_Value &, const void *)
{
  struct stat st;
  if (::stat(m_app->server_config().status_file_name.c_str(), &st) == -1 && errno == ENOENT)
    m_app->on_status_file_missing();
  return 0;
}


//MyClock//

int MyClock::handle_timeout (const ACE_Time_Value &, const void *)
{
  ++g_clock_tick;
  return 0;
}


//MyServerApp//

MyServerApp::MyServerApp(): m_sig_handler(this), m_status_file_checker(this)
{
  m_is_running = false;
  //moved the initializations of modules to the static app_init() func
  //Just can NOT do it in constructor simply because the singleton pattern
  //will make recursively calls to our constructor by the module constructor's ref
  //to MyServerApp's singleton.
  //This is Ugly, but works right now
  m_heart_beat_module = NULL;
  m_location_module = NULL;
  m_sighup = false;
  m_sigterm = false;
  m_status_file_ok = true;
  m_status_file_checking = false;
}

void MyServerApp::do_constructor()
{
  init_log();
  m_config.dump_config_info();
  MY_INFO(ACE_TEXT("loading modules...\n"));
  m_heart_beat_module = new MyHeartBeatModule();
  m_location_module = new MyLocationModule;

  MY_INFO(ACE_TEXT("loading modules done!\n"));

  m_ace_sig_handler.register_handler(SIGHUP, &m_sig_handler);
  m_ace_sig_handler.register_handler(SIGTERM, &m_sig_handler);
  if (m_config.status_file_check_interval != 0)
  {
    int fd = open(m_config.status_file_name.c_str(), O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR);
    if (fd == -1)
    {
      MY_WARNING(ACE_TEXT("status_file_check_interval enabled, but can not create/open file %s\n"),
          m_config.status_file_name.c_str());
      return;
    }
    close(fd);
    m_status_file_checking = true;

    ACE_Time_Value interval (m_config.status_file_check_interval * 60);
    ACE_Reactor::instance()->schedule_timer (&m_status_file_checker,
                             0, interval, interval);
  }

  ACE_Time_Value interval(10);
  ACE_Reactor::instance()->schedule_timer(&m_clock, 0, interval, interval);
}

MyServerApp::~MyServerApp()
{
  m_ace_sig_handler.remove_handler(SIGHUP);
  m_ace_sig_handler.remove_handler(SIGTERM);
  if (m_status_file_checking)
    ACE_Reactor::instance()->cancel_timer(&m_status_file_checker);
  ACE_Reactor::instance()->cancel_timer(&m_clock);
  stop();
  delete m_heart_beat_module;
  delete m_location_module;
}

const MyServerConfig & MyServerApp::server_config() const
{
  return m_config;
}

bool MyServerApp::running() const
{
  return m_is_running;
}

void MyServerApp::app_init(const char * app_home_path)
{
  MyServerApp * app = MyServerAppX::instance();
  if (!app->m_config.loadConfig(app_home_path))
  {
    std::printf("error loading config file, quitting\n");
    exit(5);
  }
  if (app->m_config.run_as_demon)
    MyServerApp::app_demonize();
  MyHeartBeatHandler::init_mem_pool(app->m_config.max_clients);
  MyLocationHandler::init_mem_pool(1000);
  MyMemPoolFactoryX::instance()->init(&(app->m_config));
  app->do_constructor();
}

void MyServerApp::app_fini()
{
  MyServerApp::dump_memory_pool_info();
  MyServerAppX::close();  //this comes before the releasing of memory pool
  MyHeartBeatHandler::fini_mem_pool();
  MyLocationHandler::fini_mem_pool();
  MyMemPoolFactoryX::close();
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
  if (ACE_Service_Config::process_directive (buff) == -1)
  {
    std::printf("ACE_Service_Config::process_directive failed, args = %s\n", buff);
    exit(6);
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
  MY_INFO("Starting server (Ver: %s)...\n", const_server_version);
}

void MyServerApp::dump_memory_pool_info()
{
  long nAlloc = 0, nFree = 0, nMaxUse = 0, nInUse = 0;
  if (MyHeartBeatHandler::mem_pool())
  {
    MyHeartBeatHandler::mem_pool()->get_usage(nAlloc, nFree, nMaxUse);
    nInUse = nAlloc - nFree;

    MY_INFO (ACE_TEXT ("(%P|%t) memory info dump, inUse = %d, alloc = %d, free = %d, maxInUse = %d\n"),
             nInUse, nAlloc, nFree, nMaxUse);
  }
}

MyHeartBeatModule * MyServerApp::heart_beat_module() const
{
  return m_heart_beat_module;
}

void MyServerApp::start()
{
  if (m_is_running)
    return;
  MY_INFO(ACE_TEXT("starting modules...\n"));
  m_is_running = true;
  if (m_heart_beat_module)
    m_heart_beat_module->start();
  if (m_location_module)
    m_location_module->start();
  MY_INFO(ACE_TEXT("starting modules done!\n"));
  do_event_loop();
}

void MyServerApp::stop()
{
  if (!m_is_running)
    return;
  MY_INFO(ACE_TEXT("stopping modules...\n"));
  m_is_running = false;
  if (m_heart_beat_module)
    m_heart_beat_module->stop();
  if (m_location_module)
    m_location_module->stop();
  MY_INFO(ACE_TEXT("stopping modules done!\n"));
}

void MyServerApp::on_sig_event(int signum)
{
  switch (signum)
  {
  case SIGTERM:
    m_sigterm = true;
    break;
  case SIGHUP:
    m_sighup = true;
    break;
  }
  MY_DEBUG("signal caught %d\n", signum);
}

void MyServerApp::do_event_loop()
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
    if (!m_status_file_ok)
    {
      MY_INFO("status file checking failed, quitting...\n");
      return;
    }
  }
}

MyClientIDTable & MyServerApp::client_id_table()
{
  return m_client_id_table;
}

bool MyServerApp::do_sighup()
{

  m_sighup = false;
  return true;
}

void MyServerApp::on_status_file_missing()
{
  m_status_file_ok = false;
}
