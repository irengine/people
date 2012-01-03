/*
 * serverapp.h
 *
 *  Created on: Dec 28, 2011
 *      Author: root
 */

#ifndef SERVERAPP_H_
#define SERVERAPP_H_

#include <ace/Singleton.h>
#include <string>
#include <ace/Configuration_Import_Export.h>

extern const ACE_TCHAR * const_server_version;

class MyHeartBeatModule;
class MyServerApp;

class MyServerConfig
{
public:
  MyServerConfig();
  bool loadConfig();
  void dump_config_info();

  int  max_clients;
  bool use_mem_pool;
  bool run_as_demon;
  int  mem_pool_dump_interval;
  int  status_file_check_interval;
  int  message_control_block_mem_pool_size;

  int  log_file_number;
  int  log_file_size_in_MB;
  bool log_debug_enabled;
  bool log_to_stderr;

  int module_heart_beat_port;
  int module_heart_beat_mem_pool_size;

  std::string exe_path;
  std::string status_file_name;
  std::string log_file_name;
  std::string config_file_name;
  std::string app_path;
private:
  void init_path();
};


class MySigHandler: public ACE_Event_Handler
{
public:
  MySigHandler(MyServerApp * app);
  virtual int handle_signal (int signum,
                             siginfo_t * = 0,
                             ucontext_t * = 0);
private:
  MyServerApp * m_app;
};

class MyStatusFileChecker: public ACE_Event_Handler
{
public:
  MyStatusFileChecker(MyServerApp * app);
  virtual int handle_timeout (const ACE_Time_Value &current_time, const void *act = 0);

private:
  MyServerApp * m_app;
};

class MyServerApp
{
public:
  MyServerApp();
  ~MyServerApp();
  const MyServerConfig & server_config() const;
  bool running() const;

  static void app_init();
  static void app_fini();
  static void app_demonize();

  void init_log();

  void start();
  void stop();
  static void dump_memory_pool_info();
  MyHeartBeatModule * heart_beat_module() const;

protected:
  friend class MySigHandler;
  friend class MyStatusFileChecker;

  void on_sig_event(int signum);
  void do_event_loop();
  bool do_sighup();
  void on_status_file_missing();

private:
  void do_constructor();
  MyServerConfig m_config;
  MyHeartBeatModule * m_heart_beat_module;
  MySigHandler m_sig_handler;
  ACE_Sig_Handler m_ace_sig_handler;
  MyStatusFileChecker m_status_file_checker;
  bool m_is_running;
  bool m_sighup;
  bool m_sigterm;
  bool m_status_file_ok;
  bool m_status_file_checking;
};

typedef ACE_Unmanaged_Singleton<MyServerApp, ACE_Null_Mutex> MyServerAppX;

#endif /* SERVERAPP_H_ */
