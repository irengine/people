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

class MyHeartBeatModule;

class MyServerConfig
{
public:
  MyServerConfig();
  bool loadConfig();
  void dump_config_info();

  int  log_file_number;
  int  log_file_size_in_MB;
  bool use_mem_pool;
  bool log_debug_enabled;
  bool run_as_demon;
  bool log_to_stderr;
  std::string exe_path;
  std::string status_file_name;
  std::string log_file_name;
  std::string config_file_name;
  std::string app_path;
private:
  void init_path();
};



class MyServerApp
{
public:
  MyServerApp();
  ~MyServerApp();
  const MyServerConfig & ServerConfig() const;
  bool isRunning() const;

  static void app_init();
  static void app_fini();
  static void app_demonize();

  void init_log();

  void start();
  void stop();
  static void dump_memory_pool_info();
  MyHeartBeatModule * heart_beat_module() const;

private:
  void do_constructor();
  MyServerConfig m_config;
  MyHeartBeatModule * m_heart_beat_module;
  bool m_isRunning;
};

typedef ACE_Unmanaged_Singleton<MyServerApp, ACE_Null_Mutex> MyServerAppX;

#endif /* SERVERAPP_H_ */
