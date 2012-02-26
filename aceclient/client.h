/*
 * client.h
 *
 *  Created on: Jan 9, 2012
 *      Author: root
 */

#ifndef CLIENT_H_
#define CLIENT_H_

#include "common.h"
#include "baseapp.h"
#include <ace/Process.h>

class MyClientToDistModule;

class MyProgramLauncher
{
public:
  MyProgramLauncher();
  virtual ~MyProgramLauncher();

  bool launch();
  void on_terminated(pid_t pid);
  bool running() const;
  virtual bool ready() const;

protected:
  virtual bool on_launch(ACE_Process_Options & options) = 0;

private:
  enum { INVALID_PID = 0 };
  pid_t m_pid;
  ACE_Process_Options m_options;
};

class MyVLCLauncher: public MyProgramLauncher
{
public:
  virtual bool ready() const;

protected:
  virtual bool on_launch(ACE_Process_Options & options);

};

class MyOperaLauncher: public MyProgramLauncher
{
public:
  virtual bool ready() const;

protected:
  virtual bool on_launch(ACE_Process_Options & options);

};

class MyClientApp: public MyBaseApp
{
public:
  MyClientApp();
  virtual ~MyClientApp();

  MyClientToDistModule * client_to_dist_module() const;
  bool send_mb_to_dist(ACE_Message_Block * mb);
  const MyClientVerson & client_version() const;
  const char * client_id() const;
  MyVLCLauncher & vlc_launcher();
  MyOperaLauncher & opera_launcher();

  MyClientIDTable & client_id_table()
    { return m_client_id_table; }

  static void data_path(MyPooledMemGuard & _data_path, const char * client_id = NULL);
  static void calc_display_parent_path(MyPooledMemGuard & parent_path, const char * client_id = NULL);
  static void calc_dist_parent_path(MyPooledMemGuard & parent_path, const char * dist_id, const char * client_id = NULL);
  static void calc_backup_parent_path(MyPooledMemGuard & parent_path, const char * client_id = NULL);
  static bool full_backup(const char * dist_id, const char * client_id = NULL);
  static bool full_restore(const char * dist_id, bool remove_existing, bool is_new = true, const char * client_id = NULL);
  static bool app_init(const char * app_home_path = NULL, MyConfig::RUNNING_MODE mode = MyConfig::RM_UNKNOWN);
  static void app_fini();
  static const char * index_frame_file();
  static bool get_mfile(const MyPooledMemGuard & parent_path, MyPooledMemGuard & mfile);

  static void dump_mem_pool_info();

protected:
  virtual bool on_start();
  virtual bool on_construct();
  virtual void on_stop();
  virtual void do_dump_info();
  virtual bool on_sigchild(pid_t pid);

private:
  static bool do_backup_restore(const MyPooledMemGuard & src_parent_path, const MyPooledMemGuard & dest_path, bool remove_existing);
  static bool get_mfile_from_file(const MyPooledMemGuard & parent_path, MyPooledMemGuard & mfile);

  MyClientToDistModule * m_client_to_dist_module;
  MyClientVerson m_client_version;
  std::string m_client_id;
  MyClientIDTable m_client_id_table;
  MyVLCLauncher m_vlc_launcher;
  MyOperaLauncher m_opera_launcher;
};

typedef ACE_Unmanaged_Singleton<MyClientApp, ACE_Null_Mutex> MyClientAppX;



#endif /* CLIENT_H_ */
