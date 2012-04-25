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
class MyClientApp;

class MyProgramLauncher
{
public:
  MyProgramLauncher();
  virtual ~MyProgramLauncher();

  bool launch();
  void on_terminated(pid_t pid);
  bool running() const;
  void check_relaunch();
  virtual bool ready() const;
  void kill_instance();

protected:
  virtual bool on_launch(ACE_Process_Options & options);
  virtual bool do_on_terminated();
  virtual const char * name() const;

  bool m_wait_for_term;
  ACE_Process_Options m_options;
  time_t m_launch_time;

private:
  enum { INVALID_PID = 0 };
  pid_t m_pid;
  time_t m_last_kill;
};

class MyVLCLauncher: public MyProgramLauncher
{
public:
  MyVLCLauncher();
  virtual bool ready() const;
  int next() const;
  void init_mode(bool b);
  void check_status();

protected:
  virtual bool on_launch(ACE_Process_Options & options);
  virtual const char * name() const;
  bool load(MyPooledMemGuard & file_list);
  bool file_changed();

private:
  enum { GAP_THREASHHOLD = 2 * 60 };

  bool parse_line(char * ptr, MyPooledMemGuard & file_list, bool fill_options);
  void get_file_stat(time_t & t, int & n);
  const char * adv_txt() const;
  const char * gasket() const;
  bool save_file(const char * buff);
  void clean_list() const;

  int m_next;
  MyPooledMemGuard m_current_line;
  bool m_init_mode;
  time_t m_t;
  int m_n;
  bool m_check;
  std::string m_adv_txt;
  std::string m_gasket;
};

class MyOperaLauncher: public MyProgramLauncher
{
public:
  MyOperaLauncher();

  virtual bool ready() const;
  void relaunch();

protected:
  virtual bool on_launch(ACE_Process_Options & options);
  virtual const char * name() const;
};

class MyVLCMonitor: public ACE_Event_Handler
{
public:
  MyVLCMonitor(MyClientApp * app);

  void relaunch();
  virtual int handle_timeout (const ACE_Time_Value &current_time, const void *act = 0);

private:
  void launch_vlc();

  MyClientApp * m_app;
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
  MyVLCMonitor  & vlc_monitor();
  const char * ftp_password();
  void ftp_password(const char * password);

  MyClientIDTable & client_id_table()
    { return m_client_id_table; }

  static void data_path(MyPooledMemGuard & _data_path, const char * client_id = NULL);
  static void calc_display_parent_path(MyPooledMemGuard & parent_path, const char * client_id = NULL);
  static void calc_dist_parent_path(MyPooledMemGuard & parent_path, const char * dist_id, const char * client_id = NULL);
  static void calc_backup_parent_path(MyPooledMemGuard & parent_path, const char * client_id = NULL);
  static void calc_download_parent_path(MyPooledMemGuard & parent_path, const char * client_id = NULL);
  static bool full_backup(const char * dist_id, const char * client_id = NULL);
  static bool full_restore(const char * dist_id, bool remove_existing, bool is_new = true, const char * client_id = NULL, bool init = false);
  static bool app_init(const char * app_home_path = NULL, MyConfig::RUNNING_MODE mode = MyConfig::RM_UNKNOWN);
  static void app_fini();
  static const char * index_frame_file();
  static bool get_mfile(const MyPooledMemGuard & parent_path, MyPooledMemGuard & mfile);
  static void check_prev_extract_task(const char * client_id);
  static void dump_mem_pool_info();

protected:
  virtual bool on_start();
  virtual bool on_construct();
  virtual void on_stop();
  virtual void do_dump_info();
  virtual bool on_sigchild(pid_t pid);
  virtual bool on_event_loop();

private:
  static bool do_backup_restore(const MyPooledMemGuard & src_parent_path, const MyPooledMemGuard & dest_path, bool remove_existing, bool init);
  static bool get_mfile_from_file(const MyPooledMemGuard & parent_path, MyPooledMemGuard & mfile);

  MyClientToDistModule * m_client_to_dist_module;
  MyClientVerson m_client_version;
  std::string m_client_id;
  MyClientIDTable m_client_id_table;
  MyVLCLauncher m_vlc_launcher;
  MyVLCMonitor  m_vlc_monitor;
  MyOperaLauncher m_opera_launcher;
  MyPooledMemGuard m_ftp_password;
  ACE_Thread_Mutex m_mutex;
};

typedef ACE_Unmanaged_Singleton<MyClientApp, ACE_Null_Mutex> MyClientAppX;



#endif /* CLIENT_H_ */
