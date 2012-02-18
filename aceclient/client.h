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

class MyClientToDistModule;

class MyClientApp: public MyBaseApp
{
public:
  MyClientApp();
  virtual ~MyClientApp();

  MyClientToDistModule * client_to_dist_module() const;
  bool send_mb_to_dist(ACE_Message_Block * mb);
  const MyClientVerson & client_version() const;
  const char * client_id() const;

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

  static void dump_mem_pool_info();

protected:
  virtual bool on_start();
  virtual bool on_construct();
  virtual void on_stop();
  virtual void do_dump_info();

private:
  MyClientToDistModule * m_client_to_dist_module;
  MyClientVerson m_client_version;
  std::string m_client_id;
  MyClientIDTable m_client_id_table;
};

typedef ACE_Unmanaged_Singleton<MyClientApp, ACE_Null_Mutex> MyClientAppX;



#endif /* CLIENT_H_ */
