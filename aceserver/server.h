/*
 * server.h
 *
 *  Created on: Jan 9, 2012
 *      Author: root
 */

#ifndef SERVER_H_
#define SERVER_H_

#include "common.h"
#include "baseapp.h"
#include "dbmodule.h"
#include "middlemodule.h"
#include "distmodule.h"

class MyHeartBeatModule;
class MyLocationModule;


class MyServerApp: public MyBaseApp
{
public:
  MyServerApp();
  virtual ~MyServerApp();

  MyClientIDTable & client_id_table();
  MyHeartBeatModule * heart_beat_module() const;
  MyDistLoadModule * dist_load_module() const;
  MyHttpModule * http_module() const;
  MyLocationModule * location_module() const;
  MyDistToMiddleModule * dist_to_middle_module() const;
  MyDB & db();

  static bool app_init(const char * app_home_path = NULL, MyConfig::RUNNING_MODE mode = MyConfig::RM_UNKNOWN);
  static void app_fini();
  static void dump_mem_pool_info();
  bool dist_put_to_service(ACE_Message_Block * mb);

protected:
  virtual bool on_start();
  virtual bool on_construct();
  virtual void on_stop();
  virtual void do_dump_info();

private:
  MyHeartBeatModule * m_heart_beat_module;
  MyLocationModule * m_location_module;
  MyDistLoadModule * m_dist_load_module;
  MyHttpModule     * m_http_module;
  MyDistToMiddleModule * m_dist_to_middle_module;
  MyClientIDTable m_client_id_table;
  MyDB  m_db;
};

typedef ACE_Unmanaged_Singleton<MyServerApp, ACE_Null_Mutex> MyServerAppX;

#endif /* SERVER_H_ */
