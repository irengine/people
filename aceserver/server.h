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

class MyHeartBeatModule;
class MyLocationModule;


class MyServerApp: public MyBaseApp
{
public:
  MyServerApp();
  virtual ~MyServerApp();

  MyClientIDTable & client_id_table();
  MyHeartBeatModule * heart_beat_module() const;

  static void app_init(const char * app_home_path = NULL, MyConfig::RUNNING_MODE mode = MyConfig::RM_UNKNOWN);
  static void app_fini();

  virtual void dump_info();

protected:
  virtual bool on_start();
  virtual bool on_construct();
  virtual void on_stop();

private:
  MyHeartBeatModule * m_heart_beat_module;
  MyLocationModule * m_location_module;
  MyClientIDTable m_client_id_table;
};

typedef ACE_Unmanaged_Singleton<MyServerApp, ACE_Null_Mutex> MyServerAppX;

#endif /* SERVER_H_ */
