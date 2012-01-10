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

  static void app_init(const char * app_home_path = NULL, MyConfig::RUNNING_MODE mode = MyConfig::RM_UNKNOWN);
  static void app_fini();

  virtual void dump_info();

protected:
  virtual bool on_start();
  virtual bool on_construct();
  virtual void on_stop();

private:
  MyClientToDistModule * m_client_to_dist_module;
};

typedef ACE_Unmanaged_Singleton<MyClientApp, ACE_Null_Mutex> MyClientAppX;



#endif /* CLIENT_H_ */
