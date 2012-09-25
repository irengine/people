#ifndef SERVER_H_
#define SERVER_H_

#include "tools.h"
#include "app.h"
#include "sall.h"

class MyHeartBeatModule;
class MyLocationModule;

class MyServerApp: public CApp
{
public:
  MyServerApp();
  virtual ~MyServerApp();

  CClientIDS & client_id_table();
  MyHeartBeatModule * heart_beat_module() CONST;
  MyDistLoadModule * dist_load_module() CONST;
  MyHttpModule * http_module() CONST;
  MyLocationModule * location_module() CONST;
  MyDistToMiddleModule * dist_to_middle_module() CONST;
  MyDB & db();

  SF truefalse app_init(CONST text * app_home_path = NULL, CCfg::CAppMode mode = CCfg::AM_UNKNOWN);
  SF DVOID app_fini();
  SF DVOID dump_mem_pool_info();
  truefalse dist_put_to_service(CMB * mb);

protected:
  virtual truefalse on_start();
  virtual truefalse on_construct();
  virtual DVOID on_stop();
  virtual DVOID do_dump_info();

private:
  MyHeartBeatModule * m_heart_beat_module;
  MyLocationModule * m_location_module;
  MyDistLoadModule * m_dist_load_module;
  MyHttpModule     * m_http_module;
  MyDistToMiddleModule * m_dist_to_middle_module;
  CClientIDS m_client_ids;
  MyDB  m_db;
};

typedef ACE_Unmanaged_Singleton<MyServerApp, ACE_Null_Mutex> MyServerAppX;

#endif /* SERVER_H_ */
