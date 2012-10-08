#ifndef sapp_h_dkjf834ab
#define sapp_h_dkjf834ab

#include "tools.h"
#include "app.h"
#include "sall.h"

class MyHeartBeatModule;
class MyLocationModule;

class CRunner: public CApp
{
public:
  CRunner();
  virtual ~CRunner();

  CTermSNs & termSNs();
  MyHeartBeatModule * ping_component() CONST;
  MyDistLoadModule * dist_load_module() CONST;
  MyHttpModule * http_module() CONST;
  MyLocationModule * location_module() CONST;
  MyDistToMiddleModule * dist_to_middle_module() CONST;
  MyDB & db();

  SF truefalse initialize(CONST text * hdir = NULL, CCfg::CAppMode m = CCfg::AM_UNKNOWN);
  SF DVOID cleanup();
  SF DVOID print_caches();
  truefalse post_dist_task(CMB * mb);

protected:
  virtual truefalse before_begin();
  virtual truefalse do_init();
  virtual DVOID before_finish();
  virtual DVOID i_print();

private:
  MyHeartBeatModule * m_ping_component;
  MyLocationModule * m_location_module;
  MyDistLoadModule * m_dist_load_module;
  MyHttpModule     * m_http_module;
  MyDistToMiddleModule * m_dist_to_middle_module;
  CTermSNs m_term_SNs;
  MyDB  m_db;
};

typedef ACE_Unmanaged_Singleton<CRunner, ACE_Null_Mutex> CRunnerX;

#endif