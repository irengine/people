#ifndef sapp_h_dkjf834ab
#define sapp_h_dkjf834ab

#include "tools.h"
#include "app.h"
#include "sall.h"

class CPingContainer;
class CPositionContainer;

class CRunner: public CApp
{
public:
  CRunner();
  virtual ~CRunner();

  CTermSNs & termSNs();
  CPingContainer * ping_component() CONST;
  CBalanceContainer * dist_load_module() CONST;
  CBsReqContainer * http_module() CONST;
  CPositionContainer * location_module() CONST;
  CD2MContainer * dist_to_middle_module() CONST;
  CPG & db();

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
  CPingContainer * m_ping_component;
  CPositionContainer * m_location_module;
  CBalanceContainer * m_dist_load_module;
  CBsReqContainer     * m_http_module;
  CD2MContainer * m_dist_to_middle_module;
  CTermSNs m_term_SNs;
  CPG  m_db;
};

typedef ACE_Unmanaged_Singleton<CRunner, ACE_Null_Mutex> CRunnerX;

#endif
