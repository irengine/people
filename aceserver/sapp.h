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
  CBalanceContainer * balance_container() CONST;
  CBsReqContainer * bs_req_container() CONST;
  CPositionContainer * position_container() CONST;
  CD2MContainer * d2m_container() CONST;
  CPG & pg();

  SF truefalse initialize(CONST text * hpath = NULL, CCfg::CAppMode m = CCfg::AM_UNKNOWN);
  SF DVOID cleanup();
  SF DVOID print_caches();
  truefalse post_dist_task(CMB * mb);

protected:
  virtual truefalse before_begin();
  virtual truefalse do_init();
  virtual DVOID before_finish();
  virtual DVOID i_print();

private:
  CPingContainer * m_ping_container;
  CPositionContainer * m_position_container;
  CBalanceContainer * m_balance_container;
  CBsReqContainer     * m_bs_req_container;
  CD2MContainer * m_d2m_container;
  CTermSNs m_term_SNs;
  CPG  m_pg;
};

typedef ACE_Unmanaged_Singleton<CRunner, ACE_Null_Mutex> CRunnerX;

#endif
