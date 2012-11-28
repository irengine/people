#include <cstdio>
#include "component.h"
#include "sapp.h"

std::string current_ver()
{
  std::string result = "1.1 build 120613";
  return result;
}


CRunner::CRunner()
{
  m_bs_req_container = NULL;
  m_d2m_container = NULL;
  m_ping_container = NULL;
  m_position_container = NULL;
  m_balance_container = NULL;
}

CRunner::~CRunner()
{

}

CTermSNs & CRunner::termSNs()
{
  return m_term_SNs;
}

CPingContainer * CRunner::ping_component() CONST
{
  return m_ping_container;
}

CBalanceContainer * CRunner::balance_container() CONST
{
  return m_balance_container;
}

CBsReqContainer * CRunner::bs_req_container() CONST
{
  return m_bs_req_container;
}

CPositionContainer * CRunner::position_container() CONST
{
  return m_position_container;
}

CD2MContainer * CRunner::d2m_container() CONST
{
  return m_d2m_container;
}

CPG & CRunner::pg()
{
  return m_pg;
}

truefalse CRunner::post_dist_task(CMB * mb)
{
  C_ASSERT_RETURN(mb, "\n", C_BAD);

  if (unlikely(!running()))
  {
    mb->release();
    return C_BAD;
  }

  return c_tools_mb_putq(m_ping_container->task(), mb, "post dist task");
}

truefalse CRunner::before_begin()
{
  return C_OK;
}

DVOID CRunner::before_finish()
{

}

DVOID CRunner::print_caches()
{
  ACE_DEBUG((LM_INFO, "  !!! Cache begin !!!\n"));
  long l_get = 0, l_put = 0, l_peak = 0, l_fail = 0;
  if (!g_cache)
  {
    ACE_DEBUG((LM_INFO, "    Cache Disabled\n"));
    goto _exit_;
  }
  ni l_chunks;
  //d
  if (CPingHandler::mem_block())
  {
    l_chunks = CPingHandler::mem_block()->blocks();
    CPingHandler::mem_block()->query_stats(l_get, l_put, l_peak, l_fail);
    CParentRunner::print_pool("MyHeartBeatHandler", l_get, l_put, l_peak, l_fail, sizeof(CPingHandler), l_chunks);
  }

  if (CPingProc::mem_block())
  {
    l_chunks = CPingProc::mem_block()->blocks();
    CPingProc::mem_block()->query_stats(l_get, l_put, l_peak, l_fail);
    CParentRunner::print_pool("MyHeartBeatProcessor", l_get, l_put, l_peak, l_fail, sizeof(CPingProc), l_chunks);
  }

  if (CD2BsHandler::mem_block())
  {
    l_chunks = CD2BsHandler::mem_block()->blocks();
    CD2BsHandler::mem_block()->query_stats(l_get, l_put, l_peak, l_fail);
    CParentRunner::print_pool("MyDistToBSHandler", l_get, l_put, l_peak, l_fail, sizeof(CD2BsHandler), l_chunks);
  }

  if (CD2MHandler::mem_block())
  {
    l_chunks = CD2MHandler::mem_block()->blocks();
    CD2MHandler::mem_block()->query_stats(l_get, l_put, l_peak, l_fail);
    CParentRunner::print_pool("MyDistToMiddleHandler", l_get, l_put, l_peak, l_fail, sizeof(CD2MHandler), l_chunks);
  }

  //m
  if (CPositionHandler::mem_block())
  {
    l_chunks = CPositionHandler::mem_block()->blocks();
    CPositionHandler::mem_block()->query_stats(l_get, l_put, l_peak, l_fail);
    CParentRunner::print_pool("MyLocationHandler", l_get, l_put, l_peak, l_fail, sizeof(CPositionHandler), l_chunks);
  }

  if (CPositionProc::mem_block())
  {
    l_chunks = CPositionProc::mem_block()->blocks();
    CPositionProc::mem_block()->query_stats(l_get, l_put, l_peak, l_fail);
    CParentRunner::print_pool("MyLocationProcessor", l_get, l_put, l_peak, l_fail, sizeof(CPositionProc), l_chunks);
  }

  if (CBsReqHandler::mem_block())
  {
    l_chunks = CBsReqHandler::mem_block()->blocks();
    CBsReqHandler::mem_block()->query_stats(l_get, l_put, l_peak, l_fail);
    CParentRunner::print_pool("MyHttpHandler", l_get, l_put, l_peak, l_fail, sizeof(CBsReqHandler), l_chunks);
  }

  if (CBsReqProc::mem_block())
  {
    l_chunks = CBsReqProc::mem_block()->blocks();
    CBsReqProc::mem_block()->query_stats(l_get, l_put, l_peak, l_fail);
    CParentRunner::print_pool("MyHttpProcessor", l_get, l_put, l_peak, l_fail, sizeof(CBsReqProc), l_chunks);
  }

  if (CBalanceHandler::mem_block())
  {
    l_chunks = CBalanceHandler::mem_block()->blocks();
    CBalanceHandler::mem_block()->query_stats(l_get, l_put, l_peak, l_fail);
    CParentRunner::print_pool("MyDistLoadHandler", l_get, l_put, l_peak, l_fail, sizeof(CBalanceHandler), l_chunks);
  }

  if (CM2BsHandler::mem_block())
  {
    l_chunks = CM2BsHandler::mem_block()->blocks();
    CM2BsHandler::mem_block()->query_stats(l_get, l_put, l_peak, l_fail);
    CParentRunner::print_pool("MyMiddleToBSHandler", l_get, l_put, l_peak, l_fail, sizeof(CM2BsHandler), l_chunks);
  }

  CCacheX::instance()->print_info();

_exit_:
  ACE_DEBUG((LM_INFO, "  !!! Cache Finish !!!\n"));
}

DVOID CRunner::i_print()
{
  CRunner::print_caches();
}

truefalse CRunner::do_init()
{
  CCfg * l_obj = CCfgX::instance();
  g_term_sns = &m_term_SNs;

  if (!m_pg.login_to_db())
  {
    C_FATAL("fail to connect to database. quitting...\n");
    return C_BAD;
  }
  if (!m_pg.load_term_SNs(&m_term_SNs))
  {
    C_FATAL("fail to get term sn from db. quitting...\n");
    return C_BAD;
  }

  if (l_obj->handleout())
  {
    add_component(m_ping_container = new CPingContainer(this));
    add_component(m_d2m_container = new CD2MContainer(this));
  }
  if (l_obj->pre())
  {
    add_component(m_position_container = new CPositionContainer(this));
    add_component(m_balance_container = new CBalanceContainer(this));
    add_component(m_bs_req_container = new CBsReqContainer(this));
  }
  return C_OK;
}

truefalse CRunner::initialize(CONST text * v_dir, CCfg::CXYZStyle v_m)
{
  CRunner * l_runner = CRunnerX::instance();
  CCfg* l_p = CCfgX::instance();
  if (!CCfgX::instance()->readall(v_dir, v_m))
  {
    std::printf("fail read config\n");
    exit(5);
  }
  if (l_p->run_at_back)
    CParentRunner::put_to_back();
  if (l_p->handleout())
  {
    CPingProc::mem_block_start(l_p->term_peak);
    CPingHandler::mem_block_start(l_p->term_peak);
    CD2MHandler::mem_block_start(20);
    CD2BsHandler::mem_block_start(20);
  }
  if (l_p->pre())
  {
    CBalanceHandler::mem_block_start(50);
    CPositionHandler::mem_block_start(1000);
    CPositionProc::mem_block_start(1000);
    CBsReqProc::mem_block_start(20);
    CBsReqHandler::mem_block_start(20);
    CM2BsHandler::mem_block_start(20);
    CM2BsProc::mem_block_start(20);
  }
  CCacheX::instance()->prepare(l_p);
  l_runner->init_log();
  return l_runner->delayed_init();
}

DVOID CRunner::cleanup()
{
  C_INFO("closing app...\n");
  CRunnerX::close();
  g_term_sns = NULL;
  CCfgX::close();
  print_caches();
  CPingHandler::mem_block_end();
  CPingProc::mem_block_end();
  CPositionHandler::mem_block_end();
  CPositionProc::mem_block_end();
  CBalanceHandler::mem_block_end();
  CBsReqHandler::mem_block_end();
  CBsReqProc::mem_block_end();
  CD2MHandler::mem_block_end();
  CD2BsHandler::mem_block_end();
  CM2BsHandler::mem_block_end();
  CM2BsProc::mem_block_end();
  CCacheX::close();
}


int main(ni argc, CONST text * argv[])
{
  ACE_Sig_Action l_x ((ACE_SignalHandler) SIG_IGN);
  ACE_Sig_Action l_y;
  l_x.register_action (SIGPIPE, &l_y);
  truefalse l_z;

  if (argc == 3 && strcmp(argv[1], "-home") == 0 && argv[2][0] == '/')
    l_z = CRunner::initialize(argv[2], CCfg::AM_BAD);
  else
    l_z = CRunner::initialize(NULL, CCfg::AM_BAD);

  if (l_z)
    CRunnerX::instance()->begin();
  CRunner::cleanup();
  return 0;
}
