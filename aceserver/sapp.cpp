#include <cstdio>
#include "component.h"
#include "sapp.h"

std::string current_ver()
{
  std::string result = "1.1 build 120613";
  return result;
}


//MyServerApp//

CRunner::CRunner()
{
  m_ping_component = NULL;
  m_location_module = NULL;
  m_dist_load_module = NULL;
  m_http_module = NULL;
  m_dist_to_middle_module = NULL;
}

CRunner::~CRunner()
{

}

CTermSNs & CRunner::termSNs()
{
  return m_term_SNs;
}

MyHeartBeatModule * CRunner::ping_component() CONST
{
  return m_ping_component;
}

MyDistLoadModule * CRunner::dist_load_module() CONST
{
  return m_dist_load_module;
}

MyHttpModule * CRunner::http_module() CONST
{
  return m_http_module;
}

CPositionContainer * CRunner::location_module() CONST
{
  return m_location_module;
}

MyDistToMiddleModule * CRunner::dist_to_middle_module() CONST
{
  return m_dist_to_middle_module;
}

MyDB & CRunner::db()
{
  return m_db;
}

truefalse CRunner::post_dist_task(CMB * mb)
{
  C_ASSERT_RETURN(mb, "\n", false);

  if (unlikely(!running()))
  {
    mb->release();
    return false;
  }

  return c_tools_mb_putq(m_ping_component->service(), mb, "to service's queue");
}

truefalse CRunner::before_begin()
{

  return true;
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
  ni blocks;
  //d
  if (MyHeartBeatHandler::mem_block())
  {
    blocks = MyHeartBeatHandler::mem_block()->blocks();
    MyHeartBeatHandler::mem_block()->query_stats(l_get, l_put, l_peak, l_fail);
    CApp::print_pool("MyHeartBeatHandler", l_get, l_put, l_peak, l_fail, sizeof(MyHeartBeatHandler), blocks);
  }

  if (MyHeartBeatProcessor::mem_block())
  {
    blocks = MyHeartBeatProcessor::mem_block()->blocks();
    MyHeartBeatProcessor::mem_block()->query_stats(l_get, l_put, l_peak, l_fail);
    CApp::print_pool("MyHeartBeatProcessor", l_get, l_put, l_peak, l_fail, sizeof(MyHeartBeatProcessor), blocks);
  }

  if (MyDistToBSHandler::mem_block())
  {
    blocks = MyDistToBSHandler::mem_block()->blocks();
    MyDistToBSHandler::mem_block()->query_stats(l_get, l_put, l_peak, l_fail);
    CApp::print_pool("MyDistToBSHandler", l_get, l_put, l_peak, l_fail, sizeof(MyDistToBSHandler), blocks);
  }

  if (MyDistToMiddleHandler::mem_block())
  {
    blocks = MyDistToMiddleHandler::mem_block()->blocks();
    MyDistToMiddleHandler::mem_block()->query_stats(l_get, l_put, l_peak, l_fail);
    CApp::print_pool("MyDistToMiddleHandler", l_get, l_put, l_peak, l_fail, sizeof(MyDistToMiddleHandler), blocks);
  }

  //m
  if (CPositionHandler::mem_block())
  {
    blocks = CPositionHandler::mem_block()->blocks();
    CPositionHandler::mem_block()->query_stats(l_get, l_put, l_peak, l_fail);
    CApp::print_pool("MyLocationHandler", l_get, l_put, l_peak, l_fail, sizeof(CPositionHandler), blocks);
  }

  if (CPositionProc::mem_block())
  {
    blocks = CPositionProc::mem_block()->blocks();
    CPositionProc::mem_block()->query_stats(l_get, l_put, l_peak, l_fail);
    CApp::print_pool("MyLocationProcessor", l_get, l_put, l_peak, l_fail, sizeof(CPositionProc), blocks);
  }

  if (CBsReqHandler::mem_block())
  {
    blocks = CBsReqHandler::mem_block()->blocks();
    CBsReqHandler::mem_block()->query_stats(l_get, l_put, l_peak, l_fail);
    CApp::print_pool("MyHttpHandler", l_get, l_put, l_peak, l_fail, sizeof(CBsReqHandler), blocks);
  }

  if (CBsReqProc::mem_block())
  {
    blocks = CBsReqProc::mem_block()->blocks();
    CBsReqProc::mem_block()->query_stats(l_get, l_put, l_peak, l_fail);
    CApp::print_pool("MyHttpProcessor", l_get, l_put, l_peak, l_fail, sizeof(CBsReqProc), blocks);
  }

  if (MyDistLoadHandler::mem_block())
  {
    blocks = MyDistLoadHandler::mem_block()->blocks();
    MyDistLoadHandler::mem_block()->query_stats(l_get, l_put, l_peak, l_fail);
    CApp::print_pool("MyDistLoadHandler", l_get, l_put, l_peak, l_fail, sizeof(MyDistLoadHandler), blocks);
  }

  if (MyMiddleToBSHandler::mem_block())
  {
    blocks = MyMiddleToBSHandler::mem_block()->blocks();
    MyMiddleToBSHandler::mem_block()->query_stats(l_get, l_put, l_peak, l_fail);
    CApp::print_pool("MyMiddleToBSHandler", l_get, l_put, l_peak, l_fail, sizeof(MyMiddleToBSHandler), blocks);
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
  CCfg * cfg = CCfgX::instance();
  g_term_sns = &m_term_SNs;

  if (!m_db.connect())
  {
    C_FATAL("fail to connect to database. quitting...\n");
    return false;
  }
  if (!m_db.get_client_ids(&m_term_SNs))
  {
    C_FATAL("fail to get term sn from db. quitting...\n");
    return false;
  }

  if (cfg->dist())
  {
    add_component(m_ping_component = new MyHeartBeatModule(this));
    add_component(m_dist_to_middle_module = new MyDistToMiddleModule(this));
  }
  if (cfg->middle())
  {
    add_component(m_location_module = new CPositionContainer(this));
    add_component(m_dist_load_module = new MyDistLoadModule(this));
    add_component(m_http_module = new MyHttpModule(this));
  }
  return true;
}

truefalse CRunner::initialize(CONST text * v_dir, CCfg::CAppMode v_m)
{
  CRunner * app = CRunnerX::instance();
  CCfg* l_p = CCfgX::instance();
  if (!CCfgX::instance()->readall(v_dir, v_m))
  {
    std::printf("fail read config\n");
    exit(5);
  }
  if (l_p->is_demon)
    CApp::demon();
  if (l_p->dist())
  {
    MyHeartBeatProcessor::mem_block_start(l_p->client_peak);
    MyHeartBeatHandler::mem_block_start(l_p->client_peak);
    MyDistToMiddleHandler::mem_block_start(20);
    MyDistToBSHandler::mem_block_start(20);
  }
  if (l_p->middle())
  {
    MyDistLoadHandler::mem_block_start(50);
    CPositionHandler::mem_block_start(1000);
    CPositionProc::mem_block_start(1000);
    CBsReqProc::mem_block_start(20);
    CBsReqHandler::mem_block_start(20);
    MyMiddleToBSHandler::mem_block_start(20);
    MyMiddleToBSProcessor::mem_block_start(20);
  }
  CCacheX::instance()->prepare(l_p);
  app->init_log();
  return app->delayed_init();
}

DVOID CRunner::cleanup()
{
  C_INFO(ACE_TEXT("shutdown server...\n"));
  CRunnerX::close();  //this comes before the releasing of memory pool
  g_term_sns = NULL;
  CCfgX::close();
  print_caches(); //only mem pool info, other objects should gone by now
  MyHeartBeatHandler::mem_block_end();
  MyHeartBeatProcessor::mem_block_end();
  CPositionHandler::mem_block_end();
  CPositionProc::mem_block_end();
  MyDistLoadHandler::mem_block_end();
  CBsReqHandler::mem_block_end();
  CBsReqProc::mem_block_end();
  MyDistToMiddleHandler::mem_block_end();
  MyDistToBSHandler::mem_block_end();
  MyMiddleToBSHandler::mem_block_end();
  MyMiddleToBSProcessor::mem_block_end();
  CCacheX::close();
}


int main(ni argc, CONST text * argv[])
{
  ACE_Sig_Action no_sigpipe ((ACE_SignalHandler) SIG_IGN);
  ACE_Sig_Action original_action;
  no_sigpipe.register_action (SIGPIPE, &original_action);
  truefalse ret;

  if (argc == 3 && strcmp(argv[1], "-home") == 0 && argv[2][0] == '/')
    ret = CRunner::initialize(argv[2], CCfg::AM_UNKNOWN);
  else
    ret = CRunner::initialize(NULL, CCfg::AM_UNKNOWN);

  if (ret)
    CRunnerX::instance()->begin();
  CRunner::cleanup();
  return 0;
}
