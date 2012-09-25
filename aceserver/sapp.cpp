#include <cstdio>
#include "component.h"
#include "sapp.h"

std::string current_ver()
{
  std::string result = "1.1 build 120613";
  return result;
}


//MyServerApp//

MyServerApp::MyServerApp()
{
  m_heart_beat_module = NULL;
  m_location_module = NULL;
  m_dist_load_module = NULL;
  m_http_module = NULL;
  m_dist_to_middle_module = NULL;
}

MyServerApp::~MyServerApp()
{

}

CClientIDS & MyServerApp::client_id_table()
{
  return m_client_ids;
}

MyHeartBeatModule * MyServerApp::heart_beat_module() CONST
{
  return m_heart_beat_module;
}

MyDistLoadModule * MyServerApp::dist_load_module() CONST
{
  return m_dist_load_module;
}

MyHttpModule * MyServerApp::http_module() CONST
{
  return m_http_module;
}

MyLocationModule * MyServerApp::location_module() CONST
{
  return m_location_module;
}

MyDistToMiddleModule * MyServerApp::dist_to_middle_module() CONST
{
  return m_dist_to_middle_module;
}

MyDB & MyServerApp::db()
{
  return m_db;
}

truefalse MyServerApp::dist_put_to_service(CMB * mb)
{
  C_ASSERT_RETURN(mb, "\n", false);

  if (unlikely(!running()))
  {
    mb->release();
    return false;
  }

  return c_util_mb_putq(m_heart_beat_module->service(), mb, "to service's queue");
}

truefalse MyServerApp::on_start()
{

  return true;
}

DVOID MyServerApp::on_stop()
{

}

DVOID MyServerApp::dump_mem_pool_info()
{
  ACE_DEBUG((LM_INFO, "  !!! Memory Dump start !!!\n"));
  long nAlloc = 0, nFree = 0, nMaxUse = 0, nAllocFull = 0;
  if (!g_use_mem_pool)
  {
    ACE_DEBUG((LM_INFO, "    Memory Pool Disabled\n"));
    goto _exit_;
  }
  ni chunks;
  //start of dist server stuff
  if (MyHeartBeatHandler::mem_pool())
  {
    chunks = MyHeartBeatHandler::mem_pool()->chunks();
    MyHeartBeatHandler::mem_pool()->get_usage(nAlloc, nFree, nMaxUse, nAllocFull);
    CApp::print_pool("MyHeartBeatHandler", nAlloc, nFree, nMaxUse, nAllocFull, sizeof(MyHeartBeatHandler), chunks);
  }

  if (MyHeartBeatProcessor::mem_pool())
  {
    chunks = MyHeartBeatProcessor::mem_pool()->chunks();
    MyHeartBeatProcessor::mem_pool()->get_usage(nAlloc, nFree, nMaxUse, nAllocFull);
    CApp::print_pool("MyHeartBeatProcessor", nAlloc, nFree, nMaxUse, nAllocFull, sizeof(MyHeartBeatProcessor), chunks);
  }

  if (MyDistToBSHandler::mem_pool())
  {
    chunks = MyDistToBSHandler::mem_pool()->chunks();
    MyDistToBSHandler::mem_pool()->get_usage(nAlloc, nFree, nMaxUse, nAllocFull);
    CApp::print_pool("MyDistToBSHandler", nAlloc, nFree, nMaxUse, nAllocFull, sizeof(MyDistToBSHandler), chunks);
  }

  if (MyDistToMiddleHandler::mem_pool())
  {
    chunks = MyDistToMiddleHandler::mem_pool()->chunks();
    MyDistToMiddleHandler::mem_pool()->get_usage(nAlloc, nFree, nMaxUse, nAllocFull);
    CApp::print_pool("MyDistToMiddleHandler", nAlloc, nFree, nMaxUse, nAllocFull, sizeof(MyDistToMiddleHandler), chunks);
  }

  //start of middle server stuff
  if (MyLocationHandler::mem_pool())
  {
    chunks = MyLocationHandler::mem_pool()->chunks();
    MyLocationHandler::mem_pool()->get_usage(nAlloc, nFree, nMaxUse, nAllocFull);
    CApp::print_pool("MyLocationHandler", nAlloc, nFree, nMaxUse, nAllocFull, sizeof(MyLocationHandler), chunks);
  }

  if (MyLocationProcessor::mem_pool())
  {
    chunks = MyLocationProcessor::mem_pool()->chunks();
    MyLocationProcessor::mem_pool()->get_usage(nAlloc, nFree, nMaxUse, nAllocFull);
    CApp::print_pool("MyLocationProcessor", nAlloc, nFree, nMaxUse, nAllocFull, sizeof(MyLocationProcessor), chunks);
  }

  if (MyHttpHandler::mem_pool())
  {
    chunks = MyHttpHandler::mem_pool()->chunks();
    MyHttpHandler::mem_pool()->get_usage(nAlloc, nFree, nMaxUse, nAllocFull);
    CApp::print_pool("MyHttpHandler", nAlloc, nFree, nMaxUse, nAllocFull, sizeof(MyHttpHandler), chunks);
  }

  if (MyHttpProcessor::mem_pool())
  {
    chunks = MyHttpProcessor::mem_pool()->chunks();
    MyHttpProcessor::mem_pool()->get_usage(nAlloc, nFree, nMaxUse, nAllocFull);
    CApp::print_pool("MyHttpProcessor", nAlloc, nFree, nMaxUse, nAllocFull, sizeof(MyHttpProcessor), chunks);
  }

  if (MyDistLoadHandler::mem_pool())
  {
    chunks = MyDistLoadHandler::mem_pool()->chunks();
    MyDistLoadHandler::mem_pool()->get_usage(nAlloc, nFree, nMaxUse, nAllocFull);
    CApp::print_pool("MyDistLoadHandler", nAlloc, nFree, nMaxUse, nAllocFull, sizeof(MyDistLoadHandler), chunks);
  }

  if (MyMiddleToBSHandler::mem_pool())
  {
    chunks = MyMiddleToBSHandler::mem_pool()->chunks();
    MyMiddleToBSHandler::mem_pool()->get_usage(nAlloc, nFree, nMaxUse, nAllocFull);
    CApp::print_pool("MyMiddleToBSHandler", nAlloc, nFree, nMaxUse, nAllocFull, sizeof(MyMiddleToBSHandler), chunks);
  }

  CMemPoolX::instance()->print_info();

_exit_:
  ACE_DEBUG((LM_INFO, "  !!! Memory Dump End !!!\n"));
}

DVOID MyServerApp::do_dump_info()
{
  MyServerApp::dump_mem_pool_info();
}

truefalse MyServerApp::on_construct()
{
  CCfg * cfg = CCfgX::instance();
  g_client_ids = &m_client_ids;

  if (!m_db.connect())
  {
    C_FATAL("can not connect to database. quitting...\n");
    return false;
  }
  if (!m_db.get_client_ids(&m_client_ids))
  {
    C_FATAL("can not get client_ids database. quitting...\n");
    return false;
  }

  if (cfg->is_dist())
  {
    add_module(m_heart_beat_module = new MyHeartBeatModule(this));
    add_module(m_dist_to_middle_module = new MyDistToMiddleModule(this));
  }
  if (cfg->is_middle())
  {
    add_module(m_location_module = new MyLocationModule(this));
    add_module(m_dist_load_module = new MyDistLoadModule(this));
    add_module(m_http_module = new MyHttpModule(this));
  }
  return true;
}

truefalse MyServerApp::app_init(CONST text * app_home_path, CCfg::CAppMode mode)
{
  MyServerApp * app = MyServerAppX::instance();
  CCfg* cfg = CCfgX::instance();
  if (!CCfgX::instance()->readall(app_home_path, mode))
  {
    std::printf("error loading config file, quitting\n");
    exit(5);
  }
  if (cfg->as_demon)
    CApp::demon();
  if (cfg->is_dist())
  {
    MyHeartBeatProcessor::init_mem_pool(cfg->max_client_count);
    MyHeartBeatHandler::init_mem_pool(cfg->max_client_count);
    MyDistToMiddleHandler::init_mem_pool(20);
    MyDistToBSHandler::init_mem_pool(20);
  }
  if (cfg->is_middle())
  {
    MyDistLoadHandler::init_mem_pool(50);
    MyLocationHandler::init_mem_pool(1000);
    MyLocationProcessor::init_mem_pool(1000);
    MyHttpProcessor::init_mem_pool(20);
    MyHttpHandler::init_mem_pool(20);
    MyMiddleToBSHandler::init_mem_pool(20);
    MyMiddleToBSProcessor::init_mem_pool(20);
  }
  CMemPoolX::instance()->init(cfg);
  app->init_log();
  return app->delayed_init();
}

DVOID MyServerApp::app_fini()
{
  C_INFO(ACE_TEXT("shutdown server...\n"));
  MyServerAppX::close();  //this comes before the releasing of memory pool
  g_client_ids = NULL;
  CCfgX::close();
  dump_mem_pool_info(); //only mem pool info, other objects should gone by now
  MyHeartBeatHandler::fini_mem_pool();
  MyHeartBeatProcessor::fini_mem_pool();
  MyLocationHandler::fini_mem_pool();
  MyLocationProcessor::fini_mem_pool();
  MyDistLoadHandler::fini_mem_pool();
  MyHttpHandler::fini_mem_pool();
  MyHttpProcessor::fini_mem_pool();
  MyDistToMiddleHandler::fini_mem_pool();
  MyDistToBSHandler::fini_mem_pool();
  MyMiddleToBSHandler::fini_mem_pool();
  MyMiddleToBSProcessor::fini_mem_pool();
  CMemPoolX::close();
}


int main(ni argc, CONST text * argv[])
{
  ACE_Sig_Action no_sigpipe ((ACE_SignalHandler) SIG_IGN);
  ACE_Sig_Action original_action;
  no_sigpipe.register_action (SIGPIPE, &original_action);
  truefalse ret;

  if (argc == 3 && strcmp(argv[1], "-home") == 0 && argv[2][0] == '/')
    ret = MyServerApp::app_init(argv[2], CCfg::AM_UNKNOWN);
  else
    ret = MyServerApp::app_init(NULL, CCfg::AM_UNKNOWN);

  if (ret)
    MyServerAppX::instance()->start();
  MyServerApp::app_fini();
  return 0;
}
