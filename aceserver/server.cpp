/*
 * main.cpp
 *
 *  Created on: Dec 26, 2011
 *      Author: root
 */

#include <cstdio>
#include "basemodule.h"
#include "server.h"
#include "distmodule.h"
#include "middlemodule.h"

//MyServerApp//

MyServerApp::MyServerApp()
{
  m_heart_beat_module = NULL;
  m_location_module = NULL;
  m_dist_load_module = NULL;
  m_http_module = NULL;
}

MyServerApp::~MyServerApp()
{

}

MyClientIDTable & MyServerApp::client_id_table()
{
  return m_client_id_table;
}

MyHeartBeatModule * MyServerApp::heart_beat_module() const
{
  return m_heart_beat_module;
}

MyDistLoadModule * MyServerApp::dist_load_module() const
{
  return m_dist_load_module;
}

MyHttpModule * MyServerApp::http_module() const
{
  return m_http_module;
}

MyLocationModule * MyServerApp::location_module() const
{
  return m_location_module;
}

MyDistToMiddleModule * MyServerApp::dist_to_middle_module() const
{
  return m_dist_to_middle_module;
}

MyDB & MyServerApp::db()
{
  return m_db;
}

bool MyServerApp::dist_put_to_service(ACE_Message_Block * mb)
{
  MY_ASSERT_RETURN(mb, "\n", false);

  if (unlikely(!running()))
  {
    mb->release();
    return false;
  }

  return mycomutil_mb_putq(m_heart_beat_module->service(), mb, "to service's queue");
}

bool MyServerApp::on_start()
{

  return true;
}

void MyServerApp::on_stop()
{

}

void MyServerApp::dump_mem_pool_info()
{
  ACE_DEBUG((LM_INFO, "  !!! Memory Dump start !!!\n"));
  long nAlloc = 0, nFree = 0, nMaxUse = 0, nAllocFull = 0;
  if (!g_use_mem_pool)
  {
    ACE_DEBUG((LM_INFO, "    Memory Pool Disabled\n"));
    goto _exit_;
  }
  int chunks;
  //start of dist server stuff
  if (MyHeartBeatHandler::mem_pool())
  {
    chunks = MyHeartBeatHandler::mem_pool()->chunks();
    MyHeartBeatHandler::mem_pool()->get_usage(nAlloc, nFree, nMaxUse, nAllocFull);
    MyBaseApp::mem_pool_dump_one("MyHeartBeatHandler", nAlloc, nFree, nMaxUse, nAllocFull, sizeof(MyHeartBeatHandler), chunks);
  }

  if (MyHeartBeatProcessor::mem_pool())
  {
    chunks = MyHeartBeatProcessor::mem_pool()->chunks();
    MyHeartBeatProcessor::mem_pool()->get_usage(nAlloc, nFree, nMaxUse, nAllocFull);
    MyBaseApp::mem_pool_dump_one("MyHeartBeatProcessor", nAlloc, nFree, nMaxUse, nAllocFull, sizeof(MyHeartBeatProcessor), chunks);
  }

  if (MyDistToBSHandler::mem_pool())
  {
    chunks = MyDistToBSHandler::mem_pool()->chunks();
    MyDistToBSHandler::mem_pool()->get_usage(nAlloc, nFree, nMaxUse, nAllocFull);
    MyBaseApp::mem_pool_dump_one("MyDistToBSHandler", nAlloc, nFree, nMaxUse, nAllocFull, sizeof(MyDistToBSHandler), chunks);
  }

  if (MyDistToMiddleHandler::mem_pool())
  {
    chunks = MyDistToMiddleHandler::mem_pool()->chunks();
    MyDistToMiddleHandler::mem_pool()->get_usage(nAlloc, nFree, nMaxUse, nAllocFull);
    MyBaseApp::mem_pool_dump_one("MyDistToMiddleHandler", nAlloc, nFree, nMaxUse, nAllocFull, sizeof(MyDistToMiddleHandler), chunks);
  }

  //start of middle server stuff
  if (MyLocationHandler::mem_pool())
  {
    chunks = MyLocationHandler::mem_pool()->chunks();
    MyLocationHandler::mem_pool()->get_usage(nAlloc, nFree, nMaxUse, nAllocFull);
    MyBaseApp::mem_pool_dump_one("MyLocationHandler", nAlloc, nFree, nMaxUse, nAllocFull, sizeof(MyLocationHandler), chunks);
  }

  if (MyLocationProcessor::mem_pool())
  {
    chunks = MyLocationProcessor::mem_pool()->chunks();
    MyLocationProcessor::mem_pool()->get_usage(nAlloc, nFree, nMaxUse, nAllocFull);
    MyBaseApp::mem_pool_dump_one("MyLocationProcessor", nAlloc, nFree, nMaxUse, nAllocFull, sizeof(MyLocationProcessor), chunks);
  }

  if (MyHttpHandler::mem_pool())
  {
    chunks = MyHttpHandler::mem_pool()->chunks();
    MyHttpHandler::mem_pool()->get_usage(nAlloc, nFree, nMaxUse, nAllocFull);
    MyBaseApp::mem_pool_dump_one("MyHttpHandler", nAlloc, nFree, nMaxUse, nAllocFull, sizeof(MyHttpHandler), chunks);
  }

  if (MyHttpProcessor::mem_pool())
  {
    chunks = MyHttpProcessor::mem_pool()->chunks();
    MyHttpProcessor::mem_pool()->get_usage(nAlloc, nFree, nMaxUse, nAllocFull);
    MyBaseApp::mem_pool_dump_one("MyHttpProcessor", nAlloc, nFree, nMaxUse, nAllocFull, sizeof(MyHttpProcessor), chunks);
  }

  if (MyDistLoadHandler::mem_pool())
  {
    chunks = MyDistLoadHandler::mem_pool()->chunks();
    MyDistLoadHandler::mem_pool()->get_usage(nAlloc, nFree, nMaxUse, nAllocFull);
    MyBaseApp::mem_pool_dump_one("MyDistLoadHandler", nAlloc, nFree, nMaxUse, nAllocFull, sizeof(MyDistLoadHandler), chunks);
  }

  if (MyMiddleToBSHandler::mem_pool())
  {
    chunks = MyMiddleToBSHandler::mem_pool()->chunks();
    MyMiddleToBSHandler::mem_pool()->get_usage(nAlloc, nFree, nMaxUse, nAllocFull);
    MyBaseApp::mem_pool_dump_one("MyMiddleToBSHandler", nAlloc, nFree, nMaxUse, nAllocFull, sizeof(MyMiddleToBSHandler), chunks);
  }

  MyMemPoolFactoryX::instance()->dump_info();

_exit_:
  ACE_DEBUG((LM_INFO, "  !!! Memory Dump End !!!\n"));
}

void MyServerApp::do_dump_info()
{
  MyServerApp::dump_mem_pool_info();
}

bool MyServerApp::on_construct()
{
  MyConfig * cfg = MyConfigX::instance();
  g_client_id_table = &m_client_id_table;

  if (!m_db.connect())
  {
    MY_FATAL("can not connect to database. quitting...\n");
    return false;
  }
  if (!m_db.get_client_ids(&m_client_id_table))
  {
    MY_FATAL("can not get client_ids database. quitting...\n");
    return false;
  }

  if (cfg->is_dist_server())
  {
    add_module(m_heart_beat_module = new MyHeartBeatModule(this));
    add_module(m_dist_to_middle_module = new MyDistToMiddleModule(this));
  }
  if (cfg->is_middle_server())
  {
    add_module(m_location_module = new MyLocationModule(this));
    add_module(m_dist_load_module = new MyDistLoadModule(this));
    add_module(m_http_module = new MyHttpModule(this));
  }
  return true;
}

bool MyServerApp::app_init(const char * app_home_path, MyConfig::RUNNING_MODE mode)
{
  MyServerApp * app = MyServerAppX::instance();
  MyConfig* cfg = MyConfigX::instance();
  if (!MyConfigX::instance()->load_config(app_home_path, mode))
  {
    std::printf("error loading config file, quitting\n");
    exit(5);
  }
  app->init_log();
  if (cfg->run_as_demon)
    MyBaseApp::app_demonize();
  if (cfg->is_dist_server())
  {
    MyHeartBeatProcessor::init_mem_pool(cfg->max_clients);
    MyHeartBeatHandler::init_mem_pool(cfg->max_clients);
    MyDistToMiddleHandler::init_mem_pool(20);
    MyDistToBSHandler::init_mem_pool(20);
  }
  if (cfg->is_middle_server())
  {
    MyDistLoadHandler::init_mem_pool(50);
    MyLocationHandler::init_mem_pool(1000);
    MyLocationProcessor::init_mem_pool(1000);
    MyHttpProcessor::init_mem_pool(20);
    MyHttpHandler::init_mem_pool(20);
    MyMiddleToBSHandler::init_mem_pool(20);
    MyMiddleToBSProcessor::init_mem_pool(20);
  }
  MyMemPoolFactoryX::instance()->init(cfg);
  return app->do_constructor();
}

void MyServerApp::app_fini()
{
  MY_INFO(ACE_TEXT("shutdown server...\n"));
  MyServerAppX::close();  //this comes before the releasing of memory pool
  g_client_id_table = NULL;
  MyConfigX::close();
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
  MyMemPoolFactoryX::close();
}


int main(int argc, const char * argv[])
{
  ACE_Sig_Action no_sigpipe ((ACE_SignalHandler) SIG_IGN);
  ACE_Sig_Action original_action;
  no_sigpipe.register_action (SIGPIPE, &original_action);
  bool ret;
  #if 0
  MyConfig* cfg = MyConfigX::instance();
  if (!MyConfigX::instance()->load_config("/root/distserver", MyConfig::RM_DIST_SERVER))
  {
    std::printf("error loading config file, quitting\n");
    exit(5);
  }
  MyMemPoolFactoryX::instance()->init(cfg);
  {

  #if 1 //compress/ decompress test
    {
    MyBZCompressor c;
    printf("decompressing multi %d\n", c.decompress("/root/tmp/1112001192.mbz", "/root/testdata/1", "OJZ9l63Zn$@"));
    printf("decompressing all %d\n", c.decompress("/root/tmp/all_in_one.mbz", "/root/testdata/2", "OJZ9l63Zn$@"));
    }
  #endif

  }
  MyConfigX::close();
  MyServerApp::dump_mem_pool_info(); //only mem pool info, other objects should gone by now
  MyMemPoolFactoryX::close();
  return 0;
  #endif

  if (argc == 3 && strcmp(argv[1], "-home") == 0 && argv[2][0] == '/')
    ret = MyServerApp::app_init(argv[2], MyConfig::RM_UNKNOWN);
  else
    ret = MyServerApp::app_init(NULL, MyConfig::RM_UNKNOWN);

  if (ret)
    MyServerAppX::instance()->start();
  MyServerApp::app_fini();
  return 0;
}
