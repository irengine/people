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
  //start of dist server stuff
  if (MyHeartBeatHandler::mem_pool())
  {
    MyHeartBeatHandler::mem_pool()->get_usage(nAlloc, nFree, nMaxUse, nAllocFull);
    MyBaseApp::mem_pool_dump_one("MyHeartBeatHandler", nAlloc, nFree, nMaxUse, nAllocFull, sizeof(MyHeartBeatHandler));
  }

  if (MyDistToBSHandler::mem_pool())
  {
    MyDistToBSHandler::mem_pool()->get_usage(nAlloc, nFree, nMaxUse, nAllocFull);
    MyBaseApp::mem_pool_dump_one("MyDistToBSHandler", nAlloc, nFree, nMaxUse, nAllocFull, sizeof(MyDistToBSHandler));
  }

  if (MyDistToMiddleHandler::mem_pool())
  {
    MyDistToMiddleHandler::mem_pool()->get_usage(nAlloc, nFree, nMaxUse, nAllocFull);
    MyBaseApp::mem_pool_dump_one("MyDistToMiddleHandler", nAlloc, nFree, nMaxUse, nAllocFull, sizeof(MyDistToMiddleHandler));
  }

  //start of middle server stuff
  if (MyLocationHandler::mem_pool())
  {
    MyLocationHandler::mem_pool()->get_usage(nAlloc, nFree, nMaxUse, nAllocFull);
    MyBaseApp::mem_pool_dump_one("MyLocationHandler", nAlloc, nFree, nMaxUse, nAllocFull, sizeof(MyLocationHandler));
  }

  if (MyHttpHandler::mem_pool())
  {
    MyHttpHandler::mem_pool()->get_usage(nAlloc, nFree, nMaxUse, nAllocFull);
    MyBaseApp::mem_pool_dump_one("MyHttpHandler", nAlloc, nFree, nMaxUse, nAllocFull, sizeof(MyHttpHandler));
  }

  if (MyDistLoadHandler::mem_pool())
  {
    MyDistLoadHandler::mem_pool()->get_usage(nAlloc, nFree, nMaxUse, nAllocFull);
    MyBaseApp::mem_pool_dump_one("MyDistLoadHandler", nAlloc, nFree, nMaxUse, nAllocFull, sizeof(MyDistLoadHandler));
  }

  if (MyMiddleToBSHandler::mem_pool())
  {
    MyMiddleToBSHandler::mem_pool()->get_usage(nAlloc, nFree, nMaxUse, nAllocFull);
    MyBaseApp::mem_pool_dump_one("MyMiddleToBSHandler", nAlloc, nFree, nMaxUse, nAllocFull, sizeof(MyMiddleToBSHandler));
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

#ifdef MY_server_test
  if (cfg->is_dist_server())
  {
    char * _app_data_path = new char[cfg->app_test_data_path.length() + 1];
    strcpy(_app_data_path, cfg->app_test_data_path.c_str());

    MyTestClientPathGenerator::make_paths_from_id_table(_app_data_path, &m_client_id_table);
    delete [] _app_data_path;
  }
#endif

  if (cfg->is_dist_server())
  {
    add_module(m_heart_beat_module = new MyHeartBeatModule(this));
    if (cfg->remote_access_port > 0)
      add_module(new MyDistRemoteAccessModule(this));
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
  if (cfg->run_as_demon)
    MyBaseApp::app_demonize();
  if (cfg->is_dist_server())
  {
    MyHeartBeatHandler::init_mem_pool(cfg->max_clients);
    MyDistToMiddleHandler::init_mem_pool(20);
    MyDistToBSHandler::init_mem_pool(20);
  }
  if (cfg->is_middle_server())
  {
    MyDistLoadHandler::init_mem_pool(50);
    MyLocationHandler::init_mem_pool(1000);
    MyHttpHandler::init_mem_pool(20);
    MyMiddleToBSHandler::init_mem_pool(20);
  }
  MyMemPoolFactoryX::instance()->init(cfg);
  return app->do_constructor();
}

void MyServerApp::app_fini()
{
  MY_INFO(ACE_TEXT("shutdown server...\n"));
  MyServerAppX::close();  //this comes before the releasing of memory pool
  MyConfigX::close();
  dump_mem_pool_info(); //only mem pool info, other objects should gone by now
  MyHeartBeatHandler::fini_mem_pool();
  MyLocationHandler::fini_mem_pool();
  MyDistLoadHandler::fini_mem_pool();
  MyHttpHandler::fini_mem_pool();
  MyDistToMiddleHandler::fini_mem_pool();
  MyDistToBSHandler::fini_mem_pool();
  MyMiddleToBSHandler::fini_mem_pool();
  MyMemPoolFactoryX::close();
}


int main(int argc, const char * argv[])
{
  ACE_Sig_Action no_sigpipe ((ACE_SignalHandler) SIG_IGN);
  ACE_Sig_Action original_action;
  no_sigpipe.register_action (SIGPIPE, &original_action);
  bool ret;
  if (argc == 3 && strcmp(argv[1], "-home") == 0 && argv[2][0] == '/')
    ret = MyServerApp::app_init(argv[2], MyConfig::RM_UNKNOWN);
  else
    ret = MyServerApp::app_init(NULL, MyConfig::RM_UNKNOWN);

  if (ret)
    MyServerAppX::instance()->start();
  MyServerApp::app_fini();
  return 0;
}
