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
  long nAlloc = 0, nFree = 0, nMaxUse = 0;
  if (!MyHeartBeatHandler::mem_pool())
  {
    ACE_DEBUG((LM_INFO, "    Memory Pool Disabled\n"));
    goto _exit_;
  }
  MyHeartBeatHandler::mem_pool()->get_usage(nAlloc, nFree, nMaxUse);
  MyBaseApp::mem_pool_dump_one("MyHeartBeatHandler", nAlloc, nFree, nMaxUse, sizeof(MyHeartBeatHandler));
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
#ifdef MY_server_test
  MyTestClientIDGenerator gen(cfg->test_client_start_client_id, cfg->test_client_connection_number);
  const char * id;
  while ((id = gen.get()) != NULL)
    m_client_id_table.add(id);
#endif
  if (cfg->is_dist_server())
    add_module(m_heart_beat_module = new MyHeartBeatModule(this));
  if (cfg->is_middle_server())
    add_module(m_location_module = new MyLocationModule(this));
  return true;
}

void MyServerApp::app_init(const char * app_home_path, MyConfig::RUNNING_MODE mode)
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
    MyHeartBeatHandler::init_mem_pool(cfg->max_clients);
  if (cfg->is_middle_server())
    MyLocationHandler::init_mem_pool(1000);
  MyMemPoolFactoryX::instance()->init(cfg);
  app->do_constructor();
}

void MyServerApp::app_fini()
{
  MY_INFO(ACE_TEXT("shutdown server...\n"));
  MyServerAppX::close();  //this comes before the releasing of memory pool
  MyConfigX::close();
  dump_mem_pool_info(); //only mem pool info, other objects should gone by now
  MyHeartBeatHandler::fini_mem_pool();
  MyLocationHandler::fini_mem_pool();
  MyMemPoolFactoryX::close();
}


int main(int argc, const char * argv[])
{
  ACE_UNUSED_ARG(argc);
  ACE_UNUSED_ARG(argv);
  ACE_Sig_Action no_sigpipe ((ACE_SignalHandler) SIG_IGN);
  ACE_Sig_Action original_action;
  no_sigpipe.register_action (SIGPIPE, &original_action);

  if (argc == 3 && strcmp(argv[1], "-home") == 0 && argv[2][0] == '/')
    MyServerApp::app_init(argv[2], MyConfig::RM_UNKNOWN);
  else
    MyServerApp::app_init(NULL, MyConfig::RM_UNKNOWN);

  ACE_DEBUG ((LM_DEBUG,
              ACE_TEXT ("(%P|%t) 2\n")));

  MyServerAppX::instance()->start();
#if 0
  ACE_OS::sleep(10);
  ACE_DEBUG ((LM_DEBUG,
              ACE_TEXT ("(%P|%t) stopping module ...\n")));
  MyBaseApp::dump_memory_pool_info();

  MyServerAppX::instance()->stop();
  ACE_DEBUG ((LM_DEBUG,
              ACE_TEXT ("(%P|%t) stopping module done\n")));
  //while (1)
  {
    ACE_OS::sleep(2);
    ACE_DEBUG ((LM_DEBUG,
               ACE_TEXT ("(%P|%t) MyHeartBeatModule->isRunning() = %d\n"), MyServerAppX::instance()->running()));

  }
  MyBaseApp::dump_memory_pool_info();
  ACE_DEBUG ((LM_DEBUG,
              ACE_TEXT ("(%P|%t) starting module ...\n")));
  MyServerAppX::instance()->start();
  ACE_DEBUG ((LM_DEBUG,
              ACE_TEXT ("(%P|%t) starting module done\n")));

  ACE_OS::sleep(10);

  ACE_DEBUG ((LM_DEBUG,
             ACE_TEXT ("(%P|%t) deleting module ...\n")));
#else
/*
  int i = 0;
  while (++i <= 30)
  {
    ACE_Time_Value timeout(2);
    ACE_Reactor::instance()->handle_events (&timeout);
  }
*/
#endif
  MyServerApp::app_fini();
  return 0;
}
