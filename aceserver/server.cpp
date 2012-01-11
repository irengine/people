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
  delete m_heart_beat_module;
  delete m_location_module;
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
  if (m_heart_beat_module)
    m_heart_beat_module->start();
  if (m_location_module)
    m_location_module->start();
  return true;
}

void MyServerApp::on_stop()
{
  if (m_heart_beat_module)
    m_heart_beat_module->stop();
  if (m_location_module)
    m_location_module->stop();
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
    m_heart_beat_module = new MyHeartBeatModule(this);
  if (cfg->is_middle_server())
    m_location_module = new MyLocationModule(this);
  return true;
}

void MyServerApp::dump_info()
{
  long nAlloc = 0, nFree = 0, nMaxUse = 0, nInUse = 0;
  if (MyHeartBeatHandler::mem_pool())
  {
    MyHeartBeatHandler::mem_pool()->get_usage(nAlloc, nFree, nMaxUse);
    nInUse = nAlloc - nFree;

    MY_INFO (ACE_TEXT ("(%P|%t) memory info dump, inUse = %d, alloc = %d, free = %d, maxInUse = %d\n"),
             nInUse, nAlloc, nFree, nMaxUse);
  }
}

void MyServerApp::app_init(const char * app_home_path, MyConfig::RUNNING_MODE mode)
{
  MyServerApp * app = MyServerAppX::instance();
  if (!MyConfigX::instance()->load_config(app_home_path, mode))
  {
    std::printf("error loading config file, quitting\n");
    exit(5);
  }
  if (MyConfigX::instance()->run_as_demon)
    MyBaseApp::app_demonize();
  if (MyConfigX::instance()->is_dist_server())
    MyHeartBeatHandler::init_mem_pool(MyConfigX::instance()->max_clients);
  if (MyConfigX::instance()->is_middle_server())
    MyLocationHandler::init_mem_pool(1000);
  MyMemPoolFactoryX::instance()->init(MyConfigX::instance());
  app->do_constructor();
}

void MyServerApp::app_fini()
{
  MY_INFO(ACE_TEXT("shutdown server...\n"));
  MyServerAppX::instance()->dump_info();
  MyServerAppX::close();  //this comes before the releasing of memory pool
  MyConfigX::close();
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
