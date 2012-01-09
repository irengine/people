/*
 * main.cpp
 *
 *  Created on: Dec 26, 2011
 *      Author: root
 */

#include <cstdio>
#include "basemodule.h"
#include "client.h"
#include "clientmodule.h"


//MyClientApp//

MyClientApp::MyClientApp()
{
  m_client_to_dist_module = NULL;
}

MyClientApp::~MyClientApp()
{
  delete m_client_to_dist_module;
}

MyClientToDistModule * MyClientApp::client_to_dist_module() const
{
  return m_client_to_dist_module;
}

bool MyClientApp::on_start()
{
  if (m_client_to_dist_module)
    m_client_to_dist_module->start();
  return true;
}

void MyClientApp::on_stop()
{
  if (m_client_to_dist_module)
    m_client_to_dist_module->stop();
}

bool MyClientApp::on_construct()
{
  m_client_to_dist_module = new MyClientToDistModule(this);
  return true;
}

void MyClientApp::dump_info()
{
/*  long nAlloc = 0, nFree = 0, nMaxUse = 0, nInUse = 0;
  if (MyHeartBeatHandler::mem_pool())
  {
    MyHeartBeatHandler::mem_pool()->get_usage(nAlloc, nFree, nMaxUse);
    nInUse = nAlloc - nFree;

    MY_INFO (ACE_TEXT ("(%P|%t) memory info dump, inUse = %d, alloc = %d, free = %d, maxInUse = %d\n"),
             nInUse, nAlloc, nFree, nMaxUse);
  }
*/
}

void MyClientApp::app_init(const char * app_home_path, MyConfig::RUNNING_MODE mode)
{
  MyClientApp * app = MyClientAppX::instance();
  if (!MyConfigX::instance()->load_config(app_home_path, mode))
  {
    std::printf("error loading config file, quitting\n");
    exit(5);
  }
  if (MyConfigX::instance()->run_as_demon)
    MyBaseApp::app_demonize();
  MyClientToDistHandler::init_mem_pool(1000);
  MyMemPoolFactoryX::instance()->init(MyConfigX::instance());
  app->do_constructor();
}

void MyClientApp::app_fini()
{
  MY_INFO(ACE_TEXT("shutdown client...\n"));
  MyClientAppX::instance()->dump_info();
  MyClientAppX::close();  //this comes before the releasing of memory pool
  MyConfigX::close();
  MyClientToDistHandler::fini_mem_pool();
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
    MyClientApp::app_init(argv[2], MyConfig::RM_CLIENT);
  else
    MyClientApp::app_init(NULL, MyConfig::RM_CLIENT);

  ACE_DEBUG ((LM_DEBUG,
              ACE_TEXT ("(%P|%t) 2\n")));

  MyClientAppX::instance()->start();
#if 0
  ACE_OS::sleep(10);
  ACE_DEBUG ((LM_DEBUG,
              ACE_TEXT ("(%P|%t) stopping module ...\n")));
  MyBaseApp::dump_memory_pool_info();

  MyClientAppX::instance()->stop();
  ACE_DEBUG ((LM_DEBUG,
              ACE_TEXT ("(%P|%t) stopping module done\n")));
  //while (1)
  {
    ACE_OS::sleep(2);
    ACE_DEBUG ((LM_DEBUG,
               ACE_TEXT ("(%P|%t) MyHeartBeatModule->isRunning() = %d\n"), MyClientAppX::instance()->running()));

  }
  MyBaseApp::dump_memory_pool_info();
  ACE_DEBUG ((LM_DEBUG,
              ACE_TEXT ("(%P|%t) starting module ...\n")));
  MyClientAppX::instance()->start();
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
  MyClientApp::app_fini();
  return 0;
}
