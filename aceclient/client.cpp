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

}

MyClientToDistModule * MyClientApp::client_to_dist_module() const
{
  return m_client_to_dist_module;
}

bool MyClientApp::on_start()
{
  return true;
}

void MyClientApp::on_stop()
{

}

bool MyClientApp::on_construct()
{
  add_module(m_client_to_dist_module = new MyClientToDistModule(this));
  return true;
}

void MyClientApp::do_dump_info()
{
  MyClientApp::dump_mem_pool_info();
}

void MyClientApp::dump_mem_pool_info()
{
  ACE_DEBUG((LM_INFO, "  !!! Memory Dump start !!!\n"));
  long nAlloc = 0, nFree = 0, nMaxUse = 0;
  if (!MyClientToDistHandler::mem_pool())
  {
    ACE_DEBUG((LM_INFO, "    Memory Pool Disabled\n"));
    goto _exit_;
  }
  MyClientToDistHandler::mem_pool()->get_usage(nAlloc, nFree, nMaxUse);
  MyBaseApp::mem_pool_dump_one("MyClientToDistHandler", nAlloc, nFree, nMaxUse, sizeof(MyClientToDistHandler));
  MyMemPoolFactoryX::instance()->dump_info();

_exit_:
  ACE_DEBUG((LM_INFO, "  !!! Memory Dump End !!!\n"));
}

void MyClientApp::app_init(const char * app_home_path, MyConfig::RUNNING_MODE mode)
{
  MyClientApp * app = MyClientAppX::instance();
  MyConfig * cfg = MyConfigX::instance();
  if (!cfg->load_config(app_home_path, mode))
  {
    std::printf("error loading config file, quitting\n");
    exit(5);
  }
  if (cfg->run_as_demon)
    MyBaseApp::app_demonize();
  MyClientToDistHandler::init_mem_pool(1000);
  MyMemPoolFactoryX::instance()->init(cfg);
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
/*
  MyConfigX::instance()->use_mem_pool = true;
  MyMemPoolFactoryX::instance()->init(MyConfigX::instance());
  ACE_Message_Block * mb = MyMemPoolFactoryX::instance()->get_message_block(32);
  mb->clr_self_flags(ACE_Message_Block::DONT_DELETE);
  mb->release();
  //delete mb;

  MyMemPoolFactoryX::close();
  MyConfigX::close();
  return 0;
*/
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
