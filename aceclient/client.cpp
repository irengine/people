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
  MyConfig * cfg = MyConfigX::instance();

#ifdef MY_client_test
  MyTestClientIDGenerator gen(cfg->test_client_start_client_id, cfg->test_client_connection_number);
  const char * id;
  while ((id = gen.get()) != NULL)
    m_client_id_table.add(id);

  char * _app_data_path = new char[cfg->app_test_data_path.length() + 1];
  strcpy(_app_data_path, cfg->app_test_data_path.c_str());
  MyTestClientPathGenerator::make_paths(_app_data_path, cfg->test_client_start_client_id, cfg->test_client_connection_number);
  delete [] _app_data_path;
#endif

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
  long nAlloc = 0, nFree = 0, nMaxUse = 0, nAllocFull = 0;
  if (!MyClientToDistHandler::mem_pool())
  {
    ACE_DEBUG((LM_INFO, "    Memory Pool Disabled\n"));
    goto _exit_;
  }
  MyClientToDistHandler::mem_pool()->get_usage(nAlloc, nFree, nMaxUse, nAllocFull);
  MyBaseApp::mem_pool_dump_one("MyClientToDistHandler", nAlloc, nFree, nMaxUse, nAllocFull, sizeof(MyClientToDistHandler));
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
#ifdef MY_client_test
  MyClientToDistHandler::init_mem_pool(cfg->test_client_connection_number * 1.2);
#else
  MyClientToDistHandler::init_mem_pool(100);
#endif
  MyMemPoolFactoryX::instance()->init(cfg);
  app->do_constructor();
}

void MyClientApp::app_fini()
{
  MY_INFO(ACE_TEXT("shutdown client...\n"));
  MyClientAppX::close();  //this comes before the releasing of memory pool
  MyConfigX::close();
  dump_mem_pool_info(); //only mem pool info, other objects should gone by now
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
  MyClientApp::app_fini();
  return 0;
}
