/*
 * main.cpp
 *
 *  Created on: Dec 26, 2011
 *      Author: root
 */

#include <cstdio>
#include <fstream>
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

bool MyClientApp::send_mb_to_dist(ACE_Message_Block * mb)
{
  MY_ASSERT_RETURN(mb, "", false);

  if (unlikely(!running()))
  {
    mb->release();
    return false;
  }

  ACE_Time_Value tv(ACE_Time_Value::zero);
  if (m_client_to_dist_module->dispatcher()->putq(mb, &tv) == -1)
  {
    MY_ERROR("failed to put packet to client_to_dist service queue %s\n", (const char *)MyErrno());
    mb->release();
    return false;
  }

  return true;
}

const MyClientVerson & MyClientApp::client_version() const
{
  return m_client_version;
}

void MyClientApp::data_path(MyPooledMemGuard & _data_path, const char * client_id)
{
#ifdef MY_client_test
  char tmp[128];
  MyTestClientPathGenerator::client_id_to_path(client_id, tmp, 128);
  _data_path.init_from_string(MyConfigX::instance()->app_path.c_str(), "/data/", tmp);
#else
  ACE_UNUSED_ARGS(client_id);
  _data_path.init_from_string(MyConfigX::instance()->app_path.c_str(), "/data");
#endif
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
  long nAlloc = 0, nFree = 0, nMaxUse = 0, nAllocFull = 0;
  if (!g_use_mem_pool)
  {
    ACE_DEBUG((LM_INFO, "    Memory Pool Disabled\n"));
    goto _exit_;
  }

  if (likely(MyClientToDistHandler::mem_pool() != NULL))
  {
    MyClientToDistHandler::mem_pool()->get_usage(nAlloc, nFree, nMaxUse, nAllocFull);
    MyBaseApp::mem_pool_dump_one("MyClientToDistHandler", nAlloc, nFree, nMaxUse, nAllocFull, sizeof(MyClientToDistHandler));
  }

  if (likely(MyClientToMiddleHandler::mem_pool() != NULL))
  {
    MyClientToMiddleHandler::mem_pool()->get_usage(nAlloc, nFree, nMaxUse, nAllocFull);
    MyBaseApp::mem_pool_dump_one("MyClientToMiddleHandler", nAlloc, nFree, nMaxUse, nAllocFull, sizeof(MyClientToMiddleHandler));
  }

  MyMemPoolFactoryX::instance()->dump_info();

_exit_:
  ACE_DEBUG((LM_INFO, "  !!! Memory Dump End !!!\n"));
}

bool MyClientApp::app_init(const char * app_home_path, MyConfig::RUNNING_MODE mode)
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
  std::string idfile = cfg->app_path + "/config/id.file";
  std::ifstream ifs(idfile.c_str(), std::ifstream::in);
  char id[64];
  while (!ifs.eof())
  {
    ifs.getline(id, 64);
    app->m_client_id_table.add(id);
  }
  MyTestClientPathGenerator::make_paths_from_id_table(cfg->app_test_data_path.c_str(), &app->m_client_id_table);
  MyClientToDistHandler::init_mem_pool(app->m_client_id_table.count() * 1.2);
#else
  std::string path_x = cfg->app_path + "/data/download";
  MyFilePaths::make_path(path_x.c_str(), true);
  path_x = cfg->app_path + "/data/tmp";
  MyFilePaths::make_path(path_x.c_str(), true);

  MyClientToDistHandler::init_mem_pool(100);
#endif
  MyClientToMiddleHandler::init_mem_pool(20);
  MyMemPoolFactoryX::instance()->init(cfg);
  return app->do_constructor();
}

void MyClientApp::app_fini()
{
  MY_INFO(ACE_TEXT("shutdown client...\n"));
  MyClientAppX::close();  //this comes before the releasing of memory pool
  MyConfigX::close();
  dump_mem_pool_info(); //only mem pool info, other objects should gone by now
  MyClientToDistHandler::fini_mem_pool();
  MyClientToMiddleHandler::fini_mem_pool();
  MyMemPoolFactoryX::close();
}


int main(int argc, const char * argv[])
{
  ACE_Sig_Action no_sigpipe ((ACE_SignalHandler) SIG_IGN);
  ACE_Sig_Action original_action;
  no_sigpipe.register_action (SIGPIPE, &original_action);
  bool ret;
  if (argc == 3 && strcmp(argv[1], "-home") == 0 && argv[2][0] == '/')
    ret = MyClientApp::app_init(argv[2], MyConfig::RM_CLIENT);
  else
    ret = MyClientApp::app_init(NULL, MyConfig::RM_CLIENT);

  if (ret)
    MyClientAppX::instance()->start();
  MyClientApp::app_fini();
  return 0;
}
