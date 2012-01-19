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
  long nAlloc = 0, nFree = 0, nMaxUse = 0, nAllocFull = 0;
  if (!MyHeartBeatHandler::mem_pool())
  {
    ACE_DEBUG((LM_INFO, "    Memory Pool Disabled\n"));
    goto _exit_;
  }
  MyHeartBeatHandler::mem_pool()->get_usage(nAlloc, nFree, nMaxUse, nAllocFull);
  MyBaseApp::mem_pool_dump_one("MyHeartBeatHandler", nAlloc, nFree, nMaxUse, nAllocFull, sizeof(MyHeartBeatHandler));
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

  char * _app_data_path = new char[cfg->app_test_data_path.length() + 1];
  strcpy(_app_data_path, cfg->app_test_data_path.c_str());
  MyTestClientPathGenerator::make_paths(_app_data_path, cfg->test_client_start_client_id, cfg->test_client_connection_number);
  delete [] _app_data_path;
#endif
  if (cfg->is_dist_server())
  {
    add_module(m_heart_beat_module = new MyHeartBeatModule(this));
    if (cfg->remote_access_port > 0)
      add_module(new MyDistRemoteAccessModule(this));
  }
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
#if 0
  MyConfig* cfg = MyConfigX::instance();
  if (!MyConfigX::instance()->load_config("/root/distserver", MyConfig::RM_DIST_SERVER))
  {
    std::printf("error loading config file, quitting\n");
    exit(5);
  }
  MyMemPoolFactoryX::instance()->init(cfg);
  {
#if 0
    {
    MyBZCompressor c;
    std::printf("compress prj.ini = %d\n", c.compress("/root/prj.ini", "/root/prj.bz2"));
    std::printf("decompress prj.bz2 = %d\n", c.decompress("/root/prj.bz2", "/root/prj.un"));

    std::printf("compress prj.ini = %d\n", c.compress("/root/p7zip_9.20.1_src_all.tar", "/root/p7zip.bz2"));
    std::printf("decompress prj.bz2 = %d\n", c.decompress("/root/p7zip.bz2", "/root/p7zip.un"));
    }
#endif

#if 0
    {
    MyFileMD5s md5s;
    md5s.scan_directory("/root/testdata");
    int len = md5s.total_size(true);
    char * buffer = new char[len];
    md5s.to_buffer(buffer, len, true);
    printf("to buffer include md5:%s\n", buffer);
    MyFileMD5s md5s_2;
    md5s_2.from_buffer(buffer);
    delete []buffer;

    char * buffer2 = new char [len];
    md5s_2.to_buffer(buffer2, len, true);
    printf("from buffer include md5:%s\n", buffer2);
    delete []buffer2;

    len = md5s.total_size(false);
    buffer = new char[len];
    md5s.to_buffer(buffer, len, false);
    printf("to buffer no md5:%s\n", buffer);
    delete []buffer;
    }
#endif
#if 0
    {
    MyFileMD5s md5s_1;
    md5s_1.scan_directory("/root/testdata");
    md5s_1.sort();
    MyFileMD5s md5s_2;
    md5s_2.scan_directory("/root/testdata2");
    md5s_2.sort();

    md5s_1.minus(md5s_2);
    int len = md5s_1.total_size(true);
    char * buffer = new char[len];
    md5s_1.to_buffer(buffer, len, true);
    printf("to buffer diff md5:%s\n", buffer);
    delete []buffer;
    }
#endif
  }
  MyConfigX::close();
  MyServerApp::dump_mem_pool_info(); //only mem pool info, other objects should gone by now
  MyMemPoolFactoryX::close();
  return 0;
#endif
  ACE_UNUSED_ARG(argc);
  ACE_UNUSED_ARG(argv);
  ACE_Sig_Action no_sigpipe ((ACE_SignalHandler) SIG_IGN);
  ACE_Sig_Action original_action;
  no_sigpipe.register_action (SIGPIPE, &original_action);

  if (argc == 3 && strcmp(argv[1], "-home") == 0 && argv[2][0] == '/')
    MyServerApp::app_init(argv[2], MyConfig::RM_UNKNOWN);
  else
    MyServerApp::app_init(NULL, MyConfig::RM_UNKNOWN);

  MyServerAppX::instance()->start();
  MyServerApp::app_fini();
  return 0;
}
