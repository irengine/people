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

const char * MyClientApp::client_id() const
{
  return m_client_id.c_str();
}

void MyClientApp::data_path(MyPooledMemGuard & _data_path, const char * client_id)
{
  if (g_test_mode)
  {
    char tmp[128];
    tmp[0] = 0;
    MyTestClientPathGenerator::client_id_to_path(client_id, tmp, 128);
    _data_path.init_from_string(MyConfigX::instance()->app_path.c_str(), "/data/", tmp);
  } else
    _data_path.init_from_string(MyConfigX::instance()->app_path.c_str(), "/data");
}

void MyClientApp::calc_display_parent_path(MyPooledMemGuard & parent_path, const char * client_id)
{
  if (g_test_mode)
  {
    MyPooledMemGuard path_x;
    MyClientApp::data_path(path_x, client_id);
    parent_path.init_from_string(path_x.data(), "/daily");
  } else
    parent_path.init_from_string("/tmp/daily");
}

void MyClientApp::calc_dist_parent_path(MyPooledMemGuard & parent_path, const char * dist_id, const char * client_id)
{
  MyPooledMemGuard path_x;
  MyClientApp::data_path(path_x, client_id);
  parent_path.init_from_string(path_x.data(), "/tmp/", dist_id);
}

void MyClientApp::calc_backup_parent_path(MyPooledMemGuard & parent_path, const char * client_id)
{
  MyPooledMemGuard path_x;
  MyClientApp::data_path(path_x, client_id);
  parent_path.init_from_string(path_x.data(), "/backup");
}

bool MyClientApp::full_backup(const char * dist_id, const char * client_id)
{
  MyPooledMemGuard src_parent_path;
  calc_display_parent_path(src_parent_path, client_id);

  MyPooledMemGuard tmp, dest_parent_path;
  calc_backup_parent_path(dest_parent_path, client_id);

  tmp.init_from_string(dest_parent_path.data(), "/tmp");
  MyFilePaths::remove_path(tmp.data(), true);

  if (!MyFilePaths::make_path(tmp.data(), true))
  {
    MY_ERROR("can not mkdir(%s) %s\n", tmp.data(), (const char *)MyErrno());
    return false;
  }

  MyPooledMemGuard src_path, dest_path;

  src_path.init_from_string(src_parent_path.data(), "/index.html");
  if (MyFilePaths::exist(src_path.data()))
  {
    dest_path.init_from_string(tmp.data(), "/index.html");
    if (!MyFilePaths::copy_file(src_path.data(), dest_path.data(), true))
    {
      MY_ERROR("failed to copy file (%s) to (%s) %s\n", src_path.data(), dest_path.data(), (const char *)MyErrno());
      return false;
    }
  }

  src_path.init_from_string(src_parent_path.data(), "/index");
  if (MyFilePaths::exist(src_path.data()))
  {
    dest_path.init_from_string(tmp.data(), "/index");
    if (!MyFilePaths::copy_path(src_path.data(), dest_path.data(), true))
    {
      MY_ERROR("failed to copy path (%s) to (%s) %s\n", src_path.data(), dest_path.data(), (const char *)MyErrno());
      return false;
    }
  }

  src_path.init_from_string(src_parent_path.data(), "/7");
  if (MyFilePaths::exist(src_path.data()))
  {
    dest_path.init_from_string(tmp.data(), "/7");
    if (!MyFilePaths::copy_path(src_path.data(), dest_path.data(), true))
    {
      MY_ERROR("failed to copy path (%s) to (%s) %s\n", src_path.data(), dest_path.data(), (const char *)MyErrno());
      return false;
    }
  }

  src_path.init_from_string(src_parent_path.data(), "/8");
  if (MyFilePaths::exist(src_path.data()))
  {
    dest_path.init_from_string(tmp.data(), "/8");
    if (!MyFilePaths::copy_path(src_path.data(), dest_path.data(), true))
    {
      MY_ERROR("failed to copy path (%s) to (%s) %s\n", src_path.data(), dest_path.data(), (const char *)MyErrno());
      return false;
    }
  }

  src_path.init_from_string(src_parent_path.data(), "/5");
  if (MyFilePaths::exist(src_path.data()))
  {
    dest_path.init_from_string(tmp.data(), "/5");
    if (!MyFilePaths::copy_path(src_path.data(), dest_path.data(), true))
    {
      MY_ERROR("failed to copy path (%s) to (%s) %s\n", src_path.data(), dest_path.data(), (const char *)MyErrno());
      return false;
    }
  }

  if (dist_id && *dist_id)
  {
    dest_path.init_from_string(tmp.data(), "/dist_id.txt");
    MyUnixHandleGuard fh;
    if (fh.open_write(dest_path.data(), true, true, false, true))
      ::write(fh.handle(), dist_id, strlen(dist_id));
  }

  MyPooledMemGuard old_path, new_path;
  old_path.init_from_string(dest_parent_path.data(), "/old");
  new_path.init_from_string(dest_parent_path.data(), "/new");
  MyFilePaths::remove_path(old_path.data(), true);
  if (MyFilePaths::exist(new_path.data()))
  {
    if (!MyFilePaths::rename(new_path.data(), old_path.data(), false))
      return false;
  }

  return MyFilePaths::rename(tmp.data(), new_path.data(), false);
}

bool MyClientApp::full_restore(const char * dist_id, bool remove_existing, bool is_new, const char * client_id)
{
  ACE_UNUSED_ARG(dist_id);

  MyPooledMemGuard dest_parent_path;
  calc_display_parent_path(dest_parent_path, client_id);

  MyPooledMemGuard tmp, src_parent_path;
  calc_backup_parent_path(tmp, client_id);
  if (is_new)
    src_parent_path.init_from_string(tmp.data(), "/new");
  else
    src_parent_path.init_from_string(tmp.data(), "/old");

  if (!MyFilePaths::exist(src_parent_path.data()))
    return false;

  MyPooledMemGuard src_path, dest_path;

  if (dist_id && *dist_id)
  {
    src_path.init_from_string(src_parent_path.data(), "/dist_id.txt");
    MyUnixHandleGuard fh;
    if (fh.open_read(src_path.data()))
      return false;
    char buff[64];
    int n = ::read(fh.handle(), buff, 64);
    if (n <= 0)
      return false;
    buff[n - 1] = 0;
    if (ACE_OS::memcmp(buff, dist_id, ACE_OS::strlen(dist_id)) != 0)
      return false;
  }

  src_path.init_from_string(src_parent_path.data(), "/index.html");
  if (MyFilePaths::exist(src_path.data()))
  {
    dest_path.init_from_string(dest_parent_path.data(), "/index.html");
    if (remove_existing)
      MyFilePaths::remove_path(dest_path.data(), true);
    if (!MyFilePaths::copy_file(src_path.data(), dest_path.data(), true))
    {
      MY_ERROR("failed to copy file (%s) to (%s) %s\n", src_path.data(), dest_path.data(), (const char *)MyErrno());
      return false;
    }
  }

  src_path.init_from_string(src_parent_path.data(), "/index");
  if (MyFilePaths::exist(src_path.data()))
  {
    dest_path.init_from_string(dest_parent_path.data(), "/index");
    if (remove_existing)
      MyFilePaths::remove_path(dest_path.data(), true);
    if (!MyFilePaths::copy_path(src_path.data(), dest_path.data(), true))
    {
      MY_ERROR("failed to copy path (%s) to (%s) %s\n", src_path.data(), dest_path.data(), (const char *)MyErrno());
      return false;
    }
  }

  src_path.init_from_string(src_parent_path.data(), "/7");
  if (MyFilePaths::exist(src_path.data()))
  {
    dest_path.init_from_string(dest_parent_path.data(), "/7");
    if (remove_existing)
      MyFilePaths::remove_path(dest_path.data(), true);
    if (!MyFilePaths::copy_path(src_path.data(), dest_path.data(), true))
    {
      MY_ERROR("failed to copy path (%s) to (%s) %s\n", src_path.data(), dest_path.data(), (const char *)MyErrno());
      return false;
    }
  }

  src_path.init_from_string(src_parent_path.data(), "/8");
  if (MyFilePaths::exist(src_path.data()))
  {
    dest_path.init_from_string(dest_parent_path.data(), "/8");
    if (remove_existing)
      MyFilePaths::remove_path(dest_path.data(), true);
    if (!MyFilePaths::copy_path(src_path.data(), dest_path.data(), true))
    {
      MY_ERROR("failed to copy path (%s) to (%s) %s\n", src_path.data(), dest_path.data(), (const char *)MyErrno());
      return false;
    }
  }

  src_path.init_from_string(src_parent_path.data(), "/5");
  if (MyFilePaths::exist(src_path.data()))
  {
    dest_path.init_from_string(dest_parent_path.data(), "/5");
    if (remove_existing)
      MyFilePaths::remove_path(dest_path.data(), true);
    if (!MyFilePaths::copy_path(src_path.data(), dest_path.data(), true))
    {
      MY_ERROR("failed to copy path (%s) to (%s) %s\n", src_path.data(), dest_path.data(), (const char *)MyErrno());
      return false;
    }
  }

  return true;
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
  if (!g_test_mode)
  {

    const char * const_id_ini = "/tmp/daily/id.ini";
    MY_INFO("trying to read client id from %s\n", const_id_ini);
    while (true)
    {
      MyUnixHandleGuard fh;
      fh.error_report(false);
      if (fh.open_read(const_id_ini))
      {
        char buff[64];
        int n = ::read(fh.handle(), buff, 64);
        if (n > 0)
        {
          n = std::min(n, 63);
          buff[n] = 0;
          while (--n >= 0 && (buff[n] == '\r' || buff[n] == '\n' || buff[n] == ' ' || buff[n] == '\t'))
            buff[n] = 0;
          if (n == 0)
            continue;
          m_client_id = buff;
          m_client_id_table.add(buff);
          break;
        }
      }
      ACE_OS::sleep(30);
    }
    MY_INFO("get client id [%s] from %s\n", m_client_id.c_str(), const_id_ini);

    {
      MyClientDBGuard dbg;
      if (dbg.db().open_db(NULL, true))
      {
        time_t deadline = time_t(NULL) - const_one_day * 10;
        dbg.db().remove_outdated_ftp_command(deadline);
        dbg.db().reset_ftp_command_status();
      }
    }
  }

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

  if (g_test_mode)
  {
    std::string idfile = cfg->app_path + "/config/id.file";
    std::ifstream ifs(idfile.c_str(), std::ifstream::in);
    char id[64];
    while (!ifs.eof())
    {
      ifs.getline(id, 64);
      app->m_client_id_table.add(id);
    }
    MyTestClientPathGenerator::make_paths_from_id_table(cfg->app_data_path.c_str(), &app->m_client_id_table);
    MyClientToDistHandler::init_mem_pool(app->m_client_id_table.count() * 1.2);

    int m = app->m_client_id_table.count();
    MyClientID client_id;
    time_t deadline = time_t(NULL) - const_one_day * 10;
    for (int i = 0; i < m; ++i)
    {
      app->m_client_id_table.value(i, &client_id);
      MyClientDBGuard dbg;
      if (dbg.db().open_db(client_id.as_string(), true))
      {
        dbg.db().remove_outdated_ftp_command(deadline);
        dbg.db().reset_ftp_command_status();
      }
    }
  } else
  {
    std::string path_x = cfg->app_path + "/data/download";
    MyFilePaths::make_path(path_x.c_str(), true);
    path_x = cfg->app_path + "/data/tmp";
    MyFilePaths::remove_path(path_x.c_str(), true);
    MyFilePaths::make_path(path_x.c_str(), true);
    path_x = cfg->app_path + "/data/backup";
    MyFilePaths::make_path(path_x.c_str(), true);

    if (!full_restore(NULL, true))
    {
      MY_WARNING("restore of latest data failed, now restoring previous data...\n");
      if (!full_restore(NULL, true, false))
      {
        MY_ERROR("restore of previous data failed\n");
      }
    }

    MyClientToDistHandler::init_mem_pool(100);
  }

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
