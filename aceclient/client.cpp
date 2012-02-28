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


//MyProgramLauncher//

MyProgramLauncher::MyProgramLauncher()
{
  m_pid = INVALID_PID;
}

MyProgramLauncher::~MyProgramLauncher()
{

}

bool MyProgramLauncher::launch()
{
  if (m_pid != INVALID_PID)
  {
    kill(m_pid, SIGTERM);
    m_pid = INVALID_PID;
  }
  ACE_Process_Options options;
  if (!on_launch(options))
    return false;
  ACE_Process child;
  pid_t pid = child.spawn(options);
  if (pid == -1)
  {
    MY_ERROR("failed to launch program %s %s\n", options.command_line_buf(NULL), (const char *)MyErrno());
    return false;
  } else
  {
    m_pid = pid;
    MY_INFO("launch program OK: %s\n", options.command_line_buf(NULL));
    return true;
  }
}

void MyProgramLauncher::on_terminated(pid_t pid)
{
  if (likely(pid == m_pid))
    m_pid = INVALID_PID;
}

bool MyProgramLauncher::running() const
{
  return m_pid != INVALID_PID;
}

bool MyProgramLauncher::ready() const
{
  return true;
}


//MyVLCLauncher//

bool MyVLCLauncher::on_launch(ACE_Process_Options & options)
{
  const char * adv = "/tmp/daily/5/adv.txt";
  const char * gasket = "/tmp/daily/8/gasket.avi";
  const char * vlc = "vlc --fullscreen";

  std::vector<std::string> advlist;

  if (MyFilePaths::exist(adv))
  {
    MyPooledMemGuard cmdline, line;
    MyMemPoolFactoryX::instance()->get_mem(32000, &cmdline);
    MyMemPoolFactoryX::instance()->get_mem(16000, &line);
    std::ifstream ifs(adv);
    if (!ifs || ifs.bad())
    {
      MY_WARNING("failed to open %s: %s\n", adv, (const char*)MyErrno());
      goto __next__;
    }

    while (!ifs.eof())
    {
      ifs.getline(line.data(), 16000 - 1);
      line.data()[32000 - 1] = 0;
      char * ptr = ACE_OS::strchr(line.data(), ':');
      if (!ptr)
        continue;
      *ptr ++ = 0;

      bool fake = false;
      const char separators[2] = {' ', 0 };
      MyStringTokenizer tkn(ptr, separators);
      char * token;
      while ((token = tkn.get_token()) != NULL)
      {
        if (mycomutil_string_end_with(token, ".bmp") || mycomutil_string_end_with(token, ".jpg") ||
            mycomutil_string_end_with(token, ".gif") || mycomutil_string_end_with(token, ".png"))
        {
          ACE_OS::strcat(cmdline.data(), " fake://");
          fake = true;
        } else
          ACE_OS::strcat(cmdline.data(), " ");
        ACE_OS::strcat(cmdline.data(), token);
      }

      if (cmdline.data()[0] == 0)
        continue;

      options.command_line("%s %s %s", vlc, (fake ? " --fake-duration 10000" : ""), cmdline.data());
      return true;
    }
  }

__next__:

  MY_INFO("%s not exist or content empty, trying %s\n", adv, gasket);

  if (!MyFilePaths::exist(gasket))
  {
    MY_ERROR("no %s file\n", gasket);
    return false;
  }
  options.command_line("%s %s", vlc, gasket);
  return true;
}

bool MyVLCLauncher::ready() const
{
  const char * adv = "/tmp/daily/5/adv.txt";
  const char * gasket = "/tmp/daily/8/gasket.avi";

  return (MyFilePaths::exist(adv) || MyFilePaths::exist(gasket));
}


//MyOperaLauncher//

bool MyOperaLauncher::on_launch(ACE_Process_Options & options)
{
  const char * indexhtml = "/tmp/daily/index.html";
  std::string indexfile("/tmp/daily/");
  indexfile += MyClientApp::index_frame_file();

  const char * fn = indexhtml;
  char buff[1024];
  if (!MyFilePaths::exist(indexhtml))
  {
    MY_INFO("file %s not exist, trying %s instead\n", indexhtml, indexfile.c_str());
    std::ifstream ifs(indexfile.c_str());
    if (!ifs || ifs.bad())
    {
      MY_ERROR("failed to open %s: %s\n", indexfile.c_str(), (const char*)MyErrno());
      return false;
    }
    if (ifs.eof())
    {
      MY_ERROR("file %s is empty\n", indexfile.c_str());
      return false;
    }
    char line[500];
    ifs.getline(line, 500);
    line[500 - 1] = 0;
    ACE_OS::snprintf(buff, 1024, "/tmp/daily/%s", line);
    fn = buff;
  }

  options.command_line("opera --fullscreen %s", fn);
  return true;
}

bool MyOperaLauncher::ready() const
{
  if (MyFilePaths::exist("/tmp/daily/index.html"))
    return true;
  struct stat  _stat;
  MyPooledMemGuard indexfile;
  indexfile.init_from_string("/tmp/daily/", MyClientApp::index_frame_file());
  if (!MyFilePaths::stat(indexfile.data(), &_stat))
    return false;
  return _stat.st_size > 1;
}


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

MyVLCLauncher & MyClientApp::vlc_launcher()
{
  return m_vlc_launcher;
}

MyOperaLauncher & MyClientApp::opera_launcher()
{
  return m_opera_launcher;
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

  if (!do_backup_restore(src_parent_path, tmp, false))
    return false;

  if (dist_id && *dist_id)
  {
    MyPooledMemGuard dest_path;
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
    if (n <= 1)
      return false;
    buff[n - 1] = 0;
    if (ACE_OS::memcmp(buff, dist_id, ACE_OS::strlen(dist_id)) != 0)
      return false;
  }

  return do_backup_restore(src_parent_path, dest_parent_path, remove_existing);
}

bool MyClientApp::do_backup_restore(const MyPooledMemGuard & src_parent_path, const MyPooledMemGuard & dest_parent_path, bool remove_existing)
{
  MyPooledMemGuard src_path, dest_path;
  MyPooledMemGuard mfile;
  if (!get_mfile(src_parent_path, mfile))
  {
    MY_ERROR("no main index file found @MyClientApp::do_backup_restore() in path: %s\n", src_parent_path.data());
    return false;
  }

  if (remove_existing)
  {
    MyPooledMemGuard mfile_dest;
    if (get_mfile(dest_parent_path, mfile_dest))
    {
      dest_path.init_from_string(dest_parent_path.data(), "/", mfile_dest.data());
      MyFilePaths::remove(dest_path.data());
      MyFilePaths::get_correlate_path(dest_path, 0);
      MyFilePaths::remove_path(dest_path.data(), true);
    }
  }

  src_path.init_from_string(src_parent_path.data(), "/", mfile.data());
  if (MyFilePaths::exist(src_path.data()))
  {
    dest_path.init_from_string(dest_parent_path.data(), "/", mfile.data());
    if (!MyFilePaths::copy_file(src_path.data(), dest_path.data(), true))
    {
      MY_ERROR("failed to copy file (%s) to (%s) %s\n", src_path.data(), dest_path.data(), (const char *)MyErrno());
      return false;
    }
  }

  MyFilePaths::get_correlate_path(src_path, 0);
  if (MyFilePaths::exist(src_path.data()))
  {
    MyFilePaths::get_correlate_path(dest_path, 0);
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

  src_path.init_from_string(src_parent_path.data(), "/", index_frame_file());
  dest_path.init_from_string(dest_parent_path.data(), "/", index_frame_file());
  MyFilePaths::copy_file(src_path.data(), dest_path.data(), true);
  return true;
}

bool MyClientApp::get_mfile(const MyPooledMemGuard & parent_path, MyPooledMemGuard & mfile)
{
  if (get_mfile_from_file(parent_path, mfile))
    return true;

  mfile.init_from_string("index.html");
  MyPooledMemGuard tmp;
  tmp.init_from_string(parent_path.data(), "/", mfile.data());
  if (MyFilePaths::exist(tmp.data()))
  {
    MyFilePaths::get_correlate_path(tmp, 0);
    if (MyFilePaths::exist(tmp.data()))
      return true;
  }
  return false;
}

bool MyClientApp::get_mfile_from_file(const MyPooledMemGuard & parent_path, MyPooledMemGuard & mfile)
{
  MyPooledMemGuard index_file_name;
  MyPooledMemGuard tmp;
  index_file_name.init_from_string(parent_path.data(), "/", index_frame_file());
  MyUnixHandleGuard fh;
  char buff[512];
  if (!fh.open_read(index_file_name.data()))
    return false;
  int n = ::read(fh.handle(), buff, 511);
  if (n <= 1)
    return false;
  buff[n] = 0;
  while (--n >= 0 && (buff[n] == '\r' || buff[n] == '\t' || buff[n] == '\n' || buff[n] == ' '))
    buff[n] = 0;
  mfile.init_from_string(buff);
  tmp.init_from_string(parent_path.data(), "/", mfile.data());
  if (MyFilePaths::exist(tmp.data()))
  {
    if (!MyFilePaths::get_correlate_path(tmp, 0))
      return false;
    if (MyFilePaths::exist(tmp.data()))
      return true;
  }
  return false;
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

  if (!g_test_mode)
  {
    m_vlc_launcher.launch();
    m_opera_launcher.launch();
    check_prev_extract_task(client_id());
  }

  return true;
}

void MyClientApp::do_dump_info()
{
  MyClientApp::dump_mem_pool_info();
}

bool MyClientApp::on_sigchild(pid_t pid)
{
  m_opera_launcher.on_terminated(pid);
  m_vlc_launcher.on_terminated(pid);
  return true;
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

  int chunks;
  if (likely(MyClientToDistHandler::mem_pool() != NULL))
  {
    chunks = MyClientToDistHandler::mem_pool()->chunks();
    MyClientToDistHandler::mem_pool()->get_usage(nAlloc, nFree, nMaxUse, nAllocFull);
    MyBaseApp::mem_pool_dump_one("MyClientToDistHandler", nAlloc, nFree, nMaxUse, nAllocFull, sizeof(MyClientToDistHandler), chunks);
  }

  if (likely(MyClientToMiddleHandler::mem_pool() != NULL))
  {
    chunks = MyClientToMiddleHandler::mem_pool()->chunks();
    MyClientToMiddleHandler::mem_pool()->get_usage(nAlloc, nFree, nMaxUse, nAllocFull);
    MyBaseApp::mem_pool_dump_one("MyClientToMiddleHandler", nAlloc, nFree, nMaxUse, nAllocFull, sizeof(MyClientToMiddleHandler), chunks);
  }

  MyMemPoolFactoryX::instance()->dump_info();

_exit_:
  ACE_DEBUG((LM_INFO, "  !!! Memory Dump End !!!\n"));
}

const char * MyClientApp::index_frame_file()
{
  return "indexfile";
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

  MyClientToMiddleHandler::init_mem_pool(20);
  MyMemPoolFactoryX::instance()->init(cfg);

  if (g_test_mode)
  {
    std::string idfile = cfg->app_path + "/config/id.file";
    std::ifstream ifs(idfile.c_str(), std::ifstream::in);
    if (!ifs || ifs.bad())
    {
      MY_ERROR("can not open file %s %s\n", idfile.c_str(), (const char *)MyErrno());
      exit(6);
    }
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

    if(cfg->adv_expire_days > 0)
    {
      MyPooledMemGuard mpath;
      mpath.init_from_string(cfg->app_path.c_str(), "/data/backup/new");
      MyAdvCleaner cleaner;
      cleaner.do_clean(mpath, app->client_id(), cfg->adv_expire_days);
    }

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

  return app->do_constructor();
}

void MyClientApp::check_prev_extract_task(const char * client_id)
{
  MyPooledMemGuard path;
  calc_backup_parent_path(path, client_id);

  DIR * dir = opendir(path.data());
  if (!dir)
  {
    MY_ERROR("can not open directory: %s %s\n", path.data(), (const char*)MyErrno());
    return;
  }

  MyPooledMemGuard msrc;
  struct dirent *entry;
  while ((entry = readdir(dir)) != NULL)
  {
    if (!entry->d_name)
      continue;
    if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
      continue;

    if (likely(mycomutil_string_end_with(entry->d_name, ".mbz")))
    {
      msrc.init_from_string(entry->d_name);
      msrc.data()[ACE_OS::strlen(msrc.data()) - 1 - ACE_OS::strlen(".mbz")] = 0;
      MyDistInfoFtp dist_info;
      {
        MyClientDBGuard dbg;
        if (dbg.db().open_db(client_id))
          dbg.db().load_ftp_command(dist_info, msrc.data());
      }
      if (dist_info.status == 3 && dist_info.validate())
      {
        MyDistFtpFileExtractor extractor;
        dist_info.status = extractor.extract(&dist_info) ? 4:5;
        dist_info.update_db_status();
      }
    }

    msrc.init_from_string(path.data(), "/", "");
    MyFilePaths::remove(msrc.data(), true);
  };

  closedir(dir);


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
