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
  m_wait_for_term = false;
}

MyProgramLauncher::~MyProgramLauncher()
{
  kill_instance();
}

void MyProgramLauncher::kill_instance()
{
  if (m_pid != INVALID_PID)
  {
    MY_INFO("killing child process [%d]...\n", (int)m_pid);
    kill(m_pid, SIGTERM);
    m_wait_for_term = true;
  }
}

bool MyProgramLauncher::do_on_terminated()
{
  if (!MyClientAppX::instance()->running())
    return false;
  return launch();
}

bool MyProgramLauncher::launch()
{
  if (m_pid != INVALID_PID)
  {
    MY_INFO("killing child process (%d)...\n", (int)m_pid);
    kill(m_pid, SIGTERM);
    m_pid = INVALID_PID;
  }
  m_wait_for_term = false;
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
    MY_INFO("launch program OK (pid = %d): %s\n", (int)pid, options.command_line_buf(NULL));
    return true;
  }
}

void MyProgramLauncher::on_terminated(pid_t pid)
{
  if (likely(pid == m_pid))
  {
    m_pid = INVALID_PID;
    do_on_terminated();
  }
}

bool MyProgramLauncher::running() const
{
  return m_pid != INVALID_PID;
}

bool MyProgramLauncher::ready() const
{
  return true;
}

bool MyProgramLauncher::on_launch(ACE_Process_Options & options)
{
  ACE_UNUSED_ARG(options);
  if (!ready())
    return false;

  return true;
}


//MyVLCLauncher//

const char * MyVLCLauncher::adv_txt() const
{
  return "/tmp/daily/5/adv.txt";
}

const char * MyVLCLauncher::gasket() const
{
  return "/tmp/daily/8/gasket.avi";
}

int MyVLCLauncher::next() const
{
  return m_next;
}

void MyVLCLauncher::init_mode(bool b)
{
  m_init_mode = b;
}

bool MyVLCLauncher::load(ACE_Process_Options & options)
{
  std::vector<std::string> advlist;

  m_next = 0;
  time_t next_time = 0;
  m_current_line.init_from_string(NULL);
  if (!MyFilePaths::exist(adv_txt()))
    return false;

  MyPooledMemGuard line;
  MyMemPoolFactoryX::instance()->get_mem(16000, &line);
  std::ifstream ifs(adv_txt());
  if (!ifs || ifs.bad())
  {
    MY_WARNING("failed to open %s: %s\n", adv_txt(), (const char*)MyErrno());
    return false;
  }

  time_t now = time(NULL);
  struct tm _tm;
  const int BLOCK_SIZE = 16000;
  int t;
  while (!ifs.eof())
  {
    time_t t_this;
    ifs.getline(line.data(), BLOCK_SIZE - 1);
    line.data()[BLOCK_SIZE - 1] = 0;
    char * ptr = ACE_OS::strchr(line.data(), ':');
    if (!ptr)
      continue;
    *ptr ++ = 0;
    while (*ptr == ' ' || *ptr == '\t')
      ++ptr;
    if (*ptr == 0)
      continue;
    t = atoi(line.data());
    if (t < 0 || t > 23)
      continue;
    localtime_r(&now, &_tm);
    _tm.tm_hour = t;
    _tm.tm_min = 0;
    _tm.tm_sec = 0;
    t_this = mktime(&_tm);
    if (t_this + GAP_THREASHHOLD < now)
    {
      if (parse_line(ptr, options, true))
        next_time = t_this;
    } else
    {
      if (next_time != 0)
      {
        if (parse_line(ptr, options, false))
        {
          m_next = t_this - now;
          return true;
        }
      } else
      {
        if (parse_line(ptr, options, true))
          next_time = t_this;
      }
    }
  }//while eof

  m_next = 0;
  return next_time != 0;
}

bool MyVLCLauncher::parse_line(char * ptr, ACE_Process_Options & options, bool fill_options)
{
  const char * vlc = "vlc -L --fullscreen";

  MyPooledMemGuard cmdline;
  MyMemPoolFactoryX::instance()->get_mem(64000, &cmdline);

  bool fake = false;
  const char separators[2] = {' ', 0 };
  MyStringTokenizer tkn(ptr, separators);
  char * token;
  cmdline.data()[0] = 0;
  MyPooledMemGuard fn;
  while ((token = tkn.get_token()) != NULL)
  {
    fn.init_from_string("/tmp/daily/5/", token);
    if (!MyFilePaths::exist(fn.data()))
    {
      MY_INFO("skipping non-existing adv file %s\n", token);
      continue;
    }
    if (!fill_options)
      return true;

    if (mycomutil_string_end_with(token, ".bmp") || mycomutil_string_end_with(token, ".jpg") ||
        mycomutil_string_end_with(token, ".gif") || mycomutil_string_end_with(token, ".png"))
    {
      ACE_OS::strncat(cmdline.data(), " fake:///tmp/daily/5/", 64000 - 1);
      fake = true;
    } else
      ACE_OS::strncat(cmdline.data(), " /tmp/daily/5/", 64000 - 1);
    ACE_OS::strncat(cmdline.data(), token, 64000 - 1);
  }

  if (cmdline.data()[0] == 0)
    return false;

  options.command_line("%s %s %s", vlc, (fake ? " --fake-duration 10000" : ""), cmdline.data());
  return true;
}

bool MyVLCLauncher::on_launch(ACE_Process_Options & options)
{
  const char * vlc = "vlc -L --fullscreen";

  std::vector<std::string> advlist;

  if (!m_init_mode)
  {
    if (load(options))
      return true;
    MY_INFO("%s not exist or content empty, trying %s\n", adv_txt(), gasket());
  }

  if (!MyFilePaths::exist(gasket()))
  {
    MY_ERROR("no %s file\n", gasket());
    return false;
  }
  options.command_line("%s %s", vlc, gasket());
  return true;
}

MyVLCLauncher::MyVLCLauncher()
{
  m_init_mode = false;
}

bool MyVLCLauncher::ready() const
{
  const char * adv = "/tmp/daily/5/adv.txt";
  const char * gasket = "/tmp/daily/8/gasket.avi";

  return (MyFilePaths::exist(adv) || MyFilePaths::exist(gasket));
}


//MyVLCMonitor//

MyVLCMonitor::MyVLCMonitor(MyClientApp * app)
{
  m_app = app;
  m_need_relaunch = false;
}

void MyVLCMonitor::check_relaunch()
{
  if (!m_need_relaunch)
    return;
  if (m_app->vlc_launcher().running())
    return;
  m_need_relaunch = false;
  launch_vlc();
}

void MyVLCMonitor::need_relaunch()
{
//  m_need_relaunch = true;
}

void MyVLCMonitor::relaunch()
{
  if (!m_app->vlc_launcher().running())
  {
    launch_vlc();
    return;
  }

  m_app->vlc_launcher().kill_instance();
//  m_need_relaunch = true;
}

void MyVLCMonitor::launch_vlc()
{
  ACE_Reactor::instance()->cancel_timer(this);
  if (!m_app->vlc_launcher().launch())
    return;
  if (m_app->vlc_launcher().next() > 0)
  {
    ACE_Reactor::instance()->cancel_timer(this);
    ACE_Time_Value tv(m_app->vlc_launcher().next());
    if (ACE_Reactor::instance()->schedule_timer(this, 0, tv) < 0)
      MY_ERROR("failed to setup vlc monitor timer\n");
    else
      MY_INFO("vlc next playlist will be shown in %d minute(s)\n", (int)(m_app->vlc_launcher().next() / 60));
  }
}

int MyVLCMonitor::handle_timeout(const ACE_Time_Value &, const void *)
{
  relaunch();
  return 0;
}


//MyOperaLauncher//

MyOperaLauncher::MyOperaLauncher()
{
  m_need_relaunch = false;
}

bool MyOperaLauncher::on_launch(ACE_Process_Options & options)
{
  if (!MyProgramLauncher::on_launch(options))
    return false;

  const char * indexhtml = "/tmp/daily/index.html";
//  std::string indexfile("/tmp/daily/");
//  indexfile += MyClientApp::index_frame_file();
//
//  const char * fn = indexhtml;
//  char buff[1024];
//  if (!MyFilePaths::exist(indexhtml))
//  {
//    MY_INFO("file %s not exist, trying %s instead\n", indexhtml, indexfile.c_str());
//    std::ifstream ifs(indexfile.c_str());
//    if (!ifs || ifs.bad())
//    {
//      MY_ERROR("failed to open %s: %s\n", indexfile.c_str(), (const char*)MyErrno());
//      return false;
//    }
//    if (ifs.eof())
//    {
//      MY_ERROR("file %s is empty\n", indexfile.c_str());
//      return false;
//    }
//    char line[500];
//    ifs.getline(line, 500);
//    line[500 - 1] = 0;
//    ACE_OS::snprintf(buff, 1024, "/tmp/daily/%s", line);
//    fn = buff;
//  }

  options.command_line("opera --fullscreen %s", indexhtml); //fn);
  return true;
}

bool MyOperaLauncher::ready() const
{
  return MyFilePaths::exist("/tmp/daily/index.html");
//  if (MyFilePaths::exist("/tmp/daily/index.html"))
//    return true;
//  struct stat  _stat;
//  MyPooledMemGuard indexfile;
//  indexfile.init_from_string("/tmp/daily/", MyClientApp::index_frame_file());
//  if (!MyFilePaths::stat(indexfile.data(), &_stat))
//    return false;
//  return _stat.st_size > 1;
}

void MyOperaLauncher::check_relaunch()
{
  if (!m_need_relaunch)
    return;
  if (running())
  {
    if (!m_wait_for_term)
      kill_instance();
  } else
  {
    m_need_relaunch = false;
    launch();
  }
}

void MyOperaLauncher::need_relaunch()
{
  m_need_relaunch = true;
}


//MyClientApp//

MyClientApp::MyClientApp(): m_vlc_monitor(this)
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

  return mycomutil_mb_putq(m_client_to_dist_module->dispatcher(), mb, "to client_to_dist service queue");
}

const MyClientVerson & MyClientApp::client_version() const
{
  return m_client_version;
}

const char * MyClientApp::client_id() const
{
  return m_client_id.c_str();
}

const char * MyClientApp::ftp_password()
{
  ACE_GUARD_RETURN(ACE_Thread_Mutex, ace_mon, this->m_mutex, NULL);
  return m_ftp_password.data();
}

void MyClientApp::ftp_password(const char * password)
{
  ACE_GUARD(ACE_Thread_Mutex, ace_mon, this->m_mutex);
  m_ftp_password.init_from_string(password);
}

MyVLCLauncher & MyClientApp::vlc_launcher()
{
  return m_vlc_launcher;
}

MyOperaLauncher & MyClientApp::opera_launcher()
{
  return m_opera_launcher;
}

MyVLCMonitor & MyClientApp::vlc_monitor()
{
  return m_vlc_monitor;
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

void MyClientApp::calc_download_parent_path(MyPooledMemGuard & parent_path, const char * client_id)
{
  MyPooledMemGuard path_x;
  MyClientApp::data_path(path_x, client_id);
  parent_path.init_from_string(path_x.data(), "/download");
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

  if (!do_backup_restore(src_parent_path, tmp, false, false))
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

bool MyClientApp::full_restore(const char * dist_id, bool remove_existing, bool is_new, const char * client_id, bool init)
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

  return do_backup_restore(src_parent_path, dest_parent_path, remove_existing, init);
}

bool MyClientApp::do_backup_restore(const MyPooledMemGuard & src_parent_path, const MyPooledMemGuard & dest_parent_path, bool remove_existing, bool init)
{
  MyPooledMemGuard src_path, dest_path;
  MyPooledMemGuard mfile;
  struct stat buf;

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
      MyFilePaths::zap(dest_path.data(), true);
      MyFilePaths::get_correlate_path(dest_path, 0);
      MyFilePaths::zap(dest_path.data(), true);
    }
  }

  src_path.init_from_string(src_parent_path.data(), "/8");
  dest_path.init_from_string(dest_parent_path.data(), "/8");
  if (remove_existing)
    MyFilePaths::zap(dest_path.data(), true);
  if (MyFilePaths::stat(src_path.data(), &buf) && S_ISDIR(buf.st_mode))
  {
    if (!MyFilePaths::copy_path(src_path.data(), dest_path.data(), true))
    {
      MY_ERROR("failed to copy path (%s) to (%s) %s\n", src_path.data(), dest_path.data(), (const char *)MyErrno());
      return false;
    }

    if (init && !g_test_mode)
    {
      MyClientAppX::instance()->vlc_launcher().init_mode(true);
      MyClientAppX::instance()->vlc_launcher().launch();
    }
  }

  src_path.init_from_string(src_parent_path.data(), "/", mfile.data());
  if (MyFilePaths::stat(src_path.data(), &buf) && S_ISREG(buf.st_mode))
  {
    dest_path.init_from_string(dest_parent_path.data(), "/", mfile.data());
    if (!MyFilePaths::copy_file(src_path.data(), dest_path.data(), true))
    {
      MY_ERROR("failed to copy file (%s) to (%s) %s\n", src_path.data(), dest_path.data(), (const char *)MyErrno());
      return false;
    }
  }

  MyFilePaths::get_correlate_path(src_path, 0);
  MyFilePaths::get_correlate_path(dest_path, 0);
  if (remove_existing)
    MyFilePaths::zap(dest_path.data(), true);
  if (MyFilePaths::stat(src_path.data(), &buf) && S_ISDIR(buf.st_mode))
  {
    if (!MyFilePaths::copy_path(src_path.data(), dest_path.data(), true))
    {
      MY_ERROR("failed to copy path (%s) to (%s) %s\n", src_path.data(), dest_path.data(), (const char *)MyErrno());
      return false;
    }
  }

  src_path.init_from_string(src_parent_path.data(), "/led");
  dest_path.init_from_string(dest_parent_path.data(), "/led");
  if (remove_existing)
    MyFilePaths::zap(dest_path.data(), true);
  if (MyFilePaths::stat(src_path.data(), &buf) && S_ISDIR(buf.st_mode))
  {
    if (!MyFilePaths::copy_path(src_path.data(), dest_path.data(), true))
    {
      MY_ERROR("failed to copy path (%s) to (%s) %s\n", src_path.data(), dest_path.data(), (const char *)MyErrno());
      return false;
    }
  }

  if (init && !g_test_mode)
    MyClientAppX::instance()->opera_launcher().launch();

  src_path.init_from_string(src_parent_path.data(), "/5");
  dest_path.init_from_string(dest_parent_path.data(), "/5");
  if (remove_existing)
    MyFilePaths::zap(dest_path.data(), true);
  if (MyFilePaths::stat(src_path.data(), &buf) && S_ISDIR(buf.st_mode))
  {
    if (!MyFilePaths::copy_path(src_path.data(), dest_path.data(), true))
    {
      MY_ERROR("failed to copy path (%s) to (%s) %s\n", src_path.data(), dest_path.data(), (const char *)MyErrno());
      return false;
    }
  }

//  src_path.init_from_string(src_parent_path.data(), "/", index_frame_file());
//  dest_path.init_from_string(dest_parent_path.data(), "/", index_frame_file());
//  MyFilePaths::copy_file(src_path.data(), dest_path.data(), true);
  return true;
}

bool MyClientApp::get_mfile(const MyPooledMemGuard & parent_path, MyPooledMemGuard & mfile)
{
//  if (get_mfile_from_file(parent_path, mfile))
//    return true;

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
    MyConnectIni::update_connect_status(MyConnectIni::CS_DISCONNECTED);

    {
      MyClientDBGuard dbg;
      if (dbg.db().open_db(NULL, true))
      {
        time_t deadline = time_t(NULL) - const_one_day * 10;
        dbg.db().remove_outdated_ftp_command(deadline);
//      dbg.db().reset_ftp_command_status();
      }
    }
  }

  if (!g_test_mode)
  {
    if (!full_restore(NULL, true, true, NULL, true))
    {
      MY_WARNING("restore of latest data failed, now restoring previous data...\n");
      if (!full_restore(NULL, true, false, NULL, true))
      {
        MY_ERROR("restore of previous data failed\n");
      }
    }
  }

  add_module(m_client_to_dist_module = new MyClientToDistModule(this));

  if (!g_test_mode)
  {
//    m_opera_launcher.launch();
    m_vlc_launcher.init_mode(false);
    m_vlc_monitor.relaunch();
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

bool MyClientApp::on_event_loop()
{
//  m_vlc_monitor.check_relaunch();
//  m_opera_launcher.check_relaunch();
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
  app->init_log();

  if (getenv("DISPLAY") == NULL)
  {
    MY_ERROR("no DISPLAY environment var found\n");
    exit(5);
  }

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
//        dbg.db().reset_ftp_command_status();
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

    MyClientToDistHandler::init_mem_pool(100);
  }

  return app->do_constructor();
}

void MyClientApp::check_prev_extract_task(const char * client_id)
{
  MyPooledMemGuard path;
  calc_download_parent_path(path, client_id);

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
      msrc.data()[ACE_OS::strlen(msrc.data()) - ACE_OS::strlen(".mbz")] = 0;
      MyDistInfoFtp * dist_info = new MyDistInfoFtp;
      {
        MyClientDBGuard dbg;
        if (dbg.db().open_db(client_id))
          dbg.db().load_ftp_command(*dist_info, msrc.data());
      }
//      if (dist_info->status == -2)
//        dist_info->status = 2;
      if (dist_info->validate() && (dist_info->status == 3 || dist_info->status == 2))
      {
        //MyClientAppX::instance()->client_to_dist_module()->dist_info_ftps().add(dist_info);
        delete dist_info;
        continue;
      } else
      {
        MY_INFO("removing downloaded file %s (%d)\n", entry->d_name, dist_info->status);
        delete dist_info;
      }
    }

    msrc.init_from_string(path.data(), "/", entry->d_name);
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
