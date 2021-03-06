/*
 * main.cpp
 *
 *  Created on: Dec 26, 2011
 *      Author: root
 */

#include <cstdio>
#include <fstream>
#include "component.h"
#include "client.h"
#include "clientmodule.h"


//MyProgramLauncher//

MyProgramLauncher::MyProgramLauncher()
{
  m_pid = INVALID_PID;
  m_wait_for_term = false;
  m_last_kill = 0;
  m_launch_time = 0;
}

MyProgramLauncher::~MyProgramLauncher()
{
  kill_instance();
}

void MyProgramLauncher::kill_instance()
{
/*
  if (m_pid != INVALID_PID)
  {
    C_INFO("killing child process [%d]...\n", (int)m_pid);
    kill(m_pid, SIGTERM);
    m_wait_for_term = true;
    m_last_kill = time(NULL);
  }
*/
  C_INFO("searching to kill %s\n", title());
  DIR * dir = opendir("/proc");
  if (!dir)
  {
    C_ERROR("can not open directory: /proc %s\n", (const char*)CSysError());
    return;
  }

  char buff[100], buff2[100];

  struct dirent *entry;
  while ((entry = readdir(dir)) != NULL)
  {
    if (!entry->d_name)
      continue;
    if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
      continue;
    int m = atoi(entry->d_name);
    if (m <= 1)
      continue;

    if(entry->d_type == DT_DIR)
    {
      ACE_OS::sprintf(buff, "/proc/%d/comm", m);
      if (!CSysFS::exist(buff))
        continue;
      CFileProt h;
      if (!h.open_nowrite(buff))
        continue;
      int count = ::read(h.get_fd(), buff2, 99);
      if (count <= 0)
        continue;
      buff2[count] = 0;
      if (buff2[count - 1] == '\n')
        buff2[count - 1] = 0;
      if (strcmp(title(), buff2) == 0)
      {
        C_INFO("find pid (%d) of %s, killing...\n", m, title());
        kill(m, SIGKILL);
      }
    }
  };

  closedir(dir);
  return;
}

void MyProgramLauncher::check_relaunch()
{
  if (m_wait_for_term && m_pid != INVALID_PID && time(NULL) > m_last_kill + 6)
  {
    C_INFO("killing forcefully child process [%d]...\n", (int)m_pid);
    kill(m_pid, SIGKILL);
    m_last_kill = time(NULL);
  }
}

bool MyProgramLauncher::do_on_terminated()
{
  if (!MyClientAppX::instance()->running())
    return false;
  ACE_OS::sleep(2);
  return launch();
}

const char * MyProgramLauncher::title() const
{
  return 0;
}

bool MyProgramLauncher::launch()
{
/*
  if (m_pid != INVALID_PID)
  {
    C_INFO("killing child process (%d)...\n", (int)m_pid);
    kill(m_pid, SIGTERM);
    m_pid = INVALID_PID;
  }
  m_wait_for_term = false;
//  ACE_Process_Options options(true, 64000);
 */
  return on_launch(m_options);
/*
  ACE_Process child;
  pid_t pid = child.spawn(m_options);
  if (pid == -1)
  {
    C_ERROR("failed to launch program %s %s\n", m_options.command_line_buf(), (const char *)MyErrno());
    return false;
  } else
  {
    m_pid = pid;
    m_launch_time = time(NULL);
    C_INFO("launch program OK (pid = %d): %s\n", (int)pid, m_options.command_line_buf());
    return true;
  }
*/
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
  return m_adv_txt.c_str();
}

const char * MyVLCLauncher::gasket() const
{
  return m_gasket.c_str();
}

int MyVLCLauncher::next() const
{
  return m_next;
}

bool MyVLCLauncher::empty_advlist() const
{
  return m_empty_advlist;
}

void MyVLCLauncher::empty_advlist(bool b)
{
  m_empty_advlist = b;
}

bool MyVLCLauncher::save_file(const char * buff)
{
  const char * fn = "/tmp/daily/video.txt";
  if (!buff || !*buff)
    return false;
  CFileProt h;
  if (!h.open_write(fn, true, true, false, true))
    return false;
  int len = ACE_OS::strlen(buff);
  return ::write(h.get_fd(), buff, len) == len;
}

void MyVLCLauncher::init_mode(bool)
{
  m_adv_txt = CCfgX::instance()->data_dir + "/5/adv.txt";
  m_gasket = CCfgX::instance()->data_dir + "/8/gasket.avi";
  std::string s = CCfgX::instance()->data_dir + "/5";
  m_options.working_directory(s.c_str());
}

void MyVLCLauncher::get_file_stat(time_t &t, int & n)
{
  std::string fn = CCfgX::instance()->data_dir + "/vlc-history.txt";
  struct stat stat;
  if (CSysFS::stat(fn.c_str(), &stat))
  {
    t = stat.st_mtime;
    n = stat.st_size;
  } else
  {
    t = 0;
    n = 0;
  }
}

void MyVLCLauncher::check_status()
{
  if (!m_check)
    return;
  if (m_wait_for_term || !running())
    return;
  if (time(NULL) <= m_launch_time + 12)
    return;
  m_check = false;
  if (!file_changed())
  {
    C_WARNING("restart vlc for it seems not running...\n");
    kill_instance();
  }
}

bool MyVLCLauncher::file_changed()
{
  time_t t;
  int n;
  get_file_stat(t, n);
  return t != m_t || n != m_n;
}

bool MyVLCLauncher::load(CMemProt & file_list)
{
  std::vector<std::string> advlist;

  m_next = 0;
  time_t next_time = 0;
  m_current_line.init(NULL);
  if (!CSysFS::exist(adv_txt()))
    return false;

  CMemProt line;
  CCacheX::instance()->get(16000, &line);
  std::ifstream ifs(adv_txt());
  if (!ifs || ifs.bad())
  {
    C_WARNING("failed to open %s: %s\n", adv_txt(), (const char*)CSysError());
    return false;
  }

  time_t now = time(NULL);
  struct tm _tm;
  const int BLOCK_SIZE = 16000;
  int t;
  while (!ifs.eof())
  {
    time_t t_this;
    ifs.getline(line.get_ptr(), BLOCK_SIZE - 1);
    line.get_ptr()[BLOCK_SIZE - 1] = 0;
    char * ptr = ACE_OS::strchr(line.get_ptr(), ':');
    if (!ptr)
      continue;
    *ptr ++ = 0;
    while (*ptr == ' ' || *ptr == '\t')
      ++ptr;
    if (*ptr == 0)
      continue;
    t = atoi(line.get_ptr());
    if (t < 0 || t > 23)
      continue;
    localtime_r(&now, &_tm);
    _tm.tm_hour = t;
    _tm.tm_min = 0;
    _tm.tm_sec = 0;
    t_this = mktime(&_tm);
    if (t_this + GAP_THREASHHOLD < now)
    {
      if (parse_line(ptr, file_list, true))
        next_time = t_this;
    } else
    {
      if (next_time != 0)
      {
        if (parse_line(ptr, file_list, false))
        {
          m_next = t_this - now;
          return true;
        }
      } else
      {
        if (parse_line(ptr, file_list, true))
          next_time = t_this;
      }
    }
  }//while eof

  m_next = 0;
  return next_time != 0;
}

bool MyVLCLauncher::parse_line(char * ptr, CMemProt & file_list, bool fill_options)
{
//  const char * vlc = "vlc -L --fullscreen";
  const char * sfake = "--fake-duration 10000 ";
  CMemProt cmdline;
  CCacheX::instance()->get(64000, &cmdline);

  bool fake = false, hasfile = false;
  const char separators[2] = {' ', 0 };
  CTextDelimiter tkn(ptr, separators);
  char * token;
  ACE_OS::strcpy(cmdline.get_ptr(), sfake);
  CMemProt fn;
  std::string p5 = CCfgX::instance()->data_dir + "/5/";
  while ((token = tkn.get()) != NULL)
  {
    fn.init(p5.c_str(), token);
    if (!CSysFS::exist(fn.get_ptr()))
    {
      C_INFO("skipping non-existing adv file %s\n", token);
      continue;
    }
    if (!fill_options)
      return true;
    hasfile = true;

    if (c_tools_text_tail_is(token, ".bmp") || c_tools_text_tail_is(token, ".jpg") ||
        c_tools_text_tail_is(token, ".gif") || c_tools_text_tail_is(token, ".png"))
    {
      //ACE_OS::strncat(cmdline.data(), " fake:///tmp/daily/5/", 63000);
      ACE_OS::strncat(cmdline.get_ptr(), " fake://", 63000);
      ACE_OS::strncat(cmdline.get_ptr(), token, 63000);
      fake = true;
    } else
    {
      ACE_OS::strncat(cmdline.get_ptr(), " ", 63000);
      ACE_OS::strncat(cmdline.get_ptr(), token, 63000);
    }
  }

  if (!hasfile)
    return false;

  //options.command_line("%s%s%s", vlc, (fake ? " --fake-duration 10000 " : ""), cmdline.data());
  if (fake)
    file_list.init(cmdline.get_ptr());
  else
    file_list.init(cmdline.get_ptr() + ACE_OS::strlen(sfake));
  return true;
}

const char * MyVLCLauncher::title() const
{
  return "vlc";
}

void MyVLCLauncher::clean_list(bool no_error) const
{
  CSysFS::remove("/tmp/daily/video.txt", no_error);
}

bool MyVLCLauncher::on_launch(ACE_Process_Options & )
{
//  const char * vlc = "vlc -L --fullscreen";
  m_empty_advlist = false;
  std::vector<std::string> advlist;
  clean_list(true);
  get_file_stat(m_t, m_n);
  CMemProt file_list;
  //if (!m_init_mode)
  {
    if (load(file_list))
    {
      m_check = true;
      C_INFO("%s OK, loading vlc...\n", adv_txt());
      save_file(file_list.get_ptr());
      kill_instance();
      return true;
    }
    C_INFO("%s not exist or content empty, trying %s\n", adv_txt(), gasket());
  }

  m_empty_advlist = true;

  if (!CSysFS::exist(gasket()))
  {
    C_ERROR("no %s file\n", gasket());
    kill_instance();
    return false;
  }
  m_check = true;
  C_INFO("%s OK, loading vlc...\n", gasket());
  save_file(gasket());
  kill_instance();
  return true;
}

MyVLCLauncher::MyVLCLauncher()
{
  m_next = 0;
  m_init_mode = true;
  m_empty_advlist = false;
  m_t = 0;
  m_n = 0;
  m_check = false;
}

bool MyVLCLauncher::ready() const
{
  return (CSysFS::exist(m_adv_txt.c_str()) || CSysFS::exist(m_gasket.c_str()));
}


//MyVLCMonitor//

MyVLCMonitor::MyVLCMonitor(MyClientApp * app)
{
  m_app = app;
}

void MyVLCMonitor::relaunch()
{
//  if (!m_app->vlc_launcher().running())
//  {
//    launch_vlc();
//    return;
//  }
  launch_vlc();
//  m_app->vlc_launcher().launch();
//  m_app->vlc_launcher().kill_instance();
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
      C_ERROR("failed to setup vlc monitor timer\n");
    else
      C_INFO("vlc next playlist will be shown in %d minute(s)\n", (int)(m_app->vlc_launcher().next() / 60));
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

}

const char * MyOperaLauncher::title() const
{
  return "opera";
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
//    C_INFO("file %s not exist, trying %s instead\n", indexhtml, indexfile.c_str());
//    std::ifstream ifs(indexfile.c_str());
//    if (!ifs || ifs.bad())
//    {
//      C_ERROR("failed to open %s: %s\n", indexfile.c_str(), (const char*)MyErrno());
//      return false;
//    }
//    if (ifs.eof())
//    {
//      C_ERROR("file %s is empty\n", indexfile.c_str());
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
  return CSysFS::exist("/tmp/daily/index.html");
//  if (MyFilePaths::exist("/tmp/daily/index.html"))
//    return true;
//  struct stat  _stat;
//  MyPooledMemProt indexfile;
//  indexfile.init("/tmp/daily/", MyClientApp::index_frame_file());
//  if (!MyFilePaths::stat(indexfile.data(), &_stat))
//    return false;
//  return _stat.st_size > 1;
}

void MyOperaLauncher::relaunch()
{
  if (running())
    kill_instance();
  else
    launch();
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
  C_ASSERT_RETURN(mb, "", false);

  if (unlikely(!running()))
  {
    mb->release();
    return false;
  }

  return c_tools_mb_putq(m_client_to_dist_module->dispatcher(), mb, "to client_to_dist service queue");
}

const CTermVer & MyClientApp::client_version() const
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
  return m_ftp_password.get_ptr();
}

void MyClientApp::ftp_password(const char * password)
{
  ACE_GUARD(ACE_Thread_Mutex, ace_mon, this->m_mutex);
  m_ftp_password.init(password);
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

void MyClientApp::data_path(CMemProt & _data_path, const char * client_id)
{
  if (g_is_test)
  {
    char tmp[128];
    tmp[0] = 0;
    CTerminalDirCreator::term_sn_to_dir(client_id, tmp, 128);
    _data_path.init(CCfgX::instance()->runner_dir.c_str(), "/data/", tmp);
  } else
    _data_path.init(CCfgX::instance()->runner_dir.c_str(), "/data");
}

void MyClientApp::calc_display_parent_path(CMemProt & parent_path, const char * client_id)
{
  if (g_is_test)
  {
    CMemProt path_x;
    MyClientApp::data_path(path_x, client_id);
    parent_path.init(path_x.get_ptr(), "/daily");
  } else
    parent_path.init("/tmp/daily");
}

void MyClientApp::calc_dist_parent_path(CMemProt & parent_path, const char * dist_id, const char * client_id)
{
  CMemProt path_x;
  MyClientApp::data_path(path_x, client_id);
  parent_path.init(path_x.get_ptr(), "/tmp/", dist_id);
}

void MyClientApp::calc_backup_parent_path(CMemProt & parent_path, const char * client_id)
{
  CMemProt path_x;
  MyClientApp::data_path(path_x, client_id);
  parent_path.init(path_x.get_ptr(), "/backup");
}

void MyClientApp::calc_download_parent_path(CMemProt & parent_path, const char * client_id)
{
  CMemProt path_x;
  MyClientApp::data_path(path_x, client_id);
  parent_path.init(path_x.get_ptr(), "/download");
}

bool MyClientApp::full_backup(const char * dist_id, const char * client_id)
{
  ACE_UNUSED_ARG(dist_id);
  CMemProt src_parent_path;
  calc_display_parent_path(src_parent_path, client_id);

  CMemProt snew, dest_parent_path, sold;
  calc_backup_parent_path(dest_parent_path, client_id);

  snew.init(dest_parent_path.get_ptr(), "/new");
  sold.init(dest_parent_path.get_ptr(), "/old");
  CSysFS::delete_dir(sold.get_ptr(), true);

  if (!CSysFS::create_dir(sold.get_ptr(), true))
  {
    C_ERROR("can not mkdir(%s) %s\n", sold.get_ptr(), (const char *)CSysError());
    return false;
  }

  return CSysFS::copy_dir(snew.get_ptr(), sold.get_ptr(), true, false);
}

bool MyClientApp::full_restore(const char * dist_id, bool remove_existing, bool is_new, const char * client_id, bool init)
{
  CMemProt dest_parent_path;
  calc_display_parent_path(dest_parent_path, client_id);

  CMemProt tmp, src_parent_path;
  calc_backup_parent_path(tmp, client_id);
  if (is_new)
    src_parent_path.init(tmp.get_ptr(), "/new");
  else
    src_parent_path.init(tmp.get_ptr(), "/old");

  if (!CSysFS::exist(src_parent_path.get_ptr()))
    return false;

  CMemProt src_path, dest_path;

  if (dist_id && *dist_id)
  {
    src_path.init(src_parent_path.get_ptr(), "/dist_id.txt");
    CFileProt fh;
    if (fh.open_nowrite(src_path.get_ptr()))
      return false;
    char buff[64];
    int n = ::read(fh.get_fd(), buff, 64);
    if (n <= 1)
      return false;
    buff[n - 1] = 0;
    if (ACE_OS::memcmp(buff, dist_id, ACE_OS::strlen(dist_id)) != 0)
      return false;
  }

  return do_backup_restore(src_parent_path, dest_parent_path, remove_existing, init, false);
}

bool MyClientApp::do_backup_restore(const CMemProt & src_parent_path, const CMemProt & dest_parent_path, bool remove_existing, bool init, bool syn)
{
  CMemProt src_path, dest_path;
  CMemProt mfile;
  struct stat buf;

  if (!get_mfile(src_parent_path, mfile))
  {
    C_ERROR("no main index file found @MyClientApp::do_backup_restore() in path: %s\n", src_parent_path.get_ptr());
    return false;
  }

  if (remove_existing)
  {
    CMemProt mfile_dest;
    if (get_mfile(dest_parent_path, mfile_dest))
    {
      dest_path.init(dest_parent_path.get_ptr(), "/", mfile_dest.get_ptr());
      CSysFS::ensure_delete(dest_path.get_ptr(), true);
      CSysFS::dir_from_mfile(dest_path, 0);
      CSysFS::ensure_delete(dest_path.get_ptr(), true);
    }
  }

  if (init && !g_is_test)
  {
    MyClientAppX::instance()->vlc_launcher().init_mode(true);
    MyClientAppX::instance()->vlc_launcher().launch();
  }

  src_path.init(src_parent_path.get_ptr(), "/", mfile.get_ptr());
  dest_path.init(dest_parent_path.get_ptr(), "/", mfile.get_ptr());
  CSysFS::dir_from_mfile(src_path, 0);
  CSysFS::dir_from_mfile(dest_path, 0);
  if (remove_existing)
    CSysFS::ensure_delete(dest_path.get_ptr(), true);
  if (CSysFS::stat(src_path.get_ptr(), &buf) && S_ISDIR(buf.st_mode))
  {
    if (!CSysFS::copy_dir(src_path.get_ptr(), dest_path.get_ptr(), true, syn))
    {
      C_ERROR("failed to copy path (%s) to (%s) %s\n", src_path.get_ptr(), dest_path.get_ptr(), (const char *)CSysError());
      return false;
    }
  }

  src_path.init(src_parent_path.get_ptr(), "/", mfile.get_ptr());
  if (CSysFS::stat(src_path.get_ptr(), &buf) && S_ISREG(buf.st_mode))
  {
    dest_path.init(dest_parent_path.get_ptr(), "/", mfile.get_ptr());
    if (!CSysFS::copy_file(src_path.get_ptr(), dest_path.get_ptr(), true, syn))
    {
      C_ERROR("failed to copy file (%s) to (%s) %s\n", src_path.get_ptr(), dest_path.get_ptr(), (const char *)CSysError());
      return false;
    }
  }

  src_path.init(src_parent_path.get_ptr(), "/led");
  dest_path.init(dest_parent_path.get_ptr(), "/led");
  if (remove_existing)
    CSysFS::ensure_delete(dest_path.get_ptr(), true);
  if (CSysFS::stat(src_path.get_ptr(), &buf) && S_ISDIR(buf.st_mode))
  {
    if (!CSysFS::copy_dir(src_path.get_ptr(), dest_path.get_ptr(), true, syn))
    {
      C_ERROR("failed to copy path (%s) to (%s) %s\n", src_path.get_ptr(), dest_path.get_ptr(), (const char *)CSysError());
      return false;
    }
  }

//  if (init && !g_test_mode)
//    MyClientAppX::instance()->opera_launcher().launch();

//  src_path.init(src_parent_path.data(), "/", index_frame_file());
//  dest_path.init(dest_parent_path.data(), "/", index_frame_file());
//  MyFilePaths::copy_file(src_path.data(), dest_path.data(), true);
  return true;
}

bool MyClientApp::get_mfile(const CMemProt & parent_path, CMemProt & mfile)
{
//  if (get_mfile_from_file(parent_path, mfile))
//    return true;

  mfile.init("index.html");
  CMemProt tmp;
  tmp.init(parent_path.get_ptr(), "/", mfile.get_ptr());
  if (CSysFS::exist(tmp.get_ptr()))
  {
    CSysFS::dir_from_mfile(tmp, 0);
    if (CSysFS::exist(tmp.get_ptr()))
      return true;
  }
  return false;
}

bool MyClientApp::get_mfile_from_file(const CMemProt & parent_path, CMemProt & mfile)
{
  CMemProt index_file_name;
  CMemProt tmp;
  index_file_name.init(parent_path.get_ptr(), "/", index_frame_file());
  CFileProt fh;
  char buff[512];
  if (!fh.open_nowrite(index_file_name.get_ptr()))
    return false;
  int n = ::read(fh.get_fd(), buff, 511);
  if (n <= 1)
    return false;
  buff[n] = 0;
  while (--n >= 0 && (buff[n] == '\r' || buff[n] == '\t' || buff[n] == '\n' || buff[n] == ' '))
    buff[n] = 0;
  mfile.init(buff);
  tmp.init(parent_path.get_ptr(), "/", mfile.get_ptr());
  if (CSysFS::exist(tmp.get_ptr()))
  {
    if (!CSysFS::dir_from_mfile(tmp, 0))
      return false;
    if (CSysFS::exist(tmp.get_ptr()))
      return true;
  }
  return false;
}

bool MyClientApp::before_begin()
{
  return true;
}

void MyClientApp::before_finish()
{

}

bool MyClientApp::do_init()
{
  if (!g_is_test)
  {
    const char * const_id_ini = "/tmp/daily/id.ini";
    C_INFO("trying to read client id from %s\n", const_id_ini);
    while (true)
    {
      CFileProt fh;
      fh.set_print_failure(false);
      if (fh.open_nowrite(const_id_ini))
      {
        char buff[64];
        int n = ::read(fh.get_fd(), buff, 64);
        if (n > 0)
        {
          n = std::min(n, 63);
          buff[n] = 0;
          while (--n >= 0 && (buff[n] == '\r' || buff[n] == '\n' || buff[n] == ' ' || buff[n] == '\t'))
            buff[n] = 0;
          if (n == 0)
            continue;
          m_client_id = buff;
          m_term_SNs.append(buff);
          break;
        }
      }
      ACE_OS::sleep(5);
    }
    C_INFO("get client id [%s] from %s\n", m_client_id.c_str(), const_id_ini);
    MyConnectIni::update_connect_status(MyConnectIni::CS_DISCONNECTED);

    {
      MyClientDBProt dbg;
      if (dbg.db().open_db(NULL, true))
      {
        time_t deadline = time_t(NULL) - C_1_day * 20;
        dbg.db().remove_outdated_ftp_command(deadline);
      }
    }
    MyPL::instance().load(m_client_id.c_str());
  }

  if (!g_is_test)
  {
    CMemProt pn, po, dest_parent_path;
    MyClientApp::calc_backup_parent_path(dest_parent_path, NULL);
    pn.init(dest_parent_path.get_ptr(), "/new");
    po.init(dest_parent_path.get_ptr(), "/old");
    bool bn = MyDistFtpFileExtractor::has_id(pn);
    bool bo = MyDistFtpFileExtractor::has_id(po);
    bool b = bn && full_restore(NULL, true, true, NULL, true);
    if (!b)
    {
      C_WARNING("restore of latest data failed\n");
      if (bo)
      {
        C_WARNING("restoring previous data...\n");
        b = full_restore(NULL, true, false, NULL, true);
        if (!b)
          C_WARNING("restore of previous data failed\n");
      }
      if (!b && !bn)
        b = full_restore(NULL, true, true, NULL, true);
      if (!b)
        C_ERROR("restore of data failed\n");
    }
  }

  add_component(m_client_to_dist_module = new MyClientToDistModule(this));

  return true;
}

void MyClientApp::i_print()
{
  MyClientApp::dump_mem_pool_info();
}

bool MyClientApp::do_singal_child(pid_t pid)
{
  m_opera_launcher.on_terminated(pid);
  m_vlc_launcher.on_terminated(pid);
  return true;
}

bool MyClientApp::do_schedule_work()
{
  return true;
}

void MyClientApp::dump_mem_pool_info()
{
  ACE_DEBUG((LM_INFO, "  !!! Memory Dump start !!!\n"));
  long nAlloc = 0, nFree = 0, nMaxUse = 0, nAllocFull = 0;
  if (!g_cache)
  {
    ACE_DEBUG((LM_INFO, "    Memory Pool Disabled\n"));
    goto _exit_;
  }

  int chunks;
  if (likely(MyClientToDistHandler::mem_block() != NULL))
  {
    chunks = MyClientToDistHandler::mem_block()->blocks();
    MyClientToDistHandler::mem_block()->query_stats(nAlloc, nFree, nMaxUse, nAllocFull);
    CParentRunner::print_pool("MyClientToDistHandler", nAlloc, nFree, nMaxUse, nAllocFull, sizeof(MyClientToDistHandler), chunks);
  }

  if (likely(MyClientToMiddleHandler::mem_block() != NULL))
  {
    chunks = MyClientToMiddleHandler::mem_block()->blocks();
    MyClientToMiddleHandler::mem_block()->query_stats(nAlloc, nFree, nMaxUse, nAllocFull);
    CParentRunner::print_pool("MyClientToMiddleHandler", nAlloc, nFree, nMaxUse, nAllocFull, sizeof(MyClientToMiddleHandler), chunks);
  }

  CCacheX::instance()->print_info();

_exit_:
  ACE_DEBUG((LM_INFO, "  !!! Memory Dump End !!!\n"));
}

const char * MyClientApp::index_frame_file()
{
  return "indexfile";
}

bool MyClientApp::app_init(const char * app_home_path, CCfg::CXYZStyle mode)
{
  MyClientApp * app = MyClientAppX::instance();
  CCfg * cfg = CCfgX::instance();
  if (!cfg->readall(app_home_path, mode))
  {
    std::printf("error loading config file, quitting\n");
    exit(5);
  }
  if (geteuid() == 0 && cfg->can_su == 0)
  {
    std::printf("error run as root, quitting\n");
    exit(6);
  }
  if (cfg->run_at_back)
    CParentRunner::put_to_back();

  MyClientToMiddleHandler::mem_block_start(20);
  CCacheX::instance()->prepare(cfg);
  app->init_log();

  if (getenv("DISPLAY") == NULL)
  {
    C_ERROR("no DISPLAY environment var found\n");
    exit(5);
  }

  if (g_is_test)
  {
    std::string idfile = cfg->runner_dir + "/config/id.file";
    std::ifstream ifs(idfile.c_str(), std::ifstream::in);
    if (!ifs || ifs.bad())
    {
      C_ERROR("can not open file %s %s\n", idfile.c_str(), (const char *)CSysError());
      exit(6);
    }
    char id[64];
    while (!ifs.eof())
    {
      ifs.getline(id, 64);
      app->m_term_SNs.append(id);
    }
    CTerminalDirCreator::create_dirs_from_TermSNs(cfg->data_dir.c_str(), &app->m_term_SNs);
    MyClientToDistHandler::mem_block_start(app->m_term_SNs.number() * 1.2);

    int m = app->m_term_SNs.number();
    CNumber client_id;
    time_t deadline = time_t(NULL) - C_1_day * 10;
    for (int i = 0; i < m; ++i)
    {
      app->m_term_SNs.get_sn(i, &client_id);
      MyClientDBProt dbg;
      if (dbg.db().open_db(client_id.to_str(), true))
      {
        dbg.db().remove_outdated_ftp_command(deadline);
//        dbg.db().reset_ftp_command_status();
      }
    }
  } else
  {
    std::string path_x = cfg->runner_dir + "/data/download";
    CSysFS::create_dir(path_x.c_str(), true);
    path_x = cfg->runner_dir + "/data/tmp";
    CSysFS::delete_dir(path_x.c_str(), true);
    CSysFS::create_dir(path_x.c_str(), true);
    path_x = cfg->runner_dir + "/data/backup";
    CSysFS::create_dir(path_x.c_str(), true);

//    if(cfg->adv_expire_days > 0)
//    {
//      MyPooledMemProt mpath;
//      mpath.init(cfg->app_path.c_str(), "/data/backup/new");
//      MyAdvCleaner cleaner;
//      cleaner.do_clean(mpath, app->client_id(), cfg->adv_expire_days);
//    }

    MyClientToDistHandler::mem_block_start(100);
  }

  return app->delayed_init();
}

void MyClientApp::check_prev_extract_task(const char * client_id)
{
  CMemProt path;
  calc_download_parent_path(path, client_id);

  DIR * dir = opendir(path.get_ptr());
  if (!dir)
  {
    C_ERROR("can not open directory: %s %s\n", path.get_ptr(), (const char*)CSysError());
    return;
  }

  CMemProt msrc;
  struct dirent *entry;
  while ((entry = readdir(dir)) != NULL)
  {

    if (!entry->d_name)
      continue;
    if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
      continue;

    if (likely(c_tools_text_tail_is(entry->d_name, ".mbz")))
    {
      msrc.init(entry->d_name);
      msrc.get_ptr()[ACE_OS::strlen(msrc.get_ptr()) - ACE_OS::strlen(".mbz")] = 0;
      MyDistInfoFtp * dist_info = new MyDistInfoFtp;
      {
        MyClientDBProt dbg;
        if (dbg.db().open_db(client_id))
          dbg.db().load_ftp_command(*dist_info, msrc.get_ptr());
      }
      if (dist_info->validate() && (dist_info->status == 3 || dist_info->status == 2))
      {
        //MyClientAppX::instance()->client_to_dist_module()->dist_info_ftps().add(dist_info);
        delete dist_info;
        continue;
      } else
      {
        C_INFO("removing downloaded file %s (%d)\n", entry->d_name, dist_info->status);
        delete dist_info;
      }
    }

    msrc.init(path.get_ptr(), "/", entry->d_name);
    CSysFS::remove(msrc.get_ptr(), true);
  };

  closedir(dir);
}

void MyClientApp::app_fini()
{
  C_INFO(ACE_TEXT("shutdown client...\n"));
  MyClientAppX::close();  //this comes before the releasing of memory pool
  CCfgX::close();
  dump_mem_pool_info(); //only mem pool info, other objects should gone by now
  MyClientToDistHandler::mem_block_end();
  MyClientToMiddleHandler::mem_block_end();
  CCacheX::close();
}


int main(int argc, const char * argv[])
{
  ACE_Sig_Action no_sigpipe ((ACE_SignalHandler) SIG_IGN);
  ACE_Sig_Action original_action;
  no_sigpipe.register_action (SIGPIPE, &original_action);
  bool ret;
  if (argc == 3 && strcmp(argv[1], "-home") == 0 && argv[2][0] == '/')
    ret = MyClientApp::app_init(argv[2], CCfg::AM_TERMINAL);
  else
    ret = MyClientApp::app_init(NULL, CCfg::AM_TERMINAL);

  if (ret)
    MyClientAppX::instance()->begin();
  MyClientApp::app_fini();
  return 0;
}
