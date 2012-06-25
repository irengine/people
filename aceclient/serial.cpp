#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <termios.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fstream>

#include "common_c.h"
#include "serial.h"

int open_port(int port)
{
  int fd = -1; 
  int ret;
  char device[20] = {0}; 

  if (port < 1 || port > 4)
    error_ret("port number must be 1~4.");

  sprintf(device, "/dev/ttyS%d", port-1);
  fd = open(device, O_RDWR | O_NOCTTY | O_NDELAY);
  if (fd == -1)
    unix_error_ret("Unable to open the port");

  ret = fcntl(fd, F_SETFL, 0);
  if (ret < 0)
    unix_error_ret("fcntl");
  debug_msg("Open the port success!\n");
  
  return fd;
}

int close_port(int fd)
{
  if(close(fd) < 0)
    unix_error_ret("Unable to close the port.");
  return 0;
}

int setup_port(int fd, int speed, int data_bits, int parity, int stop_bits)
{
  int speed_arr[] = {B115200, B9600, B38400, B19200, B4800};
  int name_arr[] = {115200, 9600, 38400, 19200, 4800};
  struct termios opt;
  int ret=-1;
  int i=0;
  int len=0;

  ret = tcgetattr(fd, &opt);	
  if (ret < 0)
    unix_error_ret("Unable to get the attribute");

  opt.c_cflag |= (CLOCAL | CREAD); 
  opt.c_cflag &= ~CSIZE;			

  len = sizeof(speed_arr) / sizeof(int);
  for (i = 0; i < len; i++)
  {
    if (speed == name_arr[i])
    {
      cfsetispeed(&opt, speed_arr[i]);
      cfsetospeed(&opt, speed_arr[i]);
      break;
    }
  }
  if (i == len)
    error_ret("Unsupported baud rate.");
  
  switch (data_bits)
  {
  case 8:
    opt.c_cflag |= CS8;
    break;
  case 7:
    opt.c_cflag |= CS7;
    break;
  default:
    error_ret("Unsupported data bits.");
  }

  switch (parity)
  {
  case 'N':
  case 'n':
    opt.c_cflag &= ~PARENB;
    opt.c_cflag &= ~INPCK;
    break;
  case 'O':
  case 'o':
    opt.c_cflag|=(INPCK|ISTRIP); 
    opt.c_cflag |= (PARODD | PARENB);
    break;
  case 'E':
  case 'e':
    opt.c_cflag|=(INPCK|ISTRIP); 
    opt.c_cflag |= PARENB;
    opt.c_cflag &= ~PARODD;
    break;
  case 'S':
  case 's':    
    options.c_cflag &= ~PARENB;
    options.c_cflag &= ~CSTOPB;
    break;  
  default:
    error_ret("Unsupported parity bits.");
  }

  switch (stop_bits)
  {
  case 1:
    opt.c_cflag &= ~CSTOPB;
    break;
  case 2:
    opt.c_cflag |= CSTOPB;
    break;
  default:
    error_ret("Unsupported stop bits.");
  }

  opt.c_lflag &= ~(ICANON | ECHO | ECHOE | ISIG);
  opt.c_oflag &= ~OPOST;

  tcflush(fd, TCIFLUSH);
  opt.c_cc[VTIME] = 0; 
  opt.c_cc[VMIN] = 0; 

  ret = tcsetattr(fd, TCSANOW, &opt);
  if (ret < 0)
    unix_error_ret("Unable to setup the port.");

  return 0;
}

bool read_port(int fd, char * data, int len)
{
  if (len <= 0)
    return false;
  int m = 0, n, can_try = 10;
  while (len > m)
  {
    n = read(fd, data + m, len - m);
    if (n > 0)
      m += n;
    if (len > m)
    {
      if (--can_try >= 0)
        sleep(1);  
      else
      {
        fprintf(stderr, "read port failed, completed = %d/%d\n", m, len);
        return false;  
      }  
    }  
  }
  
  return len == m;    
}

int  write_port(int fd, const char * data, int len)
{
  if (len <= 0 || !data)
    return 0;
  int n = write(fd, data, len);
  if (n < 0)
    return -1;  
  return len - n;
};


//MyBaseApp//

MyBaseApp::MyBaseApp(int port)
{
  m_port = port;
  m_fd = -1;
  m_fsize = 0;
  m_ftime = 0;
}

bool MyBaseApp::init()
{
  m_fd = open_port(m_port);
  if (m_fd == -1)
    return false;
  return setup_port();
}

bool MyBaseApp::setup_port()
{
  return (::setup_port(m_fd, 19200, 8, 'N', 1) != -1);
}

void MyBaseApp::clean_up()
{
  if (m_fd == -1)
    return;
  close_port(m_fd);
  m_fd = -1;
}

int MyBaseApp::get_fd() const
{
  return m_fd;
}

const std::string & MyBaseApp::get_value()
{
  return m_value;
}

bool MyBaseApp::check_open()
{
  if (m_fd != -1)
    return true;
  return init();
}

const char * MyBaseApp::data_file() const
{
  return NULL;
}

bool MyBaseApp::get_fstate()
{
  struct stat st;
  if (lstat(data_file(), &st) >= 0)
  {
    if (m_ftime != st.st_mtime || m_fsize != st.st_size)
    {
      m_ftime = st.st_mtime;
      m_fsize = st.st_size;
      return true;
    }
    else
      return false;
  } 
  else
    return false;
}

bool MyBaseApp::read_text()
{
  std::ifstream ifs(data_file());
  if (!ifs || ifs.bad())
    return false;

  const int BLOCK_SIZE = 400;
  char buff[BLOCK_SIZE];
  ifs.getline(buff, BLOCK_SIZE - 1);
  buff[BLOCK_SIZE - 1] = 0;
  int len = strlen(buff);
  while (len > 0 && (buff[len - 1] == '\r' || buff[len - 1] == '\n' || buff[len - 1] == ' '))
    buff[--len] = 0;
  std::string s(buff);
  bool ret = (s.compare(m_value) != 0);
  if (ret)
    m_value = s;
  return ret;
}

bool MyBaseApp::has_text() const
{
  return m_value.length() > 0;
}

void MyBaseApp::loop()
{

}

bool MyBaseApp::read_port(char * data, int len)
{
  if (!check_open())
    return false;
  return ::read_port(m_fd, data, len);
}
 
bool MyBaseApp::write_port(char * data, int len)
{
  if (!check_open())
    return false;
  int m = ::write_port(m_fd, data, len);
  if (m < 0)
  {
    unix_print_error("write to port failed");
    clean_up();
    init();
    return false;
  }
  return m == 0;
}
