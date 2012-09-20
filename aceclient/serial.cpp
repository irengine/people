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

int open_port(const char * dev)
{
  int fd = -1; 
  int ret;

  if (!dev || !*dev)
    error_ret("port dev is null.");

  fd = open(dev, O_RDWR | O_NOCTTY | O_NDELAY);
  if (fd < 0)
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
  int ret = -1;
  int i = 0;
  int len = 0;

  ret = tcgetattr(fd, &opt);
  if (ret < 0)
    unix_error_ret("Unable to get the attribute.1");

  len = sizeof(speed_arr) / sizeof(int);
  for (i = 0; i < len; i++)
  {
    if (speed == name_arr[i])
    {
//      tcflush(fd, TCIOFLUSH);
      cfsetispeed(&opt, speed_arr[i]);
      cfsetospeed(&opt, speed_arr[i]);
//      tcflush(fd, TCIOFLUSH);
      break;
    }
  }
  if (i == len)
    error_ret("Unsupported baud rate.");

  opt.c_cflag |= (CLOCAL | CREAD); 
  opt.c_cflag &= ~CSIZE;
    
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
    opt.c_iflag &= ~INPCK;
    break;
  case 'O':
  case 'o':
    opt.c_iflag |= (INPCK|ISTRIP); 
    opt.c_cflag |= (PARODD | PARENB);
    break;
  case 'E':
  case 'e':
    opt.c_iflag |= (INPCK|ISTRIP); 
    opt.c_cflag |= PARENB;
    opt.c_cflag &= ~PARODD;
    break;
  case 'S':
  case 's':
    opt.c_cflag &= ~PARENB;
    opt.c_cflag &= ~CSTOPB;    
    opt.c_iflag |= INPCK;    
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

  opt.c_iflag &= ~(IXON | IXOFF | IXANY);
  opt.c_iflag &= ~(ICRNL | INLCR);  
  opt.c_oflag &= ~(ONLCR | OCRNL);
  opt.c_cflag &= ~CRTSCTS;  
  
  tcflush(fd, TCIFLUSH);
  opt.c_cc[VTIME] = 1;
  opt.c_cc[VMIN] = 1;

  ret = tcsetattr(fd, TCSANOW, &opt);
  if (ret < 0)
    unix_error_ret("Unable to setup the port.2");

  return 0;
}


static int do_read_port(int fd, char * data, int len)
{
  int xlen,fs_sel;
  fd_set fs_read;
  
  struct timeval time;
  
  FD_ZERO(&fs_read);
  FD_SET(fd, &fs_read);
  
  time.tv_sec = 10;
  time.tv_usec = 0;
  
  fs_sel = select(fd + 1,&fs_read, NULL, NULL, &time);
  if(fs_sel)
  {
    xlen = read(fd, data, len);
/*
    printf("do_read get %d/%d bytes!\n", xlen, len);
    int j;
	  for (j = 0; j < xlen; ++ j)
	  {
      printf("%02X-%u ",(unsigned char)data[j], (unsigned char)data[j])
    }
*/
    return xlen;
  } else 
  {
//    printf("do_read get 0/%d bytes!\n", len);  
    return 0;
  }	
}

bool read_port(int fd, char * data, int len)
{
  if (len <= 0)
    return true;
  int m = 0, n;
  while (len > m)
  {
    n = do_read_port(fd, data + m, len - m);
    if (n > 0)
      m += n;
    else
    {
      fprintf(stderr, "read port failed, completed = %d/%d\n", m, len);
      return false;
    }
  }

  return len == m;
}

bool read_port_x(int fd, char * data, int len, unsigned char mark1, unsigned char mark2)
{
  if (len <= 2)
    return true;
  int i, m = 0;
  if (!read_port(fd, data, len))
    return false;
    
__loop:
  for (i = 0; i < len - 2; ++i)
  {
    if ((unsigned char)data[i] == mark1 && (unsigned char)data[i + 1] == mark2)
    {
      if (i == 0)
        return true;
      else
        break;  
    }
  }
  ++m;
  if (m > 10)
    return false;
  
  if (i < len - 2)
  {
    memmove(data, data + i, len - i);
    return read_port(fd, data + (len - i), i);
  }
  
  if ((unsigned char)data[len - 1] == mark1)
  {
    *(unsigned char*)data = mark1;
    if (!read_port(fd, data + 1, len - 1))
      return false;
    goto __loop;
  }
  if (!read_port(fd, data, len))
    return false;
  goto __loop;
  
  return true; //make compiler happy  
}

int  write_port(int fd, const char * data, int len)
{
  if (len <= 0 || !data)
    return 0;
  int n = write(fd, data, len);
  if (n < 0)
    return -1;
  my_dump_base(data, len);
  if (n != len)
  {
    tcflush(fd,TCOFLUSH);  
    printf("write_port failed: %d/%d\n", n, len);
  } else
    printf("write_port ok: %d\n", len);   
  return len - n;
};

void my_dump_base(const char * data, int len)
{
  const unsigned char * ptr = (unsigned char*)data;
  printf("dump(%03d): ", len);
  for (int i = 0; i < len; ++ i)
    printf("%02X  ", *(ptr + i));
  printf("\n         : ");
  for (int i = 0; i < len; ++ i)
    printf("%-3.u ", *(ptr + i));
  printf("\n");
}


//MyBaseApp//

MyBaseApp::MyBaseApp(const char * dev)
{
  m_fd = -1;
  m_fsize = 0;
  m_ftime = 0;
  m_mark1 = 0;
  m_mark2 = 0;
  
  if (dev && *dev)
    m_port = dev;
}

bool MyBaseApp::init()
{
  m_fd = open_port(m_port.c_str());
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

const std::string & MyBaseApp::get_value() const
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
      printf("get_fstate() return true\n");
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
  {
    unix_print_error("can not open file @read_text()");  
    return false;
  }
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
  printf("got text: [%s], return %s\n", s.c_str(), ret?"true":"false");
  return ret;
}

bool MyBaseApp::has_text() const
{
  return m_value.length() > 0;
}

void MyBaseApp::loop()
{

}

void MyBaseApp::set_text(const char * text)
{
  if (!text)
    text = "";
  m_value = text;
}

bool MyBaseApp::read_port(char * data, int len)
{
  if (!check_open())
    return false;
  
  if (!::read_port_x(m_fd, data, len, m_mark1, m_mark2))
  {  
    clean_up();
    init();
    return false;
  }
  return true;
}
 
bool MyBaseApp::write_port(char * data, int len)
{
  if (!check_open())
    return false;
  int m = ::write_port(m_fd, data, len);
  if (m != 0)
  {
    unix_print_error("write to port failed");
    clean_up();
    init();
    return false;
  }
  return true;
}
