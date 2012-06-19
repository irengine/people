#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <termios.h>

#include "common_c.h"
#include "serail.h"

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

