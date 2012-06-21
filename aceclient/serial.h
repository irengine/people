#ifndef __MYSERIAL_PORT_H
#define __MYSERIAL_PORT_H

#include <string>

int  open_port(int port);
int  close_port(int fd);
int  setup_port(int fd, int speed, int data_bits, int parity, int stop_bits);
bool read_port(int fd, char * data, int len);

class MyBaseApp
{
public:
  MyBaseApp(int port);
  bool init();
  void clean_up();
  virtual void loop();

protected:
  virtual const char * data_file() const;
  virtual bool setup_port();
  virtual bool has_text() const;
  
  bool read_port(char * data, int len);
  bool check_open();
  bool read_text();
  bool get_fstate();
  int get_fd() const;
  const std::string & get_value();
  
private:
  std::string m_value;
  int m_port;
  int m_fd;
  off_t m_fsize;
  time_t m_ftime;
};


#endif

