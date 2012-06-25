#ifndef my_relay_h
#define my_relay_h

#include <string>

#include "serial.h"
#include "common_c.h"

extern unsigned char g_dev_id;

#pragma pack(push, 1)

class MyBaseFrame
{
public:
  MyBaseFrame();
  bool check_lead() const;
  
  char * data()
  {
    return (char*)&m_lead_1;
  }
  
  unsigned char m_lead_1;
  unsigned char m_lead_2;  
};

template <typename T> int my_len(T & t)
{
  return sizeof(t);
}

template <typename T> void my_dump(T & t)
{
  int len = my_len(t);
  const unsigned char * ptr = (unsigned char*)t.data();
  printf("dump(%03d): ", len);
  for (int i = 0; i < len; ++ i)
    printf("%02X  ", *(ptr + i));
  printf("\n         : ");
  for (int i = 0; i < len; ++ i)
    printf("%-3.u ", *(ptr + i));
  printf("\n");
}



class MyBaseReqFrame: public MyBaseFrame
{
public:
  MyBaseReqFrame();
  MyBaseReqFrame(unsigned char dev_id, unsigned char command);
  
  unsigned char m_dev_id;
  unsigned char m_command;
};


class MySetTimeFrame: public MyBaseReqFrame
{
public:
  MySetTimeFrame();

  unsigned char  m_second;    
  unsigned char  m_minute;
  unsigned char  m_hour;
  unsigned char  m_weekday;
  unsigned char  m_day;
  unsigned char  m_month;
  unsigned char  m_year;
};

class MyCheckStatusFrame: public MyBaseReqFrame
{
public:
  MyCheckStatusFrame();
};

class MyCheckStatusReplyFrame: public MyBaseFrame
{
public:
  unsigned char m_status;  
};

class MyQueryDevIDFrame: public MyBaseReqFrame
{
public:
  MyQueryDevIDFrame();
};

class MyReplyDevIDFrame: public MyBaseFrame
{
public:
//  int length() const { return ; }
  
  unsigned char m_answer_id;
};

class MyModeFrame: public MyBaseReqFrame
{
public:
  MyModeFrame(unsigned char mode);
  
  unsigned char m_mode;
};

class MyOffModeFrame: public MyBaseReqFrame
{
public:
  MyOffModeFrame(unsigned char mode);
  
  unsigned char m_mode;
};

class MyOffTimeFrame: public MyBaseReqFrame
{
public:
  MyOffTimeFrame();
  
  unsigned char  m_index;
  unsigned char  m_second;    
  unsigned char  m_minute;
  unsigned char  m_hour;
  unsigned char  m_weekday;  
  unsigned char  m_day;
  unsigned char  m_status;
};



class MySetModeFrame: public MyBaseReqFrame
{
public:
  MySetModeFrame(unsigned char mode);
  
  unsigned char m_mode;
};


class MyConfigReplyFrame
{
public:
  bool ok() const;
  bool failed() const;

  unsigned char m_data;
};

#pragma pack(pop)

class MyApp: public MyBaseApp
{
public:
  MyApp(const char * dev);
  virtual void loop();
  
protected:
  template <typename T> bool write_command(T & t)
  {
    unsigned char buff[200];
    int len = my_len(t);
    memcpy(buff, t.data(), len);
    buff[len ++] = 0x55;
    buff[len ++] = 0xAA;
    return write_port((char*)buff, len);
  }

  template <typename T> bool read_reply(T & t)
  {
    unsigned char buff[200];
    int len = my_len(t);
    if (!read_port((char*)buff, len + 2))
      return false;
    if (buff[len] != 0x55 || buff[len + 1] != 0xAA)
    {
      fprintf(stderr, "read reply failed, tail is not '55AA'\n");
      return false;
    }
    memcpy(t.data(), buff, len);
    return true;
  }
  
  const char * data_file() const;
  virtual bool setup_port();
  virtual bool has_text() const;
  void get_dev_id();
    
private:

};


#endif
