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
  my_dump_base(t.data(), len);
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

class MySetStatusFrame: public MyBaseReqFrame
{
public:
  MySetStatusFrame(unsigned char index, unsigned char status);
  
  unsigned char m_index;
  unsigned char m_status;
};


class MyCheckStatusReplyFrame: public MyCheckStatusFrame
{
public:
  unsigned char m_status;
};

class MyQueryDevTimeFrame: public MyBaseReqFrame
{
public:
  MyQueryDevTimeFrame();
};

class MyQueryDevIDFrame: public MyBaseReqFrame
{
public:
  MyQueryDevIDFrame(unsigned char dev_id);
};

class MyReplyDevIDFrame: public MyBaseFrame
{
public:
  
  unsigned char m_answer_id;
};

class MySetMode1Frame: public MyBaseReqFrame
{
public:
  MySetMode1Frame(unsigned char mode);
  
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


class MySetMode2Frame: public MyBaseReqFrame
{
public:
  MySetMode2Frame(unsigned char mode);
  
  unsigned char m_mode;
};


class MyConfigReplyFrame: public MyBaseFrame
{
public:
  bool ok() const;
  bool failed() const;
  
  unsigned char m_dev_id;
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
    unsigned char buff[400];
    int len = my_len(t);
    memcpy(buff, t.data(), len);
    buff[len ++] = 0x55;
    buff[len ++] = 0xAA;
    return write_port((char*)buff, len);
  }

  template <typename T> bool read_reply(T & t)
  {
    unsigned char buff[400];
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
  bool get_dev_id();
  bool check_status(unsigned char & status);
  bool set_mode1(unsigned char mode);
  bool set_mode2(unsigned char mode);
  bool sync_time();
  bool set_status(unsigned char idx, bool on);
  bool clear_offtime();
  bool query_time(MySetTimeFrame & reply);
  bool offtime(unsigned char day, unsigned char hour, unsigned char minute); //f alone
  bool onofftime(unsigned char ohour, unsigned char ominute, unsigned char fhour, unsigned char fminute);
  
private:
  bool do_get_dev_id();
  bool do_check_status(unsigned char & status);
  bool do_set_mode1(unsigned char mode);
  bool do_set_mode2(unsigned char mode);
  bool do_sync_time();
  bool do_set_status(unsigned char idx, bool on);
  bool do_clear_offtime(unsigned char idx);
  bool do_set_offtime(unsigned char day, unsigned char hour, unsigned char minute, bool on); 
  bool do_offtime(unsigned char day, unsigned char hour, unsigned char minute); //f alone
  bool do_query_time(MySetTimeFrame & reply);
};


#endif
