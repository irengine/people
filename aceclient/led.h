#ifndef my_led_h
#define my_led_h

#include <string>

#include "serial.h"
#include "common_c.h"

#pragma pack(push, 1)

class myControlReqFrame
{
public:
  myControlReqFrame();
  void gen_crc16();
  char * data() { return (char*)&m_head; }
  int length() const { return sizeof(myControlReqFrame); }
  
  unsigned short m_head;
  unsigned short m_length;
  unsigned char  m_type;
  unsigned char  m_year;
  unsigned char  m_month;
  unsigned char  m_day;
  unsigned char  m_hour;
  unsigned char  m_minute;
  unsigned char  m_second;
  unsigned char  m_line_1_prop;
  unsigned char  m_line_2_prop;
  unsigned char  m_line_3_prop;
  unsigned char  m_line_4_prop;
  unsigned char  m_time_setting;
  unsigned char  m_time_display_period;
  unsigned char  m_port_error_time;
  unsigned char  m_op;
  unsigned char  m_brightness;
  unsigned char  m_move_speed;
  unsigned short m_crc16;  
};

class myControlReplyFrame
{
public:
  bool valid();
  char * data() { return (char*)&m_head; }
  int length() const { return sizeof(myControlReplyFrame); }
  
  unsigned short m_head;
  unsigned char  m_length;
  unsigned char  m_type;
  unsigned short m_id;
  unsigned short m_crc16;
};

class myStaticDisplayReqFrame
{
public:
  myStaticDisplayReqFrame();
  void gen_crc16();
  char * data() { return (char*)&m_head; }
  void setinfo(const char * txt);
  int length() const { return sizeof(myStaticDisplayReqFrame) - 400 + m_info_length + 2; }
  bool valid() const { return m_info_length >= 1 && m_info_length <= 384; }
  
  unsigned short m_head;
  unsigned short m_length;
  unsigned char  m_type;
  unsigned char  m_line_no;
  unsigned char  m_display_mode;
  unsigned char  m_info_no;
  unsigned int   m_info_id;
  unsigned char m_time_expire[6];
  unsigned short m_info_length;
  unsigned char m_data[400];
};

class myStaticDisplayReplyFrame
{
public:
  myStaticDisplayReplyFrame();
  void gen_crc16();
  char * data() { return (char*)&m_head; }
  int length() const { return sizeof(myStaticDisplayReplyFrame); }
  bool valid() const;

  unsigned short m_head;
  unsigned char  m_length;
  unsigned char  m_type;
  unsigned int   m_info_id;
  unsigned short m_id;
  unsigned short m_crc16;  
};

#pragma pack(pop)

class MyApp: public MyBaseApp
{
public:
  MyApp(const char * dev);
  virtual void loop();
  
protected:
  const char * data_file() const;
  virtual bool setup_port();
    
private:
  bool display_text();
  bool led_control(unsigned char line_1_prop, unsigned char op);
};

#endif
