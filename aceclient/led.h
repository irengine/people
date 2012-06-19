#ifndef my_led_h
#define my_led_h

#include "serial.h"
#include "common_c.h"

#pragma pack(push, 1)

class myControlReqFrame
{
public:
  myControlReqFrame();
  void gen_crc16();
  char * data() { return (char*)&m_header; }
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
  bool check();
  char * data() { return (char*)&m_header; }
  int length() const { return sizeof(myControlReplyFrame); }
  
  unsigned short m_head;
  unsigned char  m_length;
  unsigned char  m_type;
  unsigned short m_id;
  unsigned short m_crc16;
};

#pragma pack(pop)

#endif
