#ifndef my_relay_h
#define my_relay_h

#include <string>

#include "serial.h"
#include "common_c.h"

#pragma pack(push, 1)

extern unsigned char g_dev_id;

class MyBaseFrame
{
public:
  MyBaseFrame();
  MyBaseFrame(unsigned char dev_id, unsigned char command);
  bool check_lead() const;
  
  unsigned char m_lead_1;
  unsigned char m_lead_2;  
  unsigned char m_dev_id;
  unsigned char m_command;
};

class MySetTimeFrame: public MyBaseFrame
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

class MyCheckStatusFrame: public MyBaseFrame
{
public:
  MyCheckStatusFrame();
};

class MyCheckStatusReplyFrame: public MyBaseFrame
{
public:
  unsigned char m_status;  
};

class MyQueryDevIDFrame: public MyBaseFrame
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

class MyModeFrame: public MyBaseFrame
{
public:
  MyModeFrame(unsigned char mode);
  
  unsigned char m_mode;
};

class MyOffModeFrame: public MyBaseFrame
{
public:
  MyOffModeFrame(unsigned char mode);
  
  unsigned char m_mode;
};

class MyOffTimeFrame: public MyBaseFrame
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



class MySetModeFrame: public MyBaseFrame
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

#endif
