#include <time.h>
#include <string.h>
#include <unistd.h>
#include <fstream>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>

#include "relay.h"

unsigned char g_dev_id = 0;

//MyBaseFrame//

MyBaseFrame::MyBaseFrame()
{
  m_lead_1 = 0xAA;
  m_lead_2 = 0x55;  
}

MyBaseFrame::MyBaseFrame(unsigned char dev_id, unsigned char command)
{
  m_lead_1 = 0xAA;
  m_lead_2 = 0x55;  
  m_dev_id = dev_id;
  m_command = command;
}

bool MyBaseFrame::check_lead() const
{
  return (m_lead_1 == 0xAA && m_lead_2 == 0x55);
}


//MySetTimeFrame//

MySetTimeFrame::MySetTimeFrame(): MyBaseFrame(g_dev_id, 0xFC)
{
  time_t now = time(NULL);
  struct tm _tm;
  localtime_r(&now, &_tm);
  m_year = _tm.tm_year % 100;
  m_month = _tm.tm_mon + 1;
  m_day = _tm.tm_mday;
  m_hour = _tm.tm_hour;
  m_minute = _tm.tm_min;
  m_second = _tm.tm_sec % 60;
  m_weekday = _tm.tm_wday;
}


//MyCheckStatusFrame//

MyCheckStatusFrame::MyCheckStatusFrame(): MyBaseFrame(g_dev_id, 0xC1)
{

}


//MyQueryDevIDFrame//

MyQueryDevIDFrame::MyQueryDevIDFrame(): MyBaseFrame(g_dev_id, 0xCF)
{

}


//MyModeFrame//

MyModeFrame::MyModeFrame(unsigned char mode): MyBaseFrame(g_dev_id, 0xFB)
{
  m_mode = mode;
}


//MyOffModeFrame//

MyOffModeFrame::MyOffModeFrame(unsigned char mode): MyBaseFrame(g_dev_id, 0xFE)
{
  m_mode = mode;
}


//MyOffTimeFrame//

MyOffTimeFrame::MyOffTimeFrame(): MyBaseFrame(g_dev_id, 0xEA)
{
  m_second = 0;
  
}



//MyConfigReplyFrame//

bool MyConfigReplyFrame::ok() const
{
  return (m_data == 0xFF);
}

bool MyConfigReplyFrame::failed() const
{
  return (m_data == 0x00);
}


