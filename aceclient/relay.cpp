#include <time.h>
#include <string.h>
#include <unistd.h>
#include <fstream>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>

#include "relay.h"

unsigned char g_dev_id = 1;

//MyBaseFrame//

MyBaseFrame::MyBaseFrame()
{
  m_lead_1 = 0xAA;
  m_lead_2 = 0x55;  
}

bool MyBaseFrame::check_lead() const
{
  return (m_lead_1 == 0xAA && m_lead_2 == 0x55);
}

//MyBaseReqFrame//

MyBaseReqFrame::MyBaseReqFrame(): MyBaseFrame()
{

}
 
MyBaseReqFrame::MyBaseReqFrame(unsigned char dev_id, unsigned char command): MyBaseFrame()
{
  m_dev_id = dev_id;
  m_command = command;
}


//MySetTimeFrame//

MySetTimeFrame::MySetTimeFrame(): MyBaseReqFrame(g_dev_id, 0xFC)
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
  m_weekday = _tm.tm_wday == 0? 7: _tm.tm_wday;
}


//MyCheckStatusFrame//

MyCheckStatusFrame::MyCheckStatusFrame(): MyBaseReqFrame(g_dev_id, 0xC1)
{

}


//MySetStatusFrame//

MySetStatusFrame::MySetStatusFrame(unsigned char index, unsigned char status): MyBaseReqFrame(g_dev_id, 0xFD)
{
  m_index = index;
  m_status = status;
}


//MyQueryDevTimeFrame//

MyQueryDevTimeFrame::MyQueryDevTimeFrame(): MyBaseReqFrame(g_dev_id, 0xC4)
{

}


//MyQueryDevIDFrame//

MyQueryDevIDFrame::MyQueryDevIDFrame(unsigned char dev_id): MyBaseReqFrame(dev_id, 0xCF)
{

}


//MySetMode1Frame//

MySetMode1Frame::MySetMode1Frame(unsigned char mode): MyBaseReqFrame(g_dev_id, 0xFB)
{
  m_mode = mode;
}


//MyOffTimeFrame//

MyOffTimeFrame::MyOffTimeFrame(): MyBaseReqFrame(g_dev_id, 0xEA)
{
  m_second = 0;
  m_day = 0;
}


//MySetMode2Frame//

MySetMode2Frame::MySetMode2Frame(unsigned char mode): MyBaseReqFrame(g_dev_id, 0xFE)
{
  m_mode = mode;
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


//MyApp//

MyApp::MyApp(const char * dev): MyBaseApp(dev)
{
  m_mark1 = 0xAA;
  m_mark2 = 0x55;
}
 
void MyApp::loop()
{
  if (!get_dev_id())
  {
    fprintf(stderr, "Fatal: can not get device id\n");
    return;
  }
  MySetTimeFrame stime;
  query_time(stime);
//  sync_time();
  unsigned char status;
  check_status(status);
  set_mode1(2); //3: online 2: offline  
  set_mode2(1); //1: week; 2 day
  clear_offtime();
  onofftime(9, 31, 20, 24);    
  check_status(status);
}

const char * MyApp::data_file() const
{
  return "/tmp/daily/pctime.txt";
}

bool MyApp::has_text() const
{
  if (!MyBaseApp::has_text())
    return false;
  const std::string & s = get_value();
  if (s.length() != 10)
    return false;
  if (s[0] != '*')
    return false;
  for (int i = 1; i <= 9; ++i)
    if (s[i] > '9' || s[i] < '0')
      return false;
  return true;
}

bool MyApp::setup_port()
{
  return ::setup_port(get_fd(), 9600, 8, 'N', 1) != -1;
}

bool MyApp::do_get_dev_id(unsigned char c)
{
  MyQueryDevIDFrame f(c);
//  my_dump(f);
  if (!write_command(f))
    return false;
  MyReplyDevIDFrame ff;
  if (!read_reply(ff))
    return false;
  g_dev_id = ff.m_answer_id;
  printf("got dev id: %d\n", ff.m_answer_id);
  return true;
}

bool MyApp::do_check_status(unsigned char & status)
{
  MyCheckStatusFrame req;
  if (!write_command(req))
    return false;
  MyCheckStatusReplyFrame reply;
  if (!read_reply(reply))
    return false;
  status = reply.m_status;
  char buff[5];
  buff[4] = 0;
  unsigned char t = status & 0x0F;
  for (int i = 0; i < 4; ++ i)
  {
    buff[i] = ((t & 0x1) == 1)? '1':'0';
    t = t >> 1;
  }
  printf("got dev status: %02X %s\n", status, buff);
  return true;
}

bool MyApp::do_set_status(unsigned char idx, bool on)
{
  if (idx <= 0 || idx >= 5)
    return false;
  unsigned char status = on? 0xFF:0;
  MySetStatusFrame req(idx, status);
  if (!write_command(req))
    return false;
  MyConfigReplyFrame reply;
  if (!read_reply(reply))
    return false;
  if (!reply.check_lead())
    return false;
  return reply.ok();
}

bool MyApp::do_set_mode1(unsigned char mode)
{
  MySetMode1Frame req(mode);
  if (!write_command(req))
    return false;
  MyConfigReplyFrame reply;
  if (!read_reply(reply))
    return false;
  if (!reply.check_lead())
    return false;
  return reply.ok();
}

bool MyApp::do_set_mode2(unsigned char mode)
{
  MySetMode2Frame req(mode);
  if (!write_command(req))
    return false;
  MyConfigReplyFrame reply;
  if (!read_reply(reply))
    return false;
  if (!reply.check_lead())
    return false;
  return reply.ok();
}

bool MyApp::do_sync_time()
{
  MySetTimeFrame req;
  if (!write_command(req))
    return false;
  MyConfigReplyFrame reply;
  if (!read_reply(reply))
    return false;
  if (!reply.check_lead())
    return false;
  return reply.ok();
}

bool MyApp::do_clear_offtime(unsigned char idx)
{
  MyOffTimeFrame req;
  req.m_index = idx;
  req.m_minute = 0;
  req.m_hour = 0;
  req.m_weekday = 0;
  req.m_status = 0;
//  printf("debug_offtime: index=%d, hour=%d, minute=%d, wday=%d, status=%02X\n", 
//         req.m_index, req.m_hour, req.m_minute, req.m_weekday, req.m_status);
//  my_dump(req);
  if (!write_command(req))
    return false;
  MyConfigReplyFrame reply;
  if (!read_reply(reply))
    return false;
  if (!reply.check_lead())
    return false;
  return reply.ok();
}

bool MyApp::do_set_offtime(unsigned char index, unsigned char day, unsigned char hour, unsigned char minute, bool on)
{
  int xday = day % 7;
  if (xday == 0)
    xday = 7;
  MyOffTimeFrame req;
  req.m_index = index;
  req.m_second = index;
  req.m_minute = minute;
  req.m_hour = hour;
  req.m_weekday = xday;
  req.m_status = on? 0xF7: 0;
//  printf("debug_offtime: index=%d, hour=%d, minute=%d, wday=%d, status=%02X\n", 
//         req.m_index, req.m_hour, req.m_minute, req.m_weekday, req.m_status);
//  my_dump(req);
  if (!write_command(req))
    return false;
  MyConfigReplyFrame reply;
  if (!read_reply(reply))
    return false;
  if (!reply.check_lead())
    return false;
  return reply.ok();
}

bool MyApp::do_offtime(unsigned char day, unsigned char hour, unsigned char minute)
{
  return do_set_offtime(8, day, hour, minute, false);
  /*
  time_t now = time(NULL);
  struct tm _tm;
  localtime_r(&now, &_tm);
  _tm.tm_hour = hour;
  _tm.tm_min = minute;
  time_t target = mktime(&_tm);
  if (target > now + 2 * 60)
    return do_set_offtime(day, hour, minute, false);
  MySetTimeFrame stime;
  unsigned char xhour, xminute, yhour, yminute;
  if (query_time(stime))
  {
    xhour = stime.m_hour;
    xminute = stime.m_minute;
  } else
  {
    now = time(NULL);
    localtime_r(&now, &_tm);
    xhour = _tm.tm_hour;
    xminute = _tm.tm_min;
  }
  
  yminute = xminute + 2;
  yhour = xhour;
  if (yminute >= 60)
  {
    yminute -= 60;
    yhour ++;
    if (yhour >= 24)
    {
      yhour = 0;
      day ++;
      if (day >= 7)
        day = 0;
    }
  }
  
  return do_set_offtime(day, yhour, yminute, false);
  */
}

bool MyApp::offtime(unsigned char day, unsigned char hour, unsigned char minute)
{
  bool ret = do_offtime(day, hour, minute);
  printf("do_offtime: %s\n", ret? "ok":"failed");
  if (!ret)
  {
    ret = do_offtime(day, hour, minute);
    printf("do_offtime: %s\n", ret? "ok":"failed");  
  }
  return ret;
}

bool MyApp::onofftime(unsigned char ohour, unsigned char ominute, unsigned char fhour, unsigned char fminute)
{
  time_t now = time(NULL);
  struct tm _tm;
  localtime_r(&now, &_tm);
  int day = _tm.tm_wday? _tm.tm_wday: 7;
  bool ret, xret = true;
  
  printf("day(%d):\n", day);

  ret = do_set_offtime(day, day, 0, 1, true);
  printf("do_set_offtime(%d): %s\n", day, ret? "ok":"failed");
  if (!ret)
  {
    ret = do_set_offtime(day, day, 0, 1, true);
    printf("do_set_offtime(%d): %s\n", day, ret? "ok":"failed");
  }
  if (!ret)
    xret = false;
    
  int j;
  for (int i = 1; i <= 8; ++ i)
  {
    if (i != day && i != day + 1)
    {
      j = (i < day? i: i-1);
      ret = do_set_offtime(i, j, ohour, ominute, true);
      printf("do_set_offtime(%d): %s\n", i, ret? "ok":"failed");
      if (!ret)
      {
		    ret = do_set_offtime(i, j, ohour, ominute, true);
		    printf("do_set_offtime(%d): %s\n", i, ret? "ok":"failed");
      }
      if (!ret)
        xret = false;
    }
  }

  ret = do_set_offtime(day + 1, day, fhour, fminute, false);
  printf("do_set_offtime(%d): %s\n", day, ret? "ok":"failed");
  if (!ret)
  {
    ret = do_set_offtime(day + 1, day, fhour, fminute, false);
    printf("do_set_offtime(%d): %s\n", day, ret? "ok":"failed");
  }
  if (!ret)
    xret = false;

  sync_time();
  
//  if (!offtime(day, fhour, fminute))
//    xret = false;
    
  printf("do_set_offtime(all): %s\n", xret? "ok":"failed");
  return xret;
}

bool MyApp::do_query_time(MySetTimeFrame & reply)
{
  MyQueryDevTimeFrame req;
  if (!write_command(req))
    return false;
  if (!read_reply(reply))
    return false;
  if (!reply.check_lead())
    return false;
  printf("got dev time: %d/%d/%d w(%d) %d:%d:%d\n", 
          reply.m_year, reply.m_month, reply.m_day, reply.m_weekday, 
          reply.m_hour, reply.m_minute, reply.m_second);  
  return true;  
}

bool MyApp::get_dev_id()
{
  if (!do_get_dev_id(0x12))
    return do_get_dev_id(0x13);
  return true;  
}

bool MyApp::check_status(unsigned char & status)
{
  if (!do_check_status(status))
    return do_check_status(status);
  return true;  
}

bool MyApp::set_mode1(unsigned char mode)
{
  bool ret = do_set_mode1(mode);
  printf("set_mode1(%d): %s\n", mode, ret? "ok": "failed");
  if (!ret)
  {
    ret = do_set_mode1(mode);
    printf("set_mode1(%d): %s\n", mode, ret? "ok": "failed");
    return ret;
  }
  return true;
}

bool MyApp::set_mode2(unsigned char mode)
{
  bool ret = do_set_mode2(mode);
  printf("set_mode2(%d): %s\n", mode, ret? "ok": "failed");
  if (!ret)
  {
    ret = do_set_mode2(mode);
    printf("set_mode2(%d): %s\n", mode, ret? "ok": "failed");
    return ret;
  }
  return true;
}

bool MyApp::sync_time()
{
  bool ret = do_sync_time();
  printf("sync_time: %s\n", ret? "ok": "failed");
  if (!ret)
  {
    ret = do_sync_time();
    printf("set_time: %s\n", ret? "ok": "failed");
    return ret;
  }
  return true;
}

bool MyApp::set_status(unsigned char idx, bool on)
{
  bool ret = do_set_status(idx, on);
  printf("set_status: %s\n", ret? "ok": "failed");
  if (!ret)
  {
    ret = do_set_status(idx, on);
    printf("set_status: %s\n", ret? "ok": "failed");
    return ret;
  }
  return true;
}

bool MyApp::clear_offtime()
{
  bool ret, xret = true;;
  for (int i = 9; i <= 20; ++ i)
  {
		ret = do_clear_offtime(i);
		printf("clear_offtime(%d): %s\n", i, ret? "ok": "failed");
		if (!ret)
		{
		  ret = do_clear_offtime(i);
		  printf("clear_offtime(%d): %s\n", i, ret? "ok": "failed");
		}
    if (!ret)
      xret = false;
  }
  printf("clear_offtime(all): %s\n", xret? "ok": "failed");  
  return xret;
}

bool MyApp::query_time(MySetTimeFrame & reply)
{
  bool ret = do_query_time(reply);
  printf("query_time: %s\n", ret? "ok": "failed");
  if (!ret)
  {
    ret = do_query_time(reply);
    printf("query_time: %s\n", ret? "ok": "failed");
    return ret;
  }
  return true;
};


//Application//

int main(int argc, const char * argv[])
{

  if (argc != 2)
  {
    printf("usage: %s port_dev\n", argv[0]);
    return 1;
  }
  MyApp g_app(argv[1]);
  g_app.loop();
  return 0;
}

