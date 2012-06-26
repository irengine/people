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


//MyQueryDevIDFrame//

MyQueryDevIDFrame::MyQueryDevIDFrame(): MyBaseReqFrame(g_dev_id, 0xCF)
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

}
 
void MyApp::loop()
{
  get_dev_id();
  unsigned char status;
  check_status(status);
  set_mode1(2); //3: online 2: offline
  set_mode2(1); //1: week; 2 day
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

bool MyApp::do_get_dev_id()
{
  MyQueryDevIDFrame f;
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
  unsigned char t = status;
  for (int i = 0; i < 4; ++ i)
  {
    buff[i] = (t & 0x1 == 1)? '1':'0';
    t >= 1;
  }
  printf("got dev status: %02X %s\n", status, buff);
  return true;
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

bool MyApp::get_dev_id()
{
  if (!do_get_dev_id())
    return do_get_dev_id();
}

bool MyApp::check_status(unsigned char & status)
{
  if (!do_check_status(status))
    return do_check_status(status);
}

bool MyApp::set_mode1(unsigned char mode)
{
  bool ret = do_set_mode1(mode);
  printf("set_mode1: %s\n", ret? "ok": "failed");
  if (!ret)
  {
    ret = do_set_mode1(mode);
    printf("set_mode1: %s\n", ret? "ok": "failed");
    return ret;
  }
}

bool MyApp::set_mode2(unsigned char mode)
{
  bool ret = do_set_mode2(mode);
  printf("set_mode2: %s\n", ret? "ok": "failed");
  if (!ret)
  {
    ret = do_set_mode2(mode);
    printf("set_mode2: %s\n", ret? "ok": "failed");
    return ret;
  }
}


//Application//

int main(int argc, const char * argv[])
{
  if (argc != 2)
  {
    printf("usage: %s port_dev\n", argv[0]);
    return 1;
  }
  MySetTimeFrame m;
  my_dump(m);
  MyApp g_app(argv[1]);
  g_app.loop();
  
  return 0;
}

