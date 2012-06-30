#include <time.h>
#include <string.h>
#include <unistd.h>
#include <fstream>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>

#include "led.h"

unsigned int  CRCtbl[]={                                            
         0x0000,0xC0C1,0xC181,0x0140,0xC301,0x03C0,0x0280,0xC241,
         0xC601,0x06C0,0x0780,0xC741,0x0500,0xC5C1,0xC481,0x0440,
         0xCC01,0x0CC0,0x0D80,0xCD41,0x0F00,0xCFC1,0xCE81,0x0E40,
         0x0A00,0xCAC1,0xCB81,0x0B40,0xC901,0x09C0,0x0880,0xC841,
         0xD801,0x18C0,0x1980,0xD941,0x1B00,0xDBC1,0xDA81,0x1A40,
         0x1E00,0xDEC1,0xDF81,0x1F40,0xDD01,0x1DC0,0x1C80,0xDC41,
         0x1400,0xD4C1,0xD581,0x1540,0xD701,0x17C0,0x1680,0xD641,
         0xD201,0x12C0,0x1380,0xD341,0x1100,0xD1C1,0xD081,0x1040,
         0xF001,0x30C0,0x3180,0xF141,0x3300,0xF3C1,0xF281,0x3240,
         0x3600,0xF6C1,0xF781,0x3740,0xF501,0x35C0,0x3480,0xF441,
         0x3C00,0xFCC1,0xFD81,0x3D40,0xFF01,0x3FC0,0x3E80,0xFE41,
         0xFA01,0x3AC0,0x3B80,0xFB41,0x3900,0xF9C1,0xF881,0x3840,
         0x2800,0xE8C1,0xE981,0x2940,0xEB01,0x2BC0,0x2A80,0xEA41,
         0xEE01,0x2EC0,0x2F80,0xEF41,0x2D00,0xEDC1,0xEC81,0x2C40,
         0xE401,0x24C0,0x2580,0xE541,0x2700,0xE7C1,0xE681,0x2640,
         0x2200,0xE2C1,0xE381,0x2340,0xE101,0x21C0,0x2080,0xE041,
         0xA001,0x60C0,0x6180,0xA141,0x6300,0xA3C1,0xA281,0x6240,
         0x6600,0xA6C1,0xA781,0x6740,0xA501,0x65C0,0x6480,0xA441,
         0x6C00,0xACC1,0xAD81,0x6D40,0xAF01,0x6FC0,0x6E80,0xAE41,
         0xAA01,0x6AC0,0x6B80,0xAB41,0x6900,0xA9C1,0xA881,0x6840,
         0x7800,0xB8C1,0xB981,0x7940,0xBB01,0x7BC0,0x7A80,0xBA41,
         0xBE01,0x7EC0,0x7F80,0xBF41,0x7D00,0xBDC1,0xBC81,0x7C40,
         0xB401,0x74C0,0x7580,0xB541,0x7700,0xB7C1,0xB681,0x7640,
         0x7200,0xB2C1,0xB381,0x7340,0xB101,0x71C0,0x7080,0xB041,
         0x5000,0x90C1,0x9181,0x5140,0x9301,0x53C0,0x5280,0x9241,
         0x9601,0x56C0,0x5780,0x9741,0x5500,0x95C1,0x9481,0x5440,
         0x9C01,0x5CC0,0x5D80,0x9D41,0x5F00,0x9FC1,0x9E81,0x5E40,
         0x5A00,0x9AC1,0x9B81,0x5B40,0x9901,0x59C0,0x5880,0x9841,
         0x8801,0x48C0,0x4980,0x8941,0x4B00,0x8BC1,0x8A81,0x4A40,
         0x4E00,0x8EC1,0x8F81,0x4F40,0x8D01,0x4DC0,0x4C80,0x8C41,
         0x4400,0x84C1,0x8581,0x4540,0x8701,0x47C0,0x4680,0x8641,
         0x8201,0x42C0,0x4380,0x8341,0x4100,0x81C1,0x8081,0x4040
         };

unsigned int myCRC16(const unsigned char * data, unsigned int len)
{
  unsigned int i; 
  unsigned int result = 0;

  for (i = 0; i < len; ++i)
  {
    if (*(data + i))
    {
      for (i = 0; i < len; ++i)
        result = ((unsigned int)result >> 8) ^ CRCtbl[(result ^ *(data + i)) & 0xFF];
    }
  }
  if (!result)
    result = 0xFFFF;
  return result;
}

static unsigned char char_from_hex(char c, char d)
{
  unsigned char result;
  if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
    return 0;
  if (!((d >= '0' && d <= '9') || (d >= 'a' && d <= 'f')))
    return 0;
  if (c >= '0' && c <= '9')
    result = c - '0';
  else
    result = c - 'a' + 10;
  result = result << 4;
  if (d >= '0' && d <= '9')
    result += d - '0';
  else
    result += d - 'a' + 10;
  return result;
}

static std::string gbk_from_hex(const std::string & src)
{
  if (src.length() < 2)
    return "";
  int len = src.length();
  if (len % 2 != 0)
    len --;
  unsigned char * buff = new unsigned char[len / 2];
  unsigned char m;
  const char * ptr = src.c_str();
  buff[0] = 0;
  std::string result;
  for (int i = 0; i < len / 2; ++i)
  {
    m = char_from_hex(*ptr, *(ptr + 1));
    if (m == 0)
    {
      buff[i] = 0;
      result = (const char*)buff;
      delete [] buff;
      return result;
    }
    buff[i] = m;
    ptr += 2;
  }

  buff[len / 2] = 0;
  result = (const char*)buff;
  delete [] buff;
  return result;
}


//myControlReqFrame//

myControlReqFrame::myControlReqFrame()
{
  m_head = 0xA55A;
  m_length = sizeof(myControlReqFrame);
  m_length = swap_byte(m_length);  
  m_type = 0x55;
  m_time_setting = 0;
  m_time_display_period = 0;
  m_line_2_prop = 0;
  m_line_3_prop = 0;
  m_line_4_prop = 0;
  m_port_error_time = 0;
  m_move_speed = 0x2; //0x01 slow, 0x2 medium; 0x3 fast
  m_brightness = 0x20;
  
  time_t now = time(NULL);
  struct tm _tm;
  localtime_r(&now, &_tm);
  m_year = _tm.tm_year % 100;
  m_month = _tm.tm_mon + 1;
  m_day = _tm.tm_mday;
  m_hour = _tm.tm_hour;
  m_minute = _tm.tm_min;
  m_second = _tm.tm_sec % 60;
}

void myControlReqFrame::gen_crc16()
{
  m_crc16 = myCRC16((const unsigned char *)&m_head, sizeof(myControlReqFrame) - sizeof(unsigned short));
}

//myControlReplyFrame//

bool myControlReplyFrame::valid()
{
  return (m_head == const_in_lead && m_length == sizeof(myControlReplyFrame) && m_type == 0xC5);
}


//myStaticDisplayReqFrame//

myStaticDisplayReqFrame::myStaticDisplayReqFrame()
{
  m_head = const_out_lead;
  m_length = 0;
  m_type = 0x52;
  m_line_no = 1;
  m_display_mode = 0x01;
  m_info_no = 0;
  m_info_id = 0;
  for (int i = 0; i < 6; ++ i)
    m_time_expire[i] = 0;
  m_info_length = 0;
}

void myStaticDisplayReqFrame::gen_crc16()
{
  int len = length();
  *(unsigned short*)(data() + len - 2) = myCRC16((const unsigned char *)&m_head, len - 2);
}

void myStaticDisplayReqFrame::setinfo(const char * txt)
{
  if (!txt || !*txt)
    txt = " ";
  int len = strlen(txt);
  if (len > 384)
    len = 384;
  memcpy(m_data, txt, len);  
  m_info_length = len;
  m_info_length = swap_byte(m_info_length);  
  m_length = length();    
  m_length = swap_byte(m_length);    
}


//myStaticDisplayReplyFrame//

myStaticDisplayReplyFrame::myStaticDisplayReplyFrame()
{
  memset(data(), length(), 0);
}

void myStaticDisplayReplyFrame::gen_crc16()
{

}

bool myStaticDisplayReplyFrame::valid() const
{
  return (m_head == const_in_lead && m_type == 0xC2 && m_length == length() && m_info_id == 0);
}


//myInfoQueryFrame//

myInfoQueryFrame::myInfoQueryFrame()
{
  m_head = const_out_lead;
  m_length = sizeof(myInfoQueryFrame);
  m_length = swap_byte(m_length);
  m_type = 0x53;
  m_line_no = 1;
}
 
void myInfoQueryFrame::gen_crc16()
{
  int len = length();
  *(unsigned short*)(data() + len - 2) = myCRC16((const unsigned char *)&m_head, len - 2);
}


//MyApp//

MyApp::MyApp(const char * dev): MyBaseApp(dev)
{
  m_mark1 = 0xA5;
  m_mark2 = 0x5A;
}

const char * MyApp::data_file() const
{
  return "/tmp/daily/led/led.txt";
}

bool MyApp::setup_port()
{
  return ::setup_port(get_fd(), 19200, 8, 'N', 1) != -1;
}

void MyApp::loop()
{
  led_control(0x2, 0x3);
  set_text("");
  display_text();

  while(true)
  {
    sleep(6);
    if (!get_fstate())
      continue;
    sleep(4);
    if (!read_text())
      continue;
    if (!display_text())
    {
      sleep(10);
      display_text();
    }
/*    if (has_text())
    {
      display_text();
      led_control(0x02, 0x01);
    }
    else
      led_control(0x03, 0x02);
*/
  }

/*unsigned char txt[4] = { 0xba, 0xba, 0xd7, 0xd6};
  set_text((const char*)txt);
  display_text();
*/  
}

bool MyApp::query_info()
{
  myInfoQueryFrame req;
  req.gen_crc16();
  if (!write_port(req.data(), req.length()))
  {
    unix_print_error("write of info query frame failed");
    return false;
  }
  myInfoReplyFrame reply;
  if (!read_port(reply.data(), reply.length()))
    return false;
  printf("read reply ok\n");
  return true;  
}

bool MyApp::display_text()
{
  if (!check_open())
    return false;

  fprintf(stderr, "start display text\n");
  std::string s = gbk_from_hex(get_value());
  myStaticDisplayReqFrame req;
  req.setinfo(s.c_str());
  req.gen_crc16();
  if (!write_port(req.data(), req.length()))
  {
    unix_print_error("write of static frame failed");
    return false;
  }
  
  myStaticDisplayReplyFrame reply;
  if (!read_port(reply.data(), reply.length()))
    return false;
  bool ret = reply.valid();
  my_dump_base(reply.data(), reply.length());
  if (!ret)
    fprintf(stderr, "static frame reply error\n");
  return ret;
}

bool MyApp::led_control(unsigned char line_1_prop, unsigned char op)
{
  if (!check_open())
    return false;
    
  fprintf(stderr, "start led control(%d, %d)\n", line_1_prop, op);
    
  myControlReqFrame req;
  req.m_line_1_prop = line_1_prop;
  req.m_op = op;
  req.gen_crc16();
  if (!write_port(req.data(), req.length()))
  {
    unix_print_error("write of control frame failed");
    return false;
  }
  
  myControlReplyFrame reply;
  if (!read_port(reply.data(), reply.length()))
    return false;
  bool ret = reply.valid();
  my_dump_base(reply.data(), reply.length());
  if (!ret)
    fprintf(stderr, "control frame reply error\n");
  return ret;
}


//application//

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

