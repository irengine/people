/*
 * datapacket.h
 *
 *  Created on: Dec 30, 2011
 *      Author: root
 */

#ifndef DATAPACKET_H_
#define DATAPACKET_H_

#include <sys/types.h>
#include <stddef.h>
#include <ace/OS_NS_string.h>
#include <ace/INET_Addr.h>

#include "common.h"

#pragma pack(push, 1)

class MyClientID
{
public:
  union ClientID
  {
    char    as_string[];
    int64_t as_long[3];
  }client_id;

  enum
  {
    ID_LENGTH_AS_INT64 = sizeof(client_id)/sizeof(int64_t),
    ID_LENGTH_AS_STRING = sizeof(client_id)/sizeof(char)
  };

#define client_id_value_i client_id.as_long
#define client_id_value_s client_id.as_string

  MyClientID()
  {
    ACE_OS::memset((void*)client_id_value_i, 0, ID_LENGTH_AS_STRING);
  }

  MyClientID(const char * s)
  {
    ACE_OS::memset((void*)client_id_value_i, 0, ID_LENGTH_AS_STRING);

    if (!s || !*s)
      return;
    while(*s == ' ')
      ++s;
    ACE_OS::strsncpy(client_id_value_s, s, ID_LENGTH_AS_STRING);
  }

  void fix_data()
  {
    client_id_value_s[ID_LENGTH_AS_STRING - 1] = 0;
  }

  MyClientID & operator = (const char * s)
  {
    ACE_OS::memset((void*)client_id_value_i, 0, ID_LENGTH_AS_STRING);

    if (!s || !*s)
      return *this;
    while(*s == ' ')
      ++s;
    ACE_OS::strsncpy(client_id_value_s, s, ID_LENGTH_AS_STRING);
    return *this;
  }

  MyClientID & operator = (const MyClientID & rhs)
  {
    if (&rhs == this)
      return *this;
    ACE_OS::memcpy(client_id.as_string, rhs.client_id.as_string, ID_LENGTH_AS_STRING);
    client_id_value_s[ID_LENGTH_AS_STRING - 1] = 0;
    return *this;
  }

  const char * as_string() const
  {
    return client_id_value_s;
  }

  bool is_null() const
  {
    return (client_id_value_s[0] == 0);
  }

  bool operator < (const MyClientID & rhs) const
  {
    for (int i = 0; i < ID_LENGTH_AS_INT64; ++i)
    {
      if (client_id_value_i[i] < rhs.client_id_value_i[i])
        return true;
      if (client_id_value_i[i] > rhs.client_id_value_i[i])
        return false;
    }
    return false;
  }

  bool operator == (const MyClientID & rhs) const
  {
    for (int i = 0; i < ID_LENGTH_AS_INT64; ++i)
    {
      if (client_id_value_i[i] != rhs.client_id_value_i[i])
        return false;
    }
    return true;
  }

  bool operator != (const MyClientID & rhs) const
  {
    return ! operator == (rhs);
  }

  void trim_tail_space()
  {
    char * ptr = client_id_value_s;
    for (int i = ID_LENGTH_AS_STRING - 1; i >= 0; --i)
    {
      if (ptr[i] == 0)
        continue;
      else if (ptr[i] == ' ')
        ptr[i] = 0;
      else
        break;
    }
  }

};


#ifndef Null_Item
  #define Null_Item "!"
#endif
//every packet commute between server and clients at least has this head
class MyDataPacketHeader
{
public:
  enum { DATAPACKET_MAGIC = 0x80089397 };
  enum { ITEM_SEPARATOR = '*', MIDDLE_SEPARATOR = '?', FINISH_SEPARATOR = ':' };
  enum { NULL_ITEM_LENGTH = 1 };

  enum COMMAND
  {
    CMD_NULL = 0,
    CMD_HEARTBEAT_PING,
    CMD_CLIENT_VERSION_CHECK_REQ,
    CMD_CLIENT_VERSION_CHECK_REPLY,
    CMD_LOAD_BALANCE_REQ,
    CMD_SERVER_FILE_MD5_LIST,
    CMD_HAVE_DIST_TASK,
    CMD_FTP_FILE,
    CMD_IP_VER_REQ,
    CMD_UI_CLICK,
    CMD_PC_ON_OFF,
    CMD_HARDWARE_ALARM,
    CMD_END,
    CMD_DISCONNECT_INTERNAL
  };
  int32_t length;
  u_int32_t magic;
  int16_t command;
};

class MyDataPacketExt: public MyDataPacketHeader
{
public:
  char data[0];

  bool guard();
};


//the ultimate root class for all data packets Proc
class MyDataPacketBaseProc
{
public:
  MyDataPacketBaseProc(const char * _data = NULL): m_data((MyDataPacketHeader *)_data)
  {}
  virtual ~MyDataPacketBaseProc()
  {
  }
  virtual void init_header()
  {
    m_data->magic = MyDataPacketHeader::DATAPACKET_MAGIC;
  }
  virtual bool validate_header() const
  {
    return m_data->magic == MyDataPacketHeader::DATAPACKET_MAGIC;
  }
  virtual bool validate_data() const
  {
    return true;
  }
  void attach(const char * _data)
  //renamed just because gcc 4.4 is not smart enough to distinguish this
  //from the sub-class override and overload version
  //void data(char * _data)
  {
    m_data = (MyDataPacketHeader *)_data;
  }
  virtual MyDataPacketHeader * data() const
  {
    return m_data;
  }

protected:
  MyDataPacketHeader * m_data;
};

class MyHaveDistTaskProc: public MyDataPacketBaseProc
{
public:
  virtual void init_header()
  {
    MyDataPacketBaseProc::init_header();
    m_data->length = sizeof(MyDataPacketHeader);
    m_data->command = MyDataPacketHeader::CMD_HAVE_DIST_TASK;
  };

  virtual bool validate_header() const
  {
    if (!MyDataPacketBaseProc::validate_header())
      return false;
    return (m_data->length == sizeof(MyDataPacketHeader) &&
            m_data->command == MyDataPacketHeader::CMD_HAVE_DIST_TASK);
  }
};


//Heart Beat Packet is just an alias to the Header packet
class MyHeartBeatPingProc: public MyDataPacketBaseProc
{
public:
  virtual void init_header()
  {
    MyDataPacketBaseProc::init_header();
    m_data->length = sizeof(MyDataPacketHeader);
    m_data->command = MyDataPacketHeader::CMD_HEARTBEAT_PING;
  };

  virtual bool validate_header() const
  {
    if (!MyDataPacketBaseProc::validate_header())
      return false;
    return (m_data->length == sizeof(MyDataPacketHeader) &&
            m_data->command == MyDataPacketHeader::CMD_HEARTBEAT_PING);
  }
};


class MyClientVersionCheckRequest: public MyDataPacketHeader
{
public:
  u_int8_t client_version_major;
  u_int8_t client_version_minor;
  u_int8_t server_id;
  MyClientID client_id;
};

class MyIpVerRequest: public MyDataPacketHeader
{
public:
  u_int8_t client_version_major;
  u_int8_t client_version_minor;
};


class MyClientVersionCheckRequestProc: public MyDataPacketBaseProc
{
public:
  virtual void init_header()
  {
    MyDataPacketBaseProc::init_header();
    m_data->length = sizeof(MyClientVersionCheckRequest);
    m_data->command = MyDataPacketHeader::CMD_CLIENT_VERSION_CHECK_REQ;
  };

  virtual bool validate_header() const
  {
    if (!MyDataPacketBaseProc::validate_header())
      return false;
    return (m_data->length == sizeof(MyClientVersionCheckRequest) &&
            m_data->command == MyDataPacketHeader::CMD_CLIENT_VERSION_CHECK_REQ);
  }

  virtual MyClientVersionCheckRequest * data() const
  {
    return (MyClientVersionCheckRequest *)m_data;
  }

  virtual bool validate_data() const
  {
    data()->client_id.fix_data();
    return true;
  }
};


class MyClientVersionCheckReply: public MyDataPacketHeader
{
public:
  enum REPLY_CODE
  {
    VER_OK = 1,
    VER_OK_CAN_UPGRADE, //todo upgrade hint
    VER_MISMATCH,
    VER_ACCESS_DENIED,
    VER_SERVER_BUSY,
    VER_SERVER_LIST
  };
  enum { MAX_REPLY_DATA_LENGTH = 4096 };
  int8_t reply_code;
  char data[0]; //placeholder
};

class MyClientVersionCheckReplyProc: public MyDataPacketBaseProc
{
public:
  virtual void init_header(int extra_length = 0)
  {
    MyDataPacketBaseProc::init_header();
    m_data->length = sizeof(MyClientVersionCheckReply) + extra_length;
    m_data->command = MyDataPacketHeader::CMD_CLIENT_VERSION_CHECK_REPLY;
  };

  virtual bool validate_header() const
  {
    MyClientVersionCheckReply * pData = data();
    if (!MyDataPacketBaseProc::validate_header())
      return false;
    if (pData->command != MyDataPacketHeader::CMD_CLIENT_VERSION_CHECK_REPLY)
      return false;
    return (pData->length >= (int)sizeof(MyClientVersionCheckReply)) &&
        (pData->length <= (int)sizeof(MyClientVersionCheckReply) + MyClientVersionCheckReply::MAX_REPLY_DATA_LENGTH);
  }

  virtual bool validate_data() const
  {
    MyClientVersionCheckReply * pData = data();
    return (pData->reply_code >= MyClientVersionCheckReply::VER_OK &&
        pData->reply_code <= MyClientVersionCheckReply::VER_SERVER_LIST);
  }

  virtual MyClientVersionCheckReply * data() const
  {
    return (MyClientVersionCheckReply *)m_data;
  }

};

class MyServerFileMD5List: public MyDataPacketHeader
{
public:
  char data[0];
};

class MyServerFileMD5ListProc: public MyDataPacketBaseProc
{
public:
  virtual void init_header()
  {
    MyDataPacketBaseProc::init_header();
    m_data->command = MyDataPacketHeader::CMD_SERVER_FILE_MD5_LIST;
  };

  virtual bool validate_header() const
  {
    if (!MyDataPacketBaseProc::validate_header())
      return false;
    return (m_data->length > (int32_t)sizeof(MyDataPacketHeader) &&
            m_data->command == MyDataPacketHeader::CMD_SERVER_FILE_MD5_LIST);
  }

  virtual MyServerFileMD5List * data() const
  {
    return (MyServerFileMD5List *)m_data;
  }
};


class MyLoadBalanceRequest: public MyDataPacketHeader
{
public:
  enum { IP_ADDR_LENGTH = INET_ADDRSTRLEN };
  char ip_addr[IP_ADDR_LENGTH];
  int32_t clients_connected;
};

class MyLoadBalanceRequestProc: public MyDataPacketBaseProc
{
public:
  virtual void init_header()
  {
    MyDataPacketBaseProc::init_header();
    m_data->command = MyDataPacketHeader::CMD_LOAD_BALANCE_REQ;
    m_data->length = (int32_t)sizeof(MyLoadBalanceRequest);
  };

  virtual bool validate_header() const
  {
    if (!MyDataPacketBaseProc::validate_header())
      return false;
    return (m_data->length == (int32_t)sizeof(MyLoadBalanceRequest) &&
            m_data->command == MyDataPacketHeader::CMD_LOAD_BALANCE_REQ);
  }

  virtual MyLoadBalanceRequest * data() const
  {
    return (MyLoadBalanceRequest *)m_data;
  }

  void ip_addr(const char * s)
  {
    if (unlikely(!m_data))
      return;
    if (unlikely(!s || !*s))
      data()->ip_addr[0] = 0;
    else
    {
      ACE_OS::memset(data()->ip_addr, 0, MyLoadBalanceRequest::IP_ADDR_LENGTH); //noise muffler
      ACE_OS::strsncpy(data()->ip_addr, s, MyLoadBalanceRequest::IP_ADDR_LENGTH);
    }
  }
};

class MyFtpFile: public MyDataPacketHeader
{
public:
  char data[0];
};


class MyFtpFileProc: public MyDataPacketBaseProc
{
public:
  virtual void init_header()
  {
    MyDataPacketBaseProc::init_header();
    m_data->command = MyDataPacketHeader::CMD_FTP_FILE;
    m_data->length = (int32_t)sizeof(MyLoadBalanceRequest);
  };

  virtual bool validate_header() const
  {
    if (!MyDataPacketBaseProc::validate_header())
      return false;
    return (m_data->length > (int32_t)sizeof(MyFtpFile) && m_data->length < 4096 &&
            m_data->command == MyDataPacketHeader::CMD_FTP_FILE);
  }

  virtual MyFtpFile * data() const
  {
    return (MyFtpFile *)m_data;
  }
};

class MyPLCAlarm: public MyDataPacketHeader
{
public:
  char x;
  char y;
};


class MyBSBasePacket
{
public:
  enum { LEN_SIZE = 8, MAGIC_SIZE = 4, CMD_SIZE = 2, DATA_OFFSET = LEN_SIZE + MAGIC_SIZE + CMD_SIZE };
  enum { BS_PARAMETER_SEPARATOR = '#', BS_PACKET_END_MARK = '$' };

  void packet_len(int _len);
  int  packet_len() const;
  void packet_magic();
  bool check_header() const;
  void packet_cmd(const char * _cmd);
  bool is_cmd(const char * _cmd);
  bool guard();

  char len[LEN_SIZE];
  char magic[4];
  char cmd[2];
  char data[0];
};

#define MY_BS_HEART_BEAT_CMD    "04"
#define MY_BS_ADV_CLICK_CMD     "05"
#define MY_BS_IP_VER_CMD        "01"
#define MY_BS_HARD_MON_CMD      "03"
#define MY_BS_DIST_FEEDBACK_CMD "02"
#define MY_BS_POWERON_LINK_CMD  "07"
#define MY_BS_PATCH_FILE_CMD    "06"

#pragma pack(pop)

#endif /* DATAPACKET_H_ */
