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

class MyClientVersionCheckRequest: public MyDataPacketHeader
{
public:
  u_int8_t client_version_major;
  u_int8_t client_version_minor;
  u_int8_t server_id;
  MyClientID client_id;

  void validate_data()
  {
    client_id.fix_data();
  }

};

class MyIpVerRequest: public MyDataPacketHeader
{
public:
  u_int8_t client_version_major;
  u_int8_t client_version_minor;
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

bool my_dph_validate_base(const MyDataPacketHeader * header);
bool my_dph_validate_file_md5_list(const MyDataPacketHeader * header);
bool my_dph_validate_ftp_file(const MyDataPacketHeader * header);
bool my_dph_validate_plc_alarm(const MyDataPacketHeader * header);
bool my_dph_validate_load_balance_req(const MyDataPacketHeader * header);
bool my_dph_validate_client_version_check_reply(const MyDataPacketHeader * header);
bool my_dph_validate_client_version_check_req(const MyDataPacketHeader * header);
#define my_dph_validate_have_dist_task my_dph_validate_base
#define my_dph_validate_heart_beat my_dph_validate_base

class MyLoadBalanceRequest: public MyDataPacketHeader
{
public:
  enum { IP_ADDR_LENGTH = INET_ADDRSTRLEN };
  char ip_addr[IP_ADDR_LENGTH];
  int32_t clients_connected;

  void set_ip_addr(const char * s)
  {
    if (unlikely(!s || !*s))
      ip_addr[0] = 0;
    else
    {
      ACE_OS::memset(ip_addr, 0, MyLoadBalanceRequest::IP_ADDR_LENGTH); //noise muffler
      ACE_OS::strsncpy(ip_addr, s, MyLoadBalanceRequest::IP_ADDR_LENGTH);
    }
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
