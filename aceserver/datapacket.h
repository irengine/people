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

#include "common.h"

#pragma pack(push, 1)

class MyClientID
{
public:
  union
  {
    char    as_string[];
    int64_t as_long[2];
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
    ACE_OS::memset((void*)&(client_id_value_i), 0, ID_LENGTH_AS_STRING);
  }

  MyClientID(const char * s)
  {
    ACE_OS::memset((void*)&(client_id_value_i), 0, ID_LENGTH_AS_STRING);

    if (!s || !*s)
      return;

    ACE_OS::strsncpy(client_id_value_s, s, ID_LENGTH_AS_STRING);
  }

  MyClientID & operator = (const char * s)
  {
    ACE_OS::memset((void*)&(client_id_value_i), 0, ID_LENGTH_AS_STRING);

    if (!s || !*s)
      return *this;

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

};

//every packet commute between server and clients at least has this head
class MyDataPacketHeader
{
public:
  enum { DATAPACKET_MAGIC = 0x80089397 };
  enum COMMAND
  {
    CMD_NULL = 0,
    CMD_HEARTBEAT_PING,
    CMD_CLIENT_VERSION_CHECK_REQ,
    CMD_CLIENT_VERSION_CHECK_REPLY,
    CMD_LOAD_BALANCE_REQ,
    CMD_END
  };
  int32_t length;
  u_int32_t magic;
  int16_t command;
};

//the ultimate root class for all data packets Proc
class MyDataPacketBaseProc
{
public:
  MyDataPacketBaseProc(const char * _data = NULL): m_data((MyDataPacketHeader *)_data), m_data_owner(m_data == NULL)
  {}
  virtual ~MyDataPacketBaseProc()
  {
    if (m_data_owner && m_data)
      delete m_data;
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
  void attach(const char * _data, bool own_data = false)
  //renamed just because gcc 4.4 is not smart enough to distinguish this
  //from the sub-class override and overload version
  //void data(char * _data, bool own_data = false)
  {
    if (m_data_owner && m_data)
      delete m_data;
    m_data = (MyDataPacketHeader *)_data;
    m_data_owner = own_data;
  }
  virtual MyDataPacketHeader * data() const
  {
    return m_data;
  }
protected:
  MyDataPacketHeader * m_data;
  bool m_data_owner;
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
  int16_t client_version;
  MyClientID client_id;
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
  enum { REPLY_DATA_LENGTH = 40 * 5  };
  enum { SERVER_LIST_SEPERATOR = ';' };
  int8_t reply_code;
  char data[REPLY_DATA_LENGTH];
};

class MyClientVersionCheckReplyProc: public MyDataPacketBaseProc
{
public:
  virtual void init_header()
  {
    MyDataPacketBaseProc::init_header();
    m_data->length = sizeof(MyClientVersionCheckReply);
    m_data->command = MyDataPacketHeader::CMD_CLIENT_VERSION_CHECK_REPLY;
  };

  virtual bool validate_header() const
  {
    MyClientVersionCheckReply * pData = data();
    if (!MyDataPacketBaseProc::validate_header())
      return false;
    return (pData->command == MyDataPacketHeader::CMD_CLIENT_VERSION_CHECK_REPLY);
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



class MyLoadBalanceRequest: public MyDataPacketHeader
{
public:
  char ip_addr[40];
  int32_t clients_connected;
};


#pragma pack(pop)

#endif /* DATAPACKET_H_ */
