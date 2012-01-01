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

#pragma pack(push, 1)

//every packet commute between server and clients at least has this head
class MyDataPacketHeader
{
public:
  enum
  {
    DATAPACKET_MAGIC = 0x9397
  };
  enum
  {
    CMD_NULL = 0,
    CMD_HEARTBEAT_PING,
    CMD_CLIENT_VERSION_CHECK_REQ,
    CMD_CLIENT_VERSION_CHECK_REPLY,
    CMD_END
  };
  int32_t length;
  int16_t command;
  u_int16_t magic;
};

//the ultimate root class for all data packets Proc
class MyDataPacketBaseProc
{
public:
  MyDataPacketBaseProc(void * _data = NULL): m_data((MyDataPacketHeader *)_data), m_data_owner(m_data == NULL)
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
  virtual bool validate_header()
  {
    return m_data->magic == MyDataPacketHeader::DATAPACKET_MAGIC;
  }
  void data(void * _data, bool own_data = false)
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
    m_data->length = sizeof(MyHeartBeatPingProc);
    m_data->command = MyDataPacketHeader::CMD_HEARTBEAT_PING;
  };

  virtual bool validate_header()
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
  char client_id[8];
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

  virtual bool validate_header()
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
  enum
  {
    VER_OK = 1,
    VER_MISMATCH,
    VER_SERVER_BUSY,
    VER_SERVER_LIST
  } REPLY_CODE;
  int8_t reply_code;
  char data[0];
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

  virtual bool validate_header()
  {
    MyClientVersionCheckReply * pData = data();
    if (!MyDataPacketBaseProc::validate_header())
      return false;
    if (pData->command != MyDataPacketHeader::CMD_CLIENT_VERSION_CHECK_REPLY)
      return false;
    if (pData->reply_code >= MyClientVersionCheckReply::VER_OK &&
        pData->reply_code < MyClientVersionCheckReply::VER_SERVER_LIST)
      return pData->length == sizeof(MyClientVersionCheckReply);
    if (pData->reply_code == MyClientVersionCheckReply::VER_SERVER_LIST)
      return (pData->length > (int32_t)sizeof(MyClientVersionCheckReply));
    return false;
  }

  virtual MyClientVersionCheckReply * data() const
  {
    return (MyClientVersionCheckReply *)m_data;
  }

};


#pragma pack(pop)

#endif /* DATAPACKET_H_ */
