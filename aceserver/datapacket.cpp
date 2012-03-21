/*
 * datapacket.cpp
 *
 *  Created on: Dec 30, 2011
 *      Author: root
 */

#include "datapacket.h"
#include "mycomutil.h"

bool my_dph_validate_file_md5_list(const MyDataPacketHeader * header)
{
  return header->magic == MyDataPacketHeader::DATAPACKET_MAGIC &&
         header->length > (int32_t)sizeof(MyDataPacketHeader) &&
         header->length < 2 * 1024 * 1024;
}

bool my_dph_validate_ftp_file(const MyDataPacketHeader * header)
{
  return header->magic == MyDataPacketHeader::DATAPACKET_MAGIC &&
         header->length > (int32_t)sizeof(MyDataPacketHeader) &&
         header->length < 4096;
}

bool my_dph_validate_base(const MyDataPacketHeader * header)
{
  return header->magic == MyDataPacketHeader::DATAPACKET_MAGIC &&
         header->length == (int32_t)sizeof(MyDataPacketHeader);
}

bool my_dph_validate_plc_alarm(const MyDataPacketHeader * header)
{
  return header->magic == MyDataPacketHeader::DATAPACKET_MAGIC &&
         header->length == (int32_t)sizeof(MyPLCAlarm);
}

bool my_dph_validate_load_balance_req(const MyDataPacketHeader * header)
{
  return header->magic == MyDataPacketHeader::DATAPACKET_MAGIC &&
         header->length == (int32_t)sizeof(MyLoadBalanceRequest);
}

bool my_dph_validate_client_version_check_reply(const MyDataPacketHeader * header)
{
  return header->magic == MyDataPacketHeader::DATAPACKET_MAGIC &&
         header->length >= (int32_t)sizeof(MyClientVersionCheckReply) &&
         header->length <= (int32_t)sizeof(MyClientVersionCheckReply) + MyClientVersionCheckReply::MAX_REPLY_DATA_LENGTH;
}

bool my_dph_validate_client_version_check_req(const MyDataPacketHeader * header, const int extra)
{
  if (extra > 0)
    return header->magic == MyDataPacketHeader::DATAPACKET_MAGIC &&
           header->length > (int32_t)sizeof(MyClientVersionCheckRequest) &&
           header->length <= (int32_t)sizeof(MyClientVersionCheckRequest) + extra;
  else
    return header->magic == MyDataPacketHeader::DATAPACKET_MAGIC &&
           header->length == (int32_t)sizeof(MyClientVersionCheckRequest);
}


//MyDataPacketExt//

bool MyDataPacketExt::guard()
{
  if (unlikely(length <= (int)sizeof(MyDataPacketHeader)))
    return false;
  return data[length - sizeof(MyDataPacketHeader) - 1] == 0;
}


//MyBSBasePacket//

const char * const_bs_packet_magic = "vc5X";

void MyBSBasePacket::packet_magic()
{
  ACE_OS::memcpy(magic, const_bs_packet_magic, MAGIC_SIZE);
}

bool MyBSBasePacket::check_header() const
{
  if (ACE_OS::memcmp(magic, const_bs_packet_magic, MAGIC_SIZE) != 0)
  {
    MY_ERROR("bad magic from bs packet\n");
    return false;
  }

  for (int i = 0; i < LEN_SIZE; ++i)
  {
    if (unlikely(len[i] < '0' || len[i] > '9'))
    {
      MY_ERROR("bad len char code from bs packet\n");
      return false;
    }
  }

  int l = packet_len();
  if (unlikely(l <= 15 || l > 10 * 1024 * 1024))
  {
    MY_ERROR("invalid len (= %d) bs packet\n", l);
    return false;
  }

  return true;
}

void MyBSBasePacket::packet_len(int _len)
{
  char tmp[LEN_SIZE + 1];
  snprintf(tmp, LEN_SIZE + 1, "%08d", _len);
  ACE_OS::memcpy(len, tmp, LEN_SIZE);
}


int MyBSBasePacket::packet_len() const
{
  char tmp[LEN_SIZE + 1];
  ACE_OS::memcpy(tmp, len, LEN_SIZE);
  tmp[LEN_SIZE] = 0;
  return atoll(tmp);
}

void MyBSBasePacket::packet_cmd(const char * _cmd)
{
  if (unlikely(!_cmd || !*cmd))
    return;
  ACE_OS::memcpy(len, _cmd, 2);
}

bool MyBSBasePacket::is_cmd(const char * _cmd)
{
  if (unlikely(!_cmd || !*cmd))
    return false;
  return ACE_OS::memcmp(len, _cmd, 2) == 0;
}

bool MyBSBasePacket::guard()
{
  int len = packet_len();
  if (data[len - 14 - 1] != '$')
    return false;
  data[len - 14 - 1] = 0;
  return true;
}
