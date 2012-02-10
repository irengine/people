/*
 * datapacket.cpp
 *
 *  Created on: Dec 30, 2011
 *      Author: root
 */

#include "datapacket.h"
#include "mycomutil.h"

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
  if (unlikely(l <= 0 || l > 10 * 1024 * 1024))
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
