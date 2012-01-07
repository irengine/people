/*
 * mycomutil.cpp
 *
 *  Created on: Jan 2, 2012
 *      Author: root
 */

#include <algorithm>
#include "mycomutil.h"

int mycomutil_translate_tcp_result(ssize_t transfer_return_value)
{
  if (transfer_return_value == 0)
    return -1;
  if (transfer_return_value < 0)
  {
    if (errno == EWOULDBLOCK || errno == EAGAIN || errno == ENOBUFS) //see POSIX.1-2001
      return 0;
    return -1;
  }
  return 1;
}

int mycomutil_send_message_block(ACE_Svc_Handler<ACE_SOCK_STREAM, ACE_NULL_SYNCH> * handler, ACE_Message_Block *mb)
{
  if (!handler || !mb)
    return -1;
  if (mb->length() == 0)
    return 0;
  ssize_t send_cnt = TEMP_FAILURE_RETRY(handler->peer().send(mb->rd_ptr(), mb->length()));
  int ret = mycomutil_translate_tcp_result(send_cnt);
  if (ret < 0)
    return ret;
  mb->rd_ptr(send_cnt);
  return (mb->length() == 0 ? 0:1);
}

int mycomutil_send_message_block_queue(ACE_Svc_Handler<ACE_SOCK_STREAM, ACE_NULL_SYNCH> * handler, ACE_Message_Block *mb)
{
  int ret = mycomutil_send_message_block(handler, mb);
  if (ret < 0)
    return -1;
  if (mb->length() == 0)
  {
    mb->release();
    return 0;
  } else
  {
    ACE_Time_Value nowait(ACE_OS::gettimeofday());
    if (handler->putq(mb, &nowait) < 0)
      return -1;
    handler->reactor()->register_handler(handler, ACE_Event_Handler::WRITE_MASK);
    return 1;
  }

}

int mycomutil_recv_message_block(ACE_Svc_Handler<ACE_SOCK_STREAM, ACE_NULL_SYNCH> * handler, ACE_Message_Block *mb)
{
  if (!handler || !mb)
    return -1;
  if (mb->space() == 0)
    return 0;
  ssize_t recv_cnt = TEMP_FAILURE_RETRY(handler->peer().recv (mb->wr_ptr(), mb->space()));
  int ret = mycomutil_translate_tcp_result(recv_cnt);
  if (ret < 0)
    return -1;
  mb->wr_ptr(recv_cnt);
  return (mb->space() == 0 ? 0:1);
}
