/*
 * mycomutil.h
 *
 *  Created on: Dec 29, 2011
 *      Author: root
 *      common utility
 */

#ifndef MYCOMUTIL_H_
#define MYCOMUTIL_H_

#include <ace/Log_Msg.h>
#include <ace/Message_Block.h>
#include <ace/SOCK_Stream.h>
#include <ace/Svc_Handler.h>

#define INFO_PREFIX       ACE_TEXT ("(%D %P|%t %N.%l)\n  INFO %I")
#define MY_INFO(FMT, ...)     \
        ACE_DEBUG(( LM_INFO,  \
                    INFO_PREFIX FMT, \
                    ## __VA_ARGS__))

#define DEBUG_PREFIX       ACE_TEXT("(%D %P|%t %N.%l)\n  DEBUG  %I")
#define MY_DEBUG(FMT, ...)     \
        ACE_DEBUG(( LM_DEBUG,  \
                    DEBUG_PREFIX FMT, \
                    ## __VA_ARGS__))

#define WARNING_PREFIX       ACE_TEXT("(%D %P|%t %N.%l)\n  WARN  %I")
#define MY_WARNING(FMT, ...)     \
        ACE_DEBUG(( LM_WARNING,  \
                    WARNING_PREFIX FMT, \
                    ## __VA_ARGS__))

#define ERROR_PREFIX       ACE_TEXT("(%D %P|%t %N.%l)\n  ERROR  %I")
#define MY_ERROR(FMT, ...)     \
        ACE_DEBUG(( LM_ERROR,  \
                    ERROR_PREFIX  FMT, \
                    ## __VA_ARGS__))

#define FATAL_PREFIX       ACE_TEXT("(%D %P|%t %N.%l)\n  FATAL  %I")
#define MY_FATAL(FMT, ...)     \
        ACE_DEBUG(( LM_ERROR,  \
                    FATAL_PREFIX  FMT, \
                    ## __VA_ARGS__))


int mycomutil_translate_tcp_result(ssize_t transfer_return_value);
int mycomutil_send_message_block(ACE_Svc_Handler<ACE_SOCK_STREAM, ACE_NULL_SYNCH> * handler, ACE_Message_Block *mb);
int mycomutil_send_message_block_queue(ACE_Svc_Handler<ACE_SOCK_STREAM, ACE_NULL_SYNCH> * handler, ACE_Message_Block *mb);
int mycomutil_recv_message_block(ACE_Svc_Handler<ACE_SOCK_STREAM, ACE_NULL_SYNCH> * handler, ACE_Message_Block *mb);

#endif /* MYCOMUTIL_H_ */
