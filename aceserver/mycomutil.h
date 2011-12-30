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

#define INFO_PREFIX       ACE_TEXT ("(%D %P|%t %N.%l)\n  INFO %I")
#define MY_INFO(FMT, ...)     \
        ACE_DEBUG(( LM_INFO,  \
                    INFO_PREFIX FMT \
                    __VA_ARGS__))

#define DEBUG_PREFIX       ACE_TEXT ("(%D %P|%t %N.%l)\n  DEBUG  %I")
#define MY_DEBUG(FMT, ...)     \
        ACE_DEBUG(( LM_DEBUG,  \
                    DEBUG_PREFIX FMT \
                    __VA_ARGS__))

#define WARNING_PREFIX       ACE_TEXT ("(%D %P|%t %N.%l)\n  WARN  %I")
#define MY_WARNING(FMT, ...)     \
        ACE_DEBUG(( LM_WARNING,  \
                    WARNING_PREFIX FMT \
                    __VA_ARGS__))

#define ERROR_PREFIX       ACE_TEXT ("(%D %P|%t %N.%l)\n  ERROR  %I")
#define MY_ERROR(FMT, ...)     \
        ACE_DEBUG(( LM_ERROR,  \
                    ERROR_PREFIX  FMT\
                    __VA_ARGS__))

#endif /* MYCOMUTIL_H_ */
