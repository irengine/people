#ifndef _common_c_H
#define _common_c_H

#include <stdio.h>	
#include <string.h>	
#include <errno.h>	

#define error_exit(error)	\
    do{                                         \
        fprintf(stderr, "%s\n", error);         \
        exit(0);                                \
    } while(0)

#define error_ret(error)                          \
    do{                                           \
        fprintf(stderr, "%s\n", error);           \
        return -1;                                \
    } while(0)

#define unix_error_exit(error)                  \
    do{                                         \
        fprintf(stderr, "%s Info[%d]:%s\n",     \
                error, errno, strerror(errno));	\
        exit(1);                                \
    } while(0)

#define unix_error_ret(error)                   \
    do{                                         \
        fprintf(stderr, "%s Info[%d]:%s\n",     \
                error, errno, strerror(errno));	\
        return -1;                              \
    } while(0)

#define unix_print_error(error)                                 \
    do {                                                        \
        fprintf(stderr, "Error: File:%s Line:%d Function:%s:\n",  \
                __FILE__, __LINE__, __func__);                      \
        perror(error);                                              \
        exit(0);                                                    \
    } while(0)


#ifndef DEBUG
#define DEBUG	1
#endif

#if DEBUG > 0
#define debug_msg(fmt, ...)	\
    fprintf(stdout, fmt, ##__VA_ARGS__)
#else
#define debug_msg(fmt,...)
#endif	 

#ifndef TRACE
#define TRACE	1              
#endif

#if TRACE > 0
#define debug_trace(trace)	\
    fprintf(stdout, "%s File:%s Line:%d Func:%s.\n",   \
            trace, __FILE__, __LINE__, __func__)
#else
#define debug_trace(trace)
#endif

#endif

