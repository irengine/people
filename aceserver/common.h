#ifndef COMMON_H_
#define COMMON_H_

#ifndef MY_client_test
#define MY_client_test
#endif

#ifndef MY_server_test
#define MY_server_test
#endif

#ifdef __GNUC__
  #define likely(x)       __builtin_expect((x),1)
  #define unlikely(x)     __builtin_expect((x),0)
#else
  #define likely(x)       (x)
  #define unlikely(x)     (x)
#endif


#endif /* COMMON_H_ */
