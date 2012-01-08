/*
 * main.cpp
 *
 *  Created on: Dec 26, 2011
 *      Author: root
 */

#include "heartbeatmodule.h"
#include "serverapp.h"

int main(int argc, const char * argv[])
{
  ACE_UNUSED_ARG(argc);
  ACE_UNUSED_ARG(argv);
  ACE_Sig_Action no_sigpipe ((ACE_SignalHandler) SIG_IGN);
  ACE_Sig_Action original_action;
  no_sigpipe.register_action (SIGPIPE, &original_action);

  if (argc == 3 && strcmp(argv[1], "-home") == 0 && argv[2][0] == '/')
    MyServerApp::app_init(argv[2]);
  else
    MyServerApp::app_init(NULL);

  ACE_DEBUG ((LM_DEBUG,
              ACE_TEXT ("(%P|%t) 2\n")));

  MyServerAppX::instance()->start();
#if 0
  ACE_OS::sleep(10);
  ACE_DEBUG ((LM_DEBUG,
              ACE_TEXT ("(%P|%t) stopping module ...\n")));
  MyServerApp::dump_memory_pool_info();

  MyServerAppX::instance()->stop();
  ACE_DEBUG ((LM_DEBUG,
              ACE_TEXT ("(%P|%t) stopping module done\n")));
  //while (1)
  {
    ACE_OS::sleep(2);
    ACE_DEBUG ((LM_DEBUG,
               ACE_TEXT ("(%P|%t) MyHeartBeatModule->isRunning() = %d\n"), MyServerAppX::instance()->running()));

  }
  MyServerApp::dump_memory_pool_info();
  ACE_DEBUG ((LM_DEBUG,
              ACE_TEXT ("(%P|%t) starting module ...\n")));
  MyServerAppX::instance()->start();
  ACE_DEBUG ((LM_DEBUG,
              ACE_TEXT ("(%P|%t) starting module done\n")));

  ACE_OS::sleep(10);

  ACE_DEBUG ((LM_DEBUG,
             ACE_TEXT ("(%P|%t) deleting module ...\n")));
#else
/*
  int i = 0;
  while (++i <= 30)
  {
    ACE_Time_Value timeout(2);
    ACE_Reactor::instance()->handle_events (&timeout);
  }
*/
#endif
  MyServerApp::app_fini();
  return 0;
}
