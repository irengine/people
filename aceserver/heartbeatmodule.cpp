/*
 * heartbeatmodule.cpp
 *
 *  Created on: Dec 26, 2011
 *      Author: root
 */

#include "heartbeatmodule.h"
#include "serverapp.h"

//MyHeartBeatProcessor//

MyHeartBeatProcessor::MyHeartBeatProcessor(MyBaseHandler * handler): MyBaseServerProcessor(handler)
{

}

MyBaseProcessor::EVENT_RESULT MyHeartBeatProcessor::on_recv_header(const MyDataPacketHeader & header)
{
  if (MyBaseServerProcessor::on_recv_header(header) == ER_ERROR)
    return ER_ERROR;

  if (header.command == MyDataPacketHeader::CMD_HEARTBEAT_PING)
  { //todo: handle heart beat
    //the thread context switching and synchronization cost outbeat the benefit of using another thread

    return ER_OK_FINISHED;
  }

  return ER_ERROR;
}

MyBaseProcessor::EVENT_RESULT MyHeartBeatProcessor::on_recv_packet_i(ACE_Message_Block * mb)
{


}



//MyHeartBeatHandler//

MyHeartBeatHandler::MyHeartBeatHandler(MyBaseAcceptor * xptr): MyBaseHandler(xptr)
{
  m_processor = new MyHeartBeatProcessor(this);
}

PREPARE_MEMORY_POOL(MyHeartBeatHandler);

//MyHeartBeatService//

MyHeartBeatService::MyHeartBeatService(MyBaseModule * module, int numThreads):
    MyBaseService(module, numThreads)
{

}

int MyHeartBeatService::svc()
{
  ACE_DEBUG ((LM_DEBUG,
             ACE_TEXT ("(%P|%t) running svc()\n")));

  for (ACE_Message_Block *log_blk; getq (log_blk) != -1; )
  {
//    ACE_DEBUG ((LM_DEBUG,
//               ACE_TEXT ("(%P|%t) svc data from queue, size = %d\n"),
//               log_blk->size()));

    module_x()->dispatcher()->acceptor()->on_data_processed(NULL, log_blk->size());
    log_blk->release ();
  }
  ACE_DEBUG ((LM_DEBUG,
               ACE_TEXT ("(%P|%t) quitting svc()\n")));
  return 0;
}


//MyHeartBeatAcceptor//

MyHeartBeatAcceptor::MyHeartBeatAcceptor(MyHeartBeatModule * _module) : MyBaseAcceptor(_module)
{

}

int MyHeartBeatAcceptor::make_svc_handler(MyBaseHandler *& sh)
{
  ACE_NEW_RETURN(sh, MyHeartBeatHandler(this), -1);
  sh->reactor(reactor());
  return 0;
}

//MyHeartBeatDispatcher//


MyHeartBeatDispatcher::MyHeartBeatDispatcher(MyBaseModule * pModule, int numThreads):
    MyBaseDispatcher(pModule, numThreads)
{

}

MyBaseAcceptor * MyHeartBeatDispatcher::make_acceptor()
{
  return new MyHeartBeatAcceptor((MyHeartBeatModule *)m_module);
}




//MyHeartBeatModule//

MyHeartBeatModule::MyHeartBeatModule()
{
  m_service = new MyHeartBeatService(this, 1);
  m_dispatcher = new MyHeartBeatDispatcher(this, MyServerAppX::instance()->server_config().module_heart_beat_port);
}

MyHeartBeatModule::~MyHeartBeatModule()
{

}
/*
MyHeartBeatModule * MyHeartBeatModule::m_instance = NULL;

MyHeartBeatModule * MyHeartBeatModule::instance()
{
  if (m_instance == NULL)
    m_instance = new MyHeartBeatModule();
  return m_instance;
}
*/
