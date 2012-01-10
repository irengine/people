/*
 * heartbeatmodule.cpp
 *
 *  Created on: Dec 26, 2011
 *      Author: root
 */

#include "distmodule.h"
#include "baseapp.h"
#include "server.h"

//MyHeartBeatProcessor//

MyPingSubmitter * MyHeartBeatProcessor::m_sumbitter = NULL;

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
    do_ping();
    return ER_OK_FINISHED;
  }

  if (header.command == MyDataPacketHeader::CMD_CLIENT_VERSION_CHECK_REQ)
    return ER_OK;

  MY_ERROR(ACE_TEXT("unexpected packet header received @MyHeartBeatProcessor.on_recv_header, cmd = %d\n"),
      header.command);

  return ER_ERROR;
}

MyBaseProcessor::EVENT_RESULT MyHeartBeatProcessor::on_recv_packet_i(ACE_Message_Block * mb)
{
  MyBaseServerProcessor::on_recv_packet_i(mb);

  MyDataPacketHeader * header = (MyDataPacketHeader *)mb->base();
  if (header->command == MyDataPacketHeader::CMD_CLIENT_VERSION_CHECK_REQ)
    return do_version_check(mb);

  MY_ERROR("unsupported command received @MyHeartBeatProcessor::on_recv_packet_i, command = %d\n",
      header->command);
  return ER_ERROR;
}

void MyHeartBeatProcessor::do_ping()
{
  m_sumbitter->add_ping(m_client_id.as_string(), m_client_id_length + 1);
}

MyBaseProcessor::EVENT_RESULT MyHeartBeatProcessor::do_version_check(ACE_Message_Block * mb)
{
  MyBaseProcessor::EVENT_RESULT ret = do_version_check_common(mb, MyServerAppX::instance()->client_id_table());
  if (ret != ER_CONTINUE)
    return ret;

  MY_INFO(ACE_TEXT("client version check ok: %s\n"), info_string().c_str());

  ACE_Message_Block * reply_mb = make_version_check_reply_mb(MyClientVersionCheckReply::VER_OK);

  if (m_handler->send_data(reply_mb) < 0)
    return ER_ERROR;
  else
    return ER_OK;
}


//MyPingSubmitter//

MyPingSubmitter::MyPingSubmitter()
{
  reset();
}

MyPingSubmitter::~MyPingSubmitter()
{
  if (m_current_block)
    m_current_block->release();
}

void MyPingSubmitter::reset()
{
  m_current_block = MyMemPoolFactoryX::instance()->get_message_block(BLOCK_SIZE);
  m_current_length = 0;
  m_current_ptr = m_current_block->base();
  m_last_add = 0;
}

void MyPingSubmitter::add_ping(const char * client_id, const int len)
{
  if (!client_id || !*client_id)
    return;
  if (len + m_current_length > BLOCK_SIZE)// not zero-terminated// - 1)
  {
    do_submit();
    m_last_add = g_clock_tick;
  }
  ACE_OS::memcpy(m_current_ptr, client_id, len);
  m_current_length += len;
  m_current_ptr += len;
  *(m_current_ptr - 1) = ';';
}

void MyPingSubmitter::do_submit()
{
  m_current_block->wr_ptr(m_current_length);
  //todo: do sumbit now
  m_current_block->release(); //just a test
  //
  reset();
}

void MyPingSubmitter::check_time_out()
{
  if (m_current_length == 0)
    return;
  if (g_clock_tick > m_last_add + 4)
    do_submit();
}

//MyHeartBeatHandler//

MyHeartBeatHandler::MyHeartBeatHandler(MyBaseConnectionManager * xptr): MyBaseHandler(xptr)
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


    log_blk->release ();
  }
  ACE_DEBUG ((LM_DEBUG,
               ACE_TEXT ("(%P|%t) quitting svc()\n")));
  return 0;
}


//MyHeartBeatAcceptor//

MyHeartBeatAcceptor::MyHeartBeatAcceptor(MyHeartBeatModule * _module, MyBaseConnectionManager * _manager):
    MyBaseAcceptor(_module, _manager)
{
  m_tcp_port = MyConfigX::instance()->dist_server_heart_beat_port;
}

int MyHeartBeatAcceptor::make_svc_handler(MyBaseHandler *& sh)
{
  ACE_NEW_RETURN(sh, MyHeartBeatHandler(m_connection_manager), -1);
  sh->reactor(reactor());
  return 0;
}


//MyHeartBeatDispatcher//

MyHeartBeatDispatcher::MyHeartBeatDispatcher(MyBaseModule * pModule, int numThreads):
    MyBaseDispatcher(pModule, numThreads)
{
  m_acceptor = NULL;
}

void MyHeartBeatDispatcher::on_stop()
{
  if (m_acceptor)
  {
    m_acceptor->stop();
    delete m_acceptor;
    m_acceptor = NULL;
  }
}

int MyHeartBeatDispatcher::on_start()
{
  if (!m_acceptor)
    m_acceptor = new MyHeartBeatAcceptor((MyHeartBeatModule *)m_module, new MyBaseConnectionManager());
  return m_acceptor->start();
}


//MyHeartBeatModule//

MyHeartBeatModule::MyHeartBeatModule(MyBaseApp * app): MyBaseModule(app)
{
  m_service = new MyHeartBeatService(this, 1);
  m_dispatcher = new MyHeartBeatDispatcher(this);
  MyHeartBeatProcessor::m_sumbitter = &m_ping_sumbitter;
}

MyHeartBeatModule::~MyHeartBeatModule()
{

}
