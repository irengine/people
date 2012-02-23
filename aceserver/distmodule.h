/*
 * heartbeatmodule.h
 *
 *  Created on: Dec 26, 2011
 *      Author: root
 */

#ifndef HEARTBEATMODULE_H_
#define HEARTBEATMODULE_H_

#include <ace/Malloc_T.h>
#include <new>
#include <tr1/unordered_map>

#include "common.h"
#include "baseapp.h"
#include "basemodule.h"
#include "servercommon.h"

class MyHeartBeatModule;
class MyPingSubmitter;
class MyIPVerSubmitter;
class MyFtpFeedbackSubmitter;
class MyAdvClickSubmitter;
class MyHeartBeatAcceptor;
class MyDistClients;
class MyDistClientOne;

class MyDistClient
{
public:
  MyDistClient(MyHttpDistInfo * _dist_info, MyDistClientOne * dist_one);
  bool check_valid() const;
  bool dist_file();
  void delete_self();
  bool active();
  void update_status(int _status);
  void update_md5_list(const char * _md5);
  void dist_ftp_md5_reply(const char * md5list);
  const char * client_id() const;
  int client_id_index() const;

  MyHttpDistInfo * dist_info;
  MyDistClientOne * dist_one;
  int status;
  MyPooledMemGuard adir;
  MyPooledMemGuard md5;
  MyPooledMemGuard mbz_file;
  MyPooledMemGuard mbz_md5;
  time_t last_update;

private:
  enum { MD5_REPLY_TIME_OUT = 15, FTP_REPLY_TIME_OUT = 5 }; //in minutes

  bool do_stage_0();
  bool do_stage_1();
  bool do_stage_2();
  bool do_stage_3();
  bool do_stage_4();
  bool send_md5();
  bool send_ftp();
  bool generate_diff_mbz();
  int  dist_out_leading_length();
  void dist_out_leading_data(char * data);
};

class MyDistClientOne
{
public:
  typedef std::list<MyDistClient *, MyAllocator<MyDistClient *> > MyDistClientOneList;

  MyDistClientOne(MyDistClients * dist_clients, const char * client_id);
  ~MyDistClientOne();

  MyDistClient * create_dist_client(MyHttpDistInfo * _dist_info);
  void delete_dist_client(MyDistClient * dc);
  bool active();
  bool is_client_id(const char * _client_id) const;
  void clear();
  bool dist_files();
  const char * client_id() const;
  int client_id_index() const;

private:
  MyDistClientOneList m_client_ones;
  MyDistClients * m_dist_clients;
  MyClientID m_client_id;
  int m_client_id_index;
};

class MyClientMapKey
{
public:
  MyClientMapKey(const char * _dist_id, const char * _client_id);
  bool operator == (const MyClientMapKey & rhs) const;

  const char * dist_id;
  const char * client_id;
};

class MyClientMapHash
{
public:
  size_t operator()(const MyClientMapKey & x) const
  {
    return mycomutil_string_hash(x.client_id) ^ mycomutil_string_hash(x.dist_id);
  }
};

class MyDistClients
{
public:
  typedef std::list<MyDistClientOne *, MyAllocator<MyDistClientOne *> > MyDistClientOneList;
  typedef std::tr1::unordered_map<MyClientMapKey,
                                  MyDistClient *,
                                  MyClientMapHash,
                                  std::equal_to<MyClientMapKey>,
                                  MyAllocator <std::pair<const MyClientMapKey, MyDistClient *>>
                                > MyDistClientMap;
  typedef std::tr1::unordered_map<const char *,
                                  MyDistClientOne *,
                                  MyStringHash,
                                  MyStringEqual,
                                  MyAllocator <std::pair<const char *, MyDistClientOne *>>
                                > MyDistClientOneMap;


  MyDistClients(MyHttpDistInfos * dist_infos);
  ~MyDistClients();

  MyHttpDistInfo * find_dist_info(const char * dist_id);
  void clear();
  void dist_files();
  void on_create_dist_client(MyDistClient * dc);
  void on_remove_dist_client(MyDistClient * dc, bool finished);
  MyDistClient * find_dist_client(const char * client_id, const char * dist_id);
  MyDistClientOne * find_client_one(const char * client_id);
  MyDistClientOne * create_client_one(const char * client_id);
  void delete_client_one(MyDistClientOne * dco);

  MyDistClientOneList dist_clients;
  time_t db_time;

private:

  MyHttpDistInfos * m_dist_infos;
  MyDistClientMap m_dist_clients_map;
  MyDistClientOneMap m_dist_client_ones_map;
  int m_dist_client_finished;
};

class MyClientFileDistributor
{
public:
  MyClientFileDistributor();

  bool distribute(bool check_reload);
  void dist_ftp_file_reply(const char * client_id, const char * dist_id, int _status);
  void dist_ftp_md5_reply(const char * client_id, const char * dist_id, const char * md5list);

private:
  bool check_dist_info(bool reload);
  bool check_dist_clients(bool reload);

  MyHttpDistInfos m_dist_infos;
  MyDistClients m_dist_clients;
  time_t m_last_begin;
  time_t m_last_end;
};

class MyHeartBeatProcessor: public MyBaseServerProcessor
{
public:
  typedef MyBaseServerProcessor super;

  MyHeartBeatProcessor(MyBaseHandler * handler);
  virtual MyBaseProcessor::EVENT_RESULT on_recv_header();

  static MyPingSubmitter * m_heart_beat_submitter;
  static MyIPVerSubmitter * m_ip_ver_submitter;
  static MyFtpFeedbackSubmitter * m_ftp_feedback_submitter;
  static MyAdvClickSubmitter * m_adv_click_submitter;

protected:
  virtual MyBaseProcessor::EVENT_RESULT on_recv_packet_i(ACE_Message_Block * mb);

private:
  void do_ping();
  MyBaseProcessor::EVENT_RESULT do_version_check(ACE_Message_Block * mb);
  MyBaseProcessor::EVENT_RESULT do_md5_file_list(ACE_Message_Block * mb);
  MyBaseProcessor::EVENT_RESULT do_ftp_reply(ACE_Message_Block * mb);
  MyBaseProcessor::EVENT_RESULT do_ip_ver_req(ACE_Message_Block * mb);
  MyBaseProcessor::EVENT_RESULT do_adv_click_req(ACE_Message_Block * mb);
};

class MyBaseSubmitter;

class MyAccumulatorBlock
{
public:
  MyAccumulatorBlock(int block_size, int max_item_length, MyBaseSubmitter * submitter, bool auto_submit = false);
  ~MyAccumulatorBlock();

  void reset();
  bool add(const char * item, int len = 0);
  bool add(char c);
  const char * data();
  int data_len() const;

private:
  enum {ITEM_SEPARATOR = ';' };

  ACE_Message_Block * m_current_block;
  char * m_current_ptr;
  int m_max_item_length;
  int m_block_size;
  MyBaseSubmitter * m_submitter;
  bool m_auto_submit;
};

class MyBaseSubmitter
{
public:
  virtual ~MyBaseSubmitter();

  void submit();
  void add_block(MyAccumulatorBlock * block);
  void check_time_out();

protected:
  typedef std::list<MyAccumulatorBlock * > MyBlockList;

  void reset();
  void do_submit(const char * cmd);
  virtual const char * get_command() const = 0;

  MyBlockList m_blocks;
};

class MyFtpFeedbackSubmitter: public MyBaseSubmitter
{
public:
  MyFtpFeedbackSubmitter();
  virtual ~MyFtpFeedbackSubmitter();

  void add(const char * dist_id, char ftype, const char *client_id, char step, char ok_flag, const char * date);

protected:
  virtual const char * get_command() const;

private:
  enum { BLOCK_SIZE = 1024 };
  MyAccumulatorBlock m_dist_id_block;
  MyAccumulatorBlock m_client_id_block;
  MyAccumulatorBlock m_ftype_block;
  MyAccumulatorBlock m_step_block;
  MyAccumulatorBlock m_ok_flag_block;
  MyAccumulatorBlock m_date_block;
};


class MyPingSubmitter: public MyBaseSubmitter
{
public:
  enum {ID_SEPARATOR = ';' };
  MyPingSubmitter();
  ~MyPingSubmitter();
  void add_ping(const char * client_id, const int len);

protected:
  virtual const char * get_command() const;

private:
  enum { BLOCK_SIZE = 4096 };
  MyAccumulatorBlock m_block;
};

class MyIPVerSubmitter: public MyBaseSubmitter
{
public:
  enum {ID_SEPARATOR = ';' };
  MyIPVerSubmitter();
  void add_data(const char * client_id, int id_len, const char * ip, const char * ver);

protected:
  virtual const char * get_command() const;

private:
  enum { BLOCK_SIZE = 2048 };
  MyAccumulatorBlock m_id_block;
  MyAccumulatorBlock m_ip_block;
  MyAccumulatorBlock m_ver_block;
};

class MyAdvClickSubmitter: public MyBaseSubmitter
{
public:
  enum {ID_SEPARATOR = ';' };
  MyAdvClickSubmitter();
  void add_data(const char * client_id, int id_len, const char * chn, const char * pcode, const char * number);

protected:
  virtual const char * get_command() const;

private:
  enum { BLOCK_SIZE = 2048 };
  MyAccumulatorBlock m_id_block;
  MyAccumulatorBlock m_chn_block;
  MyAccumulatorBlock m_pcode_block;
  MyAccumulatorBlock m_number_block;
};

class MyHeartBeatHandler: public MyBaseHandler
{
public:
  MyHeartBeatHandler(MyBaseConnectionManager * xptr = NULL);

  DECLARE_MEMORY_POOL__NOTHROW(MyHeartBeatHandler, ACE_Thread_Mutex);
};

class MyHeartBeatService: public MyBaseService
{
public:
  enum { TIMED_DIST_TASK = 1 };

  MyHeartBeatService(MyBaseModule * module, int numThreads = 1);
  virtual int svc();

private:
  enum { MSG_QUEUE_MAX_SIZE = 5 * 1024 * 1024 };

  void do_have_dist_task();
  void do_ftp_file_reply(ACE_Message_Block * mb);
  void do_file_md5_reply(ACE_Message_Block * mb);

  MyClientFileDistributor m_distributor;
};

class MyHeartBeatDispatcher: public MyBaseDispatcher
{
public:
  MyHeartBeatDispatcher(MyBaseModule * pModule, int numThreads = 1);
  virtual const char * name() const;
  virtual int handle_timeout (const ACE_Time_Value &tv, const void *act);
  MyHeartBeatAcceptor * acceptor() const;

protected:
  virtual void on_stop();
  virtual void on_stop_stage_1();
  virtual bool on_start();

private:
  enum { CLOCK_INTERVAL = 3 }; //in seconds, the interval of picking send out packages
  enum { MSG_QUEUE_MAX_SIZE = 20 * 1024 * 1024 };
  enum { TIMER_ID_HEART_BEAT = 2, TIMER_ID_IP_VER, TIMER_ID_DIST_SERVICE, TIMER_ID_FTP_FEEDBACK, TIMER_ID_ADV_CLICK };
  enum { CLOCK_TICK_HEART_BEAT = 15, //seconds
         CLOCK_TICK_IP_VER = 10, //seconds
         CLOCK_TICK_FTP_FEEDBACK = 15, //seconds
         CLOCK_TICK_ADV_CLICK = 2, //in minutes
         CLOCK_TICK_DIST_SERVICE = 2 //minutes
       };
  MyHeartBeatAcceptor * m_acceptor;
};

class MyHeartBeatAcceptor: public MyBaseAcceptor
{
public:
  enum { IDLE_TIME_AS_DEAD = 5 }; //in minutes
  MyHeartBeatAcceptor(MyBaseDispatcher * _dispatcher, MyBaseConnectionManager * manager);
  virtual int make_svc_handler(MyBaseHandler *& sh);
  virtual const char * name() const;
};


class MyHeartBeatModule: public MyBaseModule
{
public:
  MyHeartBeatModule(MyBaseApp * app);
  virtual ~MyHeartBeatModule();
  MyHeartBeatDispatcher * dispatcher() const;
  virtual const char * name() const;
  MyHeartBeatService * service() const;
  int num_active_clients() const;
  MyFtpFeedbackSubmitter & ftp_feedback_submitter();

protected:
  virtual bool on_start();
  virtual void on_stop();

private:
  MyPingSubmitter m_ping_sumbitter;
  MyIPVerSubmitter m_ip_ver_submitter;
  MyFtpFeedbackSubmitter m_ftp_feedback_submitter;
  MyAdvClickSubmitter m_adv_click_submitter;
  MyHeartBeatService * m_service;
  MyHeartBeatDispatcher * m_dispatcher;
};

/////////////////////////////////////
//remote access module
/////////////////////////////////////

class MyDistRemoteAccessProcessor: public MyBaseRemoteAccessProcessor
{
public:
  typedef MyBaseRemoteAccessProcessor super;

  MyDistRemoteAccessProcessor(MyBaseHandler * handler);

protected:
  virtual int on_command(const char * cmd, char * parameter);
  virtual int on_command_help();

private:
  int on_command_dist_file_md5(char * parameter);
  int on_command_dist_batch_file_md5(char * parameter);
};

class MyDistRemoteAccessHandler: public MyBaseHandler
{
public:
  MyDistRemoteAccessHandler(MyBaseConnectionManager * xptr = NULL);
};

class MyDistRemoteAccessAcceptor: public MyBaseAcceptor
{
public:
  enum { IDLE_TIME_AS_DEAD = 10 }; //in minutes
  MyDistRemoteAccessAcceptor(MyBaseDispatcher * _dispatcher, MyBaseConnectionManager * manager);
  virtual int make_svc_handler(MyBaseHandler *& sh);
  virtual const char * name() const;
};

class MyDistRemoteAccessDispatcher: public MyBaseDispatcher
{
public:
  MyDistRemoteAccessDispatcher(MyBaseModule * pModule);
  virtual const char * name() const;

protected:
  virtual bool on_start();
};

class MyDistRemoteAccessModule: public MyBaseModule
{
public:
  MyDistRemoteAccessModule(MyBaseApp * app);
  virtual const char * name() const;

protected:
  virtual bool on_start();
};


/////////////////////////////////////
//dist to BS
/////////////////////////////////////

class MyDistToMiddleModule;

class MyDistToBSProcessor: public MyBSBasePacketProcessor
{
public:
  typedef MyBSBasePacketProcessor super;
  MyDistToBSProcessor(MyBaseHandler * handler);

protected:
  virtual MyBaseProcessor::EVENT_RESULT on_recv_packet_i(ACE_Message_Block * mb);

private:
  void process_ip_ver_reply(MyBSBasePacket * bspacket);
  void process_ip_ver_reply_one(char * item);
};

class MyDistToBSHandler: public MyBaseHandler
{
public:
  MyDistToBSHandler(MyBaseConnectionManager * xptr = NULL);
  MyDistToMiddleModule * module_x() const;
  DECLARE_MEMORY_POOL__NOTHROW(MyDistToBSHandler, ACE_Thread_Mutex);

protected:
  virtual void on_close();
  virtual int  on_open();
};

class MyDistToBSConnector: public MyBaseConnector
{
public:
  MyDistToBSConnector(MyBaseDispatcher * _dispatcher, MyBaseConnectionManager * _manager);
  virtual int make_svc_handler(MyBaseHandler *& sh);
  virtual const char * name() const;

protected:
  enum { RECONNECT_INTERVAL = 3 }; //time in minutes
};


/////////////////////////////////////
//dist to middle module
/////////////////////////////////////

class MyDistToMiddleModule;
class MyDistToMiddleConnector;

class MyDistToMiddleProcessor: public MyBaseClientProcessor
{
public:
  typedef MyBaseClientProcessor super;

  MyDistToMiddleProcessor(MyBaseHandler * handler);
  virtual MyBaseProcessor::EVENT_RESULT on_recv_header();
  virtual int on_open();
  int send_server_load();

protected:
  virtual MyBaseProcessor::EVENT_RESULT on_recv_packet_i(ACE_Message_Block * mb);

private:
  enum { IP_ADDR_LENGTH = INET_ADDRSTRLEN };

  int send_version_check_req();
  MyBaseProcessor::EVENT_RESULT do_version_check_reply(ACE_Message_Block * mb);
  MyBaseProcessor::EVENT_RESULT do_have_dist_task(ACE_Message_Block * mb);

  bool m_version_check_reply_done;
  char m_local_addr[IP_ADDR_LENGTH];
};

class MyDistToMiddleHandler: public MyBaseHandler
{
public:
  MyDistToMiddleHandler(MyBaseConnectionManager * xptr = NULL);
  virtual int handle_timeout (const ACE_Time_Value &current_time, const void *act = 0);
  void setup_timer();
  MyDistToMiddleModule * module_x() const;
  DECLARE_MEMORY_POOL__NOTHROW(MyDistToMiddleHandler, ACE_Thread_Mutex);

protected:
  virtual void on_close();
  virtual int  on_open();

private:
  enum { LOAD_BALANCE_REQ_TIMER = 1 };
  enum { LOAD_BALANCE_REQ_INTERVAL = 3 }; //in minutes
  long m_load_balance_req_timer_id;
};

class MyDistToMiddleDispatcher: public MyBaseDispatcher
{
public:
  MyDistToMiddleDispatcher(MyBaseModule * pModule, int numThreads = 1);
  virtual const char * name() const;
  void send_to_bs(ACE_Message_Block * mb);
  void send_to_middle(ACE_Message_Block * mb);

protected:
  virtual void on_stop();
  virtual bool on_start();
  virtual bool on_event_loop();

private:
  enum { MSG_QUEUE_MAX_SIZE = 5 * 1024 * 1024 };

  MyDistToMiddleConnector * m_connector;
  MyDistToBSConnector * m_bs_connector;
  ACE_Message_Queue<ACE_MT_SYNCH> m_to_bs_queue;
};


class MyDistToMiddleConnector: public MyBaseConnector
{
public:
  MyDistToMiddleConnector(MyBaseDispatcher * _dispatcher, MyBaseConnectionManager * _manager);
  virtual int make_svc_handler(MyBaseHandler *& sh);
  virtual const char * name() const;

protected:
  enum { RECONNECT_INTERVAL = 3 }; //time in minutes
};

class MyDistToMiddleModule: public MyBaseModule
{
public:
  MyDistToMiddleModule(MyBaseApp * app);
  virtual ~MyDistToMiddleModule();
  virtual const char * name() const;
  void send_to_bs(ACE_Message_Block * mb);
  void send_to_middle(ACE_Message_Block * mb);

protected:
  virtual bool on_start();
  virtual void on_stop();

private:
  MyDistToMiddleDispatcher *m_dispatcher;
};


#endif /* HEARTBEATMODULE_H_ */
