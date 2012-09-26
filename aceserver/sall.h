#ifndef SERVERCOMMON_H_
#define SERVERCOMMON_H_
#include <libpq-fe.h>
#include <tr1/unordered_map>
#include <ace/Malloc_T.h>
#include <new>
#include <tr1/unordered_set>

#include "tools.h"
#include "component.h"
#include "app.h"

class MyHttpDistInfo;

class MyHttpDistRequest
{
public:
  MyHttpDistRequest();
  MyHttpDistRequest(CONST MyHttpDistInfo & info);

  truefalse check_valid(CONST truefalse check_acode) CONST;
  truefalse need_md5() CONST;
  truefalse need_mbz_md5() CONST;

  text * acode;
  text * ftype;
  text * fdir;
  text * findex;
  text * adir;
  text * aindex;
  text * ver;
  text * type;
  text * password;

private:
  truefalse check_value(CONST text * value, CONST text * value_name) CONST;
};

class MyHttpDistInfo
{
public:
  MyHttpDistInfo(CONST text * dist_id);
  truefalse need_md5() CONST;
  truefalse need_mbz_md5() CONST;
  DVOID calc_md5_opt_len();

  text ftype[2];
  text type[2];
  CMemGuard fdir;
  CMemGuard findex;
  CMemGuard aindex;
  CMemGuard ver;
  CMemGuard password;

  CMemGuard dist_time;
  CMemGuard md5;

  CMemGuard mbz_md5;

  truefalse exist;

  ni  md5_len;
  ni  ver_len;
  ni  findex_len;
  ni  aindex_len;
  ni  password_len;

  ni  md5_opt_len;
};

class MyHttpDistInfos
{
public:
  typedef std::vector<MyHttpDistInfo *, CCppAllocator<MyHttpDistInfo *> > MyHttpDistInfoList;

  MyHttpDistInfos();
  ~MyHttpDistInfos();

  ni count() CONST;
  MyHttpDistInfo * create_http_dist_info(CONST text * dist_id);
  truefalse need_reload();
  DVOID prepare_update(CONST ni capacity);
  DVOID clear();
  MyHttpDistInfo * find(CONST text * dist_id);

  CMemGuard last_load_time;

private:
  typedef std::tr1::unordered_map<const text *,
                                  MyHttpDistInfo *,
                                  CStrHasher,
                                  CStrEqual,
                                  CCppAllocator <std::pair<const text *, MyHttpDistInfo *> >
                                > MyHttpDistInfoMap;

  MyHttpDistInfoList dist_infos;
  MyHttpDistInfoMap  m_info_map;
};

class MyDistCompressor
{
public:
  truefalse compress(MyHttpDistRequest & http_dist_request);
  SF DVOID get_all_in_one_mbz_file_name(CONST text * dist_id, CMemGuard & filename);
  SF CONST text * composite_path();
  SF CONST text * all_in_one_mbz();

private:
  truefalse do_generate_compressed_files(CONST text * src_path, CONST text * dest_path, ni prefix_len, CONST text * passwrod);

  CCompCombiner m_compositor;
  CDataComp m_compressor;
};

class MyDistMd5Calculator
{
public:
  truefalse calculate(MyHttpDistRequest & http_dist_request, CMemGuard &md5_result, ni & md5_len);
  SF truefalse calculate_all_in_one_ftp_md5(CONST text * dist_id, CMemGuard & md5_result);
};

CMB * my_get_hb_mb();

class MyActChecker
{
public:
  DVOID update()
  {
    m_tm = time(NULL);
  }
  truefalse expired() CONST
  {
    return time(NULL) - m_tm >= 85;
  }

private:
  time_t m_tm;
};


class MyLocationAcceptor;
class MyLocationModule;

class MyDistLoad
{
public:
  MyDistLoad()
  {
    m_ip_addr[0] = 0;
    m_clients_connected = 0;
    m_last_access = g_clock_counter;
  }

  MyDistLoad(CONST text * _addr, ni m)
  {
    ip_addr(_addr);
    clients_connected(m);
    m_last_access = g_clock_counter;
  }

  DVOID ip_addr(CONST text * _addr)
  {
    if (_addr)
      ACE_OS::strsncpy(m_ip_addr, _addr, IP_ADDR_LEN);
    else
      m_ip_addr[0] = 0;
  }

  DVOID clients_connected(ni m)
  {
    if (m >= 0)
      m_clients_connected = m;
    else
      m_clients_connected = 0;
  }

  truefalse operator < (CONST MyDistLoad & rhs) CONST
  {
    return m_clients_connected < rhs.m_clients_connected;
  }

  enum
  {
    IP_ADDR_LEN = 40
  };

  text    m_ip_addr[IP_ADDR_LEN];
  int32_t m_clients_connected;
  long    m_last_access;
};


class MyDistLoads
{
public:
  typedef std::vector<MyDistLoad> MyDistLoadVec;
  typedef MyDistLoadVec::iterator MyDistLoadVecIt;
  enum { SERVER_LIST_LENGTH = 2048 };
  enum { DEAD_TIME = 10 }; //in minutes

  MyDistLoads();

  DVOID update(CONST MyDistLoad & load);
  DVOID remove(CONST text * addr);
  ni  get_server_list(text * buffer, ni buffer_len);
  DVOID scan_for_dead();

private:
  DVOID calc_server_list();
  MyDistLoads::MyDistLoadVecIt find_i(CONST text * addr);

  MyDistLoadVec m_loads;
  text m_server_list[SERVER_LIST_LENGTH];
  ni  m_server_list_length;
  ACE_Thread_Mutex m_mutex;
};

class MyUnusedPathRemover
{
public:
  ~MyUnusedPathRemover();

  DVOID add_dist_id(CONST text * dist_id);
  DVOID check_path(CONST text * path);

private:
  typedef std::tr1::unordered_set<const text *, CStrHasher, CStrEqual, CCppAllocator<const text *> > MyPathSet;
  typedef std::list<CMemGuard *, CCppAllocator<CMemGuard *> > MyPathList;

  truefalse path_ok(CONST text * _path);

  MyPathSet  m_path_set;
  MyPathList m_path_list;
};

class MyLocationProcessor: public CServerProcBase
{
public:
  MyLocationProcessor(CHandlerBase * handler);
  virtual CProcBase::OUTPUT on_recv_header();
  virtual CONST text * name() CONST;

  SF MyDistLoads * m_dist_loads;

  DECLARE_MEMORY_POOL__NOTHROW(MyLocationProcessor, ACE_Thread_Mutex);

protected:
  virtual CProcBase::OUTPUT on_recv_packet_i(CMB * mb);

private:
  CProcBase::OUTPUT do_version_check(CMB * mb);
};


class MyLocationHandler: public CHandlerBase
{
public:
  MyLocationHandler(CConnectionManagerBase * xptr = NULL);
  DECLARE_MEMORY_POOL__NOTHROW(MyLocationHandler, ACE_Thread_Mutex);
};

class MyLocationService: public CTaskBase
{
public:
  MyLocationService(CMod * module, ni numThreads = 1);
  virtual ni svc();
};

class MyLocationDispatcher: public CDispatchBase
{
public:
  MyLocationDispatcher(CMod * _module, ni numThreads = 1);

protected:
  virtual truefalse before_begin();
  virtual DVOID before_finish();
  virtual CONST text * name() CONST;

private:
  enum { MSG_QUEUE_MAX_SIZE = 5 * 1024 * 1024 };

  MyLocationAcceptor * m_acceptor;
};

class MyLocationAcceptor: public CAcceptorBase
{
public:
  enum { IDLE_TIME_AS_DEAD = 5 }; //in minutes
  MyLocationAcceptor(CDispatchBase * _dispatcher, CConnectionManagerBase * manager);

  virtual ni make_svc_handler(CHandlerBase *& sh);
  virtual CONST text * name() CONST;
};


class MyLocationModule: public CMod
{
public:
  MyLocationModule(CApp * app);
  virtual ~MyLocationModule();
  MyDistLoads * dist_loads();

protected:
  virtual truefalse before_begin();
  virtual DVOID before_finish();
  virtual CONST text * name() CONST;

private:
  MyDistLoads m_dist_loads;
  MyLocationService * m_service;
  MyLocationDispatcher *m_dispatcher;
};

//============================//
//http module stuff begins here
//============================//

class MyHttpModule;
class MyHttpAcceptor;

class MyHttpProcessor: public CFormattedProcBase<ni>
{
public:
  typedef CFormattedProcBase<ni> baseclass;

  MyHttpProcessor(CHandlerBase * handler);
  virtual ~MyHttpProcessor();
  virtual CONST text * name() CONST;
  DECLARE_MEMORY_POOL__NOTHROW(MyHttpProcessor, ACE_Thread_Mutex);

protected:
  virtual ni packet_length();
  virtual CProcBase::OUTPUT on_recv_header();
  virtual CProcBase::OUTPUT on_recv_packet_i(CMB * mb);

private:
  truefalse do_process_input_data();
  truefalse do_prio(CMB * mb);
};


class MyHttpHandler: public CHandlerBase
{
public:
  MyHttpHandler(CConnectionManagerBase * xptr = NULL);

  DECLARE_MEMORY_POOL__NOTHROW(MyHttpHandler, ACE_Thread_Mutex);
};

class MyHttpService: public CTaskBase
{
public:
  MyHttpService(CMod * module, ni numThreads = 1);

  virtual ni svc();
  virtual CONST text * name() CONST;

private:
  enum { MSG_QUEUE_MAX_SIZE = 5 * 1024 * 1024 };

  truefalse handle_packet(CMB * mb);
  truefalse do_handle_packet(CMB * mb, MyHttpDistRequest & http_dist_request);
  truefalse do_handle_packet2(CMB * mb);
  truefalse parse_request(CMB * mb, MyHttpDistRequest & http_dist_request);
  truefalse do_compress(MyHttpDistRequest & http_dist_request);
  truefalse do_calc_md5(MyHttpDistRequest & http_dist_request);
  truefalse notify_dist_servers();
};

class MyHttpDispatcher: public CDispatchBase
{
public:
  MyHttpDispatcher(CMod * pModule, ni numThreads = 1);
  virtual CONST text * name() CONST;

protected:
  virtual DVOID before_finish();
  virtual truefalse before_begin();

private:
  MyHttpAcceptor * m_acceptor;
};

class MyHttpAcceptor: public CAcceptorBase
{
public:
  enum { IDLE_TIME_AS_DEAD = 5 }; //in minutes

  MyHttpAcceptor(CDispatchBase * _dispatcher, CConnectionManagerBase * manager);
  virtual ni make_svc_handler(CHandlerBase *& sh);
  virtual CONST text * name() CONST;
};


class MyHttpModule: public CMod
{
public:
  MyHttpModule(CApp * app);
  virtual ~MyHttpModule();
  virtual CONST text * name() CONST;
  MyHttpService * http_service();

protected:
  virtual truefalse before_begin();
  virtual DVOID before_finish();

private:
  MyHttpService *m_service;
  MyHttpDispatcher * m_dispatcher;
};


//============================//
//DistLoad module stuff begins here
//============================//

class MyDistLoadModule;
class MyDistLoadAcceptor;
class MyMiddleToBSConnector;

class MyDistLoadProcessor: public CServerProcBase
{
public:
  typedef CServerProcBase baseclass;

  MyDistLoadProcessor(CHandlerBase * handler);
  virtual ~MyDistLoadProcessor();
  virtual CONST text * name() CONST;
  virtual truefalse client_id_verified() CONST;
  virtual CProcBase::OUTPUT on_recv_header();
  DVOID dist_loads(MyDistLoads * dist_loads);

protected:
  virtual CProcBase::OUTPUT on_recv_packet_i(CMB * mb);

private:
  enum { MSG_QUEUE_MAX_SIZE = 1024 * 1024 };

  CProcBase::OUTPUT do_version_check(CMB * mb);
  CProcBase::OUTPUT do_load_balance(CMB * mb);

  truefalse m_client_id_verified;
  MyDistLoads * m_dist_loads;
};


class MyDistLoadHandler: public CHandlerBase
{
public:
  MyDistLoadHandler(CConnectionManagerBase * xptr = NULL);
  DVOID dist_loads(MyDistLoads * dist_loads);

  DECLARE_MEMORY_POOL__NOTHROW(MyDistLoadHandler, ACE_Thread_Mutex);
};

class MyDistLoadDispatcher: public CDispatchBase
{
public:
  MyDistLoadDispatcher(CMod * pModule, ni numThreads = 1);
  ~MyDistLoadDispatcher();
  virtual CONST text * name() CONST;
  virtual ni handle_timeout(CONST ACE_Time_Value &current_time, CONST DVOID *act = 0);
  DVOID send_to_bs(CMB * mb);

protected:
  virtual DVOID before_finish();
  virtual truefalse before_begin();
  virtual truefalse do_schedule_work();

private:
  enum { MSG_QUEUE_MAX_SIZE = 1024 * 1024 };

  MyDistLoadAcceptor * m_acceptor;
  MyMiddleToBSConnector * m_bs_connector;
  ACE_Message_Queue<ACE_MT_SYNCH> m_to_bs_queue;
};

class MyDistLoadAcceptor: public CAcceptorBase
{
public:
  enum { IDLE_TIME_AS_DEAD = 15 }; //in minutes
  MyDistLoadAcceptor(CDispatchBase * _dispatcher, CConnectionManagerBase * manager);

  virtual ni make_svc_handler(CHandlerBase *& sh);
  virtual CONST text * name() CONST;
};


class MyDistLoadModule: public CMod
{
public:
  MyDistLoadModule(CApp * app);
  virtual ~MyDistLoadModule();
  virtual CONST text * name() CONST;
  MyDistLoadDispatcher * dispatcher() CONST;

protected:
  virtual truefalse before_begin();
  virtual DVOID before_finish();

private:
  MyDistLoadDispatcher * m_dispatcher;
};



/////////////////////////////////////
//middle to BS
/////////////////////////////////////

class MyMiddleToBSProcessor: public CBSProceBase
{
public:
  typedef CBSProceBase baseclass;

  MyMiddleToBSProcessor(CHandlerBase * handler);
  virtual CONST text * name() CONST;

  DECLARE_MEMORY_POOL__NOTHROW(MyMiddleToBSProcessor, ACE_Thread_Mutex);

protected:
  virtual CProcBase::OUTPUT on_recv_packet_i(CMB * mb);
};

class MyMiddleToBSHandler: public CHandlerBase
{
public:
  MyMiddleToBSHandler(CConnectionManagerBase * xptr = NULL);
  virtual ni handle_timeout (CONST ACE_Time_Value &current_time, CONST DVOID *act = 0);
  DVOID checker_update();
  MyDistLoadModule * module_x() CONST;
  DECLARE_MEMORY_POOL__NOTHROW(MyMiddleToBSHandler, ACE_Thread_Mutex);

protected:
  virtual DVOID on_close();
  virtual ni  on_open();

private:
  MyActChecker m_checker;
};

class MyMiddleToBSConnector: public CConnectorBase
{
public:
  MyMiddleToBSConnector(CDispatchBase * _dispatcher, CConnectionManagerBase * _manager);
  virtual ni make_svc_handler(CHandlerBase *& sh);
  virtual CONST text * name() CONST;

protected:
  enum { RECONNECT_INTERVAL = 1 }; //time in minutes
};


//dist component
class MyHeartBeatModule;
class MyPingSubmitter;
class MyIPVerSubmitter;
class MyFtpFeedbackSubmitter;
class MyAdvClickSubmitter;
class MyPcOnOffSubmitter;
class MyHWAlarmSubmitter;
class MyVLCSubmitter;
class MyVLCEmptySubmitter;
class MyHeartBeatAcceptor;
class MyDistClients;
class MyDistClientOne;

class MyDistClient
{
public:
  MyDistClient(MyHttpDistInfo * _dist_info, MyDistClientOne * dist_one);
  truefalse check_valid() CONST;
  truefalse dist_file();
  DVOID delete_self();
  truefalse active();
  DVOID update_status(ni _status);
  DVOID update_md5_list(CONST text * _md5);
  DVOID dist_ftp_md5_reply(CONST text * md5list);
  CONST text * client_id() CONST;
  ni client_id_index() CONST;
  DVOID send_fb_detail(truefalse ok);
  DVOID psp(CONST text c);

  MyHttpDistInfo * dist_info;
  MyDistClientOne * dist_one;
  ni status;
  CMemGuard adir;
  CMemGuard md5;
  CMemGuard mbz_file;
  CMemGuard mbz_md5;
  time_t last_update;

private:
  enum { MD5_REPLY_TIME_OUT = 15, FTP_REPLY_TIME_OUT = 5 }; //in minutes

  truefalse do_stage_0();
  truefalse do_stage_1();
  truefalse do_stage_2();
  truefalse do_stage_3();
  truefalse do_stage_4();
  truefalse do_stage_5();
  truefalse do_stage_6();
  truefalse do_stage_7();
  truefalse do_stage_8();
  truefalse send_md5();
  truefalse send_ftp();
  truefalse send_psp(CONST text c);
  truefalse generate_diff_mbz();
  ni  dist_out_leading_length();
  DVOID dist_out_leading_data(text * data);
  CMB * make_ftp_fb_detail_mb(truefalse bok);
};

class MyDistClientOne
{
public:
  typedef std::list<MyDistClient *, CCppAllocator<MyDistClient *> > MyDistClientOneList;

  MyDistClientOne(MyDistClients * dist_clients, CONST text * client_id);
  ~MyDistClientOne();

  MyDistClient * create_dist_client(MyHttpDistInfo * _dist_info);
  DVOID delete_dist_client(MyDistClient * dc);
  truefalse active();
  truefalse is_client_id(CONST text * _client_id) CONST;
  DVOID clear();
  truefalse dist_files();
  CONST text * client_id() CONST;
  ni client_id_index() CONST;

private:
  MyDistClientOneList m_client_ones;
  MyDistClients * m_dist_clients;
  CNumber m_client_id;
  ni m_client_id_index;
};

class MyClientMapKey
{
public:
  MyClientMapKey(CONST text * _dist_id, CONST text * _client_id);
  truefalse operator == (CONST MyClientMapKey & rhs) CONST;

  CONST text * dist_id;
  CONST text * client_id;
};

class MyClientMapHash
{
public:
  size_t operator()(CONST MyClientMapKey & x) CONST
  {
    return c_tools_text_hash(x.client_id) ^ c_tools_text_hash(x.dist_id);
  }
};

class MyDistClients
{
public:
  typedef std::list<MyDistClientOne *, CCppAllocator<MyDistClientOne *> > MyDistClientOneList;
  typedef std::tr1::unordered_map<MyClientMapKey,
                                  MyDistClient *,
                                  MyClientMapHash,
                                  std::equal_to<MyClientMapKey>,
                                  CCppAllocator <std::pair<const MyClientMapKey, MyDistClient *>>
                                > MyDistClientMap;
  typedef std::tr1::unordered_map<const text *,
                                  MyDistClientOne *,
                                  CStrHasher,
                                  CStrEqual,
                                  CCppAllocator <std::pair<const text *, MyDistClientOne *>>
                                > MyDistClientOneMap;


  MyDistClients(MyHttpDistInfos * dist_infos);
  ~MyDistClients();

  MyHttpDistInfo * find_dist_info(CONST text * dist_id);
  DVOID clear();
  DVOID dist_files();
  DVOID on_create_dist_client(MyDistClient * dc);
  DVOID on_remove_dist_client(MyDistClient * dc, truefalse finished);
  MyDistClient * find_dist_client(CONST text * client_id, CONST text * dist_id);
  MyDistClientOne * find_client_one(CONST text * client_id);
  MyDistClientOne * create_client_one(CONST text * client_id);
  DVOID delete_client_one(MyDistClientOne * dco);

  MyDistClientOneList dist_clients;
  time_t db_time;

private:

  MyHttpDistInfos * m_dist_infos;
  MyDistClientMap m_dist_clients_map;
  MyDistClientOneMap m_dist_client_ones_map;
  ni m_dist_client_finished;
};

class MyClientFileDistributor
{
public:
  MyClientFileDistributor();

  truefalse distribute(truefalse check_reload);
  DVOID dist_ftp_file_reply(CONST text * client_id, CONST text * dist_id, ni _status, truefalse ok);
  DVOID dist_ftp_md5_reply(CONST text * client_id, CONST text * dist_id, CONST text * md5list);
  DVOID psp(CONST text * client_id, CONST text * dist_id, text c);

private:
  enum { IDLE_TIME = 5 }; //in minutes

  truefalse check_dist_info(truefalse reload);
  truefalse check_dist_clients(truefalse reload);

  MyHttpDistInfos m_dist_infos;
  MyDistClients m_dist_clients;
  time_t m_last_begin;
  time_t m_last_end;
};

class MyHeartBeatProcessor: public CServerProcBase
{
public:
  typedef CServerProcBase baseclass;

  MyHeartBeatProcessor(CHandlerBase * handler);
  virtual CProcBase::OUTPUT on_recv_header();
  virtual CONST text * name() CONST;

  SF MyPingSubmitter * m_heart_beat_submitter;
  SF MyIPVerSubmitter * m_ip_ver_submitter;
  SF MyFtpFeedbackSubmitter * m_ftp_feedback_submitter;
  SF MyAdvClickSubmitter * m_adv_click_submitter;
  SF MyPcOnOffSubmitter * m_pc_on_off_submitter;
  SF MyHWAlarmSubmitter * m_hardware_alarm_submitter;
  SF MyVLCSubmitter * m_vlc_submitter;
  SF MyVLCEmptySubmitter * m_vlc_empty_submitter;

  DECLARE_MEMORY_POOL__NOTHROW(MyHeartBeatProcessor, ACE_Thread_Mutex);

protected:
  virtual CProcBase::OUTPUT on_recv_packet_i(CMB * mb);

private:
  enum { MSG_QUEUE_MAX_SIZE = 2 * 1024 * 1024 };

  DVOID do_ping();
  CProcBase::OUTPUT do_version_check(CMB * mb);
  CProcBase::OUTPUT do_md5_file_list(CMB * mb);
  CProcBase::OUTPUT do_ftp_reply(CMB * mb);
  CProcBase::OUTPUT do_ip_ver_req(CMB * mb);
  CProcBase::OUTPUT do_adv_click_req(CMB * mb);
  CProcBase::OUTPUT do_pc_on_off_req(CMB * mb);
  CProcBase::OUTPUT do_hardware_alarm_req(CMB * mb);
  CProcBase::OUTPUT do_vlc_req(CMB * mb);
  CProcBase::OUTPUT do_test(CMB * mb);
  CProcBase::OUTPUT do_psp(CMB * mb);
  CProcBase::OUTPUT do_vlc_empty_req(CMB * mb);
  CProcBase::OUTPUT do_send_pq();

  text m_hw_ver[12];
};

class MyBaseSubmitter;

class MyAccumulatorBlock
{
public:
  MyAccumulatorBlock(ni block_size, ni max_item_length, MyBaseSubmitter * submitter, truefalse auto_submit = false);
  ~MyAccumulatorBlock();

  DVOID reset();
  truefalse add(CONST text * item, ni len = 0);
  truefalse add(text c);
  CONST text * data();
  ni data_len() CONST;

private:
  enum {ITEM_SEPARATOR = ';' };

  CMB * m_current_block;
  text * m_current_ptr;
  ni m_max_item_length;
  ni m_block_size;
  MyBaseSubmitter * m_submitter;
  truefalse m_auto_submit;
};

class MyBaseSubmitter
{
public:
  virtual ~MyBaseSubmitter();

  DVOID submit();
  DVOID add_block(MyAccumulatorBlock * block);
  DVOID check_time_out();

protected:
  typedef std::list<MyAccumulatorBlock * > MyBlockList;

  DVOID reset();
  DVOID do_submit(CONST text * cmd);
  virtual CONST text * get_command() CONST = 0;

  MyBlockList m_blocks;
};

class MyFtpFeedbackSubmitter: public MyBaseSubmitter
{
public:
  MyFtpFeedbackSubmitter();
  virtual ~MyFtpFeedbackSubmitter();

  DVOID add(CONST text * dist_id, text ftype, CONST text *client_id, text step, text ok_flag, CONST text * date);

protected:
  virtual CONST text * get_command() CONST;

private:
  enum { BLOCK_SIZE = 1024 };
  MyAccumulatorBlock m_dist_id_block;
  MyAccumulatorBlock m_ftype_block;
  MyAccumulatorBlock m_client_id_block;
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
  DVOID add_ping(CONST text * client_id, CONST ni len);

protected:
  virtual CONST text * get_command() CONST;

private:
  enum { BLOCK_SIZE = 4096 };
  MyAccumulatorBlock m_block;
};

class MyIPVerSubmitter: public MyBaseSubmitter
{
public:
  enum {ID_SEPARATOR = ';' };
  MyIPVerSubmitter();
  DVOID add_data(CONST text * client_id, ni id_len, CONST text * ip, CONST text * ver, CONST text * hwver);

protected:
  virtual CONST text * get_command() CONST;

private:
  enum { BLOCK_SIZE = 2048 };
  MyAccumulatorBlock m_id_block;
  MyAccumulatorBlock m_ip_block;
  MyAccumulatorBlock m_ver_block;
//  MyAccumulatorBlock m_hw_ver1_block;
//  MyAccumulatorBlock m_hw_ver2_block;
};

class MyPcOnOffSubmitter: public MyBaseSubmitter
{
public:
  enum {ID_SEPARATOR = ';' };
  MyPcOnOffSubmitter();
  DVOID add_data(CONST text * client_id, ni id_len, CONST text c_on, CONST text * datetime);

protected:
  virtual CONST text * get_command() CONST;

private:
  enum { BLOCK_SIZE = 2048 };
  MyAccumulatorBlock m_id_block;
  MyAccumulatorBlock m_on_off_block;
  MyAccumulatorBlock m_datetime_block;
};


class MyAdvClickSubmitter: public MyBaseSubmitter
{
public:
  enum {ID_SEPARATOR = ';' };
  MyAdvClickSubmitter();
  DVOID add_data(CONST text * client_id, ni id_len, CONST text * chn, CONST text * pcode, CONST text * number);

protected:
  virtual CONST text * get_command() CONST;

private:
  enum { BLOCK_SIZE = 2048 };
  MyAccumulatorBlock m_id_block;
  MyAccumulatorBlock m_chn_block;
  MyAccumulatorBlock m_pcode_block;
  MyAccumulatorBlock m_number_block;
};

class MyHWAlarmSubmitter: public MyBaseSubmitter
{
public:
  enum {ID_SEPARATOR = ';' };
  MyHWAlarmSubmitter();
  DVOID add_data(CONST text * client_id, ni id_len, CONST text x, CONST text y, CONST text * datetime);

protected:
  virtual CONST text * get_command() CONST;

private:
  enum { BLOCK_SIZE = 2048 };
  MyAccumulatorBlock m_id_block;
  MyAccumulatorBlock m_type_block;
  MyAccumulatorBlock m_value_block;
  MyAccumulatorBlock m_datetime_block;
};

class MyVLCSubmitter: public MyBaseSubmitter
{
public:
  enum {ID_SEPARATOR = ';' };
  MyVLCSubmitter();
  DVOID add_data(CONST text * client_id, ni id_len, CONST text * fn, CONST text * number);

protected:
  virtual CONST text * get_command() CONST;

private:
  enum { BLOCK_SIZE = 4096 };
  MyAccumulatorBlock m_id_block;
  MyAccumulatorBlock m_fn_block;
  MyAccumulatorBlock m_number_block;
};

class MyVLCEmptySubmitter: public MyBaseSubmitter
{
public:
  enum {ID_SEPARATOR = ';' };
  MyVLCEmptySubmitter();
  DVOID add_data(CONST text * client_id, ni id_len, CONST text state);

protected:
  virtual CONST text * get_command() CONST;

private:
  enum { BLOCK_SIZE = 4096 };
  MyAccumulatorBlock m_id_block;
  MyAccumulatorBlock m_state_block;
  MyAccumulatorBlock m_datetime_block;
};


class MyHeartBeatHandler: public CHandlerBase
{
public:
  MyHeartBeatHandler(CConnectionManagerBase * xptr = NULL);
  virtual CTermSNs * client_id_table() CONST;

  DECLARE_MEMORY_POOL__NOTHROW(MyHeartBeatHandler, ACE_Thread_Mutex);
};

class MyHeartBeatService: public CTaskBase
{
public:
  enum { TIMED_DIST_TASK = 1 };

  MyHeartBeatService(CMod * module, ni numThreads = 1);
  virtual ni svc();
  truefalse add_request(CMB * mb, truefalse btail);
  truefalse add_request_slow(CMB * mb);

private:
  enum { MSG_QUEUE_MAX_SIZE = 5 * 1024 * 1024 };

  DVOID do_have_dist_task();
  DVOID do_ftp_file_reply(CMB * mb);
  DVOID do_file_md5_reply(CMB * mb);
  DVOID do_psp(CMB * mb);

  MyClientFileDistributor m_distributor;
  ACE_Message_Queue<ACE_MT_SYNCH> m_queue2;
};

class MyHeartBeatDispatcher: public CDispatchBase
{
public:
  MyHeartBeatDispatcher(CMod * pModule, ni numThreads = 1);
  virtual CONST text * name() CONST;
  virtual ni handle_timeout (CONST ACE_Time_Value &tv, CONST DVOID *act);
  MyHeartBeatAcceptor * acceptor() CONST;

protected:
  virtual DVOID before_finish();
  virtual DVOID before_finish_stage_1();
  virtual truefalse before_begin();

private:
  enum { CLOCK_INTERVAL = 3 }; //seconds
  enum { MSG_QUEUE_MAX_SIZE = 60 * 1024 * 1024 };
  enum { TIMER_ID_HEART_BEAT = 2, TIMER_ID_IP_VER, TIMER_ID_DIST_SERVICE, TIMER_ID_FTP_FEEDBACK, TIMER_ID_ADV_CLICK };
  enum { CLOCK_TICK_HEART_BEAT = 15, //seconds
         CLOCK_TICK_IP_VER = 10, //seconds
         CLOCK_TICK_FTP_FEEDBACK = 15, //seconds
         CLOCK_TICK_ADV_CLICK = 2, //in minutes
         CLOCK_TICK_DIST_SERVICE = 2 //minutes
       };
  MyHeartBeatAcceptor * m_acceptor;
};

class MyHeartBeatAcceptor: public CAcceptorBase
{
public:
  enum { IDLE_TIME_AS_DEAD = 15 }; //in minutes
  MyHeartBeatAcceptor(CDispatchBase * _dispatcher, CConnectionManagerBase * manager);
  virtual ni make_svc_handler(CHandlerBase *& sh);
  virtual CONST text * name() CONST;
};


class MyHeartBeatModule: public CMod
{
public:
  MyHeartBeatModule(CApp * app);
  virtual ~MyHeartBeatModule();
  MyHeartBeatDispatcher * dispatcher() CONST;
  virtual CONST text * name() CONST;
  MyHeartBeatService * service() CONST;
  ni num_active_clients() CONST;
  MyFtpFeedbackSubmitter & ftp_feedback_submitter();
  DVOID pl();
  truefalse get_pl(CMemGuard & value);

protected:
  virtual truefalse before_begin();
  virtual DVOID before_finish();

private:
  MyPingSubmitter m_ping_sumbitter;
  MyIPVerSubmitter m_ip_ver_submitter;
  MyFtpFeedbackSubmitter m_ftp_feedback_submitter;
  MyAdvClickSubmitter m_adv_click_submitter;
  MyPcOnOffSubmitter m_pc_on_off_submitter;
  MyHWAlarmSubmitter m_hardware_alarm_submitter;
  MyVLCSubmitter m_vlc_submitter;
  MyVLCEmptySubmitter m_vlc_empty_submitter;
  MyHeartBeatService * m_service;
  MyHeartBeatDispatcher * m_dispatcher;
  ACE_Thread_Mutex m_mutex;
  CMemGuard m_pl;
};


/////////////////////////////////////
//dist to BS
/////////////////////////////////////

class MyDistToMiddleModule;

class MyDistToBSProcessor: public CBSProceBase
{
public:
  typedef CBSProceBase baseclass;
  MyDistToBSProcessor(CHandlerBase * handler);
  virtual CONST text * name() CONST;

protected:
  virtual CProcBase::OUTPUT on_recv_packet_i(CMB * mb);

private:
  enum { MSG_QUEUE_MAX_SIZE = 2 * 1024 * 1024 };

  DVOID process_ip_ver_reply(CBSData * bspacket);
  DVOID process_ip_ver_reply_one(text * item);
};

class MyDistToBSHandler: public CHandlerBase
{
public:
  MyDistToBSHandler(CConnectionManagerBase * xptr = NULL);
  MyDistToMiddleModule * module_x() CONST;
  virtual ni handle_timeout (CONST ACE_Time_Value &current_time, CONST DVOID *act = 0);
  DVOID checker_update();
  DECLARE_MEMORY_POOL__NOTHROW(MyDistToBSHandler, ACE_Thread_Mutex);

protected:
  virtual DVOID on_close();
  virtual ni  on_open();

private:
  MyActChecker m_checker;
};

class MyDistToBSConnector: public CConnectorBase
{
public:
  MyDistToBSConnector(CDispatchBase * _dispatcher, CConnectionManagerBase * _manager);
  virtual ni make_svc_handler(CHandlerBase *& sh);
  virtual CONST text * name() CONST;

protected:
  enum { RECONNECT_INTERVAL = 1 }; //time in minutes
};


/////////////////////////////////////
//dist to middle module
/////////////////////////////////////

class MyDistToMiddleModule;
class MyDistToMiddleConnector;

class MyDistToMiddleProcessor: public CClientProcBase
{
public:
  typedef CClientProcBase baseclass;

  MyDistToMiddleProcessor(CHandlerBase * handler);
  virtual CProcBase::OUTPUT on_recv_header();
  virtual ni on_open();
  ni send_server_load();

protected:
  virtual CProcBase::OUTPUT on_recv_packet_i(CMB * mb);

private:
  enum { IP_ADDR_LENGTH = INET_ADDRSTRLEN };
  enum { MSG_QUEUE_MAX_SIZE = 512 * 1024 };

  ni send_version_check_req();
  CProcBase::OUTPUT do_version_check_reply(CMB * mb);
  CProcBase::OUTPUT do_have_dist_task(CMB * mb);
  CProcBase::OUTPUT do_remote_cmd_task(CMB * mb);

  truefalse m_version_check_reply_done;
  text m_local_addr[IP_ADDR_LENGTH];
};

class MyDistToMiddleHandler: public CHandlerBase
{
public:
  MyDistToMiddleHandler(CConnectionManagerBase * xptr = NULL);
  virtual ni handle_timeout (CONST ACE_Time_Value &current_time, CONST DVOID *act = 0);
  DVOID setup_timer();
  MyDistToMiddleModule * module_x() CONST;
  DECLARE_MEMORY_POOL__NOTHROW(MyDistToMiddleHandler, ACE_Thread_Mutex);

protected:
  virtual DVOID on_close();
  virtual ni  on_open();

private:
  enum { LOAD_BALANCE_REQ_TIMER = 1 };
  enum { LOAD_BALANCE_REQ_INTERVAL = 2 }; //in minutes
  long m_load_balance_req_timer_id;
};

class MyDistToMiddleDispatcher: public CDispatchBase
{
public:
  MyDistToMiddleDispatcher(CMod * pModule, ni numThreads = 1);
  virtual ~MyDistToMiddleDispatcher();

  virtual CONST text * name() CONST;
  DVOID send_to_bs(CMB * mb);
  DVOID send_to_middle(CMB * mb);

protected:
  virtual DVOID before_finish();
  virtual truefalse before_begin();
  virtual truefalse do_schedule_work();
  virtual DVOID before_finish_stage_1();

private:
  enum { MSG_QUEUE_MAX_SIZE = 5 * 1024 * 1024 };

  MyDistToMiddleConnector * m_connector;
  MyDistToBSConnector * m_bs_connector;
  ACE_Message_Queue<ACE_MT_SYNCH> m_to_bs_queue;
};


class MyDistToMiddleConnector: public CConnectorBase
{
public:
  MyDistToMiddleConnector(CDispatchBase * _dispatcher, CConnectionManagerBase * _manager);
  virtual ni make_svc_handler(CHandlerBase *& sh);
  virtual CONST text * name() CONST;

protected:
  enum { RECONNECT_INTERVAL = 3 }; //time in minutes
};

class MyDistToMiddleModule: public CMod
{
public:
  MyDistToMiddleModule(CApp * app);
  virtual ~MyDistToMiddleModule();
  virtual CONST text * name() CONST;
  DVOID send_to_bs(CMB * mb);
  DVOID send_to_middle(CMB * mb);

protected:
  virtual truefalse before_begin();
  virtual DVOID before_finish();

private:
  MyDistToMiddleDispatcher *m_dispatcher;
};


class MyDB
{
public:
  MyDB();
  ~MyDB();
  SF time_t get_time_from_string(CONST text * s);

  truefalse connect();
  truefalse check_db_connection();
  truefalse ping_db_server();
  truefalse get_client_ids(CTermSNs * idtable);
  truefalse save_client_id(CONST text * s);
  truefalse save_dist(MyHttpDistRequest & http_dist_request, CONST text * md5, CONST text * mbz_md5);
  truefalse save_sr(text * dist_id, CONST text * cmd, text * idlist);
  truefalse save_prio(CONST text * prio);
  truefalse save_dist_clients(text * idlist, text * adirlist, CONST text * dist_id);
  truefalse save_dist_cmp_done(CONST text *dist_id);
  ni  load_dist_infos(MyHttpDistInfos & infos);
  truefalse load_pl(CMemGuard & value);
//  truefalse dist_take_cmp_ownership(MyHttpDistInfo * info);
//  truefalse dist_take_md5_ownership(MyHttpDistInfo * info);
  truefalse dist_mark_cmp_done(CONST text * dist_id);
  truefalse dist_mark_md5_done(CONST text * dist_id);
  truefalse save_dist_md5(CONST text * dist_id, CONST text * md5, ni md5_len);
  truefalse save_dist_ftp_md5(CONST text * dist_id, CONST text * md5);
  truefalse load_dist_clients(MyDistClients * dist_clients, MyDistClientOne * _dc_one);
  truefalse set_dist_client_status(MyDistClient & dist_client, ni new_status);
  truefalse set_dist_client_status(CONST text * client_id, CONST text * dist_id, ni new_status);
  truefalse set_dist_client_md5(CONST text * client_id, CONST text * dist_id, CONST text * md5, ni new_status);
  truefalse set_dist_client_mbz(CONST text * client_id, CONST text * dist_id, CONST text * mbz, CONST text * mbz_md5);
  truefalse delete_dist_client(CONST text * client_id, CONST text * dist_id);
  truefalse dist_info_is_update(MyHttpDistInfos & infos);
  truefalse dist_info_update_status();
  truefalse remove_orphan_dist_info();
  truefalse get_dist_ids(MyUnusedPathRemover & path_remover);
  truefalse mark_client_valid(CONST text * client_id, truefalse valid);

private:
  DVOID disconnect();
  truefalse load_db_server_time_i(time_t &t);
  truefalse connected() CONST;
  truefalse begin_transaction();
  truefalse commit();
  truefalse rollback();
  truefalse exec_command(CONST text * sql_command, ni * affected = NULL);
  DVOID wrap_str(CONST text * s, CMemGuard & wrapped) CONST;
  time_t get_db_time_i();
  truefalse take_owner_ship(CONST text * table, CONST text * field, CMemGuard & old_time, CONST text * where_clause);
  truefalse set_cfg_value(CONST ni id, CONST text * value);
  truefalse load_cfg_value(CONST ni id, CMemGuard & value);
  truefalse load_cfg_value_i(CONST ni id, CMemGuard & value);

  PGconn * m_connection;
  CMemGuard m_server_addr;
  ni m_server_port;
  CMemGuard m_user_name;
  CMemGuard m_password;
  ACE_Thread_Mutex m_mutex;
};

#endif /* SERVERCOMMON_H_ */
