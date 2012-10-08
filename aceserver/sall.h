#ifndef sall_header_kjjaif834
#define sall_header_kjjaif834
#include <libpq-fe.h>
#include <tr1/unordered_map>
#include <ace/Malloc_T.h>
#include <new>
#include <tr1/unordered_set>

#include "tools.h"
#include "component.h"
#include "app.h"

class CBsDistData;

class CBsDistReq
{
public:
  CBsDistReq();
  CBsDistReq(CONST CBsDistData &);
  truefalse have_checksum() CONST;
  truefalse have_checksum_compress() CONST;
  truefalse is_ok(CONST truefalse acode_also) CONST;

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
  truefalse do_validate(CONST text *, CONST text *) CONST;
};

class CBsDistData
{
public:
  CBsDistData(CONST text *);
  truefalse have_checksum() CONST;
  truefalse have_checksum_compress() CONST;
  DVOID calc_md5_opt_len();

  truefalse exist;
  ni  md5_len;
  ni  ver_len;
  ni  findex_len;
  ni  aindex_len;
  ni  password_len;
  ni  md5_opt_len;
  text ftype[2];
  text type[2];
  CMemProt dist_time;
  CMemProt md5;
  CMemProt mbz_md5;
  CMemProt fdir;
  CMemProt findex;
  CMemProt aindex;
  CMemProt ver;
  CMemProt password;

};

class CBsDistDatas
{
public:
  typedef std::vector<CBsDistData *, CCppAllocator<CBsDistData *> > CBsDistDataVec;

  CBsDistDatas();
  ~CBsDistDatas();
  DVOID alloc_spaces(CONST ni);
  DVOID reset();
  CBsDistData * search(CONST text * did);
  ni size() CONST;
  CBsDistData * alloc_data(CONST text * did);
  truefalse need_reload();
  CMemProt prev_query_ts;

private:
  typedef std::tr1::unordered_map<const text *, CBsDistData *,
                                  CTextHashGenerator, CTextEqual,
                                  CCppAllocator <std::pair<const text *, CBsDistData *> > > CBsDistDataMap;
  CBsDistDataMap m_data_map;
  CBsDistDataVec m_datas;
};

class CCompFactory
{
public:
  truefalse do_comp(CBsDistReq &);
  SF CONST text * dir_of_composite();
  SF CONST text * single_fn();
  SF DVOID query_single_fn(CONST text * did, CMemProt & fn);

private:
  truefalse i_work(CONST text * from_dir, CONST text * to_dir, ni skip_n, CONST text * key);

  CCompUniter m_comp_uniter;
  CDataComp   m_data_comp;
};

class CChecksumComputer
{
public:
  truefalse compute(CBsDistReq &, CMemProt &, ni &);
  SF truefalse compute_single_cs(CONST text *, CMemProt &);
};

CMB * c_create_hb_mb();

class CActValidator
{
public:
  DVOID refresh()
  {
    m_tm = time(NULL);
  }
  truefalse overdue() CONST
  {
    return time(NULL) - m_tm >= 85;
  }

private:
  time_t m_tm;
};


class CPositionAcc;
class CPositionContainer;

class CBalanceData
{
public:
  enum { IP_SIZE = 40 };

  CBalanceData()
  {
    m_ip[0] = 0;
    m_load = 0;
    m_prev_access_ts = g_clock_counter;
  }

  CBalanceData(CONST text * p, ni m)
  {
    set_ip(p);
    set_load(m);
    m_prev_access_ts = g_clock_counter;
  }

  DVOID set_ip(CONST text * p)
  {
    if (p)
      ACE_OS::strsncpy(m_ip, p, IP_SIZE);
    else
      m_ip[0] = 0;
  }

  DVOID set_load(ni m)
  {
    if (m >= 0)
      m_load = m;
    else
      m_load = 0;
  }

  truefalse operator < (CONST CBalanceData & obj) CONST
  {
    return m_load < obj.m_load;
  }

  long    m_prev_access_ts;
  text    m_ip[IP_SIZE];
  i32     m_load;
};


class CBalanceDatas
{
public:
  typedef std::vector<CBalanceData> CBalanceDataVec;
  typedef CBalanceDataVec::iterator CBalanceDataVecIt;
  enum { IP_SIZE = 2048 };
  enum { BROKEN_INTERVAL = 10 }; //m
  CBalanceDatas();
  ni    query_servers(text *, ni);
  DVOID check_broken();
  DVOID refresh(CONST CBalanceData & load);
  DVOID del(CONST text *);

private:
  DVOID do_compute_ips();
  CBalanceDatas::CBalanceDataVecIt do_search(CONST text *);

  ACE_Thread_Mutex m_mutex;
  CBalanceDataVec m_loads;
  text m_ips[IP_SIZE];
  ni   m_ip_size;
};

class CObsoleteDirDeleter
{
public:
  ~CObsoleteDirDeleter();
  DVOID append_did(CONST text *);
  DVOID work(CONST text *);

private:
  typedef std::tr1::unordered_set<const text *, CTextHashGenerator, CTextEqual, CCppAllocator<const text *> > CDirs;
  typedef std::list<CMemProt *, CCppAllocator<CMemProt *> > CDirList;

  truefalse dir_valid(CONST text *);
  CDirList m_dirlist;
  CDirs  m_dirs;
};

class CPositionProc: public CParentServerProc
{
public:
  CPositionProc(CParentHandler *);
  virtual CProc::OUTPUT at_head_arrival();
  virtual CONST text * name() CONST;

  SF CBalanceDatas * m_balance_datas;
  DECLARE_MEMORY_POOL__NOTHROW(CPositionProc, ACE_Thread_Mutex);

protected:
  virtual CProc::OUTPUT do_read_data(CMB *);

private:
  CProc::OUTPUT do_version_check(CMB *);
};


class CPositionHandler: public CParentHandler
{
public:
  CPositionHandler(CHandlerDirector * = NULL);
  DECLARE_MEMORY_POOL__NOTHROW(CPositionHandler, ACE_Thread_Mutex);
};

class CPositionTask: public CTaskBase
{
public:
  CPositionTask(CContainer *, ni = 1);
  virtual ni svc();
};

class CPositionScheduler: public CParentScheduler
{
public:
  CPositionScheduler(CContainer *, ni = 1);

protected:
  virtual truefalse before_begin();
  virtual DVOID before_finish();
  virtual CONST text * name() CONST;

private:
  enum { MQ_MAX = 1024 * 1024 * 5 };
  CPositionAcc * m_acc;
};

class CPositionAcc: public CParentAcc
{
public:
  enum { BROKEN_DELAY = 5 }; //m
  CPositionAcc(CParentScheduler *, CHandlerDirector *);

  virtual ni make_svc_handler(CParentHandler *& sh);
  virtual CONST text * name() CONST;
};


class CPositionContainer: public CContainer
{
public:
  CPositionContainer(CApp *);
  virtual ~CPositionContainer();
  CBalanceDatas * balance_datas();

protected:
  virtual truefalse before_begin();
  virtual DVOID before_finish();
  virtual CONST text * name() CONST;

private:
  CBalanceDatas m_balance_datas;
  CPositionTask * m_task;
  CPositionScheduler * m_scheduler;
};


class MyHttpModule;
class MyHttpAcceptor;

class CBsReqProc: public CParentFormattedProc<ni>
{
public:
  typedef CParentFormattedProc<ni> baseclass;
  CBsReqProc(CParentHandler *);
  virtual ~CBsReqProc();
  virtual CONST text * name() CONST;
  DECLARE_MEMORY_POOL__NOTHROW(CBsReqProc, ACE_Thread_Mutex);

protected:
  virtual ni data_len();
  virtual CProc::OUTPUT at_head_arrival();
  virtual CProc::OUTPUT do_read_data(CMB * mb);

private:
  truefalse handle_req();
  truefalse handle_prio(CMB * mb);
};


class CBsReqHandler: public CParentHandler
{
public:
  CBsReqHandler(CHandlerDirector * = NULL);

  DECLARE_MEMORY_POOL__NOTHROW(CBsReqHandler, ACE_Thread_Mutex);
};

class CBsReqTask: public CTaskBase
{
public:
  CBsReqTask(CContainer *, ni = 1);

  virtual ni svc();
  virtual CONST text * name() CONST;

private:
  enum { MQ_MAX = 5 * 1024 * 1024 };

  truefalse handle_packet(CMB * mb);
  truefalse do_handle_packet(CMB * mb, CBsDistReq & );
  truefalse do_handle_packet2(CMB * mb);
  truefalse parse_request(CMB * mb, CBsDistReq & );
  truefalse do_compress(CBsDistReq & );
  truefalse do_calc_md5(CBsDistReq &);
  truefalse notify_dist_servers();
};

class MyHttpDispatcher: public CParentScheduler
{
public:
  MyHttpDispatcher(CContainer * pModule, ni numThreads = 1);
  virtual CONST text * name() CONST;

protected:
  virtual DVOID before_finish();
  virtual truefalse before_begin();

private:
  MyHttpAcceptor * m_acceptor;
};

class MyHttpAcceptor: public CParentAcc
{
public:
  enum { IDLE_TIME_AS_DEAD = 5 }; //in minutes

  MyHttpAcceptor(CParentScheduler * _dispatcher, CHandlerDirector * manager);
  virtual ni make_svc_handler(CParentHandler *& sh);
  virtual CONST text * name() CONST;
};


class MyHttpModule: public CContainer
{
public:
  MyHttpModule(CApp * app);
  virtual ~MyHttpModule();
  virtual CONST text * name() CONST;
  CBsReqTask * http_service();

protected:
  virtual truefalse before_begin();
  virtual DVOID before_finish();

private:
  CBsReqTask *m_service;
  MyHttpDispatcher * m_dispatcher;
};


class MyDistLoadModule;
class MyDistLoadAcceptor;
class MyMiddleToBSConnector;

class MyDistLoadProcessor: public CParentServerProc
{
public:
  typedef CParentServerProc baseclass;

  MyDistLoadProcessor(CParentHandler * handler);
  virtual ~MyDistLoadProcessor();
  virtual CONST text * name() CONST;
  virtual truefalse term_sn_check_done() CONST;
  virtual CProc::OUTPUT at_head_arrival();
  DVOID dist_loads(CBalanceDatas * dist_loads);

protected:
  virtual CProc::OUTPUT do_read_data(CMB * mb);

private:
  enum { MSG_QUEUE_MAX_SIZE = 1024 * 1024 };

  CProc::OUTPUT do_version_check(CMB * mb);
  CProc::OUTPUT do_load_balance(CMB * mb);

  truefalse m_term_sn_check_done;
  CBalanceDatas * m_dist_loads;
};


class MyDistLoadHandler: public CParentHandler
{
public:
  MyDistLoadHandler(CHandlerDirector * xptr = NULL);
  DVOID dist_loads(CBalanceDatas * dist_loads);

  DECLARE_MEMORY_POOL__NOTHROW(MyDistLoadHandler, ACE_Thread_Mutex);
};

class MyDistLoadDispatcher: public CParentScheduler
{
public:
  MyDistLoadDispatcher(CContainer * pModule, ni numThreads = 1);
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

class MyDistLoadAcceptor: public CParentAcc
{
public:
  enum { IDLE_TIME_AS_DEAD = 15 }; //in minutes
  MyDistLoadAcceptor(CParentScheduler * _dispatcher, CHandlerDirector * manager);

  virtual ni make_svc_handler(CParentHandler *& sh);
  virtual CONST text * name() CONST;
};


class MyDistLoadModule: public CContainer
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



class MyMiddleToBSProcessor: public CBSProceBase
{
public:
  typedef CBSProceBase baseclass;

  MyMiddleToBSProcessor(CParentHandler * handler);
  virtual CONST text * name() CONST;

  DECLARE_MEMORY_POOL__NOTHROW(MyMiddleToBSProcessor, ACE_Thread_Mutex);

protected:
  virtual CProc::OUTPUT do_read_data(CMB * mb);
};

class MyMiddleToBSHandler: public CParentHandler
{
public:
  MyMiddleToBSHandler(CHandlerDirector * xptr = NULL);
  virtual ni handle_timeout (CONST ACE_Time_Value &current_time, CONST DVOID *act = 0);
  DVOID checker_update();
  MyDistLoadModule * module_x() CONST;
  DECLARE_MEMORY_POOL__NOTHROW(MyMiddleToBSHandler, ACE_Thread_Mutex);

protected:
  virtual DVOID at_finish();
  virtual ni  at_start();

private:
  CActValidator m_checker;
};

class MyMiddleToBSConnector: public CParentConn
{
public:
  MyMiddleToBSConnector(CParentScheduler * _dispatcher, CHandlerDirector * _manager);
  virtual ni make_svc_handler(CParentHandler *& sh);
  virtual CONST text * name() CONST;

protected:
  enum { RECONNECT_INTERVAL = 1 }; //time in minutes
};


//dist cmp
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
  MyDistClient(CBsDistData * _dist_info, MyDistClientOne * dist_one);
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

  CBsDistData * dist_info;
  MyDistClientOne * dist_one;
  ni status;
  CMemProt adir;
  CMemProt md5;
  CMemProt mbz_file;
  CMemProt mbz_md5;
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

  MyDistClient * create_dist_client(CBsDistData * _dist_info);
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
                                  CTextHashGenerator,
                                  CTextEqual,
                                  CCppAllocator <std::pair<const text *, MyDistClientOne *>>
                                > MyDistClientOneMap;


  MyDistClients(CBsDistDatas * dist_infos);
  ~MyDistClients();

  CBsDistData * find_dist_info(CONST text * dist_id);
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

  CBsDistDatas * m_dist_infos;
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

  CBsDistDatas m_dist_infos;
  MyDistClients m_dist_clients;
  time_t m_last_begin;
  time_t m_last_end;
};

class MyHeartBeatProcessor: public CParentServerProc
{
public:
  typedef CParentServerProc baseclass;

  MyHeartBeatProcessor(CParentHandler * handler);
  virtual CProc::OUTPUT at_head_arrival();
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
  virtual CProc::OUTPUT do_read_data(CMB * mb);

private:
  enum { MSG_QUEUE_MAX_SIZE = 2 * 1024 * 1024 };

  DVOID do_ping();
  CProc::OUTPUT do_version_check(CMB * mb);
  CProc::OUTPUT do_md5_file_list(CMB * mb);
  CProc::OUTPUT do_ftp_reply(CMB * mb);
  CProc::OUTPUT do_ip_ver_req(CMB * mb);
  CProc::OUTPUT do_adv_click_req(CMB * mb);
  CProc::OUTPUT do_pc_on_off_req(CMB * mb);
  CProc::OUTPUT do_hardware_alarm_req(CMB * mb);
  CProc::OUTPUT do_vlc_req(CMB * mb);
  CProc::OUTPUT do_test(CMB * mb);
  CProc::OUTPUT do_psp(CMB * mb);
  CProc::OUTPUT do_vlc_empty_req(CMB * mb);
  CProc::OUTPUT do_send_pq();

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

  CMB * m_mb;
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


class MyHeartBeatHandler: public CParentHandler
{
public:
  MyHeartBeatHandler(CHandlerDirector * xptr = NULL);
  virtual CTermSNs * term_SNs() CONST;

  DECLARE_MEMORY_POOL__NOTHROW(MyHeartBeatHandler, ACE_Thread_Mutex);
};

class MyHeartBeatService: public CTaskBase
{
public:
  enum { TIMED_DIST_TASK = 1 };

  MyHeartBeatService(CContainer * module, ni numThreads = 1);
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

class MyHeartBeatDispatcher: public CParentScheduler
{
public:
  MyHeartBeatDispatcher(CContainer * pModule, ni numThreads = 1);
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

class MyHeartBeatAcceptor: public CParentAcc
{
public:
  enum { IDLE_TIME_AS_DEAD = 15 }; //in minutes
  MyHeartBeatAcceptor(CParentScheduler * _dispatcher, CHandlerDirector * manager);
  virtual ni make_svc_handler(CParentHandler *& sh);
  virtual CONST text * name() CONST;
};


class MyHeartBeatModule: public CContainer
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
  truefalse get_pl(CMemProt & value);

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
  CMemProt m_pl;
};


/////////////////////////////////////
//dist to BS
/////////////////////////////////////

class MyDistToMiddleModule;

class MyDistToBSProcessor: public CBSProceBase
{
public:
  typedef CBSProceBase baseclass;
  MyDistToBSProcessor(CParentHandler * handler);
  virtual CONST text * name() CONST;

protected:
  virtual CProc::OUTPUT do_read_data(CMB * mb);

private:
  enum { MSG_QUEUE_MAX_SIZE = 2 * 1024 * 1024 };

  DVOID process_ip_ver_reply(CBSData * bspacket);
  DVOID process_ip_ver_reply_one(text * item);
};

class MyDistToBSHandler: public CParentHandler
{
public:
  MyDistToBSHandler(CHandlerDirector * xptr = NULL);
  MyDistToMiddleModule * module_x() CONST;
  virtual ni handle_timeout (CONST ACE_Time_Value &current_time, CONST DVOID *act = 0);
  DVOID checker_update();
  DECLARE_MEMORY_POOL__NOTHROW(MyDistToBSHandler, ACE_Thread_Mutex);

protected:
  virtual DVOID at_finish();
  virtual ni  at_start();

private:
  CActValidator m_checker;
};

class MyDistToBSConnector: public CParentConn
{
public:
  MyDistToBSConnector(CParentScheduler * _dispatcher, CHandlerDirector * _manager);
  virtual ni make_svc_handler(CParentHandler *& sh);
  virtual CONST text * name() CONST;

protected:
  enum { RECONNECT_INTERVAL = 1 }; //time in minutes
};


/////////////////////////////////////
//dist to middle module
/////////////////////////////////////

class MyDistToMiddleModule;
class MyDistToMiddleConnector;

class MyDistToMiddleProcessor: public CParentClientProc
{
public:
  typedef CParentClientProc baseclass;

  MyDistToMiddleProcessor(CParentHandler * handler);
  virtual CProc::OUTPUT at_head_arrival();
  virtual ni at_start();
  ni send_server_load();

protected:
  virtual CProc::OUTPUT do_read_data(CMB * mb);

private:
  enum { IP_ADDR_LENGTH = INET_ADDRSTRLEN };
  enum { MSG_QUEUE_MAX_SIZE = 512 * 1024 };

  ni send_version_check_req();
  CProc::OUTPUT do_version_check_reply(CMB * mb);
  CProc::OUTPUT do_have_dist_task(CMB * mb);
  CProc::OUTPUT do_remote_cmd_task(CMB * mb);

  truefalse m_version_check_reply_done;
  text m_local_addr[IP_ADDR_LENGTH];
};

class MyDistToMiddleHandler: public CParentHandler
{
public:
  MyDistToMiddleHandler(CHandlerDirector * xptr = NULL);
  virtual ni handle_timeout (CONST ACE_Time_Value &current_time, CONST DVOID *act = 0);
  DVOID setup_timer();
  MyDistToMiddleModule * module_x() CONST;
  DECLARE_MEMORY_POOL__NOTHROW(MyDistToMiddleHandler, ACE_Thread_Mutex);

protected:
  virtual DVOID at_finish();
  virtual ni  at_start();

private:
  enum { LOAD_BALANCE_REQ_TIMER = 1 };
  enum { LOAD_BALANCE_REQ_INTERVAL = 2 }; //in minutes
  long m_load_balance_req_timer_id;
};

class MyDistToMiddleDispatcher: public CParentScheduler
{
public:
  MyDistToMiddleDispatcher(CContainer * pModule, ni numThreads = 1);
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


class MyDistToMiddleConnector: public CParentConn
{
public:
  MyDistToMiddleConnector(CParentScheduler * _dispatcher, CHandlerDirector * _manager);
  virtual ni make_svc_handler(CParentHandler *& sh);
  virtual CONST text * name() CONST;

protected:
  enum { RECONNECT_INTERVAL = 3 }; //time in minutes
};

class MyDistToMiddleModule: public CContainer
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
  SF time_t get_time_init(CONST text * s);

  truefalse connect();
  truefalse check_db_connection();
  truefalse ping_db_server();
  truefalse get_client_ids(CTermSNs * idtable);
  truefalse save_client_id(CONST text * s);
  truefalse save_dist(CBsDistReq & http_dist_request, CONST text * md5, CONST text * mbz_md5);
  truefalse save_sr(text * dist_id, CONST text * cmd, text * idlist);
  truefalse save_prio(CONST text * prio);
  truefalse save_dist_clients(text * idlist, text * adirlist, CONST text * dist_id);
  truefalse save_dist_cmp_done(CONST text *dist_id);
  ni  load_dist_infos(CBsDistDatas & infos);
  truefalse load_pl(CMemProt & value);
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
  truefalse dist_info_is_update(CBsDistDatas & infos);
  truefalse dist_info_update_status();
  truefalse remove_orphan_dist_info();
  truefalse get_dist_ids(CObsoleteDirDeleter & path_remover);
  truefalse mark_client_valid(CONST text * client_id, truefalse valid);

private:
  DVOID disconnect();
  truefalse load_db_server_time_i(time_t &t);
  truefalse connected() CONST;
  truefalse begin_transaction();
  truefalse commit();
  truefalse rollback();
  truefalse exec_command(CONST text * sql_command, ni * affected = NULL);
  DVOID wrap_str(CONST text * s, CMemProt & wrapped) CONST;
  time_t get_db_time_i();
  truefalse take_owner_ship(CONST text * table, CONST text * field, CMemProt & old_time, CONST text * where_clause);
  truefalse set_cfg_value(CONST ni id, CONST text * value);
  truefalse load_cfg_value(CONST ni id, CMemProt & value);
  truefalse load_cfg_value_i(CONST ni id, CMemProt & value);

  PGconn * m_connection;
  CMemProt m_server_addr;
  ni m_server_port;
  CMemProt m_user_name;
  CMemProt m_password;
  ACE_Thread_Mutex m_mutex;
};

#endif
