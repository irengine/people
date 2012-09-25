#ifndef SERVERCOMMON_H_
#define SERVERCOMMON_H_
#include <libpq-fe.h>
#include <tr1/unordered_map>
#include <ace/Malloc_T.h>
#include <new>
#include <tr1/unordered_set>

#include "tools.h"
#include "component.h"

class MyHttpDistInfo;

class MyHttpDistRequest
{
public:
  MyHttpDistRequest();
  MyHttpDistRequest(const MyHttpDistInfo & info);

  bool check_valid(const bool check_acode) const;
  bool need_md5() const;
  bool need_mbz_md5() const;

  char * acode;
  char * ftype;
  char * fdir;
  char * findex;
  char * adir;
  char * aindex;
  char * ver;
  char * type;
  char * password;

private:
  bool check_value(const char * value, const char * value_name) const;
};

class MyHttpDistInfo
{
public:
  MyHttpDistInfo(const char * dist_id);
  bool need_md5() const;
  bool need_mbz_md5() const;
  void calc_md5_opt_len();

  char ftype[2];
  char type[2];
  CMemGuard fdir;
  CMemGuard findex;
  CMemGuard aindex;
  CMemGuard ver;
  CMemGuard password;

  CMemGuard dist_time;
  CMemGuard md5;

  CMemGuard mbz_md5;

  bool exist;

  int  md5_len;
  int  ver_len;
  int  findex_len;
  int  aindex_len;
  int  password_len;

  int  md5_opt_len;
};

class MyHttpDistInfos
{
public:
  typedef std::vector<MyHttpDistInfo *, CCppAllocator<MyHttpDistInfo *> > MyHttpDistInfoList;

  MyHttpDistInfos();
  ~MyHttpDistInfos();

  int count() const;
  MyHttpDistInfo * create_http_dist_info(const char * dist_id);
  bool need_reload();
  void prepare_update(const int capacity);
  void clear();
  MyHttpDistInfo * find(const char * dist_id);

  CMemGuard last_load_time;

private:
  typedef std::tr1::unordered_map<const char *,
                                  MyHttpDistInfo *,
                                  CStrHasher,
                                  CStrEqual,
                                  CCppAllocator <std::pair<const char *, MyHttpDistInfo *> >
                                > MyHttpDistInfoMap;

  MyHttpDistInfoList dist_infos;
  MyHttpDistInfoMap  m_info_map;
};

class MyDistCompressor
{
public:
  bool compress(MyHttpDistRequest & http_dist_request);
  static void get_all_in_one_mbz_file_name(const char * dist_id, CMemGuard & filename);
  static const char * composite_path();
  static const char * all_in_one_mbz();

private:
  bool do_generate_compressed_files(const char * src_path, const char * dest_path, int prefix_len, const char * passwrod);

  CCompCombiner m_compositor;
  CDataComp m_compressor;
};

class MyDistMd5Calculator
{
public:
  bool calculate(MyHttpDistRequest & http_dist_request, CMemGuard &md5_result, int & md5_len);
  static bool calculate_all_in_one_ftp_md5(const char * dist_id, CMemGuard & md5_result);
};

ACE_Message_Block * my_get_hb_mb();

class MyActChecker
{
public:
  void update()
  {
    m_tm = time(NULL);
  }
  bool expired() const
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

  MyDistLoad(const char * _addr, int m)
  {
    ip_addr(_addr);
    clients_connected(m);
    m_last_access = g_clock_counter;
  }

  void ip_addr(const char * _addr)
  {
    if (_addr)
      ACE_OS::strsncpy(m_ip_addr, _addr, IP_ADDR_LEN);
    else
      m_ip_addr[0] = 0;
  }

  void clients_connected(int m)
  {
    if (m >= 0)
      m_clients_connected = m;
    else
      m_clients_connected = 0;
  }

  bool operator < (const MyDistLoad & rhs) const
  {
    return m_clients_connected < rhs.m_clients_connected;
  }

  enum
  {
    IP_ADDR_LEN = 40
  };

  char    m_ip_addr[IP_ADDR_LEN];
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

  void update(const MyDistLoad & load);
  void remove(const char * addr);
  int  get_server_list(char * buffer, int buffer_len);
  void scan_for_dead();

private:
  void calc_server_list();
  MyDistLoads::MyDistLoadVecIt find_i(const char * addr);

  MyDistLoadVec m_loads;
  char m_server_list[SERVER_LIST_LENGTH];
  int  m_server_list_length;
  ACE_Thread_Mutex m_mutex;
};

class MyUnusedPathRemover
{
public:
  ~MyUnusedPathRemover();

  void add_dist_id(const char * dist_id);
  void check_path(const char * path);

private:
  typedef std::tr1::unordered_set<const char *, CStrHasher, CStrEqual, CCppAllocator<const char *> > MyPathSet;
  typedef std::list<CMemGuard *, CCppAllocator<CMemGuard *> > MyPathList;

  bool path_ok(const char * _path);

  MyPathSet  m_path_set;
  MyPathList m_path_list;
};

class MyLocationProcessor: public CServerProcBase
{
public:
  MyLocationProcessor(CHandlerBase * handler);
  virtual CProcBase::EVENT_RESULT on_recv_header();
  virtual const char * name() const;

  static MyDistLoads * m_dist_loads;

  DECLARE_MEMORY_POOL__NOTHROW(MyLocationProcessor, ACE_Thread_Mutex);

protected:
  virtual CProcBase::EVENT_RESULT on_recv_packet_i(ACE_Message_Block * mb);

private:
  CProcBase::EVENT_RESULT do_version_check(ACE_Message_Block * mb);
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
  MyLocationService(CMod * module, int numThreads = 1);
  virtual int svc();
};

class MyLocationDispatcher: public CDispatchBase
{
public:
  MyLocationDispatcher(CMod * _module, int numThreads = 1);

protected:
  virtual bool on_start();
  virtual void on_stop();
  virtual const char * name() const;

private:
  enum { MSG_QUEUE_MAX_SIZE = 5 * 1024 * 1024 };

  MyLocationAcceptor * m_acceptor;
};

class MyLocationAcceptor: public CAcceptorBase
{
public:
  enum { IDLE_TIME_AS_DEAD = 5 }; //in minutes
  MyLocationAcceptor(CDispatchBase * _dispatcher, CConnectionManagerBase * manager);

  virtual int make_svc_handler(CHandlerBase *& sh);
  virtual const char * name() const;
};


class MyLocationModule: public CMod
{
public:
  MyLocationModule(CApp * app);
  virtual ~MyLocationModule();
  MyDistLoads * dist_loads();

protected:
  virtual bool on_start();
  virtual void on_stop();
  virtual const char * name() const;

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

class MyHttpProcessor: public CFormattedProcBase<int>
{
public:
  typedef CFormattedProcBase<int> super;

  MyHttpProcessor(CHandlerBase * handler);
  virtual ~MyHttpProcessor();
  virtual const char * name() const;
  DECLARE_MEMORY_POOL__NOTHROW(MyHttpProcessor, ACE_Thread_Mutex);

protected:
  virtual int packet_length();
  virtual CProcBase::EVENT_RESULT on_recv_header();
  virtual CProcBase::EVENT_RESULT on_recv_packet_i(ACE_Message_Block * mb);

private:
  bool do_process_input_data();
  bool do_prio(ACE_Message_Block * mb);
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
  MyHttpService(CMod * module, int numThreads = 1);

  virtual int svc();
  virtual const char * name() const;

private:
  enum { MSG_QUEUE_MAX_SIZE = 5 * 1024 * 1024 };

  bool handle_packet(ACE_Message_Block * mb);
  bool do_handle_packet(ACE_Message_Block * mb, MyHttpDistRequest & http_dist_request);
  bool do_handle_packet2(ACE_Message_Block * mb);
  bool parse_request(ACE_Message_Block * mb, MyHttpDistRequest & http_dist_request);
  bool do_compress(MyHttpDistRequest & http_dist_request);
  bool do_calc_md5(MyHttpDistRequest & http_dist_request);
  bool notify_dist_servers();
};

class MyHttpDispatcher: public CDispatchBase
{
public:
  MyHttpDispatcher(CMod * pModule, int numThreads = 1);
  virtual const char * name() const;

protected:
  virtual void on_stop();
  virtual bool on_start();

private:
  MyHttpAcceptor * m_acceptor;
};

class MyHttpAcceptor: public CAcceptorBase
{
public:
  enum { IDLE_TIME_AS_DEAD = 5 }; //in minutes

  MyHttpAcceptor(CDispatchBase * _dispatcher, CConnectionManagerBase * manager);
  virtual int make_svc_handler(CHandlerBase *& sh);
  virtual const char * name() const;
};


class MyHttpModule: public CMod
{
public:
  MyHttpModule(CApp * app);
  virtual ~MyHttpModule();
  virtual const char * name() const;
  MyHttpService * http_service();

protected:
  virtual bool on_start();
  virtual void on_stop();

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
  typedef CServerProcBase super;

  MyDistLoadProcessor(CHandlerBase * handler);
  virtual ~MyDistLoadProcessor();
  virtual const char * name() const;
  virtual bool client_id_verified() const;
  virtual CProcBase::EVENT_RESULT on_recv_header();
  void dist_loads(MyDistLoads * dist_loads);

protected:
  virtual CProcBase::EVENT_RESULT on_recv_packet_i(ACE_Message_Block * mb);

private:
  enum { MSG_QUEUE_MAX_SIZE = 1024 * 1024 };

  CProcBase::EVENT_RESULT do_version_check(ACE_Message_Block * mb);
  CProcBase::EVENT_RESULT do_load_balance(ACE_Message_Block * mb);

  bool m_client_id_verified;
  MyDistLoads * m_dist_loads;
};


class MyDistLoadHandler: public CHandlerBase
{
public:
  MyDistLoadHandler(CConnectionManagerBase * xptr = NULL);
  void dist_loads(MyDistLoads * dist_loads);

  DECLARE_MEMORY_POOL__NOTHROW(MyDistLoadHandler, ACE_Thread_Mutex);
};

class MyDistLoadDispatcher: public CDispatchBase
{
public:
  MyDistLoadDispatcher(CMod * pModule, int numThreads = 1);
  ~MyDistLoadDispatcher();
  virtual const char * name() const;
  virtual int handle_timeout(const ACE_Time_Value &current_time, const void *act = 0);
  void send_to_bs(ACE_Message_Block * mb);

protected:
  virtual void on_stop();
  virtual bool on_start();
  virtual bool on_event_loop();

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

  virtual int make_svc_handler(CHandlerBase *& sh);
  virtual const char * name() const;
};


class MyDistLoadModule: public CMod
{
public:
  MyDistLoadModule(CApp * app);
  virtual ~MyDistLoadModule();
  virtual const char * name() const;
  MyDistLoadDispatcher * dispatcher() const;

protected:
  virtual bool on_start();
  virtual void on_stop();

private:
  MyDistLoadDispatcher * m_dispatcher;
};



/////////////////////////////////////
//middle to BS
/////////////////////////////////////

class MyMiddleToBSProcessor: public CBSProceBase
{
public:
  typedef CBSProceBase super;

  MyMiddleToBSProcessor(CHandlerBase * handler);
  virtual const char * name() const;

  DECLARE_MEMORY_POOL__NOTHROW(MyMiddleToBSProcessor, ACE_Thread_Mutex);

protected:
  virtual CProcBase::EVENT_RESULT on_recv_packet_i(ACE_Message_Block * mb);
};

class MyMiddleToBSHandler: public CHandlerBase
{
public:
  MyMiddleToBSHandler(CConnectionManagerBase * xptr = NULL);
  virtual int handle_timeout (const ACE_Time_Value &current_time, const void *act = 0);
  void checker_update();
  MyDistLoadModule * module_x() const;
  DECLARE_MEMORY_POOL__NOTHROW(MyMiddleToBSHandler, ACE_Thread_Mutex);

protected:
  virtual void on_close();
  virtual int  on_open();

private:
  MyActChecker m_checker;
};

class MyMiddleToBSConnector: public CConnectorBase
{
public:
  MyMiddleToBSConnector(CDispatchBase * _dispatcher, CConnectionManagerBase * _manager);
  virtual int make_svc_handler(CHandlerBase *& sh);
  virtual const char * name() const;

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
  bool check_valid() const;
  bool dist_file();
  void delete_self();
  bool active();
  void update_status(int _status);
  void update_md5_list(const char * _md5);
  void dist_ftp_md5_reply(const char * md5list);
  const char * client_id() const;
  int client_id_index() const;
  void send_fb_detail(bool ok);
  void psp(const char c);

  MyHttpDistInfo * dist_info;
  MyDistClientOne * dist_one;
  int status;
  CMemGuard adir;
  CMemGuard md5;
  CMemGuard mbz_file;
  CMemGuard mbz_md5;
  time_t last_update;

private:
  enum { MD5_REPLY_TIME_OUT = 15, FTP_REPLY_TIME_OUT = 5 }; //in minutes

  bool do_stage_0();
  bool do_stage_1();
  bool do_stage_2();
  bool do_stage_3();
  bool do_stage_4();
  bool do_stage_5();
  bool do_stage_6();
  bool do_stage_7();
  bool do_stage_8();
  bool send_md5();
  bool send_ftp();
  bool send_psp(const char c);
  bool generate_diff_mbz();
  int  dist_out_leading_length();
  void dist_out_leading_data(char * data);
  ACE_Message_Block * make_ftp_fb_detail_mb(bool bok);
};

class MyDistClientOne
{
public:
  typedef std::list<MyDistClient *, CCppAllocator<MyDistClient *> > MyDistClientOneList;

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
    return c_util_string_hash(x.client_id) ^ c_util_string_hash(x.dist_id);
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
  typedef std::tr1::unordered_map<const char *,
                                  MyDistClientOne *,
                                  CStrHasher,
                                  CStrEqual,
                                  CCppAllocator <std::pair<const char *, MyDistClientOne *>>
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
  void dist_ftp_file_reply(const char * client_id, const char * dist_id, int _status, bool ok);
  void dist_ftp_md5_reply(const char * client_id, const char * dist_id, const char * md5list);
  void psp(const char * client_id, const char * dist_id, char c);

private:
  enum { IDLE_TIME = 5 }; //in minutes

  bool check_dist_info(bool reload);
  bool check_dist_clients(bool reload);

  MyHttpDistInfos m_dist_infos;
  MyDistClients m_dist_clients;
  time_t m_last_begin;
  time_t m_last_end;
};

class MyHeartBeatProcessor: public CServerProcBase
{
public:
  typedef CServerProcBase super;

  MyHeartBeatProcessor(CHandlerBase * handler);
  virtual CProcBase::EVENT_RESULT on_recv_header();
  virtual const char * name() const;

  static MyPingSubmitter * m_heart_beat_submitter;
  static MyIPVerSubmitter * m_ip_ver_submitter;
  static MyFtpFeedbackSubmitter * m_ftp_feedback_submitter;
  static MyAdvClickSubmitter * m_adv_click_submitter;
  static MyPcOnOffSubmitter * m_pc_on_off_submitter;
  static MyHWAlarmSubmitter * m_hardware_alarm_submitter;
  static MyVLCSubmitter * m_vlc_submitter;
  static MyVLCEmptySubmitter * m_vlc_empty_submitter;

  DECLARE_MEMORY_POOL__NOTHROW(MyHeartBeatProcessor, ACE_Thread_Mutex);

protected:
  virtual CProcBase::EVENT_RESULT on_recv_packet_i(ACE_Message_Block * mb);

private:
  enum { MSG_QUEUE_MAX_SIZE = 2 * 1024 * 1024 };

  void do_ping();
  CProcBase::EVENT_RESULT do_version_check(ACE_Message_Block * mb);
  CProcBase::EVENT_RESULT do_md5_file_list(ACE_Message_Block * mb);
  CProcBase::EVENT_RESULT do_ftp_reply(ACE_Message_Block * mb);
  CProcBase::EVENT_RESULT do_ip_ver_req(ACE_Message_Block * mb);
  CProcBase::EVENT_RESULT do_adv_click_req(ACE_Message_Block * mb);
  CProcBase::EVENT_RESULT do_pc_on_off_req(ACE_Message_Block * mb);
  CProcBase::EVENT_RESULT do_hardware_alarm_req(ACE_Message_Block * mb);
  CProcBase::EVENT_RESULT do_vlc_req(ACE_Message_Block * mb);
  CProcBase::EVENT_RESULT do_test(ACE_Message_Block * mb);
  CProcBase::EVENT_RESULT do_psp(ACE_Message_Block * mb);
  CProcBase::EVENT_RESULT do_vlc_empty_req(ACE_Message_Block * mb);
  CProcBase::EVENT_RESULT do_send_pq();

  char m_hw_ver[12];
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
  void add_data(const char * client_id, int id_len, const char * ip, const char * ver, const char * hwver);

protected:
  virtual const char * get_command() const;

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
  void add_data(const char * client_id, int id_len, const char c_on, const char * datetime);

protected:
  virtual const char * get_command() const;

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

class MyHWAlarmSubmitter: public MyBaseSubmitter
{
public:
  enum {ID_SEPARATOR = ';' };
  MyHWAlarmSubmitter();
  void add_data(const char * client_id, int id_len, const char x, const char y, const char * datetime);

protected:
  virtual const char * get_command() const;

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
  void add_data(const char * client_id, int id_len, const char * fn, const char * number);

protected:
  virtual const char * get_command() const;

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
  void add_data(const char * client_id, int id_len, const char state);

protected:
  virtual const char * get_command() const;

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
  virtual CClientIDS * client_id_table() const;

  DECLARE_MEMORY_POOL__NOTHROW(MyHeartBeatHandler, ACE_Thread_Mutex);
};

class MyHeartBeatService: public CTaskBase
{
public:
  enum { TIMED_DIST_TASK = 1 };

  MyHeartBeatService(CMod * module, int numThreads = 1);
  virtual int svc();
  bool add_request(ACE_Message_Block * mb, bool btail);
  bool add_request_slow(ACE_Message_Block * mb);

private:
  enum { MSG_QUEUE_MAX_SIZE = 5 * 1024 * 1024 };

  void do_have_dist_task();
  void do_ftp_file_reply(ACE_Message_Block * mb);
  void do_file_md5_reply(ACE_Message_Block * mb);
  void do_psp(ACE_Message_Block * mb);

  MyClientFileDistributor m_distributor;
  ACE_Message_Queue<ACE_MT_SYNCH> m_queue2;
};

class MyHeartBeatDispatcher: public CDispatchBase
{
public:
  MyHeartBeatDispatcher(CMod * pModule, int numThreads = 1);
  virtual const char * name() const;
  virtual int handle_timeout (const ACE_Time_Value &tv, const void *act);
  MyHeartBeatAcceptor * acceptor() const;

protected:
  virtual void on_stop();
  virtual void on_stop_stage_1();
  virtual bool on_start();

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
  virtual int make_svc_handler(CHandlerBase *& sh);
  virtual const char * name() const;
};


class MyHeartBeatModule: public CMod
{
public:
  MyHeartBeatModule(CApp * app);
  virtual ~MyHeartBeatModule();
  MyHeartBeatDispatcher * dispatcher() const;
  virtual const char * name() const;
  MyHeartBeatService * service() const;
  int num_active_clients() const;
  MyFtpFeedbackSubmitter & ftp_feedback_submitter();
  void pl();
  bool get_pl(CMemGuard & value);

protected:
  virtual bool on_start();
  virtual void on_stop();

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
  typedef CBSProceBase super;
  MyDistToBSProcessor(CHandlerBase * handler);
  virtual const char * name() const;

protected:
  virtual CProcBase::EVENT_RESULT on_recv_packet_i(ACE_Message_Block * mb);

private:
  enum { MSG_QUEUE_MAX_SIZE = 2 * 1024 * 1024 };

  void process_ip_ver_reply(MyBSBasePacket * bspacket);
  void process_ip_ver_reply_one(char * item);
};

class MyDistToBSHandler: public CHandlerBase
{
public:
  MyDistToBSHandler(CConnectionManagerBase * xptr = NULL);
  MyDistToMiddleModule * module_x() const;
  virtual int handle_timeout (const ACE_Time_Value &current_time, const void *act = 0);
  void checker_update();
  DECLARE_MEMORY_POOL__NOTHROW(MyDistToBSHandler, ACE_Thread_Mutex);

protected:
  virtual void on_close();
  virtual int  on_open();

private:
  MyActChecker m_checker;
};

class MyDistToBSConnector: public CConnectorBase
{
public:
  MyDistToBSConnector(CDispatchBase * _dispatcher, CConnectionManagerBase * _manager);
  virtual int make_svc_handler(CHandlerBase *& sh);
  virtual const char * name() const;

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
  typedef CClientProcBase super;

  MyDistToMiddleProcessor(CHandlerBase * handler);
  virtual CProcBase::EVENT_RESULT on_recv_header();
  virtual int on_open();
  int send_server_load();

protected:
  virtual CProcBase::EVENT_RESULT on_recv_packet_i(ACE_Message_Block * mb);

private:
  enum { IP_ADDR_LENGTH = INET_ADDRSTRLEN };
  enum { MSG_QUEUE_MAX_SIZE = 512 * 1024 };

  int send_version_check_req();
  CProcBase::EVENT_RESULT do_version_check_reply(ACE_Message_Block * mb);
  CProcBase::EVENT_RESULT do_have_dist_task(ACE_Message_Block * mb);
  CProcBase::EVENT_RESULT do_remote_cmd_task(ACE_Message_Block * mb);

  bool m_version_check_reply_done;
  char m_local_addr[IP_ADDR_LENGTH];
};

class MyDistToMiddleHandler: public CHandlerBase
{
public:
  MyDistToMiddleHandler(CConnectionManagerBase * xptr = NULL);
  virtual int handle_timeout (const ACE_Time_Value &current_time, const void *act = 0);
  void setup_timer();
  MyDistToMiddleModule * module_x() const;
  DECLARE_MEMORY_POOL__NOTHROW(MyDistToMiddleHandler, ACE_Thread_Mutex);

protected:
  virtual void on_close();
  virtual int  on_open();

private:
  enum { LOAD_BALANCE_REQ_TIMER = 1 };
  enum { LOAD_BALANCE_REQ_INTERVAL = 2 }; //in minutes
  long m_load_balance_req_timer_id;
};

class MyDistToMiddleDispatcher: public CDispatchBase
{
public:
  MyDistToMiddleDispatcher(CMod * pModule, int numThreads = 1);
  virtual ~MyDistToMiddleDispatcher();

  virtual const char * name() const;
  void send_to_bs(ACE_Message_Block * mb);
  void send_to_middle(ACE_Message_Block * mb);

protected:
  virtual void on_stop();
  virtual bool on_start();
  virtual bool on_event_loop();
  virtual void on_stop_stage_1();

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
  virtual int make_svc_handler(CHandlerBase *& sh);
  virtual const char * name() const;

protected:
  enum { RECONNECT_INTERVAL = 3 }; //time in minutes
};

class MyDistToMiddleModule: public CMod
{
public:
  MyDistToMiddleModule(CApp * app);
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


class MyDB
{
public:
  MyDB();
  ~MyDB();
  static time_t get_time_from_string(const char * s);

  bool connect();
  bool check_db_connection();
  bool ping_db_server();
  bool get_client_ids(CClientIDS * idtable);
  bool save_client_id(const char * s);
  bool save_dist(MyHttpDistRequest & http_dist_request, const char * md5, const char * mbz_md5);
  bool save_sr(char * dist_id, const char * cmd, char * idlist);
  bool save_prio(const char * prio);
  bool save_dist_clients(char * idlist, char * adirlist, const char * dist_id);
  bool save_dist_cmp_done(const char *dist_id);
  int  load_dist_infos(MyHttpDistInfos & infos);
  bool load_pl(CMemGuard & value);
//  bool dist_take_cmp_ownership(MyHttpDistInfo * info);
//  bool dist_take_md5_ownership(MyHttpDistInfo * info);
  bool dist_mark_cmp_done(const char * dist_id);
  bool dist_mark_md5_done(const char * dist_id);
  bool save_dist_md5(const char * dist_id, const char * md5, int md5_len);
  bool save_dist_ftp_md5(const char * dist_id, const char * md5);
  bool load_dist_clients(MyDistClients * dist_clients, MyDistClientOne * _dc_one);
  bool set_dist_client_status(MyDistClient & dist_client, int new_status);
  bool set_dist_client_status(const char * client_id, const char * dist_id, int new_status);
  bool set_dist_client_md5(const char * client_id, const char * dist_id, const char * md5, int new_status);
  bool set_dist_client_mbz(const char * client_id, const char * dist_id, const char * mbz, const char * mbz_md5);
  bool delete_dist_client(const char * client_id, const char * dist_id);
  bool dist_info_is_update(MyHttpDistInfos & infos);
  bool dist_info_update_status();
  bool remove_orphan_dist_info();
  bool get_dist_ids(MyUnusedPathRemover & path_remover);
  bool mark_client_valid(const char * client_id, bool valid);

private:
  void disconnect();
  bool load_db_server_time_i(time_t &t);
  bool connected() const;
  bool begin_transaction();
  bool commit();
  bool rollback();
  bool exec_command(const char * sql_command, int * affected = NULL);
  void wrap_str(const char * s, CMemGuard & wrapped) const;
  time_t get_db_time_i();
  bool take_owner_ship(const char * table, const char * field, CMemGuard & old_time, const char * where_clause);
  bool set_cfg_value(const int id, const char * value);
  bool load_cfg_value(const int id, CMemGuard & value);
  bool load_cfg_value_i(const int id, CMemGuard & value);

  PGconn * m_connection;
  CMemGuard m_server_addr;
  int m_server_port;
  CMemGuard m_user_name;
  CMemGuard m_password;
  ACE_Thread_Mutex m_mutex;
};

#endif /* SERVERCOMMON_H_ */
