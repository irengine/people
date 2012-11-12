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

  text * what_;
  text * remote_kind;
  text * remote_path;
  text * remote_file;
  text * local_path;
  text * local_file;
  text * edition;
  text * local_kind;
  text * key;

private:
  truefalse do_validate(CONST text *, CONST text *) CONST;
};

class CBsDistData
{
public:
  CBsDistData(CONST text *);
  truefalse have_checksum() CONST;
  truefalse have_checksum_compress() CONST;
  DVOID calc_checksum_opt_sum();

  truefalse exist;
  ni  checksum_size;
  ni  edition_size;
  ni  remote_file_size;
  ni  local_file_size;
  ni  key_size;
  ni  checksum_opt_size;
  text remote_kind[2];
  text local_kind[2];
  CMemProt when_handleout;
  CMemProt check_sum;
  CMemProt compress_checksum;
  CMemProt remote_path;
  CMemProt remote_file;
  CMemProt local_file;
  CMemProt edition;
  CMemProt key;
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
    return time(NULL) - m_tm >= 90;
  }

private:
  time_t m_tm;
};


class CPositionAcc;
class CPositionContainer;

class CChargeData
{
public:
  enum { IP_SIZE = 40 };

  CChargeData()
  {
    m_ip[0] = 0;
    m_load = 0;
    m_prev_access_ts = g_clock_counter;
  }

  CChargeData(CONST text * p, ni m)
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

  truefalse operator < (CONST CChargeData & obj) CONST
  {
    return m_load < obj.m_load;
  }

  long    m_prev_access_ts;
  text    m_ip[IP_SIZE];
  i32     m_load;
};


class CChargeDatas
{
public:
  typedef std::vector<CChargeData> CChargeDataVec;
  typedef CChargeDataVec::iterator CChargeDataVecIt;
  enum { IP_SIZE = 2048 };
  enum { BROKEN_INTERVAL = 10 }; //m
  CChargeDatas();
  ni    query_servers(text *, ni);
  DVOID check_broken();
  DVOID refresh(CONST CChargeData & load);
  DVOID del(CONST text *);

private:
  DVOID do_compute_ips();
  CChargeDatas::CChargeDataVecIt do_search(CONST text *);

  ACE_Thread_Mutex m_mutex;
  CChargeDataVec m_loads;
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
  virtual CONST text * title() CONST;

  SF CChargeDatas * m_charge_datas;
  xx_enable_cache_easy(CPositionProc, ACE_Thread_Mutex);

protected:
  virtual CProc::OUTPUT do_read_data(CMB *);

private:
  CProc::OUTPUT do_login_check(CMB *);
};


class CPositionHandler: public CParentHandler
{
public:
  CPositionHandler(CHandlerDirector * = NULL);
  xx_enable_cache_easy(CPositionHandler, ACE_Thread_Mutex);
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
  virtual CONST text * title() CONST;

private:
  enum { MQ_PEAK = 5000000 };
  CPositionAcc * m_acc;
};

class CPositionAcc: public CParentAcc
{
public:
  enum { BROKEN_DELAY = 5 }; //m
  CPositionAcc(CParentScheduler *, CHandlerDirector *);

  virtual ni make_svc_handler(CParentHandler *&);
  virtual CONST text * title() CONST;
};


class CPositionContainer: public CContainer
{
public:
  CPositionContainer(CParentRunner *);
  virtual ~CPositionContainer();
  CChargeDatas * charge_datas();

protected:
  virtual truefalse before_begin();
  virtual DVOID before_finish();
  virtual CONST text * title() CONST;

private:
  CChargeDatas m_charge_datas;
  CPositionTask * m_task;
  CPositionScheduler * m_scheduler;
};


class CBsReqContainer;
class CBsReqAcc;

class CBsReqProc: public CParentFormattedProc<ni>
{
public:
  typedef CParentFormattedProc<ni> baseclass;
  CBsReqProc(CParentHandler *);
  virtual ~CBsReqProc();
  virtual CONST text * title() CONST;
  xx_enable_cache_easy(CBsReqProc, ACE_Thread_Mutex);

protected:
  virtual ni data_len();
  virtual CProc::OUTPUT at_head_arrival();
  virtual CProc::OUTPUT do_read_data(CMB *);

private:
  truefalse handle_req();
  truefalse handle_prio(CMB *);
};


class CBsReqHandler: public CParentHandler
{
public:
  CBsReqHandler(CHandlerDirector * = NULL);

  xx_enable_cache_easy(CBsReqHandler, ACE_Thread_Mutex);
};

class CBsReqTask: public CTaskBase
{
public:
  CBsReqTask(CContainer *, ni = 1);
  virtual ni svc();
  virtual CONST text * title() CONST;

private:
  enum { MQ_PEAK = 5000000 };

  truefalse process_mb(CMB * mb);
  truefalse process_mb_i(CMB * mb, CBsDistReq & );
  truefalse process_mb_i2(CMB * mb);
  truefalse analyze_cmd(CMB * mb, CBsDistReq & );
  truefalse process_comp(CBsDistReq & );
  truefalse compute_checksum(CBsDistReq &);
  truefalse tell_dists();
};

class CBsReqScheduler: public CParentScheduler
{
public:
  CBsReqScheduler(CContainer *, ni = 1);
  virtual CONST text * title() CONST;

protected:
  virtual DVOID before_finish();
  virtual truefalse before_begin();

private:
  CBsReqAcc * m_acc;
};

class CBsReqAcc: public CParentAcc
{
public:
  enum { BROKEN_DELAY = 5 }; //m

  CBsReqAcc(CParentScheduler *, CHandlerDirector *);
  virtual ni make_svc_handler(CParentHandler *&);
  virtual CONST text * title() CONST;
};


class CBsReqContainer: public CContainer
{
public:
  CBsReqContainer(CParentRunner * app);
  virtual ~CBsReqContainer();
  virtual CONST text * title() CONST;
  CBsReqTask * bs_req_task();

protected:
  virtual truefalse before_begin();
  virtual DVOID before_finish();

private:
  CBsReqTask * m_bs_req_task;
  CBsReqScheduler * m_scheduler;
};


class CBalanceContainer;
class CBalanceAcc;
class CM2BsConn;

class CBalanceProc: public CParentServerProc
{
public:
  typedef CParentServerProc baseclass;

  CBalanceProc(CParentHandler *);
  virtual ~CBalanceProc();
  virtual CONST text * title() CONST;
  virtual truefalse term_sn_check_done() CONST;
  virtual CProc::OUTPUT at_head_arrival();
  DVOID charge_datas(CChargeDatas *);

protected:
  virtual CProc::OUTPUT do_read_data(CMB *);

private:
  enum { MQ_PEAK = 1000000 };

  CProc::OUTPUT term_ver_validate(CMB *);
  CProc::OUTPUT handle_balance(CMB *);

  truefalse m_term_sn_check_done;
  CChargeDatas * m_charge_datas;
};


class CBalanceHandler: public CParentHandler
{
public:
  CBalanceHandler(CHandlerDirector * = NULL);
  DVOID balance_datas(CChargeDatas *);

  xx_enable_cache_easy(CBalanceHandler, ACE_Thread_Mutex);
};

class CBalanceScheduler: public CParentScheduler
{
public:
  CBalanceScheduler(CContainer *, ni = 1);
  ~CBalanceScheduler();
  virtual CONST text * title() CONST;
  virtual ni handle_timeout(CONST CTV &, CONST DVOID * = 0);
  DVOID post_bs(CMB * mb);

protected:
  virtual DVOID before_finish();
  virtual truefalse before_begin();
  virtual truefalse do_schedule_work();

private:
  enum { MQ_PEAK = 1000000 };

  CBalanceAcc * m_acc;
  CM2BsConn * m_bs_conn;
  ACE_Message_Queue<ACE_MT_SYNCH> m_bs_mq;
};

class CBalanceAcc: public CParentAcc
{
public:
  enum { REAP_DELAY = 15 }; //m
  CBalanceAcc(CParentScheduler *, CHandlerDirector *);

  virtual ni make_svc_handler(CParentHandler *&);
  virtual CONST text * title() CONST;
};


class CBalanceContainer: public CContainer
{
public:
  CBalanceContainer(CParentRunner *);
  virtual ~CBalanceContainer();
  virtual CONST text * title() CONST;
  CBalanceScheduler * scheduler() CONST;

protected:
  virtual truefalse before_begin();
  virtual DVOID before_finish();

private:
  CBalanceScheduler * m_scheduler;
};



class CM2BsProc: public CBSProceBase
{
public:
  typedef CBSProceBase baseclass;

  CM2BsProc(CParentHandler *);
  virtual CONST text * title() CONST;

  xx_enable_cache_easy(CM2BsProc, ACE_Thread_Mutex);

protected:
  virtual CProc::OUTPUT do_read_data(CMB *);
};

class CM2BsHandler: public CParentHandler
{
public:
  CM2BsHandler(CHandlerDirector * = NULL);
  virtual ni handle_timeout (CONST CTV &, CONST DVOID * = 0);
  DVOID checker_update();
  CBalanceContainer * container() CONST;
  xx_enable_cache_easy(CM2BsHandler, ACE_Thread_Mutex);

protected:
  virtual DVOID at_finish();
  virtual ni  at_start();

private:
  CActValidator m_validator;
};

class CM2BsConn: public CParentConn
{
public:
  CM2BsConn(CParentScheduler *, CHandlerDirector *);
  virtual ni make_svc_handler(CParentHandler *&);
  virtual CONST text * title() CONST;

protected:
  enum { RETRY_DELAY = 1 }; //m
};


//dst
class CPingContainer;
class CHeartBeatGatherer;
class CLocationGatherer;
class CDownloadReplyGatherer;
class CClickGatherer;
class CHwPowerTimeGatherer;
class CHardwareWarnGatherer;
class CVideoGatherer;
class CNoVideoWarnGatherer;
class CPingAcc;
class CTermStations;
class CTermStation;

class CDistTermItem
{
public:
  CDistTermItem(CBsDistData *, CTermStation *);
  DVOID download_checksum_feedback(CONST text *);
  CONST text * term_sn() CONST;
  ni term_position() CONST;
  DVOID post_subs(truefalse ok);
  DVOID control_pause_stop(CONST text);
  truefalse is_ok() CONST;
  truefalse work();
  DVOID destruct_me();
  truefalse connected();
  DVOID set_condition(ni);
  DVOID set_checksum(CONST text *);

  CBsDistData * dist_data;
  CTermStation * term_station;
  ni condition;
  CMemProt cmp_fn;
  CMemProt cmp_checksum;
  CMemProt adir;
  CMemProt checksum;
  time_t prev_access;

private:
  enum { CS_FEEDBACK_TV = 15, DOWNLOAD_FEEDBACK_TV = 5 }; //m

  truefalse post_cs();
  truefalse post_download();
  truefalse post_pause_stop(CONST text);
  truefalse create_cmp_file();
  ni  calc_common_header_len();
  DVOID format_common_header(text *);
  CMB * create_mb_of_download_sub(truefalse fine);
  truefalse on_conditon0();
  truefalse on_conditon1();
  truefalse on_conditon2();
  truefalse on_conditon3();
  truefalse on_conditon4();
  truefalse on_conditon5();
  truefalse on_conditon6();
  truefalse on_conditon7();
  truefalse on_conditon8();
};

class CTermStation
{
public:
  typedef std::list<CDistTermItem *, CCppAllocator<CDistTermItem *> > CDistTermItems;

  CTermStation(CTermStations *, CONST text *);
  ~CTermStation();

  CDistTermItem * generate_term_item(CBsDistData *);
  DVOID destruct_term_item(CDistTermItem *);
  truefalse connected();
  truefalse check_term_sn(CONST text *) CONST;
  DVOID reset();
  truefalse work();
  CONST text * term_sn() CONST;
  ni term_position() CONST;

private:
  CDistTermItems m_items;
  CTermStations * m_stations;
  CNumber m_term_sn;
  ni m_term_position;
};

class CTermQuickFinder
{
public:
  CTermQuickFinder(CONST text * did, CONST text * term_sn);
  truefalse operator == (CONST CTermQuickFinder &) CONST;

  CONST text * did;
  CONST text * term_sn;
};

class CTermHasher
{
public:
  size_t operator()(CONST CTermQuickFinder & x) CONST
  {
    return c_tools_text_hash(x.term_sn) ^ c_tools_text_hash(x.did);
  }
};

class CTermStations
{
public:
  typedef std::list<CTermStation *, CCppAllocator<CTermStation *> > CTermStationList;
  typedef std::tr1::unordered_map<CTermQuickFinder, CDistTermItem *, CTermHasher, std::equal_to<CTermQuickFinder>,
                                  CCppAllocator <std::pair<const CTermQuickFinder, CDistTermItem *>>
                                > CDistTermItemMap;
  typedef std::tr1::unordered_map<const text *, CTermStation *, CTextHashGenerator, CTextEqual,
                                  CCppAllocator <std::pair<const text *, CTermStation *>>
                                > CTermStationMap;

  CTermStations(CBsDistDatas *);
  ~CTermStations();
  CBsDistData * search_dist_data(CONST text *);
  DVOID reset();
  DVOID work();
  DVOID at_new_term_item(CDistTermItem *);
  DVOID at_del_term_item(CDistTermItem *, truefalse done);
  CDistTermItem * search_term_item(CONST text *, CONST text *);
  CTermStation *  search_term_station(CONST text *);
  CTermStation *  generate_term_station(CONST text *);
  DVOID destruct_term_station(CTermStation *);

  CTermStationList term_stations;
  time_t database_ts;

private:

  CBsDistDatas *   m_datas;
  CDistTermItemMap m_term_items;
  CTermStationMap  m_term_stations;
  ni m_term_station_done;
};

class CSpreader
{
public:
  CSpreader();
  truefalse work(truefalse);
  DVOID at_download_cmd_feedback(CONST text *, CONST text *, ni, truefalse);
  DVOID at_download_checksum_feedback(CONST text *, CONST text *, CONST text *);
  DVOID control_pause_stop(CONST text *, CONST text *, text);

private:
  enum { Vacation_Delay = 5 }; //m

  truefalse do_jobs(truefalse);
  truefalse do_term_stations(truefalse);

  CBsDistDatas m_datas;
  CTermStations m_stations;
  time_t m_prev_start;
  time_t m_prev_stop;
};

class CPingProc: public CParentServerProc
{
public:
  typedef CParentServerProc baseclass;

  CPingProc(CParentHandler *);
  virtual CProc::OUTPUT at_head_arrival();
  virtual CONST text * title() CONST;

  SF CHeartBeatGatherer * m_ping_gatherer;
  SF CLocationGatherer * m_location_gatherer;
  SF CDownloadReplyGatherer * m_download_reply_gatherer;
  SF CClickGatherer * m_click_gatherer;
  SF CHwPowerTimeGatherer * m_HW_powertime_gatherer;
  SF CHardwareWarnGatherer * m_HW_warn_gatherer;
  SF CVideoGatherer * m_video_gatherer;
  SF CNoVideoWarnGatherer * m_no_vide_warn_gatherer;

  xx_enable_cache_easy(CPingProc, ACE_Thread_Mutex);

protected:
  virtual CProc::OUTPUT do_read_data(CMB *);

private:
  enum { MQ_PEAK = 2000000 };

  DVOID i_ping();
  CProc::OUTPUT i_hw_warn(CMB *);
  CProc::OUTPUT i_video(CMB *);
  CProc::OUTPUT i_test(CMB *);
  CProc::OUTPUT i_pause_stop(CMB *);
  CProc::OUTPUT i_no_video_warn(CMB *);
  CProc::OUTPUT i_post_pq();
  CProc::OUTPUT i_ver(CMB *);
  CProc::OUTPUT i_checksums(CMB *);
  CProc::OUTPUT i_download_feedback(CMB *);
  CProc::OUTPUT i_location(CMB *);
  CProc::OUTPUT i_click(CMB *);
  CProc::OUTPUT i_hw_powertime(CMB *);

  text m_version_driver[12];
};

class CParentGatherer;

class CGatheredData
{
public:
  CGatheredData(ni, ni peak_size, CParentGatherer *, truefalse = false);
  ~CGatheredData();

  DVOID clear();
  truefalse append(CONST text *, ni len = 0);
  truefalse append(text);
  CONST text * data();
  ni chunk_size() CONST;

private:
  enum { DATA_MARK = ';' };

  CMB * m_mb;
  text * m_free_pos;
  CParentGatherer * m_gatherer;
  truefalse m_post_automatic;
  ni m_peak_piece_size;
  ni m_chunk_size;
};

class CParentGatherer
{
public:
  virtual ~CParentGatherer();
  DVOID post();
  DVOID add_chunk(CGatheredData *);
  DVOID post_if_needed();

protected:
  typedef std::list<CGatheredData * > CGatheredDatas;

  DVOID clear();
  DVOID i_post(CONST text *);
  virtual CONST text * what_action() CONST = 0;

  CGatheredDatas m_chunks;
};

class CDownloadReplyGatherer: public CParentGatherer
{
public:
  CDownloadReplyGatherer();
  virtual ~CDownloadReplyGatherer();
  DVOID append(CONST text *, text, CONST text *, text, text, CONST text *);

protected:
  virtual CONST text * what_action() CONST;

private:
  enum { BUFF_LEN = 1024 };
  CGatheredData m_task_chunk;
  CGatheredData m_ftype_chunk;
  CGatheredData m_term_sn_chunk;
  CGatheredData m_step_chunk;
  CGatheredData m_fine_chunk;
  CGatheredData m_date_chunk;
};


class CHeartBeatGatherer: public CParentGatherer
{
public:
  enum { ITEM_MARK = ';' };
  CHeartBeatGatherer();
  ~CHeartBeatGatherer();
  DVOID append(CONST text *, CONST ni);

protected:
  virtual CONST text * what_action() CONST;

private:
  enum { BUFF_LEN = 4096 };
  CGatheredData m_chunk;
};

class CLocationGatherer: public CParentGatherer
{
public:
  enum { ITEM_MARK = ';' };
  CLocationGatherer();
  DVOID append(CONST text *, ni, CONST text *, CONST text *, CONST text *);

protected:
  virtual CONST text * what_action() CONST;

private:
  enum { BUFF_LEN = 2048 };
  CGatheredData m_term_sn_chunk;
  CGatheredData m_ip_chunk;
  CGatheredData m_ver_chunk;
};

class CHwPowerTimeGatherer: public CParentGatherer
{
public:
  enum { ITEM_MARK = ';' };
  CHwPowerTimeGatherer();
  DVOID append(CONST text *, ni, CONST text, CONST text *);

protected:
  virtual CONST text * what_action() CONST;

private:
  enum { BUFF_LEN = 2048 };
  CGatheredData m_term_sn_chunk;
  CGatheredData m_on_off_chunk;
  CGatheredData m_datetime_chunk;
};


class CClickGatherer: public CParentGatherer
{
public:
  enum { ITEM_MARK = ';' };
  CClickGatherer();
  DVOID append(CONST text *, ni, CONST text *, CONST text *, CONST text *, CONST text *);

protected:
  virtual CONST text * what_action() CONST;

private:
  enum { BUFF_LEN = 2048 };
  CGatheredData m_term_sn_chunk;
  CGatheredData m_chn_chunk;
  CGatheredData m_pcode_chunk;
  CGatheredData m_number_chunk;
  CGatheredData m_ran_chunk;
};

class CHardwareWarnGatherer: public CParentGatherer
{
public:
  enum { ITEM_MARK = ';' };
  CHardwareWarnGatherer();
  DVOID append(CONST text *, ni, CONST text, CONST text, CONST text *);

protected:
  virtual CONST text * what_action() CONST;

private:
  enum { BUFF_LEN = 2048 };
  CGatheredData m_term_sn_chunk;
  CGatheredData m_type_chunk;
  CGatheredData m_value_chunk;
  CGatheredData m_datetime_chunk;
};

class CVideoGatherer: public CParentGatherer
{
public:
  enum { ITEM_MARK = ';' };
  CVideoGatherer();
  DVOID append(CONST text *, ni, CONST text *, CONST text *);

protected:
  virtual CONST text * what_action() CONST;

private:
  enum { BUFF_LEN = 4096 };
  CGatheredData m_term_sn_chunk;
  CGatheredData m_fn_chunk;
  CGatheredData m_number_chunk;
};

class CNoVideoWarnGatherer: public CParentGatherer
{
public:
  enum { ITEM_MARK = ';' };
  CNoVideoWarnGatherer();
  DVOID append(CONST text *, ni, CONST text);

protected:
  virtual CONST text * what_action() CONST;

private:
  enum { BUFF_LEN = 4096 };
  CGatheredData m_term_sn_chunk;
  CGatheredData m_state_chunk;
  CGatheredData m_datetime_chunk;
};


class CPingHandler: public CParentHandler
{
public:
  CPingHandler(CHandlerDirector * = NULL);
  virtual CTermSNs * term_SNs() CONST;

  xx_enable_cache_easy(CPingHandler, ACE_Thread_Mutex);
};

class CPingTask: public CTaskBase
{
public:
  enum { TID_ = 1 };

  CPingTask(CContainer *, ni = 1);
  virtual ni svc();
  truefalse append_task(CMB *, truefalse);
  truefalse append_task_delay(CMB *);

private:
  enum { MQ_PEAK = 5000000 };

  DVOID handle_have_job();
  DVOID handle_download_feedback(CMB *);
  DVOID handle_cs_feedback(CMB *);
  DVOID handle_pause_stop(CMB *);

  CSpreader m_spreader;
  ACE_Message_Queue<ACE_MT_SYNCH> m_mq_two;
};

class CPingScheduler: public CParentScheduler
{
public:
  CPingScheduler(CContainer *, ni = 1);
  virtual CONST text * title() CONST;
  virtual ni handle_timeout (CONST CTV &, CONST DVOID *);
  CPingAcc * acc() CONST;

protected:
  virtual DVOID before_finish();
  virtual DVOID before_finish_stage_1();
  virtual truefalse before_begin();

private:
  enum { TIMER_VALUE_PING = 15, //s
         TIMER_VALUE_LOCATION = 10, //s
         TIMER_VALUE_DOWNLOAD_REPLY = 15, //s
         TIMER_VALUE_CLICK = 2, //m
         TIMER_VALUE_HAS_JOB = 2 //m
       };
  enum { TIMER_DELAY_VALUE = 3 }; //s
  enum { MQ_PEAK = 60000000 };
  enum { TID_PING = 2, TID_LOCATION, TID_HAS_JOB, TID_DOWNLOAD_REPLY, TID_CLICK };

  CPingAcc * m_acc;
};

class CPingAcc: public CParentAcc
{
public:
  enum { REAP_TIMEOUT = 15 }; //m
  CPingAcc(CParentScheduler *, CHandlerDirector *);
  virtual ni make_svc_handler(CParentHandler *&);
  virtual CONST text * title() CONST;
};


class CPingContainer: public CContainer
{
public:
  CPingContainer(CParentRunner *);
  virtual ~CPingContainer();
  CPingScheduler * scheduler() CONST;
  virtual CONST text * title() CONST;
  CPingTask * task() CONST;
  ni connected_count() CONST;
  CDownloadReplyGatherer & download_reply_gatherer();
  DVOID prio();
  truefalse get_prio(CMemProt &);

protected:
  virtual truefalse before_begin();
  virtual DVOID before_finish();

private:
  CHeartBeatGatherer m_heart_beat_gatherer;
  CLocationGatherer m_location_gatherer;
  CDownloadReplyGatherer m_download_reply_gatherer;
  CClickGatherer m_click_gatherer;
  CHwPowerTimeGatherer m_hw_power_gatherer;
  CHardwareWarnGatherer m_hw_warn_gatherer;
  CVideoGatherer m_video_gatherer;
  CNoVideoWarnGatherer m_no_video_warn_gatherer;
  CPingTask * m_ping_task;
  CPingScheduler * m_schduler;
  ACE_Thread_Mutex m_mutex;
  CMemProt m_prio;
};


//d2bs

class CD2MContainer;

class CD2BsProc: public CBSProceBase
{
public:
  typedef CBSProceBase baseclass;
  CD2BsProc(CParentHandler *);
  virtual CONST text * title() CONST;

protected:
  virtual CProc::OUTPUT do_read_data(CMB *);

private:
  enum { MQ_PEAK = 2000000 };
  DVOID i_location_entry(text *);
  DVOID i_location(CBSData *);
};

class CD2BsHandler: public CParentHandler
{
public:
  CD2BsHandler(CHandlerDirector * = NULL);
  CD2MContainer * container() CONST;
  virtual ni handle_timeout (CONST CTV &, CONST DVOID * = 0);
  DVOID refresh();
  xx_enable_cache_easy(CD2BsHandler, ACE_Thread_Mutex);

protected:
  virtual DVOID at_finish();
  virtual ni  at_start();

private:
  CActValidator m_validator;
};

class CD2BsConn: public CParentConn
{
public:
  CD2BsConn(CParentScheduler *, CHandlerDirector *);
  virtual ni make_svc_handler(CParentHandler *&);
  virtual CONST text * title() CONST;

protected:
  enum { RETRY_DELAY = 1 }; //m
};


//d2m
class CD2MContainer;
class CD2MConn;

class CD2MProc: public CParentClientProc
{
public:
  typedef CParentClientProc baseclass;

  CD2MProc(CParentHandler *);
  virtual CProc::OUTPUT at_head_arrival();
  virtual ni at_start();
  ni post_charge();

protected:
  virtual CProc::OUTPUT do_read_data(CMB *);

private:
  enum { IP_SIZE = INET_ADDRSTRLEN };
  enum { MQ_PEAK = 512 * 1024 };

  ni post_ver_mb();
  CProc::OUTPUT handle_login_back(CMB *);
  CProc::OUTPUT handle_has_job(CMB *);
  CProc::OUTPUT handle_rmt_command(CMB *);

  truefalse m_edition_back_finished;
  text m_self_ip[IP_SIZE];
};

class CD2MHandler: public CParentHandler
{
public:
  CD2MHandler(CHandlerDirector * = NULL);
  virtual ni handle_timeout (CONST CTV &, CONST DVOID * = 0);
  DVOID init_timer();
  CD2MContainer * container() CONST;
  xx_enable_cache_easy(CD2MHandler, ACE_Thread_Mutex);

protected:
  virtual DVOID at_finish();
  virtual ni  at_start();

private:
  enum { CHARGE_TIMER = 1 };
  enum { CHARGE_DELAY = 2 };
  long m_tid;
};

class CD2MSchduler: public CParentScheduler
{
public:
  CD2MSchduler(CContainer *, ni = 1);
  virtual ~CD2MSchduler();

  virtual CONST text * title() CONST;
  DVOID post_bs(CMB *);
  DVOID post_pre(CMB *);

protected:
  virtual DVOID before_finish();
  virtual truefalse before_begin();
  virtual truefalse do_schedule_work();
  virtual DVOID before_finish_stage_1();

private:
  enum { MQ_PEAK = 5000000 };

  CD2MConn * m_conn;
  CD2BsConn * m_2_bs_conn;
  ACE_Message_Queue<ACE_MT_SYNCH> m_2_bs_mq;
};


class CD2MConn: public CParentConn
{
public:
  CD2MConn(CParentScheduler *, CHandlerDirector *);
  virtual ni make_svc_handler(CParentHandler *&);
  virtual CONST text * title() CONST;

protected:
  enum { RETRY_DELAY = 3 }; //m
};

class CD2MContainer: public CContainer
{
public:
  CD2MContainer(CParentRunner *);
  virtual ~CD2MContainer();
  virtual CONST text * title() CONST;
  DVOID post_bs(CMB *);
  DVOID post_pre(CMB *);

protected:
  virtual truefalse before_begin();
  virtual DVOID before_finish();

private:
  CD2MSchduler * m_scheduler;
};


class CPG
{
public:
  CPG();
  ~CPG();
  SF time_t get_time_init(CONST text * s);

  truefalse write_task_cs(CONST text *, CONST text *, ni);
  truefalse write_task_download_cs(CONST text *, CONST text *);
  truefalse read_task_terms(CTermStations *, CTermStation *);
  truefalse write_task_term_item_condition(CDistTermItem &, ni);
  truefalse write_task_term_condition(CONST text *, CONST text *, ni);
  truefalse write_task_term_cs(CONST text *, CONST text *, CONST text *, ni);
  truefalse write_task_term_mbz(CONST text *, CONST text *, CONST text *, CONST text *);
  truefalse destruct_task_term(CONST text *, CONST text *);
  truefalse is_dist_data_new(CBsDistDatas &);
  truefalse refresh_task_condition();
  truefalse delete_unused_tasks();
  truefalse read_term_SNs(CObsoleteDirDeleter &);
  truefalse change_term_valid(CONST text *, truefalse);
  truefalse login_to_db();
  truefalse validate_db_online();
  truefalse check_online();
  truefalse load_term_SNs(CTermSNs *);
  truefalse save_term_sn(CONST text * s);
  truefalse write_task(CBsDistReq &, CONST text *, CONST text *);
  truefalse write_sr(text *, CONST text *, text *);
  truefalse write_pl(CONST text *);
  truefalse write_task_terms(text *, text *, CONST text *);
  ni        read_tasks(CBsDistDatas &);
  truefalse read_pl(CMemProt &);

private:
  DVOID make_offline();
  truefalse do_read_db_time(time_t &);
  truefalse is_online() CONST;
  truefalse tr_start();
  truefalse tr_finish();
  truefalse tr_cancel();
  truefalse run_sql(CONST text *, ni * = NULL);
  DVOID prepare_text(CONST text *, CMemProt &) CONST;
  time_t    get_db_time_i();
  truefalse write_xinfo(CONST ni, CONST text *);
  truefalse read_xinfo(CONST ni, CMemProt &);
  truefalse read_xinfo_i(CONST ni, CMemProt &);

  PGconn * m_pg_con;
  CMemProt m_db_ip;
  ni m_db_port;
  CMemProt m_db_login;
  CMemProt m_db_key;
  ACE_Thread_Mutex m_mutex;
};

#endif
