#ifndef SERVERCOMMON_H_
#define SERVERCOMMON_H_

#include "mycomutil.h"
#include "basemodule.h"
#include <tr1/unordered_map>

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

#endif /* SERVERCOMMON_H_ */
