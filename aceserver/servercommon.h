/*
 * servercommon.h
 *
 *  Created on: Feb 2, 2012
 *      Author: root
 */

#ifndef SERVERCOMMON_H_
#define SERVERCOMMON_H_

#include "common.h"
#include "mycomutil.h"
#include "basemodule.h"

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
  MyHttpDistInfo();
  bool need_md5() const;
  bool need_mbz_md5() const;
  bool is_cmp_done() const;
  bool is_mbz_md5_done() const;

  char ftype[2];
  char type[2];
  MyPooledMemGuard fdir;
  MyPooledMemGuard findex;
  MyPooledMemGuard aindex;
  MyPooledMemGuard ver;
  MyPooledMemGuard password;

  MyPooledMemGuard dist_time;
  MyPooledMemGuard md5;
  MyPooledMemGuard md5_time;

  MyPooledMemGuard mbz_md5;
  MyPooledMemGuard mbz_md5_time;

  MyPooledMemGuard cmp_time;
  char cmp_done[2];


  bool exist;
  bool cmp_needed;
  bool md5_needed;

  int  md5_len;
  int  ver_len;
  int  findex_len;
  int  aindex_len;
  int  password_len;
};

class MyHttpDistInfos
{
public:
  MyHttpDistInfos();
  ~MyHttpDistInfos();

  typedef std::vector<MyHttpDistInfo *, MyAllocator<MyHttpDistInfo *> > MyHttpDistInfoList;
  void add(MyHttpDistInfo *);
  bool need_reload() const;
  void prepare_update();
  void clear();
  MyHttpDistInfo * find(const char * dist_id);

  MyHttpDistInfoList dist_infos;
  time_t last_load_time;
  MyPooledMemGuard last_dist_time;
};

class MyDistCompressor
{
public:
  bool compress(MyHttpDistRequest & http_dist_request);
  static void get_all_in_one_mbz_file_name(const char * dist_id, MyPooledMemGuard & filename);
  static const char * composite_path();
  static const char * all_in_one_mbz();

private:
  bool do_generate_compressed_files(const char * src_path, const char * dest_path, int prefix_len, const char * passwrod);

  MyBZCompositor m_compositor;
  MyBZCompressor m_compressor;
};

class MyDistMd5Calculator
{
public:
  bool calculate(MyHttpDistRequest & http_dist_request, MyPooledMemGuard &md5_result, int & md5_len);
  static bool calculate_all_in_one_ftp_md5(const char * dist_id, MyPooledMemGuard & md5_result);
};

#endif /* SERVERCOMMON_H_ */
