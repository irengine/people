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

class MyHttpDistRequest
{
public:
  MyHttpDistRequest();
  bool check_valid(const bool check_acode) const;

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
  MyPooledMemGuard acode;
  MyPooledMemGuard ftype;
  MyPooledMemGuard fdir;
  MyPooledMemGuard findex;
  MyPooledMemGuard adir;
  MyPooledMemGuard aindex;
  MyPooledMemGuard ver;
  MyPooledMemGuard type;
  MyPooledMemGuard password;

  MyPooledMemGuard dist_time;

  MyPooledMemGuard cmp_owner;
  MyPooledMemGuard cmp_time;
  MyPooledMemGuard cmp_done;
};

class MyHttpDistInfos
{
public:
  ~MyHttpDistInfos();

  typedef std::vector<MyHttpDistInfo *, MyAllocator<MyHttpDistInfo *> > MyHttpDistInfoList;
  void add(MyHttpDistInfo *);

  MyHttpDistInfoList m_dist_infos;
  MyPooledMemGuard m_last_ts;
};

class MyDistCompressor
{
public:
  bool compress(MyHttpDistRequest & http_dist_request);
  static const char * composite_path();

private:
  bool do_generate_compressed_files(const char * src_path, const char * dest_path, int prefix_len, const char * passwrod);

  MyBZCompositor m_compositor;
  MyBZCompressor m_compressor;
};

#endif /* SERVERCOMMON_H_ */
