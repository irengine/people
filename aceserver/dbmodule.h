/*
 * dbmodule.h
 *
 *  Created on: Jan 20, 2012
 *      Author: root
 */

#ifndef DBMODULE_H_
#define DBMODULE_H_

#include <libpq-fe.h>

#include "common.h"
#include "mycomutil.h"
#include "servercommon.h"

class MyClientIDTable;

class MyDB
{
public:
  MyDB();
  ~MyDB();
  static time_t get_time_from_string(const char * s);

  bool connect();
  bool get_client_ids(MyClientIDTable * idtable);
  bool save_client_id(const char * s);
  bool save_dist(MyHttpDistRequest & http_dist_request);
  bool save_dist_clients(char * idlist, const char * dist_id);
  bool save_dist_cmp_done(const char *dist_id);
  int  load_dist_infos(MyHttpDistInfos & infos);
  bool dist_take_cmp_ownership(MyHttpDistInfo * info);


private:
  void disconnect();
  bool connected() const;
  bool begin_transaction();
  bool commit();
  bool rollback();
  bool exec_command(const char * sql_command, int * affected = NULL);
  const char * wrap_str(const char * s) const;

  PGconn * m_connection;
  MyPooledMemGuard m_server_addr;
  int m_server_port;
  MyPooledMemGuard m_user_name;
  MyPooledMemGuard m_password;
  ACE_Thread_Mutex m_mutex;
};

#endif /* DBMODULE_H_ */
