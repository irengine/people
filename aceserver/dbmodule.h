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
#include "distmodule.h"

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
  bool save_dist_clients(char * idlist, char * adirlist, const char * dist_id);
  bool save_dist_cmp_done(const char *dist_id);
  int  load_dist_infos(MyHttpDistInfos & infos);
  bool dist_take_cmp_ownership(MyHttpDistInfo * info);
  bool dist_take_md5_ownership(MyHttpDistInfo * info);
  bool dist_mark_cmp_done(const char * dist_id);
  bool dist_mark_md5_done(const char * dist_id);
  bool save_dist_md5(const char * dist_id, const char * md5, int md5_len);
  bool load_dist_clients(MyDistClients * dist_clients);
  bool set_dist_client_status(MyDistClient & dist_client, int new_status);

private:
  void disconnect();
  bool connected() const;
  bool begin_transaction();
  bool commit();
  bool rollback();
  bool exec_command(const char * sql_command, int * affected = NULL);
  void wrap_str(const char * s, MyPooledMemGuard & wrapped) const;
  time_t get_db_time_i();
  bool take_owner_ship(const char * table, const char * field, const char * old_time, const char * where_clause);

  PGconn * m_connection;
  MyPooledMemGuard m_server_addr;
  int m_server_port;
  MyPooledMemGuard m_user_name;
  MyPooledMemGuard m_password;
  ACE_Thread_Mutex m_mutex;
};

#endif /* DBMODULE_H_ */
