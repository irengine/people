#ifndef DBMODULE_H_
#define DBMODULE_H_

#include <libpq-fe.h>

#include "mycomutil.h"
#include "servercommon.h"
#include "distmodule.h"
#include "middlemodule.h"

class MyClientIDTable;

class MyDB
{
public:
  MyDB();
  ~MyDB();
  static time_t get_time_from_string(const char * s);

  bool connect();
  bool check_db_connection();
  bool ping_db_server();
  bool get_client_ids(MyClientIDTable * idtable);
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

#endif /* DBMODULE_H_ */
