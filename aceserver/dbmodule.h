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

class MyClientIDTable;

class MyDB
{
public:
  MyDB();
  ~MyDB();
  bool connect();
  bool get_client_ids(MyClientIDTable * idtable);
  bool save_client_id(const char * s);
  bool save_dist(const char * acode, const char *ftype, const char * fdir,
       const char * findex, const char * adir, const char * aindex,
       const char * ver, const char * type);

private:
  void disconnect();
  bool connected() const;
  bool begin_transaction();
  bool commit();
  bool rollback();
  bool exec_command(const char * sql_command);

  PGconn * m_connection;
  MyPooledMemGuard m_server_addr;
  int m_server_port;
  MyPooledMemGuard m_user_name;
  MyPooledMemGuard m_password;
  ACE_Thread_Mutex m_mutex;
};

#endif /* DBMODULE_H_ */
