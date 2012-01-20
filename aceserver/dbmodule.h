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

private:
  void disconnect();
  bool connected() const;
  bool pre_sql();
  bool post_sql();
  bool exec_command(const char * sql_command);

  PGconn * m_connection;
  MyPooledMemGuard m_server_addr;
  int m_server_port;
  MyPooledMemGuard m_user_name;
  MyPooledMemGuard m_password;
};

#endif /* DBMODULE_H_ */
