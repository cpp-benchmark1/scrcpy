#ifndef USER_DB_H
#define USER_DB_H

#include <mysql/mysql.h>

void process_user_input(MYSQL *conn, const char *user_input);

#endif // USER_DB_H