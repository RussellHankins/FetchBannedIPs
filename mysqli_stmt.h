#ifndef __MYSQLI_STMT_H
#define __MYSQLI_STMT_H
#include <mysql.h>
#include "mysqli_result.h"
#ifndef nullptr
#define nullptr 0
#endif
class mysqli_stmt
{
	public:
	mysqli_stmt();
	~mysqli_stmt();
	void close(); // http://php.net/manual/en/mysqli-stmt.close.php
	bool bind_param(MYSQL_BIND *bind); // http://php.net/manual/en/mysqli-stmt.bind-param.php
	bool execute(); // http://php.net/manual/en/mysqli-stmt.execute.php
	void data_seek(my_ulonglong offset); // http://php.net/manual/en/mysqli-stmt.data-seek.php
	bool bind_result(MYSQL_BIND *bind); //  http://php.net/manual/en/mysqli-stmt.bind-result.php
	bool fetch(); // http://php.net/manual/en/mysqli-stmt.fetch.php
	bool store_result(); // http://php.net/manual/en/mysqli-stmt.store-result.php
	unsigned long param_count(); // http://php.net/manual/en/mysqli-stmt.param-count.php
	void result_metadata(mysqli_result &result); // http://php.net/manual/en/mysqli-stmt.result-metadata.php
	private:
	MYSQL_STMT *_stmt;
	friend class mysqli;
};
#endif
