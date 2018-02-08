#ifndef __MYSQLI_H
#define __MYSQLI_H
#include <mysql.h>
#include "mysqli_stmt.h"
#include "mysqli_result.h"
#ifndef nullptr
#define nullptr 0
#endif

class mysqli
{
	public:
	mysqli();
	mysqli(const char *host,const char *username,const char *password,const char *db,int port);
	~mysqli();
	void real_connect(const char *host,const char *username,const char *password,const char *db,int port); // http://php.net/manual/en/mysqli.real-connect.php
	void prepare(const char *query,unsigned long length,mysqli_stmt &stmt);
	void store_result(mysqli_result &result); // http://php.net/manual/en/mysqli.store-result.php
	void close();  // http://php.net/manual/en/mysqli.close.php
	unsigned int field_count(); // http://php.net/manual/en/mysqli.field-count.php
	unsigned int errno(); // http://php.net/manual/en/mysqli.errno.php
	const char *error(); // http://php.net/manual/en/mysqli.error.php
	bool next_result(); // http://php.net/manual/en/mysqli.next-result.php
	bool more_results(); // http://php.net/manual/en/mysqli.more-results.php
	void use_result(mysqli_result &result); // http://php.net/manual/en/mysqli.use-result.php
	const char *host_info(); // http://php.net/manual/en/mysqli.get-host-info.php
	static void throw_null_reference_error();
	static void throw_out_of_memory_error();	
	private:	
	MYSQL *_mysql;		
	
};

	
#endif
