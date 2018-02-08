#include "mysqli.h"
#include <stdlib.h>

mysqli::mysqli(const char *host,const char *username,const char *password,const char *db,int port)
{
	_mysql = nullptr;
	real_connect(host,username,password,db,port);
}
mysqli::mysqli()
{
	_mysql = nullptr;	
}
mysqli::~mysqli()
{
	close();
}
void mysqli::real_connect(const char *host,const char *username,const char *password,const char *db,int port)
{
	if (_mysql == nullptr) {
		_mysql = new MYSQL();
		if (_mysql == nullptr) {
			mysqli::throw_out_of_memory_error();
		}
	}
	mysql_init(_mysql);
	// https://dev.mysql.com/doc/refman/5.7/en/mysql-real-connect.html
	if (nullptr == mysql_real_connect(_mysql, host, username, password, db, port, nullptr, CLIENT_COMPRESS | CLIENT_MULTI_RESULTS)) {
		throw mysql_error(_mysql);
    }
    return;
}
void mysqli::close()
{
	if (_mysql != nullptr) {
		mysql_close(_mysql);
		delete _mysql;		
		_mysql = nullptr;
	}
	return;
}
const char *mysqli::error()
{
	if (_mysql == nullptr) {
		return "";
	}
	return mysql_error(_mysql); // https://dev.mysql.com/doc/refman/5.7/en/mysql-error.html
}

void mysqli::prepare(const char *query,unsigned long length,mysqli_stmt &stmt)
{
	stmt.close();
	stmt._stmt = mysql_stmt_init(_mysql); // https://dev.mysql.com/doc/refman/5.7/en/mysql-stmt-init.html
	if (stmt._stmt == nullptr) {
		mysqli::throw_null_reference_error();
	}
	if (0!= mysql_stmt_prepare(stmt._stmt, query, length)) { // https://dev.mysql.com/doc/refman/5.7/en/mysql-stmt-prepare.html
		throw mysql_stmt_error(stmt._stmt); // https://dev.mysql.com/doc/refman/5.7/en/mysql-stmt-error.html
	}
	return;
}
void mysqli::throw_null_reference_error()
{
	// Save on memory by calling from one place.
	throw "Null reference error";
}
void mysqli::throw_out_of_memory_error()
{
	throw "Out of memory.";
}
unsigned int mysqli::field_count()
{
	if (_mysql == nullptr) {
		mysqli::throw_null_reference_error();
	}
	return mysql_field_count(_mysql); // https://dev.mysql.com/doc/refman/5.7/en/mysql-field-count.html
}

unsigned int mysqli::errno()
{
	if (_mysql == nullptr) {
		mysqli::throw_null_reference_error();
	}
	return mysql_errno(_mysql);
}
bool mysqli::next_result()
{
	// Returns true if there's a result. Throws an error if there's an error.
	if (_mysql == nullptr) {
		mysqli::throw_null_reference_error();
	}
	int status = mysql_next_result(_mysql); // https://dev.mysql.com/doc/refman/5.7/en/mysql-next-result.html
	if (status == 0) {
		return true; // There's another result set.
	}
	if (status == -1) {
		return false; // There are no other result sets.
	}
	// There was an error.
	const char *error = mysql_error(_mysql); // https://dev.mysql.com/doc/refman/5.7/en/mysql-error.html
	if (error != nullptr) {
		throw error; // Throw the error.
	}
	return false; // This probably will never happen.
}
bool mysqli::more_results()
{
	if (_mysql == nullptr) {
		mysqli::throw_null_reference_error();
	}
	return mysql_more_results(_mysql); // https://dev.mysql.com/doc/refman/5.7/en/mysql-more-results.html
}
const char *mysqli::host_info()
{
	if (_mysql == nullptr) {
		mysqli::throw_null_reference_error();
	}
	return mysql_get_host_info(_mysql); // https://dev.mysql.com/doc/refman/5.7/en/mysql-get-host-info.html
}
void mysqli::use_result(mysqli_result &result)
{	
	result.free();
	if (_mysql == nullptr) {
		mysqli::throw_null_reference_error();
	}
	result._result = mysql_use_result(_mysql); // https://dev.mysql.com/doc/refman/5.7/en/mysql-use-result.html
	return;
}
