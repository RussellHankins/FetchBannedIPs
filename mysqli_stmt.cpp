#include "mysqli_stmt.h"
#include "mysqli.h"
mysqli_stmt::mysqli_stmt()
{
	_stmt = nullptr;
}
mysqli_stmt::~mysqli_stmt()
{
	close();
}
void mysqli_stmt::close()
{
	if (_stmt != nullptr) {
		mysql_stmt_close(_stmt); // https://dev.mysql.com/doc/refman/5.7/en/mysql-stmt-close.html
		_stmt = nullptr;
	}
	return;
}
bool mysqli_stmt::bind_param(MYSQL_BIND *bind)
{
	if (_stmt == nullptr) {
		mysqli::throw_null_reference_error();
	}
	return mysql_stmt_bind_param(_stmt,bind); // https://dev.mysql.com/doc/refman/5.7/en/mysql-stmt-bind-param.html
}
bool mysqli_stmt::execute()
{
	const char *error;
	if (_stmt == nullptr) {
		mysqli::throw_null_reference_error();
	}
	int status = mysql_stmt_execute(_stmt); // https://dev.mysql.com/doc/refman/5.7/en/mysql-stmt-execute.html
	if (status == 0) {
		return true;
	}
	error = mysql_stmt_error(_stmt); // https://dev.mysql.com/doc/refman/5.7/en/mysql-stmt-error.html
	if (error == nullptr) {
		error = "";
	}
	throw error;	
}
void mysqli_stmt::data_seek(my_ulonglong offset)
{
	if (_stmt == nullptr) {
		mysqli::throw_null_reference_error();
	}
	mysql_stmt_data_seek(_stmt, offset); // https://dev.mysql.com/doc/refman/5.7/en/mysql-stmt-data-seek.html
	return;
}
bool mysqli_stmt::bind_result(MYSQL_BIND *bind)
{
	if (_stmt == nullptr) {
		mysqli::throw_null_reference_error();
	}
	return 0 == mysql_stmt_bind_result(_stmt, bind); // https://dev.mysql.com/doc/refman/5.7/en/mysql-stmt-bind-result.html
}
bool mysqli_stmt::fetch()
{
	const char *error;
	int status;
	
	if (_stmt == nullptr) {
		mysqli::throw_null_reference_error();
	}
	status = mysql_stmt_fetch(_stmt); // https://dev.mysql.com/doc/refman/5.7/en/mysql-stmt-fetch.html
	switch (status) {
		case 0:
		{
			return true;
		}
		case MYSQL_NO_DATA:
		{
			return false;
		}
		case MYSQL_DATA_TRUNCATED:
		{
			throw "Data would be truncated.";
		}
	}	
	error = mysql_stmt_error(_stmt); // https://dev.mysql.com/doc/refman/5.7/en/mysql-stmt-error.html
	if (error == nullptr) {
		error = "";
	}
	throw error;
}
unsigned long mysqli_stmt::param_count()
{
	if (_stmt == nullptr) {
		mysqli::throw_null_reference_error();
	}
	return mysql_stmt_param_count(_stmt); // https://dev.mysql.com/doc/refman/5.7/en/mysql-stmt-param-count.html
}

void mysqli_stmt::result_metadata(mysqli_result &result)
{
	if (_stmt == nullptr) {
		mysqli::throw_null_reference_error();
	}
	result.free();
	result._result = mysql_stmt_result_metadata(_stmt); // https://dev.mysql.com/doc/refman/5.7/en/mysql-stmt-result-metadata.html
	return;
}
bool mysqli_stmt::store_result()
{
	if (_stmt == nullptr) {
		mysqli::throw_null_reference_error();
	}
	int status = mysql_stmt_store_result(_stmt); // https://dev.mysql.com/doc/refman/5.7/en/mysql-stmt-store-result.html
	return status == 0;
}
