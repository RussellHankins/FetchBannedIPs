#include "mysqli_result.h"
#include "mysqli.h"
mysqli_result::mysqli_result()
{
	_result = nullptr;
}

mysqli_result::~mysqli_result()
{
	free();
}
void mysqli_result::free()
{
	if (_result != nullptr) {
		mysql_free_result(_result); // https://dev.mysql.com/doc/refman/5.7/en/mysql-free-result.html
		_result = nullptr;
	}
	return;
}
unsigned int mysqli_result::num_fields()
{
	if (_result == nullptr) {
		mysqli::throw_null_reference_error();
	}
	return mysql_num_fields(_result);
}

