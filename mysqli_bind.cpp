#include "mysqli_bind.h"
#include <string.h>
// Constructor
mysqli_bind::mysqli_bind(int size)
{
	_size = 0;
	_bind = nullptr;
	_is_on_stack = false;
	allocate(size);	
}
mysqli_bind::mysqli_bind(MYSQL_BIND &bind,int size)
{
	_size = size;
	_bind = &bind;
	_is_on_stack = true;
	allocate(size);	
}
void mysqli_bind::allocate(int size)
{
	if (size > 0)
	{
		_bind = new MYSQL_BIND[size];
		if (_bind != nullptr) 
		{
			_size = size;
			memset(_bind,0,sizeof(MYSQL_BIND)*size);			
		}
	}
	return;
}
// Destructor
mysqli_bind::~mysqli_bind()
{
	clear();	
}
int mysqli_bind::size() const
{
	return _size;
}
bool mysqli_bind::is_null(int index) const
{
	check_index_range(index);
	return _bind[index].is_null_value;
}
bool mysqli_bind::is_error(int index) const
{
	check_index_range(index);
	return _bind[index].error_value;
}
void mysqli_bind::clear()
{
	if (_bind != nullptr) 
	{
		if (!_is_on_stack) {
			delete[] _bind;
		}
		_bind = nullptr;
	}
	_size = 0;	
	return;
}
void mysqli_bind::check_index_range(int index) const
{
	if ((index < 0) || (index >= _size))
	{
		throw "Bind index out of range.";
	}
	return;
}
void mysqli_bind::bind(int index,short &value)
{	
	check_index_range(index);
	_bind[index].buffer_type= MYSQL_TYPE_SHORT;
	_bind[index].buffer= (char *)&value;
	return;
}
void mysqli_bind::bind(int index,int &value)
{
	check_index_range(index);
	_bind[index].buffer_type= MYSQL_TYPE_LONG;
	_bind[index].buffer= (char *)&value;
	return;
}
void mysqli_bind::bind(int index,const char *string,int buffer_size,unsigned long &length)
{
	check_index_range(index);
	_bind[index].buffer_type= MYSQL_TYPE_STRING;
	_bind[index].buffer= (char *)string;
	_bind[index].buffer_length= buffer_size;
	_bind[index].length= &length;	
	return;
}
