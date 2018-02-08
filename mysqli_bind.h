#ifndef __MYSQL_BIND_H
#define __MYSQL_BIND_H
#ifndef nullptr
#define nullptr 0
#endif
#include <mysql.h>
class mysqli_bind
{
	public:
	mysqli_bind(int size);
	mysqli_bind(MYSQL_BIND &bind,int size);
	~mysqli_bind();
	int size() const;
	void clear();
	MYSQL_BIND *operator[](int index) { check_index_range(index); return _bind+index; };
	operator MYSQL_BIND*() { return _bind; };
	void bind(int index,short &value);
	void bind(int index,int &value);
	void bind(int index,const char *string,int buffer_size,unsigned long &length);	
	bool is_null(int index) const;
	bool is_error(int index) const;
	private:
	void allocate(int size);
	void check_index_range(int index) const;
	int _size;
	MYSQL_BIND *_bind;
	bool _is_on_stack;
};
#endif
