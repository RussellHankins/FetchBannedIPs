#ifndef __MYSQLI_RESULT_H
#define __MYSQLI_RESULT_H
#ifndef nullptr
#define nullptr 0
#endif

#include <mysql.h>
class mysqli_result
{
	public:
	mysqli_result();
	~mysqli_result();
	unsigned int num_fields();
	void free(); 
	private:
	MYSQL_RES *_result;
	friend class mysqli;	
	friend class mysqli_stmt;	
};
#endif
