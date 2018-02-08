rm -f FetchBannedIPs
g++ -std=c++11 FetchBannedIPs.cpp mysqli.cpp mysqli_stmt.cpp mysqli_result.cpp mysqli_bind.cpp `mysql_config --cflags` `mysql_config --libs` -o FetchBannedIPs

ls -l FetchBannedIPs
