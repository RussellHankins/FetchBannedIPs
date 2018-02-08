# FetchBannedIPs
Read the list of banned IP addresses from the database and either display them or ban them by adding rules to iptables.

This solves a problem I had:

* The website and database are on separate servers.
* The database has port 3306 open to the world (for collaboration). 
* The website detects people trying to hack into the web server on port 80.
* The website bans these IP addresses.
* This program is to run on the database server every 5 minutes to ban the IP address there too.
* This program also runs on other web servers in different locations serving different web sites. 
* If an IP gets banned on one website, it gets banned on all other web sites within 5 minutes.

Website attacks include, but are not limited to:
* Someone browsing to the IP address directly without using a .com name. This goes to a special website saying Coming Soon (they get banned).
* A 404 file not found error contains a reference to a [WordPress](https://www.cvedetails.com/vulnerability-list/vendor_id-2337/product_id-4096/) or [PHPMyAdmin](https://www.exploit-db.com/exploits/8921/) vulnerability.
* Someone browses to the home page with ?author=1 appended to the url (WordPress [vulnerability](https://hackertarget.com/wordpress-user-enumeration/)).
* The UserAgent string of the browser contains reference to programs used to browse to every IP address in the internet looking for web servers (Examples include, but are not limited to: [masscan](https://github.com/robertdavidgraham/masscan), wget, python, curl, zgrab).

This program is written in C++ (well, maybe mostly C). It uses the Mysql C API to connect to a MySql database.

I wrote it in C++11 instead of a bash script because:
* I wanted the database password to be difficult to recover.
* I wanted the program to run fast.
* I had just written a set of wrapper classes for the MySQL C API and wanted to test it out.
* Feel free download/modify

Install MySQL C API: apt-get install libmysqlclient-dev
[MySQL C API Tutorial](http://zetcode.com/db/mysqlc/)
[MySQL C API Function Overview](https://dev.mysql.com/doc/refman/5.5/en/c-api-function-overview.html)
[MySQL C API Prepared Statements Sample](https://dev.mysql.com/doc/refman/5.5/en/c-api-prepared-call-statements.html)
