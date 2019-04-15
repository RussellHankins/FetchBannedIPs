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

Version 1.5 now has optional support for using ipset instead of iptables. Add ipset at the end as an extra parameter.<br />
Examples:<br />
Example 1 - List banned IPs from the database:<br />
FetchBannedIPs 192.168.0.204<br />
Example 2 - Read the banned IPs from the database and ban them here:<br />
FetchBannedIPs 192.168.0.204 BAN<br />
Example 3 - Read the banned IPs from the database and ban them with ipset:<br />
FetchBannedIPs 192.168.0.204 BAN IPSET<br />
Example 4 - Read the banned IPs from the database and ban them here (Stop at 200):<br />
FetchBannedIPs 192.168.0.204 BAN200<br />
Example 5 - Read the banned IPs from the database and ban them here with ipset (Stop at 200):<br />
FetchBannedIPs 192.168.0.204 BAN200 IPSET<br />
Example 6 - List all the IPs banned in iptables:<br />
FetchBannedIPs LIST<br />
Example 7 - List the banned IPs from ipset:<br />
FetchBannedIPs LIST IPSET<br />
Example 8 - Clear all banned IPs from iptables:<br />
FetchBannedIPs CLEAR<br />
Example 9 - Clear the banned IPs from ipset:<br />
FetchBannedIPs CLEAR IPSET<br />

Some versions of iptables don't support the -w option. You can take that out if it causes problems.<br />
Some versions of g++ don't support -std=c++11. You can take that out of the make file if it causes problems.

The ipset rules that are automatically created (if you use ipset):<br />
sudo ipset create evil_hackers iphash<br />
sudo iptables -A INPUT -m set --match-set evil_hackers src -j DROP<br />
The evil_hackers set is a constant at the top of the program.

This program is written in C++ (well, maybe mostly C). It uses the Mysql C API to connect to a MySql database.

I wrote it in C++11 instead of a bash script because:
* I wanted the database password to be difficult to recover.
* I wanted the program to run fast.
* I had just written a set of wrapper classes for the MySQL C API for [another project](http://russellhankins.com/ban_hackers.chp) and wanted to test it out.
* Feel free download/modify

# Links to help you compile:
* Install MySQL C API: apt-get install libmysqlclient-dev
* [MySQL C API Tutorial](http://zetcode.com/db/mysqlc/)
* [MySQL C API Function Overview](https://dev.mysql.com/doc/refman/5.5/en/c-api-function-overview.html)
* [MySQL C API Prepared Statements Sample](https://dev.mysql.com/doc/refman/5.5/en/c-api-prepared-call-statements.html)
