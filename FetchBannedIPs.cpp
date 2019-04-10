#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "mysqli.h"
#include "mysqli_bind.h"
#include <string.h>

struct node
{
	char *item;
	int length;
	struct node *next;
};

void FetchBannedIPs(const char *server,struct node **current_ips,bool actually_ban,int stop_count);
bool AddIPToList(struct node **list,char *line,bool parse);
bool BanThisIP(const char *bannedIP,int length,struct node **current_ips);
void FreeNodes(struct node **current_ips);
void OpenDatabase(mysqli &db,const char *server);
void rot13(const char *original,char *output);
bool IsIP(const char *ip);
void ListCurrent();
void ClearCurrent();
struct node *ReadFromIptables();
struct node *GetIPsToBan(const char *server);

// Opens a database connection.
void OpenDatabase(mysqli &db,const char *server)
{	
	char username[50];
	char password[50];
	char database[50];
	
	rot13("Put encrypted user name here",username);
	rot13("Put encrypted password here",password);
	rot13("Put encrypted database name here",database);
	db.real_connect(server,username,password,database,3306);
	return;
}

int main(int argc,char *argv[])
{
	struct node *current_ips;	
	char line[1000];
	current_ips = nullptr;
	try
	{
		switch (argc)
		{
			case 2:
			{
				if (strcmp(argv[1],"LIST")==0) {
					ListCurrent();
				} else {
					if (strcmp(argv[1],"CLEAR")==0) {
					ClearCurrent();
					printf("Cleared.\n");
					} else {
					printf("Here's a list of IPs that need to be banned:\n");
					FetchBannedIPs(argv[1],nullptr,false,0);
					}
				}
				break;
			}
			case 3:
			{
				if (strcmp(argv[2],"BAN")==0) {
					current_ips = ReadFromIptables();
					FetchBannedIPs(argv[1],&current_ips,true,0);
					FreeNodes(&current_ips);
				} else {
					if (strcmp(argv[2],"BAN200")==0) {
						current_ips = ReadFromIptables();
						FetchBannedIPs(argv[1],&current_ips,true,200);
						FreeNodes(&current_ips);
					} else {
						printf("Argument 3 %s was not understood.\n",argv[2]);
					}
				}
				break;
			}
			default:
			{
			   printf("FetchBannedIPs V 1.3\nReads banned IPs from a database and bans them on this server.\n");
			   printf("FetchBannedIPs {server}\n");
			   printf("Connects to {server}, fetches new banned IPs and adds them to iptables if needed.\n");
			   printf("FetchBannedIPs LIST\nReads the banned IPs from iptables and displays them.");
			   printf("FetchBannedIPs CLEAR\nRemoves all the ban rules from iptables.");
			   printf("FetchBannedIPs {server} BAN\nReads banned IPs from a database and bans them.\n");
			   printf("Example 1 - List banned IPs from the database:\nFetchBannedIPs 192.168.0.204\n");	   
			   printf("Example 2 - Read the banned IPs from the database and ban them here:\n");
			   printf("FetchBannedIPs 192.168.0.204 BAN\n");
			   printf("Example 3 - Read the banned IPs from the database and ban them here (Stop at 200):\n");
			   printf("FetchBannedIPs 192.168.0.204 BAN200\n");
			   break;
			}
		}
	} catch(const char *error) {
		 printf("%s\n",error);
	}
	return 0;
}

// Clear the current list of IPs.
void ClearCurrent()
{
	struct node *ipList;
	struct node *loop;
	const int BUFFER_SIZE=1024;
	char buffer[BUFFER_SIZE];
	ipList = ReadFromIptables();
	loop = ipList;
	while (loop != nullptr) {
		snprintf(buffer,BUFFER_SIZE,"sudo iptables -D INPUT -s %s/32 -j DROP",loop->item);
		printf("%s\n",buffer);
		system(buffer);
		loop = loop->next;
	}
	FreeNodes(&ipList);
	return;
}

// List the current banned IPs from iptables.
void ListCurrent()
{
	struct node *ipList;
	struct node *loop;
	ipList = ReadFromIptables();
	loop = ipList;
	while (loop != nullptr) {
		printf("%s\n",loop->item);
		loop = loop->next;
	}
	FreeNodes(&ipList);
	return;
}

// Reads all the IPs from the iptables program.
struct node *ReadFromIptables()
{
	FILE *fInput;
	struct node *ipList;
	const int BUFFER_SIZE = 1024;
	char buffer[BUFFER_SIZE];
	bool outOfMemory;

	ipList = nullptr;
	outOfMemory = false;
	fInput = popen("sudo iptables -S","r");
	if (fInput != nullptr) {
		while (fgets(buffer,BUFFER_SIZE,fInput) != nullptr) {
			if (!outOfMemory) {
				if (!AddIPToList(&ipList,buffer,true)) {
					outOfMemory = true;
				}
			}
		}
		pclose(fInput);
	}
	if (outOfMemory) {
		FreeNodes(&ipList);
		throw "Out of memory reading IPs from iptables.";
	}
	return ipList;
}

// Adds one IP from iptables to the list.
bool AddIPToList(struct node **list,char *line,bool parse)
{
	char *search1;
	char *search2;
	int length;
	char *ip;
	struct node *new_node;	
	if (parse) {
		if (strncmp(line,"-A INPUT -s ",12)==0) {
			search1 = strstr(line,"-j DROP");
			if (search1 != nullptr) {
				search2 = strstr(line,"/");
				if (search2 == nullptr) {
					length = (search1-line)-12;
				} else {
					length = (search2-line)-12;
				}
				ip = new char[length+1];
				if (ip == nullptr) {
					return false;
				}
				memcpy(ip,line+12,length);
				ip[length]=0;
				new_node = new node;// (struct node *)malloc(sizeof(struct node));
				if (new_node == nullptr) {
					delete[] ip;
					return false;
				}
				new_node->item = ip;
				new_node->length = length;
				new_node->next = *list;
				*list = new_node;
			}
		}
	} else {
		length = strlen(line);
		ip = new char[length+1];
		if (ip == nullptr) {
			return false;
		}
		strcpy(ip,line);		
		new_node = new node;// (struct node *)malloc(sizeof(struct node));
		if (new_node == nullptr) {
			delete[] ip;
			return false;
		}
		new_node->item = ip;
		new_node->length = length;
		new_node->next = *list;
		*list = new_node;
	}
	return true;
}

void rot13(const char *original,char *output)
{
	// A simple cipher that's
	// good enough to beat someone with a hex editor.
	// Not exactly rot13.
	// Assumes that output is a buffer big enough to hold the data.
	// output is probably a char array on the stack.
	const char *input;
	char *loop;
	char ch;
	
	input = original;
	loop = output;
	while (true) {
		ch = *(input++);
		if (ch == 0) {
			break;
		}
		if ((ch >='A') && (ch <= 'Z')) {
			ch = ('A'+'Z') - ch;
		}
		if ((ch >='a') && (ch <= 'z')) {
			ch = ('a'+'z') - ch;
		}
		if ((ch >='0') && (ch <= '9')) {
			ch = ('0'+'9')-ch;
		}
		*(loop++) = ch;
	}
	*loop = 0;

	return;
}

// Prepares the query to get new banned IPs.
void PrepareGetNewBannedQuery(mysqli &db,mysqli_stmt &stmt)
{
   char query[100];
   rot13("xzoo yzmmvw.hk_tvg_mvd_yzmmvw(?)",query); // "call banned.sp_get_new_banned(?)";
   db.prepare(query,strlen(query),stmt);
   return;
}

struct node *GetIPsToBan(const char *server)
{
	struct node *list;
    mysqli db;
	bool outOfMemory;
	mysqli_stmt stmt;
	int inputBannedID;
	int outputBannedID;
	char outputBannedIP[51];
	unsigned long outputBannedIPLength;
	int numberofsaves;

	outOfMemory= false;
	list = nullptr;
    OpenDatabase(db,server);
	outputBannedIP[50] = 0;
	PrepareGetNewBannedQuery(db,stmt);
	int param_count = stmt.param_count();
       if (param_count != 1) {
		   throw "Incorrect number of parameters.";
	   }
       mysqli_bind inputs(1);
       inputBannedID = 0; // In the future, this will be a different number.
       inputs.bind(0,inputBannedID);
       stmt.bind_param(inputs);
       stmt.execute();
       // Build outputs for the loop.
       mysqli_bind outputs(2);
       outputs.bind(0,outputBannedID);
       outputs.bind(1,outputBannedIP,50,outputBannedIPLength);
       if (!stmt.bind_result(outputs)) {
		   throw "bind results failed.";
	   }
	   if (!stmt.store_result()) {
		   throw "Error in store_result.";
	   }	   
	   numberofsaves = 0;
       while (stmt.fetch()) {
		if (!AddIPToList(&list,outputBannedIP,false)) {
			outOfMemory = true;
			break;
		}
	}
	stmt.close();
       db.close();
	if (outOfMemory) {
		FreeNodes(&list);
		throw "Out of memory reading the list of IPs from the database.";
	}
	return list;
}

void FetchBannedIPs(const char *server,struct node **current_ips,bool actually_ban,int stop_count)
{
	struct node *ipsToBan;
	struct node *loop;
	int numberofsaves;
	try
	{
		numberofsaves = 0;
		ipsToBan = nullptr;
		ipsToBan = GetIPsToBan(server);
		loop = ipsToBan;
		while (loop != nullptr) {
			if (actually_ban && IsIP(loop->item)) {
				if (BanThisIP(loop->item,loop->length,current_ips))
				{
					numberofsaves++;
					printf("Added %s\n",loop->item);
					if ((stop_count > 0) && (numberofsaves > stop_count)) {
					   // Run for a little over 3 minutes, then exit.
					   printf("Stopped at %d.\n",stop_count);
					   break;
					}
					sleep(1); // Sleep 1 second				   
				}
			} else {
				printf("%s\n",loop->item);
			}
			loop = loop->next;
		}
		FreeNodes(&ipsToBan);
     } catch(const char *error) {
		 printf(error);
	 }	 
  return; 
}
// Frees all the memory of the node list.
void FreeNodes(struct node **current_ips)
{
	struct node *to_delete;
	struct node *loop;
	if (current_ips == nullptr) {
		return;
	}
	loop = *current_ips;
	while (loop != nullptr) {
		to_delete = loop;
		loop = loop->next;
		delete[] to_delete->item;
		delete to_delete;
	}
	*current_ips = nullptr;
	return;
}
// Ban bannedIP if it's not in current_ips. Then add it to current_ips.
bool BanThisIP(const char *bannedIP,int length,struct node **current_ips)
{
	struct node *loop;
	char command[200];
	loop = *current_ips;
	while (loop != nullptr)
	{
		if ((loop->length == length) && (strcmp(loop->item,bannedIP)==0)) {
			// Has already been banned.
			return false;
		}
		loop = loop->next;
	}
	
	// Security issue: Make sure bannedIP is an actual IP address and not some malicious text string.
	snprintf(command,199,"sudo iptables -A INPUT -s %s -j DROP",bannedIP);
	//printf("%s\n",command);
	command[199] = 0;
	system(command);
	return true;
}
// Is this an IP address? You can't trust the database because it might have been hacked.
bool IsIP(const char *ip)
{
	const char *loop;
	char ch;
	if (ip == nullptr) {
		return false;
	}
	if (*ip == 0) {
		return false;
	}
	loop = ip;
	while(true)
	{
		ch = *(loop++);
		if (ch == 0) {
			break;
		}
		if ((ch != '.') && ((ch < '0') || (ch > '9'))) {
			return false;
		}
	}
	return true;
}
