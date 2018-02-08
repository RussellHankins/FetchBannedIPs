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

void FetchBannedIPs(const char *server,struct node **current_ips,bool actually_ban);
bool AddIPToList(struct node **list,char *line);
bool BanThisIP(const char *bannedIP,int length,struct node **current_ips);
void FreeNodes(struct node **current_ips);
void OpenDatabase(mysqli &db,const char *server);
void rot13(const char *original,char *output);
bool IsIP(const char *ip);

// Opens a database connection.
void OpenDatabase(mysqli &db,const char *server)
{	
	char username[30];
	char password[30];
	char database[30];
	
	rot13("Put encrypted user name here",username);
	rot13("Put encrypted password here",password);
	rot13("Put encrypted database name here",database);
	db.real_connect(server,username,password,database,3306);
	return;
}

int main(int argc,char *argv[])
{
	struct node *current_ips = nullptr;	
	char line[1000];
   if (argc==2) {
	   if (isatty(fileno(stdin))) {
			printf("Here's a list of IPs that need to be banned:\n");			
			FetchBannedIPs(argv[1],nullptr,false);
		} else {			
			// Read the list of currently banned IPs from the 
		   while (!feof(stdin)) {			   
			   fgets(line,999,stdin);
			   line[999] = 0;
			   if (!AddIPToList(&current_ips,line)) {
				   printf("Out of memory reading the input list\n.");
				   return 0;
			   }
		   }
		   FetchBannedIPs(argv[1],&current_ips,true);
		   FreeNodes(&current_ips);
		}	    
   } else {
	   printf("FetchBannedIPs V 1.2\nReads banned IPs from a database and bans them on this server.\n");
	   printf("FetchBannedIPs {server}\n");
	   printf("Connects to {server}, fetches new banned IPs and adds them to iptables if needed.\n");	   
	   printf("Example 1 - List banned IPs from the database:\nFetchBannedIPs 192.168.0.204\n");	   
	   printf("Example 2 - Read the banned IPs from the database and ban them here:\nsudo iptables -S|FetchBannedIPs 192.168.0.204\n");
   }
   return 0;
}

// Adds one IP from iptables to the list.
bool AddIPToList(struct node **list,char *line)
{
	char *search1;
	char *search2;
	int length;
	char *ip;
	struct node *new_node;
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

void FetchBannedIPs(const char *server,struct node **current_ips,bool actually_ban)
{
	try
	{
       mysqli db;
       OpenDatabase(db,server);
       mysqli_stmt stmt;
       int inputBannedID;
       int outputBannedID;
       char outputBannedIP[200];
       unsigned long outputBannedIPLength;
       
       PrepareGetNewBannedQuery(db,stmt);
       int param_count = stmt.param_count();
       if (param_count != 1) {
		   printf("Incorrect number of parameters.\n");
		   return;
	   }
       mysqli_bind inputs(1);
       inputBannedID = 0; // In the future, this will be a different number.
       inputs.bind(0,inputBannedID);
       stmt.bind_param(inputs);
       stmt.execute();
       // Build outputs for the loop.
       mysqli_bind outputs(2);
       outputs.bind(0,outputBannedID);
       outputs.bind(1,outputBannedIP,199,outputBannedIPLength);
       if (!stmt.bind_result(outputs)) {
		   printf("bind results failed.");
		   return;
	   }
	   if (!stmt.store_result()) {
		   printf("Error in store_result.\n");
		   return;
	   }
       while (stmt.fetch()) {
		   if (actually_ban) {
			   if (IsIP(outputBannedIP)) {
				   if (BanThisIP(outputBannedIP,(int)outputBannedIPLength,current_ips)) {
					   printf("Added %s\n",outputBannedIP);
					}
				}
		   } else {
			   printf("%d %s\n",outputBannedID,outputBannedIP);
		   }
	   }
       // Close objects.
       stmt.close();
       db.close();
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
