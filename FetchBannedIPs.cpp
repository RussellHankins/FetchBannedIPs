#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "mysqli.h"
#include "mysqli_bind.h"
#include <string.h>

#ifdef __linux__
#include <sys/types.h>
#include <sys/syscall.h>
#include <signal.h>
#endif

// Turn this on to debug segmentation faults:
#define DEBUG LineNumber = __LINE__
volatile int LineNumber; // For debugging.

const char *ipset_name = "evil_hackers";

struct node
{
	char *item;
	int length;
	struct node *smaller;
	struct node *bigger;
};

// Run this if the user sent in one parameter.
void ProcessOneParameter(const char *argv1,bool useIpset);
// Run this if the user sent in two parameters.
void ProcessTwoParameters(const char *argv1,const char *argv2,bool useIpset);
// Runs if the user sent three parameters.
void ProcessThreeParameters(const char *argv1,const char *argv2,const char *argv3);
// Show a message telling the user how to use this program.
void ShowHelpMessage();
// Fetch banned IPs from the database and ban them.
void FetchBannedIPs(const char *server,struct node **current_ips,bool actually_ban,int stop_count,bool useIpset);
// Adds one IP from iptables or database to the list.
bool AddIPToList(struct node **list,char *line,bool parse,bool sort,struct node **duplicates);
// Adds a node to a list. Finds the right spot for it. sorted = true for a binary tree else linked list.
void AddNode(struct node *item,struct node **list,bool sorted,struct node **duplicates);
// Ban bannedIP if it's not in current_ips. Then add it to current_ips.
bool BanThisIP(struct node **bannedIP,struct node **current_ips,bool useIpset);
// Frees all the memory of the node list.
void FreeNodes(struct node **current_ips);
// Opens a database connection.
void OpenDatabase(mysqli &db,const char *server);
// A simple cipher that's good enough to beat someone with a hex editor.
void rot13(const char *original,char *output);
// Is this an IP address? You can't trust the database because it might have been hacked.
bool IsIP(const char *ip);
// List the current banned IPs from iptables.
void ListCurrent(bool useIpset);
// Clear the current list of IPs.
void ClearCurrent(bool useIpset);
// Clears a list of IPs.
void ClearIPList(struct node *ipList,bool useIpset);
// Find a node or the next place it goes. Returns found status in found.
struct node *FindNode(struct node *list,const char *item,int length,int &found);
// Reads all the IPs from the iptables program. If sort = true then return a tree otherwise return a linked list.
struct node *ReadFromIptables(bool sort,struct node **duplicates,bool useIpset,bool readAll);
// Get the list of IPs to ban from the database. Returns a linked list, not a tree.
struct node *GetIPsToBan(const char *server);
// Create the ipset name. The program must already know it doesn't exist before calling.
void CreateIpsetSetname();
// Make sure iptables has the right ban rule for ipset.
void MakeSureIptablesHasIpsetRule();

#ifdef __linux__
// Linux uses signals to 
// Display an error from a segmentation fault.
void ErrorHandler(int signum);
// Add error handlers for segmenation faults not caught with try/catch.
void AddErrorHandler();
// Make sure the signals don't point to some function that might not exist in the future.
void RemoveErrorHandler();
#endif

// Opens a database connection.
void OpenDatabase(mysqli &db,const char *server)
{	
	char username[50];
	char password[50];
	char database[50];
	
	// Put the database username/password/database name here:
	// Encrypt it with rot13 so someone doesn't find it with a binary editor.
	// The formula I use is 27 - X for letters and 9 - X for numbers.
	rot13("YztSzxpvih",username);
	rot13("HgkrwSzxpvi$",password);
	rot13("yzmmvw",database);
	DEBUG;
	db.real_connect(server,username,password,database,3306);
	DEBUG;
	return;
}

int main(int argc,char *argv[])
{
	LineNumber = __LINE__;
	
	#ifdef __linux__
	AddErrorHandler();
	#endif	
	
	try
	{
		switch (argc)
		{
			case 2:
			{
				ProcessOneParameter(argv[1],false);
				break;
			}
			case 3:
			{
				ProcessTwoParameters(argv[1],argv[2],false);
				break;
			}
			case 4:
			{
				ProcessThreeParameters(argv[1],argv[2],argv[3]);
				break;
			}
			default:
			{
				ShowHelpMessage();
				break;
			}
		}
	} catch(const char *error) {
		 printf("%s in line %d\n",error,LineNumber);
	} catch (...) {
		printf("Unknown error in line %d\n",LineNumber);
	}
	
	#ifdef __linux__
	RemoveErrorHandler();
	#endif
	
	return 0;
}

// Run this if the user sent in one parameter.
void ProcessOneParameter(const char *argv1,bool useIpset)
{
	if (strcasecmp(argv1,"LIST")==0) {
		ListCurrent(useIpset);
		return;
	}
	if (strcasecmp(argv1,"CLEAR")==0) {
		ClearCurrent(useIpset);
		printf("Cleared.\n");
		return;
	}
	printf("Here's a list of IPs that need to be banned:\n");
	FetchBannedIPs(argv1,nullptr,false,0,useIpset);
	return;
}

// Run this if the user sent in two parameters.
void ProcessTwoParameters(const char *argv1,const char *argv2,bool useIpset)
{
	struct node *duplicates = nullptr;
	struct node *current_ips;
	
	do { // Loop only once
		if (strcasecmp(argv2,"IPSET")==0) {
			ProcessOneParameter(argv1,true);
			break;
		}
		if (strcasecmp(argv2,"BAN")==0) {
			current_ips = ReadFromIptables(true,&duplicates,useIpset,false);
			FetchBannedIPs(argv1,&current_ips,true,0,useIpset);
			FreeNodes(&current_ips);
			break;
		}
		if (strcasecmp(argv2,"BAN200")==0) {
			current_ips = ReadFromIptables(true,&duplicates,useIpset,false);
			FetchBannedIPs(argv1,&current_ips,true,200,useIpset);
			FreeNodes(&current_ips);
			break;
		}
		printf("Argument 2 %s was not understood.\n",argv2);
	} while (false);
	if (duplicates != nullptr) {
		// Remove duplicates.
		ClearIPList(duplicates,useIpset);
		FreeNodes(&duplicates);
		duplicates = nullptr;
	}
	return;
}

// Runs if the user sent three parameters.
void ProcessThreeParameters(const char *argv1,const char *argv2,const char *argv3)
{
	if (strcasecmp(argv3,"IPSET")==0) {
		ProcessTwoParameters(argv1,argv2,true);
	} else {
		printf("Argument 3 %s was not understood.\n",argv3);
	}
	return;
}

// Show a message telling the user how to use this program.
void ShowHelpMessage()
{
	printf("FetchBannedIPs V 1.5 reads banned IPs from a database and bans them on this server.\n");
	printf("It uses iptables, but if you add the IPSET parameter,it will use ipset.\n");
	printf("Examples:\n");
	printf("List banned IPs from the database: FetchBannedIPs 192.168.0.204\n");
	printf("Read the banned IPs from the database and ban them here:\n");
	printf("FetchBannedIPs 192.168.0.204 BAN\n");
	printf("Read the banned IPs from the database and ban them with ipset:\n");
	printf("FetchBannedIPs 192.168.0.204 BAN IPSET\n");
	printf("Read the banned IPs from the database and ban up to 200 of them here:\n");
	printf("FetchBannedIPs 192.168.0.204 BAN200\n");
	printf("Read the banned IPs from the database and ban up to 200 of them here with ipset:");
	printf("FetchBannedIPs 192.168.0.204 BAN200 IPSET\n");
	printf("List all the IPs banned in iptables: FetchBannedIPs LIST\n");
	printf("List the banned IPs from ipset: FetchBannedIPs LIST IPSET\n");
	printf("Clear all banned IPs from iptables: FetchBannedIPs CLEAR\n");
	printf("Clear the banned IPs from ipset: FetchBannedIPs CLEAR IPSET\n");
	printf("The iptables and ipset rules for the set name \"evil_hackers\" are automatically created if you use ipset.\n");
	return;
}

// Clear the current list of IPs.
void ClearCurrent(bool useIpset)
{
	struct node *ipList;	
	struct node *duplicates;	
	
	if (useIpset) {
		ClearIPList(nullptr,useIpset);
	} else {
		duplicates = nullptr;
		ipList = ReadFromIptables(false,&duplicates,useIpset,false);
		ClearIPList(ipList,useIpset);
		ClearIPList(duplicates,useIpset);
		FreeNodes(&ipList);
		FreeNodes(&duplicates);
	}
	return;
}
// Clears a list of IPs.
void ClearIPList(struct node *ipList,bool useIpset)
{
	const int BUFFER_SIZE = 1024;
	char buffer[BUFFER_SIZE];
	struct node *loop;
	
	if (useIpset) {
		snprintf(buffer,BUFFER_SIZE,"sudo ipset flush %s",ipset_name);
		printf("%s\n",buffer);
		system(buffer);
	} else {		
		loop = ipList;
		while (loop != nullptr) {
			snprintf(buffer,BUFFER_SIZE,"sudo iptables -D INPUT -s %s/32 -j DROP",loop->item);
			printf("%s\n",buffer);
			system(buffer);
			loop = loop->bigger;
		}
	}
	return;
}

// List the current banned IPs from iptables.
void ListCurrent(bool useIpset)
{
	struct node *ipList;
	struct node *loop;
	ipList = ReadFromIptables(false,nullptr,useIpset,false);
	loop = ipList;
	while (loop != nullptr) {
		printf("%s\n",loop->item);
		loop = loop->bigger;
	}
	FreeNodes(&ipList);
	return;
}

// Reads all the IPs from the iptables program.
struct node *ReadFromIptables(bool sort,struct node **duplicates,bool useIpset,bool readAll)
{
	// If sort is true then the list is a binary tree. 
	// If sort if false then the list is a linked list.
	// If duplicates != nullptr then add duplicates to this duplicates list.
	FILE *fInput;
	struct node *ipList;
	const int BUFFER_SIZE = 1024;
	char buffer[BUFFER_SIZE];
	bool outOfMemory;
	bool foundMembers;

	ipList = nullptr;
	outOfMemory = false;
	DEBUG;
	if (useIpset) {
		snprintf(buffer,BUFFER_SIZE,"sudo ipset list %s",ipset_name);
		fInput = popen(buffer,"r");
		foundMembers = false;
	} else {
		fInput = popen("sudo iptables -w -S","r");
	}
	if (fInput != nullptr) {
		DEBUG;
		while (fgets(buffer,BUFFER_SIZE,fInput) != nullptr) {
			DEBUG;
			if (!outOfMemory) {
				DEBUG;
				if (useIpset) {
					// Use ipset
					if ((readAll) || (foundMembers)) {
						if (!AddIPToList(&ipList,buffer,false,sort,duplicates)) {
							outOfMemory = true;
						}
					} else {
						if (strncasecmp(buffer,"Members:",8)==0) {
							foundMembers = true;
						}						
					}
				} else {
					// Use iptables.					
					if (!AddIPToList(&ipList,buffer,!readAll,sort,duplicates)) {
						outOfMemory = true;
					}
				}
				DEBUG;
			}
		}
		DEBUG;
		pclose(fInput);
	}
	if (outOfMemory) {
		FreeNodes(&ipList);
		throw "Out of memory reading IPs from iptables.";
	}
	if ((useIpset) && (!foundMembers)) {
		// If Members: wasn't found then the set doesnt' exist. Create it.
		CreateIpsetSetname();
		MakeSureIptablesHasIpsetRule();
	}
	return ipList;
}

// Adds one IP from iptables or database to the list.
bool AddIPToList(struct node **list,char *line,bool parse,bool sorted,struct node **duplicates)
{
	char *search1;
	char *search2;
	int length;
	char *ip;
	struct node *new_node;
	struct node *search;
	DEBUG;
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
				// Remove enter character.
				while (length > 0) {
					if (ip[length-1] < ' ') {
						length--;
					} else {
						break;
					}
				}	
				ip[length]=0;
				new_node = new node;// (struct node *)malloc(sizeof(struct node));
				if (new_node == nullptr) {
					delete[] ip;
					return false;
				}
				new_node->item = ip;
				new_node->length = length;
				new_node->smaller = nullptr;
				new_node->bigger = nullptr;
				DEBUG;
				AddNode(new_node,list,sorted,duplicates);
				DEBUG;
			}
		}
	} else {
		length = strlen(line);
		ip = new char[length+1];
		if (ip == nullptr) {
			return false;
		}
		strcpy(ip,line);
		// Remove enter character.
		while (length > 0) {
			if (ip[length-1] < ' ') {
				length--;
				ip[length] = 0;
			} else {
				break;
			}
		}
		new_node = new node;// (struct node *)malloc(sizeof(struct node));
		if (new_node == nullptr) {
			delete[] ip;
			return false;
		}
		new_node->item = ip;
		new_node->length = length;
		new_node->smaller = nullptr;
		new_node->bigger = nullptr;
		DEBUG;
		AddNode(new_node,list,sorted,duplicates);
		DEBUG;
	}
	DEBUG;
	return true;
}

// Adds a node to a list. Finds the right spot for it.
void AddNode(struct node *item,struct node **list,bool sorted,struct node **duplicates)
{
	struct node *search;
	int found;	
	if (list != nullptr) {
		if (*list == nullptr) {
			*list = item;
		} else {
			if (sorted) {
				// Sorted.		
				search = FindNode(*list,item->item,item->length,found);
				if (found < 0) {
					search->bigger = item;
				}
				if (found > 0) {
					search->smaller = item;
				}
				if ((found == 0) && (search != nullptr) && (duplicates != nullptr)) {
					item->bigger = *duplicates;
					*duplicates = item;
				}
			} else {
				// Unsorted.
				item->bigger = *list;
				*list = item;
			}
		}
	}
	return;
}
// Find a node or the next place it goes. Returns found status in found. 
struct node *FindNode(struct node *list,const char *item,int length,int &found)
{	
	// If the node was found then found = 0 and the node is returned.
	// If the node was not found then found !=0 and the insert point is returned.
	// If found < 0 then add to ->bigger.
	// If found > 0 then add to ->smaller.
	// If list == nullptr then found = 0 and nullptr is returned.
	struct node *loop;
	struct node *next;
	int compare;
	
	compare = 0;
	loop = list;
	if (list != nullptr) {
		while (true) {
			compare = loop->length - length;
			if (compare == 0) {
				compare = memcmp(loop->item,item,length);
			}
			if (compare < 0) {
				next = loop->bigger;
				if (next == nullptr) {
					break;
				}
				loop = next;
				continue;
			}
			if (compare > 0) {
				next = loop->smaller;
				if (next == nullptr) {
					break;
				}
				loop = next;
				continue;
			}
			break;
		}
	}
	found = compare;
	return loop;
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

// Get the list of IPs to ban from the database. Returns a linked list, not a tree.
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

	DEBUG;
	outOfMemory= false;
	list = nullptr;
    OpenDatabase(db,server);
	outputBannedIP[50] = 0;
	PrepareGetNewBannedQuery(db,stmt);
	int param_count = stmt.param_count();
	if (param_count != 1) {
		throw "Incorrect number of parameters.";
	}
	DEBUG;
	mysqli_bind inputs(1);
	inputBannedID = 0; // In the future, this will be a different number.
	inputs.bind(0,inputBannedID);
	stmt.bind_param(inputs);
	DEBUG;
	stmt.execute();
	DEBUG;
	// Build outputs for the loop.
	mysqli_bind outputs(2);
	outputs.bind(0,outputBannedID);
	outputs.bind(1,outputBannedIP,50,outputBannedIPLength);
	DEBUG;
	if (!stmt.bind_result(outputs)) {
		throw "bind results failed.";
	}
	DEBUG;
	if (!stmt.store_result()) {
		throw "Error in store_result.";
	}	   
	DEBUG;
	numberofsaves = 0;
	while (stmt.fetch()) {
		DEBUG;
		if (!AddIPToList(&list,outputBannedIP,false,false,nullptr)) {
			outOfMemory = true;
			break;
		}
		DEBUG;
	}
	stmt.close();
	db.close();
	DEBUG;
	if (outOfMemory) {
		DEBUG;
		FreeNodes(&list);
		DEBUG;
		throw "Out of memory reading the list of IPs from the database.";
	}
	DEBUG;
	return list;
}

// Fetch banned IPs from the database and ban them.
void FetchBannedIPs(const char *server,struct node **current_ips,bool actually_ban,int stop_count,bool useIpset)
{
	struct node *ipsToBan;
	struct node *loop;
	struct node *banned;
	const char *item;
	int numberofsaves;
	try
	{
		numberofsaves = 0;
		ipsToBan = nullptr;
		DEBUG;
		ipsToBan = GetIPsToBan(server); // Linked list using ->bigger.
		DEBUG;
		loop = ipsToBan;
		while (loop != nullptr) {
			// Save the item, then save the location of the next item.
			DEBUG;
			banned = loop;
			item = banned->item;
			loop = loop->bigger;
			DEBUG;
			if (actually_ban && IsIP(item)) {				
				// banned will be set to nullptr if it is move to the current_ips list.
				DEBUG;
				if (BanThisIP(&banned,current_ips,useIpset))
				{
					DEBUG;
					numberofsaves++;
					printf("Added %s\n",item);
					if ((stop_count > 0) && (numberofsaves > stop_count)) {
					   // Run for a little over 3 minutes, then exit.
					   printf("Stopped at %d.\n",stop_count);
					   break;
					}
					if (stop_count > 0) {
						sleep(1); // Sleep 1 second.
					}
				}
				DEBUG;
			} else {
				DEBUG;
				printf("%s\n",item);
				DEBUG;
			}
			// Delete this item if it's not already deleted.
			DEBUG;
			if (banned != nullptr) {
				delete[] banned->item;
				delete banned;
			}
			DEBUG;
		}
		ipsToBan = nullptr;
     } catch(const char *error) {
		 printf(error);
	 }
	 DEBUG;
	return; 
}
// Frees all the memory of the node list.
void FreeNodes(struct node **current_ips)
{	
	// I know there's a simple recursive algorhythm to delete a tree.
	// But for large trees, deleting recursively can crash the stack.
	// This deletes iteratively to not crash the stack.
	struct node *smaller;	
	struct node *bigger;
	struct node *loop;
	if (current_ips == nullptr) {
		return;
	}
	while (*current_ips != nullptr) {		
		loop = *current_ips;
		// Look to possibly delete the first node.
		smaller = loop->smaller;
		bigger = loop->bigger;
		if (smaller == nullptr) {
			// Delete the current item and make ->bigger the first item.
			delete[] loop->item;
			delete loop;
			*current_ips = bigger;
			continue;
		}
		if (bigger == nullptr) {
			// Delete the current item and make ->smaller the first item.
			delete[] loop->item;
			delete loop;
			*current_ips = smaller;
			continue;
		}
		while (loop != nullptr) {
			smaller = loop->smaller;
			if (smaller != nullptr) {
				// Look to see if smaller can be deleted.
				if ((smaller->smaller == nullptr) && (smaller->bigger == nullptr)) {
					// ->smaller is at the bottom of the tree. Delete it.
					delete[] smaller->item;
					delete smaller;
					loop->smaller = nullptr;
					smaller = nullptr;				
				}
			}
			bigger = loop->bigger;
			if (bigger != nullptr) {
				// Look to see if bigger can be deleted.
				if ((bigger->smaller == nullptr) && (bigger->bigger == nullptr)) {
					// ->bigger is at the bottom of the tree. Delete it.
					delete[] bigger->item;
					delete bigger;
					loop->bigger = nullptr;
					bigger = nullptr;
				}
			}
			if ((smaller == nullptr) && (bigger != nullptr)) {
				// Delete the current node and move ->bigger in its place.
				delete[] loop->item;
				loop->item = bigger->item;
				loop->smaller = bigger->smaller;
				loop->bigger = bigger->bigger;
				delete bigger;
				continue;
			}
			if ((bigger == nullptr) && (smaller != nullptr)) {
				// Delete the current node and move ->smaller in its place.
				delete[] loop->item;
				loop->item = smaller->item;
				loop->smaller = smaller->smaller;
				loop->bigger = smaller->bigger;
				delete smaller;
				continue;
			}
			// Move to the next node.
			// Pick a random direction from available choices. It doesn't matter.
			if (smaller != nullptr) {
				loop = smaller;
			} else {
				loop = bigger;
			}
		}
	}	
	return;
}
// Ban bannedIP if it's not in current_ips. Then add it to current_ips.
// Sets *bannedIP to nullptr if it was added to current_ips.
bool BanThisIP(struct node **bannedIP,struct node **current_ips,bool useIpset)
{
	struct node *search;
	struct node *banned;
	const int COMMAND_SIZE = 200;
	char command[COMMAND_SIZE];
	int found;
	
	banned = *bannedIP;
	if (*current_ips == nullptr) {
		*current_ips = banned;
		banned->smaller = nullptr;
		banned->bigger = nullptr;
		*bannedIP = nullptr;
	} else {
		search = FindNode(*current_ips,banned->item,banned->length,found);
		if ((search != nullptr) && (found == 0)) {
			// Already found.
			return false;
		}
		// Add this IP to current_ips.
		banned->smaller = nullptr;
		banned->bigger = nullptr;
		if (found < 0) {
			search->bigger = banned;
		}
		if (found > 0) {
			search->smaller = banned;
		}
		*bannedIP = nullptr;
	}
	if (useIpset) {
		snprintf(command,COMMAND_SIZE,"sudo ipset add %s %s",ipset_name,banned->item);
	} else {
		snprintf(command,COMMAND_SIZE,"sudo iptables -w -A INPUT -s %s -j DROP",banned->item);
	}
	//printf("%s\n",command);
	command[COMMAND_SIZE-1] = 0;
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
// Create the ipset name. The program must already know it doesn't exist before calling.
void CreateIpsetSetname()
{
	const int BUFFER_SIZE = 200;
	char buffer[BUFFER_SIZE];

	snprintf(buffer,BUFFER_SIZE,"sudo ipset create %s iphash",ipset_name);
	printf("%s\n",buffer);
	system(buffer);
	return;
}
// Make sure iptables has the right ban rule for ipset.
void MakeSureIptablesHasIpsetRule()
{
	struct node *ipList;
	struct node *loop;
	const int BUFFER_SIZE = 200;
	char buffer[BUFFER_SIZE];
	bool hasIpsetRule;
	
	// Look for rule in iptables.
	ipList = ReadFromIptables(false,nullptr,false,true);
	hasIpsetRule = false;
	loop = ipList;
	while (loop != nullptr) {
		if (strcasestr(loop->item,ipset_name)!=nullptr) {
			hasIpsetRule = true;
			break;
		}
		loop = loop->bigger;
	}
	FreeNodes(&ipList);
	if (!hasIpsetRule) {
		snprintf(buffer,BUFFER_SIZE,"sudo iptables -A INPUT -m set --match-set %s src -j DROP",ipset_name);
		printf("%s\n",buffer);
		system(buffer);
	}
	return;
}

#ifdef __linux__
// Display an error from a segmentation fault.
void ErrorHandler(int signum)
{
	const char *errorType = "Segmentation fault";
	switch (signum) {
		case SIGFPE:
		{
			errorType = "Division by zero";
			break;
		}
		case SIGILL:
		{
			errorType = "Illegal instruction";
			break;
		}
		case SIGSEGV:
		{
			errorType = "Bad memory read/write";
			break;
		}
		case SIGBUS:
		{
			errorType = "Access misalligned memory or non-existent memory";
			break;
		}
	}
	printf("%s after line %d.\n",errorType,LineNumber);
	exit(signum);
	return;	
}

// Add error handlers for segmenation faults not caught with try/catch.
void AddErrorHandler()
{
	signal (SIGFPE, ErrorHandler); // division by 0
	signal (SIGILL, ErrorHandler); // illegal instruction
	signal (SIGSEGV, ErrorHandler); // bad memory read/write
	signal (SIGBUS, ErrorHandler); // access misalligned memory or non-existent memory	
}

// Make sure the signals don't point to some function that might not exist in the future.
void RemoveErrorHandler()
{	
	signal (SIGFPE, SIG_DFL); // division by 0
	signal (SIGILL, SIG_DFL); // illegal instruction
	signal (SIGSEGV, SIG_DFL); // bad memory read/write
	signal (SIGBUS, SIG_DFL); // access misalligned memory or non-existent memory	
	return;
}
#endif
