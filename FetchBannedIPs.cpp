#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "mysqli.h"
#include "mysqli_bind.h"
#include <string.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <signal.h>


// Turn this on to debug segmentation faults:
#define DEBUG LineNumber = __LINE__
volatile int LineNumber; // For debugging.	

struct node
{
	char *item;
	int length;
	struct node *smaller;
	struct node *bigger;
};

// Fetch banned IPs from the database and ban them.
void FetchBannedIPs(const char *server,struct node **current_ips,bool actually_ban,int stop_count);
// Adds one IP from iptables or database to the list.
bool AddIPToList(struct node **list,char *line,bool parse,bool sort,struct node **duplicates);
// Adds a node to a list. Finds the right spot for it. sorted = true for a binary tree else linked list.
void AddNode(struct node *item,struct node **list,bool sorted,struct node **duplicates);
// Ban bannedIP if it's not in current_ips. Then add it to current_ips.
bool BanThisIP(struct node **bannedIP,struct node **current_ips);
// Frees all the memory of the node list.
void FreeNodes(struct node **current_ips);
// Opens a database connection.
void OpenDatabase(mysqli &db,const char *server);
// A simple cipher that's good enough to beat someone with a hex editor.
void rot13(const char *original,char *output);
// Is this an IP address? You can't trust the database because it might have been hacked.
bool IsIP(const char *ip);
// List the current banned IPs from iptables.
void ListCurrent();
// Clear the current list of IPs.
void ClearCurrent();
// Clears a list of IPs.
void ClearIPList(struct node *ipList);
// Find a node or the next place it goes. Returns found status in found.
struct node *FindNode(struct node *list,const char *item,int length,int &found);
// Reads all the IPs from the iptables program. If sort = true then return a tree otherwise return a linked list.
struct node *ReadFromIptables(bool sort,struct node **duplicates);
// Get the list of IPs to ban from the database. Returns a linked list, not a tree.
struct node *GetIPsToBan(const char *server);

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
	
	rot13("YzmSzxpvih",username); // "BanHackers"
	rot13("$Yzmmvw5Vevi",password); // "$Banned4Ever"
	rot13("yzmmvw",database); // "banned"
	DEBUG;
	db.real_connect(server,username,password,database,3306);
	DEBUG;
	return;
}

int main(int argc,char *argv[])
{
	struct node *current_ips;
	struct node *duplicates;
	char line[1000];
	
	current_ips = nullptr;
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
				duplicates = nullptr;
				if (strcmp(argv[2],"BAN")==0) {					
					current_ips = ReadFromIptables(true,&duplicates);
					FetchBannedIPs(argv[1],&current_ips,true,0);
					FreeNodes(&current_ips);
				} else {
					if (strcmp(argv[2],"BAN200")==0) {
						current_ips = ReadFromIptables(true,&duplicates);
						FetchBannedIPs(argv[1],&current_ips,true,200);
						FreeNodes(&current_ips);
					} else {
						printf("Argument 3 %s was not understood.\n",argv[2]);
					}
				}
				if (duplicates != nullptr) {
					ClearIPList(duplicates);
					FreeNodes(&duplicates);
					duplicates = nullptr;
				}
				break;
			}
			default:
			{
			   printf("FetchBannedIPs V 1.4\nReads banned IPs from a database and bans them on this server.\n");
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
		 printf("%s in line %d\n",error,LineNumber);
	} catch (...) {
		printf("Unknown error in line %d\n",LineNumber);
	}
	
	#ifdef __linux__
	RemoveErrorHandler();
	#endif
	
	return 0;
}

// Clear the current list of IPs.
void ClearCurrent()
{
	struct node *ipList;	
	struct node *duplicates;	
	duplicates = nullptr;
	ipList = ReadFromIptables(false,&duplicates);
	ClearIPList(ipList);
	ClearIPList(duplicates);
	FreeNodes(&ipList);
	FreeNodes(&duplicates);
	return;
}
// Clears a list of IPs.
void ClearIPList(struct node *ipList)
{
	const int BUFFER_SIZE = 1024;
	char buffer[BUFFER_SIZE];
	struct node *loop;
	loop = ipList;
	while (loop != nullptr) {
		snprintf(buffer,BUFFER_SIZE,"sudo iptables -w -D INPUT -s %s/32 -j DROP",loop->item);
		printf("%s\n",buffer);
		system(buffer);
		loop = loop->bigger;
	}
	return;
}

// List the current banned IPs from iptables.
void ListCurrent()
{
	struct node *ipList;
	struct node *loop;
	ipList = ReadFromIptables(false,nullptr);	
	loop = ipList;
	while (loop != nullptr) {
		printf("%s\n",loop->item);
		loop = loop->bigger;
	}
	FreeNodes(&ipList);
	return;
}

// Reads all the IPs from the iptables program.
struct node *ReadFromIptables(bool sort,struct node **duplicates)
{
	// If sort is true then the list is a binary tree. 
	// If sort if false then the list is a linked list.
	// If duplicates != nullptr then add duplicates to this duplicates list.
	FILE *fInput;
	struct node *ipList;
	const int BUFFER_SIZE = 1024;
	char buffer[BUFFER_SIZE];
	bool outOfMemory;

	ipList = nullptr;
	outOfMemory = false;
	DEBUG;
	fInput = popen("sudo iptables -w -S","r");
	if (fInput != nullptr) {
		DEBUG;
		while (fgets(buffer,BUFFER_SIZE,fInput) != nullptr) {
			DEBUG;
			if (!outOfMemory) {
				DEBUG;
				if (!AddIPToList(&ipList,buffer,true,sort,duplicates)) {
					outOfMemory = true;
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
void FetchBannedIPs(const char *server,struct node **current_ips,bool actually_ban,int stop_count)
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
				if (BanThisIP(&banned,current_ips))
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
bool BanThisIP(struct node **bannedIP,struct node **current_ips)
{
	struct node *search;
	struct node *banned;
	char command[200];
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
	
	snprintf(command,199,"sudo iptables -w -A INPUT -s %s -j DROP",banned->item);
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
