#ifndef NS_PSP9PJHU
#define NS_PSP9PJHU

#include "TCPClient.h"
#include "SSLClient.h"
#include "Account.h"
#include "ContactList.h"
#include "SwitchBoard.h"
#include "CmdQueue.h"
#include "OIM.h"

struct _NS
{
	TCPClient *tclient;	
	SSLClient *sclient;	
	Account *account;
	SB *sblist;
	bool verified;
	int TrID;
	int flag;
	int nextping;
	ContactList *contacts;
	CmdQueue cmdq;
	CmdQueue notifications;
	pthread_t nsthread;
	char *oticket;
};
#define NS_WAITFORTRID 1
#define NS_CONNECTED 2
#define PKEY "PK}_A_0N_K%O?A9S"
#define PID "PROD0114ES4Z%Q5W"

struct nsdispatch {
	const char * cmd;
	NSDispatchFunc func;
};

typedef struct tagMSGRUSRKEY
{
       unsigned long uStructHeaderSize; // 28. Does not count data
       unsigned long uCryptMode; // CRYPT_MODE_CBC (1)
       unsigned long uCipherType; // TripleDES (0x6603)
       unsigned long uHashType; // SHA1 (0x8004)
       unsigned long uIVLen;    // 8
       unsigned long uHashLen;  // 20
       unsigned long uCipherLen; // 72
		// Data
       unsigned char aIVBytes[8];
       unsigned char aHashBytes[20];
       unsigned char aCipherBytes[72];
} MSGUSRKEY;

NS *NS_new(Account *account);
void NS_destroy(NS *ns);
int NS_connect(NS *ns);
int NS_ping(NS *ns);
int NS_dispatch_blocking(NS *ns);
int NS_dispatch_nblocking(NS *ns, int sec, int usec);
bool NS_dispatch_commands(NS *ns);
void NS_remove_SB(NS *ns, unsigned long int sbid);
bool NS_fork(NS *ns);
NSNotifyData *NS_notify_data_new(NSNotify notify);
void NS_notify_data_destroy(void *notifydata);
void NS_msg_destroy(void *data);
int NS_request_SB(NS *ns);

#endif /* end of include guard: NS_PSP9PJHU */
