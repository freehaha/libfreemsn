#ifndef SWITCHBOARD_D6RK4SQJ
#define SWITCHBOARD_D6RK4SQJ

#include "msnlib.h"
#include "NS.h"
#include "TCPClient.h"
#include "ContactList.h"
#include "Account.h"
#include "CmdQueue.h"

struct _switchboard
{
	unsigned long id;
	int TrID;
	TCPClient *client;
	SBBuddy *list;
	Account *account;
	char *ticket;
	int sesid;
	int flag;
	SB *next;
	unsigned int count;
	CmdQueue cmdq;
	CmdQueue notifications;
};
#define SB_CONNECTED 1

enum _sbmsgtype
{
	SBMSG_CONTROL, SBMSG_TEXT, SBMSG_INVITE, SBMSG_P2P
};

/* got message from SB */
struct _sbmsgnotify
{
	SB *sb;
	SBNotify type;
	SBMsgType msgtype;
	char *nick;
	char *email;
	char *text;
};

struct _sbbuddy {
	char *nick;
	char *email;
	//Contact *buddy;
	int cid;
	SBBuddy *next;
};

SB *SB_new(Account *account, const char *server, int port, const char *ticket, int sesid);
int SB_connect(SB *sb);
void SB_destroy(SB *sb);
SBBuddy *sbbuddy_new(const char *nick, const char *email, int cid);
void sbbuddy_destroy(SBBuddy *bd);
int SB_sendmsg(SB *sb, const char *msg);
bool SB_dispatch_commands(SB *sb);
SBNotifyData *SB_notify_data_new(SB *sb, SBNotify notify);
int SB_buddy_count(SB*);
void SB_notify_data_destroy(void *notifydata);
void SB_msg_destroy(void *data);
int SB_invite(SB *sb, const char *email);
SBMsgData *SB_msg_new(SB *sb, MsgType type, const char *cmd, const char* arg, const char *payload, int length, bool appendID);

int SB_dispatch_nblocking(SB *sb, int sec, int usec);
struct sbdispatch
{
	const char * cmd;
	SBDispatchFunc func;
};


int _SB_disp_MSG(SB* sb, char * command); /* messenges */
int _SB_disp_ANS(SB* sb, char * command); /* answer response to join notification */
int _SB_disp_USR(SB* sb, char * command); /* authentication confirm */
int _SB_disp_CAL(SB* sb, char * command); /* success of calling buddy */
int _SB_disp_JOI(SB* sb, char * command); /* somebody joins */
int _SB_disp_IRO(SB* sb, char * command); /* init user list */
int _SB_disp_BYE(SB* sb, char * command); /* somebody leaves */
int _SB_disp_NAK(SB *sb, char * commnad); /* failed sending message */
extern struct sbdispatch _sb_dispatch_table[];
#endif /* end of include guard: SWITCHBOARD_D6RK4SQJ */
