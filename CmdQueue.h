#ifndef MSGQUEUE_IY2NVXY0
#define MSGQUEUE_IY2NVXY0

#include "pthread.h"
#include "msnlib.h"

/* enum, structs {{{*/
enum _cmdtype_t
{
	CMD_NS, CMD_SB, CMD_NS_NOTIFY, CMD_SB_NOTIFY, CMD_MAX, _CMD_MAX=INT_MAX
};

enum _msgtype_t
{
	MSG_MESSAGE, MSG_PAYLOAD, MSG_MAX, _MSG_MAX=INT_MAX
};
enum _nsnotify_e
{
	NS_NOTIFY_SHUTDOWN, NS_NOTIFY_REQSB, NS_NOTIFY_NEWSB, NOTIFY_MAX,  _NTY_MAX=INT_MAX
};
enum _sbnotify_e
{
	SB_NOTIFY_SHUTDOWN, SB_NOTIFY_MSG, SB_NOTIFY_REQSB, SB_NOTIFY_NEWSB, SB_NOTIFY_NAK, SB_NOTIFY_MAX, _SNTY_MAX=INT_MAX
};
struct _msgdata_t
{
	MsgType type;
	bool appendID;
	char *cmd;
	char *argument;
	char *payload;
	int length;
	long int time;
};
struct _nsnotify_t
{
	NSNotify type;
	void *data;
};

struct _sbnotify_t
{
	SBNotify type;
	SB *sb;
	void *data;
};
/* message to dispatch to SB */
struct _sbmsgdata_t
{
	MsgType type;
	SB *sb;
	bool appendID;
	char *cmd;
	char *argument;
	char *payload;
	int length;
	long int time;
};
/* got message from SB */
struct _sbmsgnotify
{
	SB *sb;
	SBNotify type;
	char *nick;
	char *email;
	char *text;
};

struct _cmd_t
{
	CmdType type;
	void *data;
	Command *next;
	CmdDestroyFunc desfunc;
};

struct _cmdqueue_t
{
	int size;
	Command *front, *rear;
	pthread_mutex_t lock;
};
/*}}}*/

typedef CmdQueue CQ;
CQ cmdqueue_new();
void cmdqueue_destroy(CQ q);
inline bool cmdqueue_empty(CQ q);
void cmdqueue_push(CQ q, Command *cmd);
Command *cmdqueue_pop(CQ q);
Command *command_new(CmdType type, void *data, CmdDestroyFunc desfunc);
void command_destroy(Command *c);
#endif /* end of include guard: MSGQUEUE_IY2NVXY0 */
