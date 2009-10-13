#ifndef MSGQUEUE_IY2NVXY0
#define MSGQUEUE_IY2NVXY0

#include "Prerequisites.h"
#include <pthread.h>
#include "msnlib.h"

/* enum, structs {{{*/
struct _nsmsgdata_t
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
bool cmdqueue_empty(CQ q);
void cmdqueue_push(CQ q, Command *cmd);
Command *cmdqueue_pop(CQ q);
Command *command_new(CmdType type, void *data, CmdDestroyFunc desfunc);
void command_destroy(Command *c);
#endif /* end of include guard: MSGQUEUE_IY2NVXY0 */
