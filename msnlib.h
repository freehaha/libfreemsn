#ifndef MSNLIB_NPEP82FY
#define MSNLIB_NPEP82FY

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <pthread.h>
#include "xmalloc.h"
xmlNodePtr findNode(xmlNodePtr start, const char * name, int max_depth);

#ifdef DEBUG
#define DMSG fprintf
#else
#define DMSG (void) 
#endif

#define bool char
#ifndef TRUE
#define TRUE 1
#define FALSE 0
#endif

#ifndef INT_MAX
#define INT_MAX ((uint)-1)
#endif

/* enums {{{ */

enum _sbmsgtype
{
	SBMSG_CONTROL, SBMSG_TEXT, SBMSG_INVITE, SBMSG_P2P
};
enum _status
{
	NLN, BSY, BRB, AWY, IDL, PHN, LUN, HDN, NA
};
enum _cmdtype_e
{
	CMD_NS, CMD_SB, CMD_NS_NOTIFY, CMD_SB_NOTIFY, CMD_MAX, _CMD_MAX=INT_MAX
};

enum _msgtype_e
{
	MSG_MESSAGE, MSG_PAYLOAD, MSG_MAX, _MSG_MAX=INT_MAX
};
enum _nsnotify_e
{
	NS_NOTIFY_SHUTDOWN, NS_NOTIFY_REQSB, NS_NOTIFY_NEWSB, NS_NOTIFY_MAX,  _NTY_MAX=INT_MAX
};
enum _sbnotify_e
{
	SB_NOTIFY_SHUTDOWN, SB_NOTIFY_MSG, SB_NOTIFY_REQSB, SB_NOTIFY_NEWSB, SB_NOTIFY_NAK, SB_NOTIFY_MAX, _SNTY_MAX=INT_MAX
};
enum _sstate{
	None, Read, Write, ReadWrite, Err
};
/* }}} */
typedef enum _sstate SState;
typedef struct _tcpclient TCPClient;
typedef int (*TCPCallback)(TCPClient*, void *);
typedef struct _httpheader HTTPHeader;
typedef struct _NS NS;
typedef int (*NSDispatchFunc)(NS*, char *);
typedef struct nsdispatch Dispatch;
typedef struct sbdispatch SBDispatch;
typedef struct _switchboard SwitchBoard;
typedef SwitchBoard SB;
typedef int (*SBDispatchFunc)(SB*, char *);
typedef struct _sslclient SSLClient;
typedef struct _sbbuddy SBBuddy;
typedef struct _account Account;
typedef struct _cmd_t Command;
typedef struct _nsmsgdata_t NSMsgData; /* message to NS */
typedef enum _nsnotify_e NSNotify; /* notify types */
typedef enum _sbnotify_e SBNotify; /* notify types */
typedef struct _nsnotify_t NSNotifyData; /* notify to NS */
typedef struct _sbnotify_t SBNotifyData; /* notify to SB */
typedef struct _sbmsgnotify SBNotifyMsg; /* msg notify from SB */
typedef struct _sbmsgdata_t SBMsgData; /* message to SB */
typedef struct _cmdqueue_t *CmdQueue;
typedef enum _cmdtype_e CmdType; /* command type */
typedef enum _msgtype_e MsgType; /* message type */
typedef void (*CmdDestroyFunc)(void *);
typedef struct _contact Contact;
typedef struct _contactlist ContactList;
typedef ContactList CL;
typedef enum _status Status;
typedef enum _sbmsgtype SBMsgType;
typedef struct _OIM_t OIM;
typedef struct _OIMList_t OIMList;


#include "TCPClient.h"


int _msn_send_command(TCPClient *client, const char *command, const char *argument, int TrID);
int _msn_send_payload(TCPClient *client, const char *command, const char *argument, const char *payload, int len, int TrID);
int _msn_read_payload(TCPClient *client, char **buf, int len);
char *get_one_arg(char *argument, char *buffer, int size);
const char *get_one_line(const char *argument, char *buffer, int *size);
char *unbase64(unsigned char *input, int length);
char *base64(const unsigned char *input, int length);


#endif /* end of include guard: MSNLIB_NPEP82FY */
