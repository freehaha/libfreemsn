#ifndef MSNLIB_NPEP82FY
#define MSNLIB_NPEP82FY

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <pthread.h>
#include "xmalloc.h"
xmlNodePtr findNode(xmlNodePtr start, char * name, int max_depth);

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
typedef struct _msgdata_t MsgData; /* message to NS */
typedef enum _notify_e Notify; /* notify types */
typedef struct _nsnotify_t NSNotifyData; /* notify to NS */
typedef struct _sbnotify_t SBNotifyData; /* notify to SB */
typedef struct _sbmsgnotify SBNotifyMsg; /* msg notify from SB */
typedef struct _sbmsgdata_t SBMsgData; /* message to SB */
typedef struct _cmdqueue_t *CmdQueue;
typedef enum _cmdtype_t CmdType; /* command type */
typedef enum _msgtype_t MsgType; /* message type */
typedef void (*CmdDestroyFunc)(void *);
typedef struct _contact Contact;
typedef struct _contactlist ContactList;
typedef ContactList CL;
typedef enum _status Status;


#include "TCPClient.h"


int _msn_send_command(TCPClient *client, const char *command, const char *argument, int TrID);
int _msn_send_payload(TCPClient *client, const char *command, const char *argument, const char *payload, int len, int TrID);
int _msn_read_payload(TCPClient *client, char **buf, int len);
char *get_one_arg(char *argument, char *buffer, int size);
const char *get_one_line(const char *argument, char *buffer, int *size);


#endif /* end of include guard: MSNLIB_NPEP82FY */
