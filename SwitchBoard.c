#include "SwitchBoard.h"

static unsigned long int _sbid = 0;
int _SB_dispatch(SB *sb, char *line);
int _SB_send_command(SB *sb, const char *command, const char *argument, bool appendID);
int _SB_send_payload(SB *sb, const char *command, const char *argument, const char *payload, int len, bool appendID);
int _SB_read_payload(SB *sb, char **buf, int len);
bool _SB_add_buddy(SB *sb, SBBuddy *bud);
bool _SB_remove_buddy(SB *sb, const char *email);
int _SB_push_command(SB *sb, Command *c);
SBMsgType StrToSBMsgType(const char *type);
SBNotifyMsg *_SB_make_notify_msg(SB *sb, const char *email, const char *nick, const char *message, int length);
const char textmessage_header[] = "MIME-Version: 1.0\r\n"/*{{{*/
		"Content-Type: text/plain; charset=UTF-8\r\n"
		"X-MMS-IM-Format: FN=Arial; EF=I; CO=0; CS=0; PF=22\r\n"
		"\r\n";/*}}}*/
SBBuddy *sbbuddy_new(const char *nick, const char *email, int cid)/*{{{*/
{
	SBBuddy *bd = (SBBuddy*)xmalloc(sizeof(SBBuddy));
	memset(bd, 0, sizeof(*bd));
	bd->nick = strdup(nick);
	bd->email = strdup(email);
	bd->cid = cid;
	return bd;
}/*}}}*/
bool SB_dispatch_commands(SB *sb) /* {{{ */
{
	if(cmdqueue_empty(sb->cmdq)) return TRUE;
	Command *c = cmdqueue_pop(sb->cmdq);
	while(c)
	{
		switch(c->type)
		{
			case CMD_SB:
				{
					SBMsgData *data = (SBMsgData*)c->data;
					switch(data->type)
					{
						case MSG_MESSAGE:
							_SB_send_command(sb, data->cmd, data->argument, data->appendID);
							break;
						case MSG_PAYLOAD:
							_SB_send_payload(sb, data->cmd, data->argument, data->payload, data->length, data->appendID);
							break;
						default:
							fprintf(stderr, "unknown sbmsg type\n");
							command_destroy(c);
					}
					break;
				}
			case CMD_SB_NOTIFY:
				{
					SBNotifyData *data = (SBNotifyData*)c->data;
					switch(data->type)
					{
						case SB_NOTIFY_SHUTDOWN:
							DMSG(stderr, "SB: shutting down..\n");
							return FALSE;
							break;
						default:
							break;
					}
					break;
				}
			default:
				fprintf(stderr, "SB: unknown command\n");
				break;
		}
		command_destroy(c);
		c = cmdqueue_pop(sb->cmdq);
	}
	return TRUE;
}/*}}}*/
inline bool SB_is_connected(SB *sb)/*{{{*/
{
	if(!sb) return FALSE;
	return (sb->flag&SB_CONNECTED);
}/*}}}*/
SB *SB_new(Account *account, int tid, int sesid)/*{{{*/
{
	SB *sb = (SB*)xmalloc(sizeof(SB));
	memset(sb, 0, sizeof(SB));
	sb->ticket = NULL;
	sb->sesid = sesid;
	sb->account = account;
	sb->cmdq = cmdqueue_new();
	sb->notifications = account->ns->notifications;
	sb->tid = tid;
	sb->id = _sbid;
	_sbid++;
	sb->client = NULL;
	return sb;
}/*}}}*/
int SB_close(SB *sb)/*{{{*/
{
	SBNotifyData *data = SB_notify_data_new(sb, SB_NOTIFY_SHUTDOWN);
	Command *c = command_new(CMD_SB_NOTIFY, data, SB_notify_data_destroy);
	_SB_push_command(sb, c);
	return 1;
}/*}}}*/
int SB_connect(SB *sb, const char *server, int port, const char *ticket)/*{{{*/
{
	char hello[128];
	sb->client = tcpclient_new(server, port);
	sb->ticket = strdup(ticket);
	if(!tcpclient_connect(sb->client)) return 0;
	DMSG(stderr, "SB connecting...\n");
	if(sb->sesid)
	{
		sprintf(hello, "%s %s %d", sb->account->username, sb->ticket, sb->sesid);
		return _SB_send_command(sb, "ANS", hello, TRUE);
	}
	else
	{
		sprintf(hello, "%s %s", sb->account->username, sb->ticket);
		return _SB_send_command(sb, "USR", hello, TRUE);
	}
}/*}}}*/
int SB_sendmsg(SB *sb, const char *msg)/*{{{*/
{
	if(SB_buddy_count(sb) <= 0)
	{
		fprintf(stderr, "nobody except you is connecting to the SB\n");
		return TRUE;
	}
	char *msgbuf = (char*)xmalloc(strlen(msg)+sizeof(textmessage_header));
	int len;
	len = sprintf(msgbuf, "%s%s", textmessage_header, msg);
	len = _SB_send_payload(sb, "MSG", "N", msgbuf, len, TRUE);
	xfree(msgbuf);
	return len;
}/*}}}*/
void SB_destroy(SB *sb)/*{{{*/
{
	SBBuddy *tmp;
	while(sb->list)
	{
		tmp = sb->list->next;
		sbbuddy_destroy(sb->list);
		sb->list = tmp;
	}
	if(sb->client) tcpclient_destroy(sb->client);
	cmdqueue_destroy(sb->cmdq);
	xfree(sb->ticket);
	xfree(sb);
}/*}}}*/
void sbbuddy_destroy(SBBuddy *bd)/*{{{*/
{
	xfree(bd->nick);
	xfree(bd->email);
	xfree(bd);
}/*}}}*/
/* upon receive return value <= 0 the caller should destroy the SB immediately */
int SB_dispatch_nblocking(SB *sb, int sec, int usec)/*{{{*/
{
	char *buf = NULL;
	int ret;
	if(!sb->client) return 0;
	SState s = tcpclient_checkio(sb->client, sec, usec);
	if(s == Read || s == ReadWrite)
	{
		ret = tcpclient_getline(sb->client, &buf, 512);
		if(ret <= 0)
		{
			xfree(buf);
			return ret-1;
		}
		else
		{
			ret = _SB_dispatch(sb, buf);
			xfree(buf);
			return ret;
		}
	}
	return 0;
}/*}}}*/
/* upon receive -1 the caller should destroy the SB immediately */
int _SB_dispatch(SB *ns, char *line)/*{{{*/
{
	char cmd[8]; /* protocol says 4 is enough, but just in case .. */
	SBDispatch *dp;
	char *arg = line;
	line = get_one_arg(line, cmd, 8);
	for(dp=_sb_dispatch_table;dp->cmd;dp++)
	{
		if(!strcmp(dp->cmd, cmd))
		{
			DMSG(stderr, "SB dispatched to %s.\n", cmd);
			return (*dp->func)(ns, line);
		}
	}
	int error, trid;
	if(sscanf(line, "%d %d", &error, &trid) == 2)
	{
		fprintf(stderr, "error message: %d respose to %d\n", error, trid);
		return error;
	}
	fprintf(stderr, "unknown command: %s\n", arg);
	return -1;
}/*}}}*/
int _SB_push_command(SB *sb, Command *c)/*{{{*/
{
	cmdqueue_push(sb->cmdq, c);
	return 1;
}/*}}}*/
int SB_invite(SB *sb, const char *email)/*{{{*/
{
	Command *c;
	SBMsgData *data = SB_msg_new(sb, MSG_MESSAGE, "CAL", email, NULL, 0, TRUE);
	c = command_new(CMD_SB, data, SB_msg_destroy);
	return _SB_push_command(sb, c);
}/*}}}*/
/* send/recv functions {{{*/
int _SB_send_command(SB *sb, const char *command, const char *argument, bool appendID)/*{{{*/
{
	int ret;
	ret = _msn_send_command(sb->client, command, argument, appendID?sb->TrID:-1);
	/* TODO: TrID verification */
	if(appendID) sb->TrID++;
	if(sb->TrID > 128) sb->TrID = 0;
	return ret;
}/*}}}*/
int _SB_send_payload(SB *sb, const char *command, const char *argument, const char *payload, int len, bool appendID)/*{{{*/
{
	int ret;
	ret = _msn_send_payload(sb->client, command, argument, payload, len, appendID?sb->TrID:-1);
	/* TODO: TrID verification */
	if(appendID) sb->TrID++;
	if(sb->TrID > 128) sb->TrID = 0;
	return ret;
}/*}}}*/
int _SB_read_payload(SB *sb, char **buf, int len)/*{{{*/
{
	return _msn_read_payload(sb->client, buf, len);
}/*}}}*/
/*}}}*/
SBMsgType StrToSBMsgType(const char *type)/*{{{*/
{
	if(!strncmp(type, "text/x-msmsgscontrol", 20)) return SBMSG_CONTROL;
	else if (!strncmp(type, "text/x-msmsgsinvite", 19)) return SBMSG_INVITE;
	else if (!strncmp(type, "application/x-msnmsgrp2p", 24)) return  SBMSG_P2P;
	else return SBMSG_TEXT;
}/*}}}*/
SBNotifyMsg *_SB_make_notify_msg(SB *sb, const char *email, const char *nick, const char *message, int length)/*{{{*/
{
	char line[256];
	char *msg;
	SBNotifyMsg *data;
	SBMsgType msgtype;
	int size = 0;
	int ret;
	ret = 256;
	message = get_one_line(message, line, &ret);
	/* FIXME: header discarded */
	while(line[0])
	{
		if(!strncmp(line, "Content-Type: ",14))
		{
			DMSG(stderr, "msg type: %s\n", line+14);
			msgtype = StrToSBMsgType(line+14);
		}
		size += ret;
		ret = 256;
		message = get_one_line(message, line, &ret);
	}
	size+=ret;
	data = (SBNotifyMsg*)xmalloc(sizeof(*data));
	msg = (char*)xmalloc(length-size+1);
	memcpy(msg, message, length-size);
	msg[length-size] = '\0';
	data->msgtype = msgtype;
	data->sb = sb;
	data->nick = strdup(nick);
	data->email = strdup(email);
	data->text = msg;
	return data;
}/*}}}*/
void _SB_notify_msg_destroy(void *data)/*{{{*/
{
	SBNotifyData *notify = (SBNotifyData*)data;
	SBNotifyMsg *msg = (SBNotifyMsg*)notify->data;
	xfree(msg->nick);
	xfree(msg->email);
	xfree(msg->text);
	xfree(msg);
	xfree(notify);
}/*}}}*/
int _SB_disp_MSG(SB* sb, char * command) /* messenges *//*{{{*/
{
	//MSG example@passport.com Mike 133
	char email[64];
	char nick[256];
	int len;
	if(sscanf(command, "%s %s %d", email, nick, &len) == 3)
	{
		char *pl = NULL;
		int ret = _SB_read_payload(sb, &pl, len);
		SBNotifyData *data = (SBNotifyData*)xmalloc(sizeof(*data));
		data->type = SB_NOTIFY_MSG;
		data->data = _SB_make_notify_msg(sb, email, nick, pl, len);
		Command *c = command_new(CMD_SB_NOTIFY, data, _SB_notify_msg_destroy);
		cmdqueue_push(sb->notifications, c);
		xfree(pl);
		return ret;
	}
	return 0;
}/*}}}*/
int _SB_disp_ACK(SB *sb, char *command) /* message ack *//*{{{*/
{
	DMSG(stderr, "ACK: %s\n", command);
	return 1;
}/*}}}*/
int _SB_disp_ANS(SB* sb, char * command) /* answer response to join notification *//*{{{*/
{
	int trid;
	if(sscanf(command, "%d OK", &trid) == 1)
	{
		DMSG(stderr, "ANS DONE\n");
		return 1;
	}
	/* unknown */
	return 0;
}/*}}}*/
int _SB_disp_USR(SB* sb, char * command) /* authentication confirm *//*{{{*/
{
	sb->flag |= SB_CONNECTED;
	DMSG(stderr, "SB %lu Connected\n", sb->id);
	/* TODO: send notification back to account */
	return 1;
}/*}}}*/
int _SB_disp_NAK(SB *sb, char *commnad)/*{{{*/
{
	SBNotifyData *data = SB_notify_data_new(sb, SB_NOTIFY_NAK);
	Command *c = command_new(CMD_SB_NOTIFY, data, SB_notify_data_destroy);
	cmdqueue_push(sb->notifications, c);
	DMSG(stderr, "SB: NAK\n");
	return 0;
}/*}}}*/
int _SB_disp_CAL(SB* sb, char * command) /* success of calling buddy *//*{{{*/
{
	DMSG(stderr, "CAL: %s\n", command);
	return 1;
}/*}}}*/
int _SB_disp_JOI(SB* sb, char * command) /* somebody joins *//*{{{*/
{
	//JOI buddy_email buddy_name client_id
	char email[64];
	char nick[256];
	int cid;
	if(sscanf(command, "%s %s %d", email, nick, &cid) == 3)
	{
		DMSG(stderr, "%s joins SB %lu\n", nick, sb->id);
		SBBuddy *bd = sbbuddy_new(nick, email, cid);
		_SB_add_buddy(sb, bd);
		SBNotifyData *notify = SB_notify_data_new(sb, SB_NOTIFY_JOI);
		notify->data = strdup(email);
		Command *c = command_new(CMD_SB_NOTIFY, notify, SB_notify_data_destroy);
		cmdqueue_push(sb->notifications, c);
		return 1;
	}
	return 0;
}/*}}}*/
int _SB_disp_IRO(SB* sb, char * command) /* init user list *//*{{{*/
{
	//IRO trid roster rostercount passport friendlyname rosterclientid
	int id;
	int max;
	char email[64];
	char nick[256];
	int cid;
	if(sscanf(command, "%*d %d %d %s %s %d", &id, &max, email, nick, &cid) == 5)
	{
		SBBuddy *bd = sbbuddy_new(nick, email, cid);
		_SB_add_buddy(sb, bd);
		return id;
	}
	return 0;
}/*}}}*/
bool _SB_add_buddy(SB *sb, SBBuddy *bud)/*{{{*/
{
	if(!bud) return FALSE;
	bud->next = sb->list;
	sb->list = bud;
	sb->count++;
	return TRUE;
}/*}}}*/
bool _SB_remove_buddy(SB *sb, const char *email)/*{{{*/
{
	SBBuddy *bud, *prev;
	if(!sb->list) return FALSE;
	if(!strcmp(sb->list->email, email))
	{
		bud = sb->list;
		sb->list = sb->list->next;
		sbbuddy_destroy(bud);
		sb->count--;
		return TRUE;
	}
	for(prev=sb->list;prev->next;prev=prev->next)
	{
		if(!strcmp(prev->next->email, email))
		{
			bud = prev->next;
			prev->next = prev->next->next;
			sbbuddy_destroy(bud);
			sb->count--;
			return TRUE;
		}
	}
	return FALSE;
}/*}}}*/
int _SB_disp_BYE(SB* sb, char * command) /* somebody leaves {{{*/
{
	//BYE contact@passport.com 1

	char email[64];
	int timeout;
	if(sscanf(command, "%s %d", email, &timeout) == 2)
	{
		/* message sent timeouted */
		/* FIXME: remove from the list or not ?*/
		_SB_remove_buddy(sb, email);
		return 2;
	}
	else if (sscanf(command, "%s", email) == 1)
	{
		/* somebody leaves */
		DMSG(stderr, "%s leaves the conversation ...\n", email);
		_SB_remove_buddy(sb, email);
		return 1;
	}
	return 0;
}/*}}}*/
int SB_buddy_count(SB *sb)/*{{{*/
{
	return sb->count;
}/*}}}*/
struct sbdispatch _sb_dispatch_table[] =/*{{{*/
{
	{"MSG",_SB_disp_MSG},
	{"ANS",_SB_disp_ANS},
	{"USR",_SB_disp_USR},
	{"NAK",_SB_disp_NAK},
	{"CAL",_SB_disp_CAL},
	{"JOI",_SB_disp_JOI},
	{"IRO",_SB_disp_IRO},
	{"BYE",_SB_disp_BYE},
	{NULL, NULL}
};/*}}}*/
void SB_msg_destroy(void *data)/*{{{*/
{
	SBMsgData *msg = (SBMsgData*)data;
	if(!data)
	{
		fprintf(stderr, "NULL data passed to SB_msg_destroy\n");
		return;
	}
	xfree(msg->cmd);
	xfree(msg->argument);
	xfree(msg->payload);
	xfree(data);
}/*}}}*/
SBMsgData *SB_msg_new(SB *sb, MsgType type, const char *cmd, const char* arg, const char *payload, int length, bool appendID)/*{{{*/
{
	SBMsgData *data = (SBMsgData*)xmalloc(sizeof(*data));
	data->sb = sb;
	data->type = type;
	data->cmd = strdup(cmd);
	data->argument = (arg&&*arg)?strdup(arg):NULL;
	if(type == MSG_PAYLOAD)
	{
		if(!payload)
		{
			fprintf(stderr, "NULL paload!\n");
			return NULL;
		}
		data->payload = (char*)xmalloc(length);
		memcpy(data->payload, payload, length);
		data->length = length;
	}
	else
	{
		data->payload = NULL;
		data->length = 0;
	}
	data->time = time(0);
	data->appendID = appendID;
	return data;
}/*}}}*/
SBNotifyData *SB_notify_data_new(SB *sb, SBNotify notify)/*{{{*/
{
	SBNotifyData *data;
	data = (SBNotifyData*)xmalloc(sizeof(*data));
	data->sb = sb;
	data->type = notify;
	return data;
}/*}}}*/
void SB_notify_data_destroy(void *notifydata)/*{{{*/
{
	xfree(notifydata);
}/*}}}*/
