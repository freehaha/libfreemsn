#include "SwitchBoard.h"

static unsigned long int _sbid = 0;
int _SB_dispatch(SB *sb, char *line);
int _SB_send_command(SB *sb, const char *command, const char *argument, bool appendID);
int _SB_send_payload(SB *sb, const char *command, const char *argument, const char *payload, int len, bool appendID);
int _SB_read_payload(SB *sb, char **buf, int len);
bool _SB_add_buddy(SB *sb, SBBuddy *bud);
bool _SB_remove_buddy(SB *sb, const char *email);
SBNotifyMsg *_SB_make_notify_msg(SB *sb, const char *email, const char *nick, const char *message, int length);
const char msgheader[] = "MIME-Version: 1.0\r\n"
		"Content-Type: text/plain; charset=UTF-8\r\n"
		"X-MMS-IM-Format: FN=Arial; EF=I; CO=0; CS=0; PF=22\r\n"
		"\r\n";

SBBuddy *sbbuddy_new(const char *nick, const char *email, int cid)/*{{{*/
{
	SBBuddy *bd = xmalloc(sizeof(SBBuddy));
	memset(bd, 0, sizeof(*bd));
	bd->nick = strdup(nick);
	bd->email = strdup(email);
	bd->cid = cid;
	return bd;
}/*}}}*/
bool SB_dispatch_command(SB *sb, Command *c)/*{{{*/
{
	switch(c->type)
	{
		case CMD_SB:
			{
				SBMsgData *data = c->data;
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
				//SBNotifyData *data = c->data;
				break;
			}
		default:
			fprintf(stderr, "SB: unknown command\n");
			break;
	}
	return TRUE;
}/*}}}*/
SB *SB_new(Account *account, const char *server, int port, const char *ticket, int sesid)/*{{{*/
{
	SB *sb = xmalloc(sizeof(SB));
	memset(sb, 0, sizeof(SB));
	sb->ticket = strdup(ticket);
	sb->sesid = sesid;
	sb->account = account;
	sb->cmdq = account->ns->cmdq;
	sb->notifies = account->ns->notifies;
	sb->id = _sbid;
	_sbid++;
	sb->client = tcpclient_new(server, port);
	return sb;
}/*}}}*/
int SB_connect(SB *sb)/*{{{*/
{
	char hello[128];
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
	char *msgbuf = xmalloc(strlen(msg)+sizeof(msgheader));
	int len;
	len = sprintf(msgbuf, "%s%s", msgheader, msg);
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
int _SB_push_command(SB *sb, Command *c)
{
	cmdqueue_push(sb->cmdq, c);
	return 1;
}

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
SBNotifyMsg *_SB_make_notify_msg(SB *sb, const char *email, const char *nick, const char *message, int length)/*{{{*/
{
	char line[256];
	char *msg;
	SBNotifyMsg *data;
	int size = 0;
	int ret;
	ret = 256;
	message = get_one_line(message, line, &ret);
	/* FIXME: header discarded */
	while(line[0])
	{
		size += ret;
		ret = 256;
		message = get_one_line(message, line, &ret);
	}
	size+=ret;
	data = xmalloc(sizeof(*data));
	msg = xmalloc(length-size+1);
	memcpy(msg, message, length-size);
	msg[length-size] = '\0';
	data->sb = sb;
	data->nick = strdup(nick);
	data->email = strdup(email);
	data->text = msg;
	return data;
}/*}}}*/
void _SB_notify_msg_destroy(void *data)/*{{{*/
{
	SBNotifyData *notify = data;
	SBNotifyMsg *msg = notify->data;
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
		SBNotifyData *data = xmalloc(sizeof(*data));
		data->type = NOTIFY_MSG;
		data->data = _SB_make_notify_msg(sb, email, nick, pl, len);
		Command *c = command_new(CMD_SB_NOTIFY, data, _SB_notify_msg_destroy);
		cmdqueue_push(sb->notifies, c);
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
	SBNotifyData *data = SB_notify_data_new(sb, NOTIFY_NAK);
	Command *c = command_new(CMD_SB_NOTIFY, data, SB_notify_data_destroy);
	cmdqueue_push(sb->notifies, c);
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
	SBMsgData *msg = data;
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
	SBMsgData *data = xmalloc(sizeof(*data));
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
		data->payload = xmalloc(length);
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
SBNotifyData *SB_notify_data_new(SB *sb, Notify notify)/*{{{*/
{
	SBNotifyData *data;
	data = xmalloc(sizeof(*data));
	data->sb = sb;
	data->type = notify;
	return data;
}/*}}}*/
void SB_notify_data_destroy(void *notifydata)/*{{{*/
{
	xfree(notifydata);
}/*}}}*/
