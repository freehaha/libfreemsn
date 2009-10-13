#include "Account.h"

static uint cid = 0;
#ifdef DEBUG
int account_shutdown_cb(Account *ac, int type, void *ns, void *data, void *init)
{
	DMSG(stderr, "AC receives shutdown from NS..\n");
	return -1;
}
int account_sbnak_cb(Account *ac, int type, void *vSB, void *data, void *init)
{
	DMSG(stderr, "SB NAK\n");
	return 1;
}
int account_sbmsg_cb(Account *ac, int type, void *vSB, void *data, void *init)
{
	SBNotifyData *note = (SBNotifyData*)data;
	SBNotifyMsg *msg = (SBNotifyMsg*)note->data;
	if(msg->msgtype == SBMSG_TEXT)
	{
		if(!*msg->text)
			return 1;
		DMSG(stderr, "SB MSG: %s(%s): %s\n", msg->email, msg->nick, msg->text);
	}
	return 1;
}

int account_sbjoi_cb(Account *ac, int type, void *vSB, void *data, void *init)
{
	SBNotifyData *note = (SBNotifyData*)data;
	DMSG(stderr, "SB Joined: %s\n",(char*) note->data);
	return 1;
}
#endif
Account *account_new(const char *nick, const char *name, const char *pwd)/*{{{*/
{
	Account *ac = (Account*)xmalloc(sizeof(Account));
	ac->username = strdup(name);
	ac->pwd = strdup(pwd);
	ac->nick = strdup(nick);
	ac->next = NULL;
	ac->notifications = cmdqueue_new();
	ac->ns = NS_new(ac);
	ac->nscbtable = (AC_CALLBACK*)xmalloc(sizeof(AC_CALLBACK)*(uint)NS_NOTIFY_MAX);
	ac->sbcbtable = (AC_CALLBACK*)xmalloc(sizeof(AC_CALLBACK)*(uint)SB_NOTIFY_MAX);
	memset(ac->nscbtable, 0, sizeof(AC_CALLBACK)*(uint)NS_NOTIFY_MAX);
	memset(ac->sbcbtable, 0, sizeof(AC_CALLBACK)*(uint)SB_NOTIFY_MAX);
#ifdef DEBUG
	account_addcallback(ac->nscbtable, NS_NOTIFY_SHUTDOWN, account_shutdown_cb, NULL, 0);
	account_addcallback(ac->sbcbtable, SB_NOTIFY_MSG, account_sbmsg_cb, NULL, 0);
	account_addcallback(ac->sbcbtable, SB_NOTIFY_NAK, account_sbnak_cb, NULL, 0);
	account_addcallback(ac->sbcbtable, SB_NOTIFY_JOI, account_sbjoi_cb, NULL, 0);
#endif
	return ac;
}/*}}}*/
int account_addSBCallback(Account *ac, uint type, AC_CALLBACK_FUNC cb, void *initdata, uint flag)/*{{{*/
{
	return account_addcallback(ac->sbcbtable, type, cb, initdata, flag);
}/*}}}*/
int account_addNSCallback(Account *ac, uint type, AC_CALLBACK_FUNC cb, void *initdata, uint flag)/*{{{*/
{
	return account_addcallback(ac->nscbtable, type, cb, initdata, flag);
}/*}}}*/
int account_addcallback(AccountCallbackTable table, uint type, AC_CALLBACK_FUNC cb, void *initdata, uint flag)/*{{{*/
{
	AC_CALLBACK_ELEM *elem = (AC_CALLBACK_ELEM*)xmalloc(sizeof(*elem));
	elem->cb = cb;
	elem->id = cid++;
	elem->flag = flag;
	elem->init = initdata;
	elem->next = NULL;
	if(table[(uint)type].front && table[(uint)type].rear)
	{
		table[(uint)type].rear->next = elem;
	}
	else
	{
		table[(uint)type].front = table[(uint)type].rear = elem;
	}
	return elem->id;
}/*}}}*/
void account_rmcallback(AccountCallbackTable table, uint type, uint id)/*{{{*/
{
	AC_CALLBACK_ELEM *elem, *prev;
	if(!table[(uint)type].front)
	{
		fprintf(stderr, "account_rmcallback: table NULL.\n");
		return;
	}
	if(table[(uint)type].front->id == id)
	{
		elem = table[(uint)type].front;
		if(elem == table[(uint)type].rear)
		{
			table[(uint)type].front = table[(uint)type].rear = NULL;
		}
		else
			table[(uint)type].front = elem->next;

		xfree(elem);
		return;
	}
	for(prev=table[(uint)type].front;prev->next;prev=prev->next)
	{
		if(prev->next->id == id)
		{
			elem = prev->next;
			prev->next = elem->next;
			if(elem == table[(uint)type].rear)
			{
				table[(uint)type].rear = prev;
			}
			xfree(elem);
			return;
		}
	}
	fprintf(stderr, "account_rmcallback: non-existing callback id\n");
}/*}}}*/
int _account_dispatch_notify(Account *ac, CmdType type, void *data)/*{{{*/
{
	int ret = 0;
	int res;
	switch(type)
	{
		case CMD_NS_NOTIFY:
			{
				NSNotifyData *note = (NSNotifyData*)data;
				AC_CALLBACK_ELEM *elem, *elem_next;
				for(elem=ac->nscbtable[(uint)note->type].front;elem;elem=elem_next)
				{
					elem_next = elem->next;
					res = elem->cb(ac, type, ac->ns, data, elem->init);
					if(elem->flag & ACCB_ONCE)
					{
						account_rmcallback(ac->sbcbtable, type, elem->id);
					}
					if(res < 0) return res;
					if(res == 0) break;
					ret++;
				}
				return ret;
			}
			break;
		case CMD_SB_NOTIFY:
			{
				SBNotifyData *note = (SBNotifyData*)data;
				AC_CALLBACK_ELEM *elem, *elem_next;
				for(elem=ac->sbcbtable[(uint)note->type].front;elem;elem=elem_next)
				{
					elem_next = elem->next;
					res = elem->cb(ac, type, note->sb, data, elem->init);
					if(elem->flag & ACCB_ONCE)
					{
						account_rmcallback(ac->sbcbtable, note->type, elem->id);
					}
					if(res < 0) return res;
					if(res == 0) break;
					ret++;
				}
				return ret;
			}
			break;
		default:
			fprintf(stderr, "unknown Notify type!\n");
			break;
	}
	return 0;
}/*}}}*/
int _account_check_notify(Account *ac)/*{{{*/
{
	if(cmdqueue_empty(ac->notifications)) return 0;
	int ret;
	Command *c = cmdqueue_pop(ac->notifications);
	if(c->type == CMD_NS_NOTIFY || c->type == CMD_SB_NOTIFY)
	{
		ret = _account_dispatch_notify(ac, c->type, c->data);
	}
	command_destroy(c);
	return ret;
}/*}}}*/
void * _account_loop(void *data)/*{{{*/
{
	Account *ac = (Account*)data;
	struct timeval tv;
	int ret;
	while(1)
	{
		if((ret = _account_check_notify(ac)) < 0)
		{
			DMSG(stderr, "account shutted down\n");
			pthread_exit((void*)ret);
		}
		if(ret > 0) continue;
		/* no notify .. rest for a while */
		tv.tv_usec = 0;
		tv.tv_sec = 3;
		select(0, NULL, NULL, NULL, &tv);
	}
	pthread_exit(NULL);
}/*}}}*/
void _account_destroy_cbtable(AccountCallbackTable table, int size)/*{{{*/
{
	AC_CALLBACK_ELEM *elem, *tmp;
	int i;
	for(i=0;i<size;i++)
	{
		elem = table[i].front;
		while(elem)
		{
			tmp = elem->next;
			xfree(elem);
			elem = tmp;
		}
	}
	xfree(table);
}/*}}}*/
void account_destroy(Account *ac)/*{{{*/
{
	int i;
	NS_destroy(ac->ns);
	pthread_join(ac->thread, (void**)&i);
	_account_destroy_cbtable(ac->nscbtable, NS_NOTIFY_MAX);
	_account_destroy_cbtable(ac->sbcbtable, SB_NOTIFY_MAX);
	xfree(ac->username);
	xfree(ac->pwd);
	xfree(ac->nick);
	xfree(ac);
}/*}}}*/
bool account_fork(Account *ac)/*{{{*/
{
	return (0 == pthread_create(&ac->thread, NULL, _account_loop, ac));
}/*}}}*/
bool account_connect(Account *account)/*{{{*/
{
	bool ret = NS_connect(account->ns);
	if(!ret) return ret;
	ret = NS_fork(account->ns);
	if(!ret) return ret;
	ret = account_fork(account);
	return ret;
}/*}}}*/
bool account_is_connected(Account *ac)/*{{{*/
{
	return (ac->ns->flag & NS_CONNECTED);
}/*}}}*/
/* SB requesting functionalities */
int account_reqsb_cb(Account *ac, int type, void *vSB, void *data, void *init)/*{{{*/
{
	struct _sbreq_t *sbrequest = (struct _sbreq_t*) init;
	if(sbrequest->callback)
		sbrequest->callback((SB*)vSB, sbrequest->init);
	DMSG(stderr, "requested SB arrived.\n");
	return 0;
}/*}}}*/
SB * account_request_SB(Account *ac, SBREQ_CALLBACK_FUNC callback, void *init) /* {{{ */
{
	SB *sb;
	struct _sbreq_t *sbrequest;

	sbrequest = (struct _sbreq_t*)malloc(sizeof(struct _sbreq_t));
	sbrequest->init = init;
	sbrequest->callback = callback;
	uint id = account_addcallback(ac->sbcbtable, SB_NOTIFY_REQSB, account_reqsb_cb, (void*)sbrequest, ACCB_ONCE);
	if(!(sb=NS_request_SB(ac->ns)))
	{
		account_rmcallback(ac->sbcbtable, SB_NOTIFY_REQSB, id);
	}
	return sb;
}/*}}}*/
