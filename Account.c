#include "Account.h"

static uint cid = 0;
int account_shutdown_cb(Account *ac, Notify type, void *ns, void *data, void *init)
{
	DMSG(stderr, "AC receives shutdown from NS..\n");
	return -1;
}
int account_sbmsg_cb(Account *ac, Notify type, void *vSB, void *data, void *init)
{
	SBNotifyData *note = data;
	SBNotifyMsg *msg = note->data;
	DMSG(stderr, "SB MSG: %s(%s): %s\n", msg->email, msg->nick, msg->text);
	return 1;
}
Account *account_new(const char *nick, const char *name, const char *pwd)/*{{{*/
{
	Account *ac = xmalloc(sizeof(Account));
	ac->username = strdup(name);
	ac->pwd = strdup(pwd);
	ac->nick = strdup(nick);
	ac->next = NULL;
	ac->ns = NS_new(ac);
	ac->nscbtable = xmalloc(sizeof(AC_CALLBACK)*(uint)NOTIFY_MAX);
	ac->sbcbtable = xmalloc(sizeof(AC_CALLBACK)*(uint)NOTIFY_MAX);
	ac->notifies = ac->ns->notifies;
	memset(ac->nscbtable, 0, sizeof(AC_CALLBACK)*(uint)NOTIFY_MAX);
	memset(ac->sbcbtable, 0, sizeof(AC_CALLBACK)*(uint)NOTIFY_MAX);
	account_addcallback(ac->nscbtable, NOTIFY_SHUTDOWN, account_shutdown_cb, NULL, 0);
	account_addcallback(ac->sbcbtable, NOTIFY_MSG, account_sbmsg_cb, NULL, 0);
	return ac;
}/*}}}*/
int account_addcallback(AccountCallbackTable table, Notify type, AC_CALLBACK_FUNC cb, void *initdata, uint flag)/*{{{*/
{
	AC_CALLBACK_ELEM *elem = xmalloc(sizeof(*elem));
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
void account_rmcallback(AccountCallbackTable table, Notify type, uint id)/*{{{*/
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
int _account_dispatch_notify(Account *ac, Notify type, void *data)/*{{{*/
{
	int ret = 0;
	int res;
	switch(type)
	{
		case CMD_NS_NOTIFY:
			{
				NSNotifyData *note = data;
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
				SBNotifyData *note = data;
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
	if(cmdqueue_empty(ac->notifies)) return 0;
	int ret;
	Command *c = cmdqueue_pop(ac->notifies);
	if(c->type == CMD_NS_NOTIFY || c->type == CMD_SB_NOTIFY)
	{
		ret = _account_dispatch_notify(ac, c->type, c->data);
	}
	command_destroy(c);
	return ret;
}/*}}}*/
void * _account_loop(void *data)/*{{{*/
{
	Account *ac = data;
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
void _account_destroy_cbtable(AccountCallbackTable table)/*{{{*/
{
	AC_CALLBACK_ELEM *elem, *tmp;
	int i;
	for(i=0;i<(uint)NOTIFY_MAX;i++)
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
	_account_destroy_cbtable(ac->nscbtable);
	_account_destroy_cbtable(ac->sbcbtable);
	xfree(ac->username);
	xfree(ac->pwd);
	xfree(ac->nick);
	xfree(ac);
}/*}}}*/
void account_update(Account *ac)/*{{{*/
{

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

int account_reqsb_cb(Account *ac, Notify type, void *vSB, void *data, void *init)
{
	*(SB**)init = vSB;
	DMSG(stderr, "requested SB arrived.\n");
	return 0;
}

void account_request_SB(Account *ac, SB **sb)
{
	account_addcallback(ac->sbcbtable, NOTIFY_REQSB, account_reqsb_cb, (void*)sb, ACCB_ONCE);
	NS_request_SB(ac->ns);
}
