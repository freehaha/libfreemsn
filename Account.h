#ifndef ACCOUNT_TPAWEVBG
#define ACCOUNT_TPAWEVBG
#include "msnlib.h"
#include "NS.h"
#include "CmdQueue.h"

typedef int (*AC_CALLBACK_FUNC)(Account*, int, void *NSorSB,  void *data, void *init);
typedef struct _ac_callback_elem AC_CALLBACK_ELEM;
typedef struct _ac_callback AC_CALLBACK;
typedef AC_CALLBACK* AccountCallbackTable;

struct _ac_callback
{
	AC_CALLBACK_ELEM *front;
	AC_CALLBACK_ELEM *rear;
};
struct _ac_callback_elem
{
	AC_CALLBACK_FUNC cb;
	uint id;
	AC_CALLBACK_ELEM *next;
	void *init;
	uint flag;
};
#define ACCB_ONCE 1
struct _account
{
	char *nick;
	char *username;
	char *pwd;
	pthread_t thread;
	NS *ns;
	Account *next;
	AccountCallbackTable nscbtable;
	AccountCallbackTable sbcbtable;
	CmdQueue notifies;
	int flag;
};

Account *account_new(const char *nick, const char *name, const char *pwd);
void account_destroy(Account *account);
bool account_connect(Account *account);
int account_addcallback(AccountCallbackTable table, uint type, AC_CALLBACK_FUNC cb, void *initdata, uint flag);
void account_rmcallback(AccountCallbackTable table, uint type, uint id);
void account_request_SB(Account *ac, SB **sb);

#endif /* end of include guard: ACCOUNT_TPAWEVBG */
