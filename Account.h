#ifndef ACCOUNT_TPAWEVBG
#define ACCOUNT_TPAWEVBG

#include "Prerequisites.h"
#include "msnlib.h"
#include "NS.h"
#include "CmdQueue.h"

typedef int (*AC_CALLBACK_FUNC)(Account*, int, void *NSorSB,  void *data, void *init);
typedef void (*SBREQ_CALLBACK_FUNC)(SB *sb, void* init);
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
	CmdQueue notifications;
	int flag;
};
struct _sbreq_t
{
	SBREQ_CALLBACK_FUNC callback;
	void *init;
};

Account *account_new(const char *nick, const char *name, const char *pwd);
void account_destroy(Account *account);
bool account_connect(Account *account);
int account_addcallback(AccountCallbackTable table, uint type, AC_CALLBACK_FUNC cb, void *initdata, uint flag);
void account_rmcallback(AccountCallbackTable table, uint type, uint id);
bool account_is_connected(Account *ac);
SB * account_request_SB(Account *ac, SBREQ_CALLBACK_FUNC callback, void *init);

int account_addNSCallback(Account *ac, uint type, AC_CALLBACK_FUNC cb, void *initdata, uint flag);
int account_addSBCallback(Account *ac, uint type, AC_CALLBACK_FUNC cb, void *initdata, uint flag);
#endif /* end of include guard: ACCOUNT_TPAWEVBG */
