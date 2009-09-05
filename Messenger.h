#ifndef MESSENGER_3ZO4DGN
#define MESSENGER_3ZO4DGN

#include "msnlib.h"
#include "Account.h"

typedef struct _messenger Messenger;
struct _messenger
{
	Account *accounts;
};

Messenger *messenger_new();
Messenger *messenger_new_with_account(char *username, char *pwd, int mode);
void messenger_destroy(Messenger *m);
void messenger_disconnect_all(Messenger *m);
Account *messenger_add_account(char *alias, char *username, char *pwd);
Account *messenger_get_account(char *alias);
void messenger_remove_account(Account *account);


#endif /* end of include guard: MESSENGER_3ZO4DGN */
