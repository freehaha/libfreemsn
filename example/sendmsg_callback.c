#include <stdio.h>
#include <stdlib.h>
#include <msnlib.h>
#include <Account.h>

int cb_joined(Account *ac, int type, void *vSB, void *data, void *init)
{
	SBNotifyData *note = (SBNotifyData*)data;
	printf("%s has joined the conversation.\n",(char*) note->data);
	return 0;
}
void sb_arrived_cb(SB* sb, void *init)
{
	printf("SB arrived, inviting %s...\n", (char*)init);
	while(!SB_is_connected(sb));
	SB_invite(sb, (char*)init);
}

/* on receive message */
int sb_msg_cb(Account *ac, int type, void *vSB, void *data, void *init)
{
	if(vSB != init) return 1; /* not the sb we're listening */
	SBNotifyData *note = (SBNotifyData*)data;
	SBNotifyMsg *msg = (SBNotifyMsg*)note->data;
	if(msg->msgtype == SBMSG_TEXT)
	{
		if(!*msg->text)
			return 1;
		printf("%s(%s) says: %s\n", msg->email, msg->nick, msg->text);
	}
	return 0; /* cut the callback chain */
}
int main(int argc, const char **argv)
{
	Account *ac = account_new("NICK", "ID@hotmail.com", "PWD");
	char buf[256] = {0};
	SB *sb = NULL;

	account_addSBCallback(ac, SB_NOTIFY_JOI, cb_joined, NULL, 0);
	account_addSBCallback(ac, SB_NOTIFY_MSG, sb_msg_cb, sb, 0);
	account_connect(ac);
	sb = account_request_SB(ac, sb_arrived_cb,  "to whom you want to send");

	while(1)
	{
		if(scanf("%[^\n]%*c", buf) == EOF) break;
		if(!SB_is_connected(sb))
		{
			fprintf(stderr, "sb is not connected yet\n");
			continue;
		}
		SB_sendmsg(sb, buf);

	}
	account_destroy(ac);
	return 0;
}

