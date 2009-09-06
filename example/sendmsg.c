#include <stdio.h>
#include <stdlib.h>
#include <msnlib.h>
#include <Account.h>

int main(int argc, const char **argv)
{
	Account *ac = account_new("NICK", "ID@hotmail.com", "PWD");
	account_connect(ac);
	SB *sb = NULL;
	account_request_SB(ac, &sb);
	while(1)
	{
		/* wait for sb */
		if(!sb)
			sleep(1);
		else
		{
			SB_invite(sb, "to whom you want to send");
			/* wait for him to join.
			 * you can use sleep or use the callback on JOI message, here i'll just sleep a few seconds*/
			sleep(3);
			SB_sendmsg(sb, "test!");
			break;
		}
	}
	account_destroy(ac);
	return 0;
}

