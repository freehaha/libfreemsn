#define _GNU_SOURCE
#include "msnlib.h"
#include "NS.h"
#include "Account.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/select.h>
int main(int argc, const char **argv)
{
	Account *ac = account_new("NICK", "account@example.com", "password");
	account_connect(ac);
	NS *ns = ac->ns;
	fd_set fds;
	char *buf;
	size_t size;
	int ret;
	struct timeval tv;
	SB *sb = NULL;
	while(1)
	{
		FD_ZERO(&fds);
		FD_SET(STDIN_FILENO, &fds);
		tv.tv_sec = 0;
		tv.tv_usec = 500;
		if((ret=select(1, &fds, NULL, NULL, &tv) > 0))
		{
			buf = NULL;
			ret = getline(&buf, &size, stdin);
			if(ret == -1) break;
			if(!strcmp(buf, "1\n"))
			{
				tcpclient_send(ns->tclient, "OUT\r\n", 5);
			}
			else if(!strcmp(buf, "2\n"))
			{
				sb = account_request_SB(ac, NULL, NULL);
			}
			else if(buf[0] == '3')
			{
				char email[64];
				if(SB_is_connected(sb) && sscanf(buf, "3 %[^\n]", email) == 1)
				{
					SB_invite(sb, email);
					DMSG(stderr, "inviting %s\n", email);
				}
			}
			else
			{
				if(SB_is_connected(sb))
				{
					SB_sendmsg(sb, buf);
				}
			}
			if(buf)
			{
				free(buf);
			}
		}
		else if (ret < 0)
		{
			break;
		}
	}
	account_destroy(ac);
	return 0;
}
