#include "msnlib.h"
#include <openssl/evp.h>

xmlNodePtr findNode(xmlNodePtr start, const char * name, int max_depth)/*{{{*/
{
	xmlNodePtr sibling;
	if(max_depth <= 0) return NULL;
	if(start == NULL) return NULL;
	for(sibling=start;sibling;sibling=sibling->next)
	{
		if(!xmlStrcmp(sibling->name, (xmlChar*)name))
		{
			return sibling;
		}
	}
	for(sibling=start;sibling;sibling=sibling->next)
	{
		xmlNodePtr find;
		find = findNode(sibling->children, name, max_depth-1);
		if(find) return find;
	}
	return NULL;
}/*}}}*/

const char *get_one_line(const char *argument, char *buffer, int *size)
{
	int sz = 0;
	if(!argument || !*argument)
	{
		*buffer = '\0';
		*size = 0;
		return argument;
	}
	for(;*argument && sz<*size-1;argument++)
	{
		if(*argument == '\r')
		{
			sz++;
			if(*(++argument) == '\n')
			{
				argument++;
				sz++;
			}

			break;
		}
		else if(*argument == '\n')
		{
			sz++;
			argument++;
			break;
		}
		*buffer++ = *argument;
		sz++;
	}
	*size = sz;
	*buffer = '\0';

	return argument;
}
int _msn_send_command(TCPClient *client, const char *command, const char *argument, int TrID)
{
	char buf[128];
	int len;
	if(TrID >= 0)
	{
		len = sprintf(buf, "%s %d %s\r\n", command, TrID, argument);
	}
	else
		len = sprintf(buf, "%s %s\r\n", command, argument);

	return tcpclient_send(client, buf, len);
}
int _msn_send_payload(TCPClient *client, const char *command, const char *argument, const char *payload, int len, int TrID)
{
	char buf[128];
	int ret;
	if(argument && *argument)
	{
		if(TrID>=0)
		{
			ret = sprintf(buf, "%s %d %s %d\r\n", command, TrID, argument, len);
		}
		else
			ret = sprintf(buf, "%s %s %d\r\n", command, argument, len);
	}
	else
	{
		if(TrID>=0)
		{
			ret = sprintf(buf, "%s %d %d\r\n", command, TrID, len);
		}
		else
			ret = sprintf(buf, "%s %d\r\n", command, len);
	}

	DMSG(stderr, "payload cmd: %s",buf);
	ret = tcpclient_send(client, buf, ret);
	if(ret > 0)
	{
		ret = tcpclient_send(client, payload, len);
	}
	return ret;
}
int _msn_read_payload(TCPClient *client, char **buf, int len)
{
	int size = 0;
	int ret;
	char *ptr;
	if(len <= 0)
	{
		*buf = NULL;
		return len;
	}
	/* TODO: setting timeout */
	*buf = (char*)xmalloc(len+1);
	ptr = *buf;
	while(len > 0)
	{
		ret = tcpclient_recv(client, ptr, len);
		if(ret <= 0)
			return size;
		size += ret;
		ptr += ret;
		len -= ret;
	}
	*ptr = '\0';
	return size;
}
char *get_one_arg(char *argument, char *buffer, int size)
{
	int sz = 0;
	char *ret;
	for(ret=argument;*ret && sz<size;ret++)
	{
		if(*ret == ' ')
		{
			*buffer = '\0';
			ret++;
			break;
		}
		*buffer++ = *ret;
		sz++;
	}
	if(sz>=size) *(buffer-1) = '\0';
	return ret;
}
/* base64 conversions {{{ */
char *unbase64(unsigned char *input, int length)
{
	char *buffer = (char*)xmalloc(length);
	memset(buffer, 0, length);
	EVP_DecodeBlock((unsigned char*)buffer, input, length);
	return buffer;
}
char *base64(const unsigned char *input, int length)
{
	char *buffer = (char*)xmalloc(length*2);
	memset(buffer, 0, length*2);
	EVP_EncodeBlock((unsigned char*)buffer, input, length);
	return buffer;
}
/* }}} */
