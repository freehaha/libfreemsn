#include "TCPClient.h"

TCPClient *tcpclient_new(const char *host, int port)
{
	TCPClient *client;
	client = xmalloc(sizeof(*client));
	if(!client)
	{
		perror("error creating new TCPClient");
		exit(1);
	}
	memset(client, 0, sizeof(*client));
	strncpy(client->hostname, host, sizeof(client->hostname));
	client->port = port;
	return client;
}
void tcpclient_destroy(TCPClient *client)
{
	if(!client)
	{
		fprintf(stderr, "error: xfreeing NULL TCPClient\n");
		exit(1);
	}
	xfree(client->sin);
	if(TCP_FD(client))
	{
		close(TCP_FD(client));
	}
	xfree(client);
}
bool tcpclient_connect(TCPClient *client)
{
	if(!client->sin)
	{
		struct hostent *hp;
		client->sin = xmalloc(sizeof(*client->sin));
		memset(client->sin, 0, sizeof(*client->sin));
		if((hp=gethostbyname(client->hostname))==0)
		{
			fprintf(stderr, "gethostbyname: %s", strerror(errno));
			xfree(client->sin);
			return FALSE;
		}
		client->sin->sin_family = AF_INET;
		client->sin->sin_addr.s_addr = ((struct in_addr *)(hp->h_addr))->s_addr;
		client->sin->sin_port = htons(client->port);
	}
	if(TCP_FD(client))
	{
		close(TCP_FD(client));
		TCP_FD(client) = 0;
	}
	TCP_FD(client) = socket(AF_INET, SOCK_STREAM, 0);
	if( connect(TCP_FD(client), (struct sockaddr*)client->sin, sizeof(*client->sin)) == -1)
	{
		perror("connect: ");
		return FALSE;
	}

	return TRUE;
}
int tcpclient_send(TCPClient *client, const char *buffer, int size)
{
	return send(TCP_FD(client), buffer, size, 0);
}
int tcpclient_recv(TCPClient *client, char *buffer, int size)
{
	return recv(TCP_FD(client), buffer, size, 0);
}
/* TODO seperate it to a http client or something */
int tcpclient_recv_header(TCPClient *client, char **buffer)
{
	char *buf;
	int size = 1024;
	int ret;

	xfree(*buffer);
	*buffer = xmalloc(size);
	buf = *buffer;
	if(buf == NULL)
	{
		fprintf(stderr, "load_soapreq: bad xmalloc\n");
		return 0;
	}
	memset(buf, 0, size);
	ret = 0;
	int len = 0;
	char *line = NULL;
	while(1)
	{
		ret = tcpclient_getline(client, &line, 0);
		if(ret < 0)
		{
			xfree(*buffer);
			return 0;
		}
		/* check for buffer size */
		if(ret + len > size)
		{
			size += 1024;
			buf = xrealloc(*buffer, size);
			if(*buffer == buf)
			{
				fprintf(stderr, "failed to xrealloc !\n");
				xfree(buf);
				xfree(line);
				*buffer = NULL;
				return 0;
			}
			*buffer = buf;
			buf = *buffer+len;
			*buf = '\0';
		}
		if(ret == 0) /* empty line, end of header */
		{
			xfree(line);
			return len;
		}
		else
		{
			buf += sprintf(buf, "%s\r\n", line);
		}
		len += ret;
	}
	xfree(line);
	line = NULL;
	return len;
}
int tcpclient_getline(TCPClient *client, char **buffer, int maxsize)
{
	char c;
	int sz, ret;
	int count;
	char *buf;
	sz = 128;
	xfree(*buffer);
	*buffer =  xmalloc(sz);
	buf = *buffer;
	if (maxsize == 0)
		maxsize = 32768;
	for(count=0;count<maxsize;count++)
	{
		if(count >= sz)
		{
			sz *= 2;
			*buffer = xrealloc(*buffer, sz);
			buf = *buffer;
		}
		ret = recv(TCP_FD(client), &c, 1, 0);
		if(ret == 0) return count-1;
		else if(ret < 0) return ret;
		if(c == '\r')
		{
			ret = recv(TCP_FD(client), &c, 1, 0);
			if(ret == 0) return count-1;
			else if(ret < 0) return ret;
			if(c == '\n') /* got a line */
			{
				buf[count] = '\0';
				return count;
			}
			else /* not a [standard] line */
				buf[count] = c;
		}
		else
			buf[count] = c;
	}
	/* not getting a line, probably because line too long  */
	return count;
}
SState tcpclient_checkio(TCPClient *client, int sec, int usec)
{
	struct timeval tv;
	tv.tv_sec = sec;
	tv.tv_usec = usec;
	fd_set wfds, rfds;
	FD_ZERO(&wfds);
	FD_ZERO(&rfds);
	FD_SET(TCP_FD(client), &wfds);
	FD_SET(TCP_FD(client), &rfds);
	
	int ret;
	SState state = None;
	if((ret = select(TCP_FD(client)+1, &rfds, NULL, NULL, &tv)))
	{
		if(ret == -1) return Err;
		if(FD_ISSET(TCP_FD(client), &rfds))
			state = Read;
#if 0
		if(FD_ISSET(TCP_FD(client), &wfds))
		{
			if(state == Read)
				state = ReadWrite;
			else
				state = Write;
		}
#endif

	}
	return state;
}
HTTPHeader *http_parse_header(char *input)
{
	HTTPHeader *header = xmalloc(sizeof(HTTPHeader));
	char line[512];
	while(sscanf(input, "%[^\n]", line) == 1)
	{
		input += strlen(line)+1;
		if(!strncmp(line, "Content-Length", 14))
		{
			sscanf(line, "Content-Length: %d", &header->content_length);
		}
	}
	return header;
}
void http_header_destroy(HTTPHeader *header)
{
	xfree(header);
}
#if 0 /* not yet implemented */
int tcpclient_send_async(TCPClient *client, const char *buffer, int size, TCPCallback sent)
{
}
int tcpclient_recv_async(TCPClient *client, char *buffer, int *size, TCPCallback recved)
{
}
#endif
