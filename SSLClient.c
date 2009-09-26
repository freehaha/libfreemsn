#include "SSLClient.h"
static bool _SSL_INITED = FALSE;
SSLClient * sslclient_new(const char *host, int port)
{
	TCPClient *client = tcpclient_new(host, port);
	return sslclient_new_from_TCPClient(client);
}
SSLClient * sslclient_new_from_TCPClient(TCPClient *tclient)
{
	char buf[128];
	SSLClient *client;
	/* OpenSSL initialization */
	if(!_SSL_INITED)
	{
		SSL_load_error_strings();
		SSL_library_init();
		RAND_seed(buf, 128);
		_SSL_INITED = TRUE;
	}

	client = (SSLClient*)xmalloc(sizeof(*client));
	memset(client, 0, sizeof(*client));
	client->tclient = tclient;
	client->ctx = SSL_CTX_new(TLSv1_client_method());
	if((client->ssl = SSL_new(client->ctx))==NULL)
	{
		perror("error createing SSL object");
		return NULL;
	}

	return client;
}
void sslclient_destroy(SSLClient *sslc, bool KeepConnection)
{
	if(!sslc) return;
	if(sslc->ctx) SSL_CTX_free(sslc->ctx);
	if(!KeepConnection && sslc->tclient) tcpclient_destroy(sslc->tclient);
	if(sslc->ssl) SSL_free(sslc->ssl);
	xfree(sslc);
}
/* connect the tcp connection and perform handshake */
bool sslclient_connect(SSLClient *sslc)
{
	if(!tcpclient_connect(sslc->tclient)) return FALSE;
	if(SSL_set_fd(sslc->ssl, TCP_FD(sslc->tclient)) == 0)
	{
		fprintf(stderr, "error setting fd: %d\n", SSL_get_error(sslc->ssl, 0));
		return FALSE;
	}
	int ret = SSL_connect(sslc->ssl);
	if(ret != 1)
	{
		fprintf(stderr, "\nhandshake error:");
		ERR_print_errors_fp(stderr);
		//fprintf(stderr, "SSL handshake failed: %s\n", ERR_error_string(SSL_get_error(sslc->ssl, ret), NULL));
		return FALSE;
	}
	return TRUE;
}
bool sslclient_shutdown(SSLClient *sslc)
{
	int ret, i;
	for(i=0;i<3;i++) /* try 3 times for shutting down */
	{
		ret = SSL_shutdown(sslc->ssl);
		switch(ret)
		{
			case 1:
				return TRUE;
			case 0:
				continue;
			case -1:
				return FALSE;
		}
	}
	/* close it anyway */
	SSL_set_shutdown(sslc->ssl, SSL_SENT_SHUTDOWN|SSL_RECEIVED_SHUTDOWN);
	return FALSE;
}
SState sslclient_checkio(SSLClient *sslc, int sec, int usec)
{
	return tcpclient_checkio(sslc->tclient, sec, usec);
}
int sslclient_send(SSLClient *sslc, const char *msg, int size)
{
	if(size <= 0) return 0;
	int ret = SSL_write(sslc->ssl, msg, size);
	if(ret > 0) return ret;
	fprintf(stderr, "sslclient_send: %d\n", SSL_get_error(sslc->ssl, ret));
	return ret;
}
int sslclient_recv(SSLClient *sslc, char *buf, int size)
{
	if(size <= 0) return 0;
	int ret = SSL_read(sslc->ssl, buf, size);
	if(ret > 0) return ret;
	if(ret == 0)
	{
#ifdef DEBUG
		fprintf(stderr, "sslclient_recv: connection broken\n");
#endif
	}
	else
		fprintf(stderr, "sslclient_recv: %d %d\n", ret, SSL_get_error(sslc->ssl, ret));

	return ret;
}
int sslclient_getline(SSLClient *client, char **buffer, int maxsize)/*{{{*/
{
	char c;
	int sz, ret;
	int count;
	char *buf;
	sz = 128;
	xfree(*buffer);
	*buffer =  (char*)xmalloc(sz);
	buf = *buffer;
	if (maxsize == 0)
		maxsize = 32768;
	for(count=0;count<maxsize;count++)
	{
		if(count >= sz)
		{
			sz *= 2;
			*buffer = (char*)xrealloc(*buffer, sz);
			buf = *buffer;
		}
		ret = SSL_read(client->ssl, &c, 1);
		if(ret == 0) return count-1;
		else if(ret < 0) return ret;
		if(c == '\r')
		{
			ret = SSL_read(client->ssl, &c, 1);
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
}/*}}}*/
int sslclient_recv_header(SSLClient *client, char **buffer)/*{{{*/
{
	char *buf;
	int size = 1024;
	int ret;

	xfree(*buffer);
	*buffer = (char*)xmalloc(size);
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
		ret = sslclient_getline(client, &line, 0);
		if(ret < 0)
		{
			xfree(*buffer);
			return 0;
		}
		/* check for buffer size */
		if(ret + len > size)
		{
			size += 1024;
			buf = (char*)xrealloc(*buffer, size);
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
}/*}}}*/
