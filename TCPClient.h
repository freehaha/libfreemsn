#ifndef TCPCLIENT_GZX86FGO
#define TCPCLIENT_GZX86FGO
#include "msnlib.h"
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>

#define TCPC_CONNECTING 1
#define TCPC_CONNECTED 2

struct _tcpclient
{
	int sockfd;
	char hostname[64];
	int port;
	struct sockaddr_in *sin;
	int flag;
	TCPCallback connected_callback;
	TCPCallback recv_callback;
	TCPCallback send_callback;
};

struct _httpheader {
	int content_length;
};

typedef enum {
	None, Read, Write, ReadWrite, Err
} SState;

TCPClient *tcpclient_new(const char *host, int port);
void tcpclient_destroy(TCPClient *client);
bool tcpclient_connect(TCPClient *client);
int tcpclient_send(TCPClient *client, const char *buffer, int size);
int tcpclient_recv(TCPClient *client, char *buffer, int size);
int tcpclient_getline(TCPClient *client, char **buffer, int maxsize);
int tcpclient_recv_header(TCPClient *client, char **buffer);
int tcpclient_send_async(TCPClient *client, const char *buffer, int size, TCPCallback sent);
int tcpclient_recv_async(TCPClient *client, char *buffer, int *size, TCPCallback recved);
SState tcpclient_checkio(TCPClient *client, int sec, int usec);
void http_header_destroy(HTTPHeader *header);
HTTPHeader *http_parse_header(char *input);

#define TCP_FD(x) (x->sockfd)

#endif /* end of include guard: TCPCLIENT_GZX86FGO */
