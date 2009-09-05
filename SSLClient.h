#ifndef SSLCLIENT_Y81JD7JB
#define SSLCLIENT_Y81JD7JB

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include "TCPClient.h"
#include "msnlib.h"

struct _sslclient
{
	SSL_CTX *ctx;
	SSL *ssl;
	TCPClient *tclient;
	int flag;
};

SSLClient * sslclient_new(const char *, int);
SSLClient * sslclient_new_from_TCPClient(TCPClient *);
void sslclient_destroy(SSLClient *sslc, bool KeepConnection);
bool sslclient_shutdown(SSLClient *sslc);
bool sslclient_connect(SSLClient *sslc);
SState sslclient_checkio(SSLClient *sslc, int sec, int usec);
int sslclient_send(SSLClient *sslc, const char *msg, int size);
int sslclient_recv(SSLClient *sslc, char *buf, int size);
int sslclient_recv_header(SSLClient *client, char **buffer);
int sslclient_getline(SSLClient *client, char **buffer, int maxsize);

#endif /* end of include guard: SSLCLIENT_Y81JD7JB */
