#include "NS.h"
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/des.h>
#include <openssl/md5.h>
#include <pthread.h>

/* internal functions {{{*/
int _NS_load_ssoreq(char *buffer, char *username, char *password, char *policy);
int _NS_initial_ADL(NS *ns);
void _NS_do_ssoreq(NS *ns, char *policy, char* nonce);
int _NS_get_tickets(xmlDocPtr doc, char **ticket, char **secret, char **cticket, char **oticket);
int _NS_compute_usrkey(MSGUSRKEY *key, char *challenge, char *secret);
char *_NS_compute_hash(char *key, int klen, const char *magic, char *result);
int _NS_send_command(NS *ns, const char *command, const char *argument, bool appendID);
int _NS_send_payload(NS *ns, const char *command, const char *argument, const char *payload, int len, bool appendID);
int _NS_add_payload(NS *ns, char *command, char *argument, char *payload, int len, bool appendID);
int _NS_add_command(NS *ns, char *command, char *argument, bool appendID);
SB * _NS_get_SB_by_tid(NS *ns, int tid);
int isBigEndian(void);
void _NS_calculate_chl(char *input, char *output);
unsigned int swapInt(unsigned int dw);
int _NS_push_command(NS *ns, Command *c);

/* dispatches */
int _NS_dispatch(NS *ns, char *);
int _NS_disp_VER(NS *ns, char *command); /* version */
int _NS_disp_CVR(NS *ns, char *command);
int _NS_disp_USR(NS *ns, char *command); /* login */
int _NS_disp_XFR(NS *ns, char *command); /* transfer */
int _NS_disp_CHG(NS *ns, char *command); /* change state */
int _NS_disp_CHL(NS *ns, char *command); /* challenge */
int _NS_disp_GCF(NS *ns, char *command); /* get config */
int _NS_disp_SBS(NS *ns, char *command); /* Unknown null command */
int _NS_disp_MSG(NS *ns, char *command); /* profile messages */
int _NS_disp_NLN(NS *ns, char *command);
int _NS_disp_ILN(NS *ns, char *command); /* initial contract */
int _NS_disp_QNG(NS *ns, char *command); /* end of ping */
int _NS_disp_QRY(NS *ns, char *command); /* confirm of challenge */
int _NS_disp_BLP(NS *ns, char *command); /* response to default list setting */
int _NS_disp_ADL(NS *ns, char *command); /* add list response */
int _NS_disp_UBX(NS *ns, char *command); /* buddy status changes */
int _NS_disp_UUX(NS *ns, char* command); /* personal status */
int _NS_disp_FLN(NS *ns, char* command); /* buddy goes offline */
int _NS_disp_RNG(NS *ns, char* command); /* ringring */
int _NS_disp_PRP(NS *ns, char* command); /* PRP */
int _NS_disp_OUT(NS *ns, char* command); /* OUT */

struct nsdispatch _ns_dispatch_table[] = /*{{{*/
{
	{"ILN", _NS_disp_ILN},
	{"NLN", _NS_disp_NLN},
	{"UBX", _NS_disp_UBX},
	{"FLN", _NS_disp_FLN},
	{"RNG", _NS_disp_RNG},
	{"QNG", _NS_disp_QNG},
	{"CHG", _NS_disp_CHG},
	{"VER", _NS_disp_VER},
	{"QRY", _NS_disp_QRY},
	{"CVR", _NS_disp_CVR},
	{"XFR", _NS_disp_XFR},
	{"MSG", _NS_disp_MSG},
	{"CHL", _NS_disp_CHL},
	{"OUT", _NS_disp_OUT},
	{"GCF", _NS_disp_GCF},
	{"SBS", _NS_disp_SBS},
	{"USR", _NS_disp_USR},
	{"ADL", _NS_disp_ADL},
	{"PRP", _NS_disp_PRP},
	{"BLP", _NS_disp_BLP},
	{"UUX", _NS_disp_UUX},
	{NULL, NULL}
};/*}}}*/
/* requests */
const char sso_request[] = /*{{{*/
"<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
"<Envelope xmlns=\"http://schemas.xmlsoap.org/soap/envelope/\""
"          xmlns:wsse=\"http://schemas.xmlsoap.org/ws/2003/06/secext\""
"          xmlns:saml=\"urn:oasis:names:tc:SAML:1.0:assertion\""
"          xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2002/12/policy\""
"          xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\""
"          xmlns:wsa=\"http://schemas.xmlsoap.org/ws/2004/03/addressing\""
"          xmlns:wssc=\"http://schemas.xmlsoap.org/ws/2004/04/sc\""
"          xmlns:wst=\"http://schemas.xmlsoap.org/ws/2004/04/trust\">"
"<Header>"
"  <ps:AuthInfo xmlns:ps=\"http://schemas.microsoft.com/Passport/SoapServices/PPCRL\" Id=\"PPAuthInfo\">"
"    <ps:HostingApp>{7108E71A-9926-4FCB-BCC9-9A9D3F32E423}</ps:HostingApp>"
"    <ps:BinaryVersion>4</ps:BinaryVersion>"
"    <ps:UIVersion>1</ps:UIVersion>"
"    <ps:Cookies></ps:Cookies>"
"    <ps:RequestParams>AQAAAAIAAABsYwQAAAAxMDMz</ps:RequestParams>"
"  </ps:AuthInfo>"
"  <wsse:Security>"
"    <wsse:UsernameToken Id=\"user\">"
"    <wsse:Username>%s</wsse:Username>"
"    <wsse:Password>%s</wsse:Password>"
"    </wsse:UsernameToken>"
"  </wsse:Security>"
"</Header>"
"<Body>"
"  <ps:RequestMultipleSecurityTokens xmlns:ps=\"http://schemas.microsoft.com/Passport/SoapServices/PPCRL\" Id=\"RSTS\">"
"    <wst:RequestSecurityToken Id=\"RST0\">"
"      <wst:RequestType>http://schemas.xmlsoap.org/ws/2004/04/security/trust/Issue</wst:RequestType>"
"      <wsp:AppliesTo>"
"        <wsa:EndpointReference>"
"          <wsa:Address>http://Passport.NET/tb</wsa:Address>"
"        </wsa:EndpointReference>"
"      </wsp:AppliesTo>"
"    </wst:RequestSecurityToken>"
"    <wst:RequestSecurityToken Id=\"RST1\">"
"      <wst:RequestType>http://schemas.xmlsoap.org/ws/2004/04/security/trust/Issue</wst:RequestType>"
"      <wsp:AppliesTo>"
"        <wsa:EndpointReference>"
"          <wsa:Address>messengerclear.live.com</wsa:Address>"
"        </wsa:EndpointReference>"
"      </wsp:AppliesTo>"
"    <wsse:PolicyReference URI=\"%s\"></wsse:PolicyReference>"
"    </wst:RequestSecurityToken>"
"    <wst:RequestSecurityToken Id=\"RST2\">"
"      <wst:RequestType>http://schemas.xmlsoap.org/ws/2004/04/security/trust/Issue</wst:RequestType>"
"      <wsp:AppliesTo>"
"        <wsa:EndpointReference>"
"          <wsa:Address>messenger.msn.com</wsa:Address>"
"        </wsa:EndpointReference>"
"      </wsp:AppliesTo>"
"      <wsse:PolicyReference URI=\"?id=507\"></wsse:PolicyReference>"
"    </wst:RequestSecurityToken>"
"    <wst:RequestSecurityToken Id=\"RST3\">"
"      <wst:RequestType>http://schemas.xmlsoap.org/ws/2004/04/security/trust/Issue</wst:RequestType>"
"      <wsp:AppliesTo>"
"        <wsa:EndpointReference>"
"          <wsa:Address>contacts.msn.com</wsa:Address>"
"        </wsa:EndpointReference>"
"      </wsp:AppliesTo>"
"      <wsse:PolicyReference URI=\"MBI\"></wsse:PolicyReference>"
"    </wst:RequestSecurityToken>"
"    <wst:RequestSecurityToken Id=\"RST4\">"
"      <wst:RequestType>http://schemas.xmlsoap.org/ws/2004/04/security/trust/Issue</wst:RequestType>"
"      <wsp:AppliesTo>"
"        <wsa:EndpointReference>"
"          <wsa:Address>messengersecure.live.com</wsa:Address>"
"        </wsa:EndpointReference>"
"      </wsp:AppliesTo>"
"      <wsse:PolicyReference URI=\"MBI_SSL\"></wsse:PolicyReference>"
"    </wst:RequestSecurityToken>"
"    <wst:RequestSecurityToken Id=\"RST5\">"
"      <wst:RequestType>http://schemas.xmlsoap.org/ws/2004/04/security/trust/Issue</wst:RequestType>"
"      <wsp:AppliesTo>"
"        <wsa:EndpointReference>"
"          <wsa:Address>spaces.live.com</wsa:Address>"
"        </wsa:EndpointReference>"
"      </wsp:AppliesTo>"
"      <wsse:PolicyReference URI=\"MBI\"></wsse:PolicyReference>"
"    </wst:RequestSecurityToken>"
"    <wst:RequestSecurityToken Id=\"RST6\">"
"      <wst:RequestType>http://schemas.xmlsoap.org/ws/2004/04/security/trust/Issue</wst:RequestType>"
"      <wsp:AppliesTo>"
"        <wsa:EndpointReference>"
"          <wsa:Address>storage.msn.com</wsa:Address>"
"        </wsa:EndpointReference>"
"      </wsp:AppliesTo>"
"      <wsse:PolicyReference URI=\"MBI\"></wsse:PolicyReference>"
"    </wst:RequestSecurityToken>"
"  </ps:RequestMultipleSecurityTokens>"
"</Body>"
"</Envelope>";/*}}}*/
const char sso_request_header[] = /*{{{*/
	"POST /RST.srf HTTP/1.1\r\n"
	"Host: login.live.com\r\n"
	"User-Agent: MSMSGS\r\n"
	"Accept: */*\r\n"
	"Content-Type: application/soap+xml; charset=utf-8\r\n"
	"Content-Length: %d\r\n\r\n";/*}}}*/
/* }}} */

NS *NS_new(Account *account)/*{{{*/
{
	NS *ns = (NS*)xmalloc(sizeof(NS));
	memset(ns, 0, sizeof(NS));
	ns->account = account;
	ns->cmdq = cmdqueue_new();
	ns->notifications = account->notifications;
	return ns;
}/*}}}*/
void NS_destroy(NS *ns)/*{{{*/
{
	int ret;
	SB *sb;
	if(ns->nsthread)
	{
		Command *c;
		NSNotifyData *data = NS_notify_data_new(NS_NOTIFY_SHUTDOWN);
		c = command_new(CMD_NS_NOTIFY, data, NS_notify_data_destroy);
		cmdqueue_push(ns->cmdq, c);
		pthread_join(ns->nsthread, (void**)&ret);
	}

	if(ns->tclient) tcpclient_destroy(ns->tclient);
	if(ns->sclient) sslclient_destroy(ns->sclient, FALSE);
	if(ns->contacts) cl_destroy(ns->contacts);
	
	while(ns->sblist)
	{
		sb = ns->sblist->next;
		SB_destroy(ns->sblist);
		ns->sblist = sb;
	}
	if(ns->cmdq) cmdqueue_destroy(ns->cmdq);
	xfree(ns);
	ERR_free_strings();
}/*}}}*/
int NS_connect(NS *ns)/*{{{*/
{
	char hello[] = "VER 1 MSNP15 CVR0\r\n";

	/* connect and send the first message */
	if(ns->tclient)
	{
		tcpclient_destroy(ns->tclient);
		ns->tclient = NULL;
	}
	if(ns->sclient)
	{
		sslclient_destroy(ns->sclient, FALSE);
		ns->sclient = NULL;
	}
	ns->tclient = tcpclient_new("messenger.hotmail.com", 1863);
	tcpclient_connect(ns->tclient);
	DMSG(stderr, "NS: connected\n");
	if(!ns->tclient) return FALSE;
	tcpclient_send(ns->tclient, hello, sizeof(hello)-1);
	return TRUE;
}/*}}}*/
void *NS_loop(void *data)/*{{{*/
{
	NS *ns = (NS*)data;
	while(1)
	{
		if(NS_dispatch_nblocking(ns, 0, 500) < 0)
		{
			Command *c;
			NSNotifyData *data;
			fprintf(stderr, "end\n");
			/* tell account we're down */
			
			data = NS_notify_data_new(NS_NOTIFY_SHUTDOWN);
			c = command_new(CMD_NS_NOTIFY, data, NS_notify_data_destroy);
			cmdqueue_push(ns->notifications, c);
			pthread_exit(0);
		}
		if(!NS_dispatch_commands(ns))
		{
			pthread_exit(0);
		}
		if(ns->nextping > 0)
		{
			if(ns->flag&NS_CONNECTED && ns->nextping <= time(0))
			{
				NS_ping(ns);
				ns->nextping = -1;
			}
		}
	}
	pthread_exit(0);
	return 0;
}/*}}}*/
bool NS_dispatch_commands(NS *ns)/*{{{*/
{
	Command *c;
	SB *sb = NULL;
	if(! (ns->flag & NS_CONNECTED)) return TRUE;
	c = cmdqueue_pop(ns->cmdq);
	while(c)
	{
		switch(c->type)
		{
			case CMD_NS:/*{{{*/
				{
					NSMsgData *data = (NSMsgData*)c->data;
					switch(data->type)
					{
						case MSG_MESSAGE:
							_NS_send_command(ns, data->cmd, data->argument, data->appendID);
							break;
						case MSG_PAYLOAD:
							_NS_send_payload(ns, data->cmd, data->argument, data->payload, data->length, data->appendID);
							break;
						default:
							fprintf(stderr, "unknown command!\n");
							command_destroy(c);
							return FALSE;
					}
				}
				break;/*}}}*/
			case CMD_NS_NOTIFY:/*{{{*/
				{
					NSNotifyData *data = (NSNotifyData*)c->data;
					switch(data->type)
					{
						case NS_NOTIFY_SHUTDOWN:
							{
								/* pass it to Account */
								Command *c;
								NSNotifyData *data = NS_notify_data_new(NS_NOTIFY_SHUTDOWN);
								c = command_new(CMD_NS_NOTIFY, data, NS_notify_data_destroy);
								cmdqueue_push(ns->notifications, c);
							}
							DMSG(stderr, "NS: shutting down..\n");
							return FALSE;
							break;
						case NS_NOTIFY_REQSB:
							{
								DMSG(stderr, "SB request from account ...\n");
								int tid = ns->TrID;
								ns->TrID = (int)data->data;
								_NS_send_command(ns, "XFR", "SB", TRUE);
								ns->TrID = tid;
								break;
							}
						default:
							break;
					}
				}
				break;/*}}}*/
			case CMD_SB_NOTIFY:
			case CMD_SB:
				break;
			default:
				break;

		}

		command_destroy(c);
		c = cmdqueue_pop(ns->cmdq);
	}
	for(sb=ns->sblist;sb;sb=sb->next)
	{
		SB_dispatch_commands(sb);
	}
	return TRUE;
}/*}}}*/
void NS_remove_SB(NS *ns, unsigned long int sbid)/*{{{*/
{
	SB *prev;
	DMSG(stderr, "removing SB %lu from NS\n", sbid);
	if(sbid == ns->sblist->id)
	{
		prev = ns->sblist;
		ns->sblist = ns->sblist->next;
	}
	else
	{
		for(prev=ns->sblist;prev->next;prev=prev->next)
		{
			if(prev->next->id == sbid)
			{
				prev->next = prev->next->next;
				break;
			}
		}
		fprintf(stderr, "NS_remove_SB error: SB not on list !!\n");
	}
	SB_destroy(prev);
}/*}}}*/
bool NS_fork(NS *ns)/*{{{*/
{
	return 0==pthread_create(&ns->nsthread, NULL, NS_loop, ns);
}/*}}}*/
int NS_dispatch_nblocking(NS *ns, int sec, int usec)/*{{{*/
{
	char *buf = NULL;
	SB *sb, *sb_next, *sb_prev;
	int ret;
	SState s = tcpclient_checkio(ns->tclient, sec, usec);
	if(s == Read || s == ReadWrite)
	{
		ret = tcpclient_getline(ns->tclient, &buf, 512);
		if(ret <= 0)
		{
			xfree(buf);
			return ret-1;
		}
		else
		{
			ret = _NS_dispatch(ns, buf);
			xfree(buf);
			return ret;
		}
	}
	sb_prev = ns->sblist;
	for(sb=ns->sblist;sb;sb=sb_next)
	{
		SBNotifyData *data;
		Command *cmd;
		sb_next = sb->next;
		if(SB_dispatch_nblocking(sb, 0, 100) < 0)
		{
			DMSG(stderr, "destroying SB %lu\n", sb->id);
			if(sb == ns->sblist)
			{
				ns->sblist = sb->next;
			}
			else
			{
				sb_prev->next = sb->next;
			}
			data = SB_notify_data_new(sb, SB_NOTIFY_SHUTDOWN);
			cmd = command_new(CMD_SB_NOTIFY, data, SB_notify_data_destroy);
			cmdqueue_push(ns->notifications, cmd);
			SB_destroy(sb);
			continue;
		}
		sb_prev = sb;
	}
	return 0;
}/*}}}*/
int _NS_dispatch(NS *ns, char *line)/*{{{*/
{
	char cmd[8]; /* protocol says 4 is enough, but just in case .. */
	Dispatch *dp;
	char *arg = line;
	line = get_one_arg(line, cmd, 8);
	for(dp=_ns_dispatch_table;dp->cmd;dp++)
	{
		if(!strcmp(dp->cmd, cmd))
		{
#ifdef DEBUG
			fprintf(stderr, "dispatched to %s.\n", cmd);
#endif
			return (*dp->func)(ns, line);
		}
	}
	fprintf(stderr, "unknown command: %s\n", arg);
	return -1;
}/*}}}*/
void NS_msg_destroy(void *data)/*{{{*/
{
	NSMsgData *msg = (NSMsgData*)data;
	if(!data)
	{
		fprintf(stderr, "NULL data passed to _NS_msg_destroy\n");
		return;
	}
	xfree(msg->cmd);
	xfree(msg->argument);
	xfree(msg->payload);
	xfree(data);
}/*}}}*/
int _NS_add_command(NS *ns, char *command, char *argument, bool appendID)/*{{{*/
{
	Command *c;
	NSMsgData *data;

	if( !command || !*command)
	{
		fprintf(stderr, "_NS_add_command: adding NULL command !\n");
		return 0;
	}
	DMSG(stderr, "add NS command: %s...\n", command);
	data = (NSMsgData*)xmalloc(sizeof(NSMsgData));
	data->type = MSG_MESSAGE;
	data->appendID = appendID;
	data->cmd = STRDUP(command);
	if(argument)
		data->argument = STRDUP(argument);
	else
		data->argument = NULL;
	data->payload = NULL;
	data->length = 0;
	data->time = time(NULL);
	c = command_new(CMD_NS, data, NS_msg_destroy);
	cmdqueue_push(ns->cmdq, c);
	return 1;
}/*}}}*/
int _NS_push_command(NS *ns, Command *c)/*{{{*/
{
	if(!c) return 0;
	cmdqueue_push(ns->cmdq, c);
	return 1;
}/*}}}*/
SB* NS_request_SB(NS *ns)/*{{{*/
{
	Command *c;
	int tid = ns->TrID;
	SB *sb;
	NSNotifyData *data = NS_notify_data_new(NS_NOTIFY_REQSB);
	data->data = (void*)tid;
	c = command_new(CMD_NS_NOTIFY, data, NS_notify_data_destroy);
	_NS_push_command(ns, c);
	sb = SB_new(ns->account, tid, 0);
	sb->next = ns->sblist;
	ns->sblist = sb;
	return sb;
}/*}}}*/
SB * _NS_get_SB_by_tid(NS *ns, int tid)/*{{{*/
{
	SB *sb = NULL;
	for(sb=ns->sblist;sb;sb=sb->next)
	{
		if(sb->tid == tid) return sb;
	}
	return NULL;
}/*}}}*/


int _NS_add_payload(NS *ns, char *command, char *argument, char *payload, int len, bool appendID)/*{{{*/
{
	/* NOTE: payload WILL be freed after pop from the queue */
	Command *c;
	NSMsgData *data = (NSMsgData*)xmalloc(sizeof(NSMsgData));
	data->type = MSG_PAYLOAD;
	data->appendID = appendID;
	data->cmd = STRDUP(command);
	data->argument = STRDUP(argument);
	data->payload = payload;
	data->length = len;
	data->time = time(NULL);
	c = command_new(CMD_NS, data, NS_msg_destroy);
	return _NS_push_command(ns, c);
}/*}}}*/
int _NS_send_command(NS *ns, const char *command, const char *argument, bool appendID)/*{{{*/
{
	int ret;
	ret = _msn_send_command(ns->tclient, command, argument, appendID?ns->TrID:-1);
	/* TODO: TrID verification */
	if(appendID) ns->TrID++;
	if(ns->TrID > 128) ns->TrID = 0;
	return ret;
}/*}}}*/
int _NS_send_payload(NS *ns, const char *command, const char *argument, const char *payload, int len, bool appendID)/*{{{*/
{
	int ret;
	ret = _msn_send_payload(ns->tclient, command, argument, payload, len, appendID?ns->TrID:-1);
	/* TODO: TrID verification */
	if(appendID) ns->TrID++;
	if(ns->TrID > 128) ns->TrID = 0;
	return ret;
}/*}}}*/
int _NS_read_payload(NS *ns, char **buf, int len)/*{{{*/
{
	return _msn_read_payload(ns->tclient, buf, len);
}/*}}}*/
int _NS_get_tickets(xmlDocPtr doc, char **ticket, char **secret, char **cticket, char **oticket)/*{{{*/
{
	xmlNodePtr node;
	xmlNodePtr tokenCollection;
	bool found = 0;

	node = xmlDocGetRootElement(doc);
	tokenCollection = findNode(node, "RequestSecurityTokenResponseCollection", 3);
	xfree(*secret);
	xfree(*ticket);
	xfree(*cticket);
	xfree(*oticket);
	if(!tokenCollection)
	{
		fprintf(stderr, "cannot find token collection\n");
		return FALSE;
	}
	for(node=tokenCollection->children;node;node=node->next)
	{
		xmlNodePtr ref = findNode(node->children, "BinarySecurityToken", 3);
		if(ref)
		{
			if(!*ticket && !xmlStrcmp(ref->properties->children->content, (const xmlChar *)"Compact1"))
			{
				DMSG(stderr, "found login ticket\n");
				/* ticket */
				*ticket = (char*)xmalloc(strlen((char*)ref->children->content)+1);
				strcpy(*ticket, (char*)ref->children->content);
				/* binary secret */
				ref = findNode(node->children, "BinarySecret", 3);
				if(ref)
				{
					xmlChar *content = xmlNodeGetContent(ref);
					*secret = (char*)xmalloc(strlen((char*)content)+1);
					strcpy(*secret, (char*)content);
					xmlFree(content);
				}
				else
				{
					fprintf(stderr, "error: cannot find binary secret");
					break;
				}
				found++;
				continue;
			}
			if(!*oticket && !xmlStrcmp(ref->properties->children->content, (const xmlChar *)"PPToken2"))
			{
				/* ticket */
				DMSG(stderr, "found oim ticket\n");
				*oticket = (char*)xmalloc(strlen((char*)ref->children->content)+1);
				strcpy(*oticket, (char*)ref->children->content);
				found++;
				continue;
			}
			if(!*cticket && !xmlStrcmp(ref->properties->children->content, (const xmlChar *)"Compact3"))
			{
				/* ticket */
				DMSG(stderr, "found contact ticket\n");
				*cticket = (char*)xmalloc(strlen((char*)ref->children->content)+1);
				strcpy(*cticket, (char*)ref->children->content);
				found++;
				continue;
			}
		}
	}
	if(found != 3)
	{
		fprintf(stderr, "failed to get ticket, secret, or cticket");
	}
	return found == 3;
}/*}}}*/
int NS_ping(NS *ns)/*{{{*/
{
	_NS_send_command(ns, "PNG", "", FALSE);
	return 1;
}/*}}}*/

int _NS_load_ssoreq(char *buffer, char *username, char *password, char *policy)/*{{{*/
{
	return sprintf(buffer, sso_request, username, password, policy);
}/*}}}*/
void _NS_do_ssoreq(NS *ns, char *policy, char* nonce)/*{{{*/
{
	char buf[sizeof(sso_request)+256] = {0};
	char header[sizeof(sso_request_header)+32];
	int len, hlen;
	xmlDocPtr doc;
	xmlParserCtxtPtr ctxt;
	FILE *fp;
	char *ticket = NULL, *secret = NULL, *cticket = NULL, *oticket = NULL;
	MSGUSRKEY key;
	char *p;
	char send[2048];

	ns->sclient = sslclient_new("login.live.com", 443);
	if(!sslclient_connect(ns->sclient))
	{
		fprintf(stderr, "error connecting to server login.live.com:443...\n");
		return;
	}

	len = _NS_load_ssoreq(buf, ns->account->username, ns->account->pwd, policy);
	hlen = sprintf(header, sso_request_header, len);
	sslclient_send(ns->sclient, header, hlen);
	sslclient_send(ns->sclient, buf, len);
	memset(buf, 0, sizeof(buf));
	sslclient_recv(ns->sclient, buf, sizeof(buf)-1); /* header */
	memset(buf, 0, sizeof(buf));
	/* parse the resulting xml */
	LIBXML_TEST_VERSION;
	len = sslclient_recv(ns->sclient, buf, sizeof(buf)-1);
	ctxt = xmlCreatePushParserCtxt(NULL, NULL, buf, len, "response.xml");
	fp = fopen("response.xml", "w");
	fprintf(fp, buf);
	if(ctxt == NULL)
	{
		fprintf(stderr, "failed to create parser context");
		return;
	}
	while(len > 0)
	{
		memset(buf, 0, sizeof(buf));
		len = sslclient_recv(ns->sclient, buf, sizeof(buf)-1);
		fprintf(fp, buf);
		xmlParseChunk(ctxt, buf, len, 0);
	}
	fclose(fp);
	xmlParseChunk(ctxt, buf, 0, 1);
	sslclient_destroy(ns->sclient, FALSE);
	ns->sclient = NULL;
	doc = ctxt->myDoc;
	len = ctxt->wellFormed;
	xmlFreeParserCtxt(ctxt);
	DMSG(stderr, "xml parsing done: %s\n", len?"good":"malformed");
	if(!_NS_get_tickets(doc, &ticket, &secret, &cticket, &oticket))
	{
		fprintf(stderr, "error getting ticket & secret, restarting... \n");
		xfree(ticket);
		xfree(secret);
		xfree(cticket);
		xmlFreeDoc(doc);
		xmlCleanupParser();
		NS_connect(ns);
		return;
	}
	if(cticket)
	{
		if(ns->contacts)
			cl_destroy(ns->contacts);
		ns->contacts = cl_new(ns->account, cticket);
	}

	if(oticket) /* don't free it */
		ns->oticket = oticket;

	_NS_compute_usrkey(&key, nonce, secret);
	p = base64((unsigned char*)&key, sizeof(MSGUSRKEY));
	len = sprintf(send, "USR 5 SSO S %s %s\r\n", ticket, p);
	xfree(p);
#if 0/*{{{*/
	fprintf(stderr, "ticket: %s\n", ticket);
	fprintf(stderr, "nonce: %s\nsecret: %s\n", nonce, secret);
	fprintf(stderr, "key: %s\n", p);
	fprintf(stderr, "send: '%s' %d", send, len);
#endif/*}}}*/
	len = tcpclient_send(ns->tclient, send, len);
	DMSG(stderr, "\nlen: %d\n", len);
	xmlFreeDoc(doc);
	xmlCleanupParser();
	xfree(ticket);
	xfree(cticket);
	xfree(secret);
}/*}}}*/
int _NS_compute_usrkey(MSGUSRKEY *key, char *challenge, char *secret)/*{{{*/
{
	char *key1;
	char key2[24];
	char key3[24];
	int klen = 0;
	char *chg;
	DES_cblock iv = {0,0,0,0,0,0,0,0};
	DES_key_schedule sched1, sched2, sched3;
	const_DES_cblock dkey1, dkey2, dkey3;

	key->uStructHeaderSize = 28;
	key->uCryptMode = 1;
	key->uCipherType = 0x6603;
	key->uHashType = 0x8004;
	key->uIVLen = 8;
	key->uHashLen = 20;
	key->uCipherLen = 72;
	memset(key->aIVBytes, 0, 8);

	key1 = (char*)unbase64((unsigned char*)secret, strlen(secret));
	klen = 24;
	_NS_compute_hash(key1, klen, "WS-SecureConversationSESSION KEY HASH", key2);
	_NS_compute_hash(key1, klen, "WS-SecureConversationSESSION KEY ENCRYPTION", key3);

	HMAC(EVP_sha1(), (unsigned char*)key2, klen, (unsigned char*)challenge, strlen(challenge), key->aHashBytes, NULL);
	
	memcpy(dkey1, key3, 8);
	memcpy(dkey2, key3+8, 8);
	memcpy(dkey3, key3+16, 8);
	DES_set_key_unchecked(&dkey1, &sched1);		// set the key schedule
	DES_set_key_unchecked(&dkey2, &sched2);		// set the key schedule
	DES_set_key_unchecked(&dkey3, &sched3);		// set the key schedule
	chg = (char*)xmalloc(strlen(challenge)+9);
	memcpy(chg, challenge, strlen(challenge));
	memset(chg+strlen(challenge), 8, 8);
	*(chg+strlen(challenge)+8) = 0;
	DES_ede3_cbc_encrypt((unsigned char*)chg, key->aCipherBytes, 72, &sched1, &sched2, &sched3, &iv, DES_ENCRYPT);
	xfree(chg);
	xfree(key1);
	return 0;
}/*}}}*/
char *_NS_compute_hash(char *key, int klen, const char *magic, char *result)/*{{{*/
{
	int mlen = strlen(magic);
	static char ret[24];
	unsigned int mdlen1, mdlen2, mdlen3, mdlen4;
	unsigned char hash1[EVP_MAX_MD_SIZE];
	unsigned char hash2[EVP_MAX_MD_SIZE];
	unsigned char hash3[EVP_MAX_MD_SIZE];
	unsigned char hash4[EVP_MAX_MD_SIZE];
	unsigned char buf[EVP_MAX_MD_SIZE*2];

	HMAC(EVP_sha1(), (unsigned char*)key, klen, (unsigned char*)magic, mlen, hash1, &mdlen1);
	memcpy(buf, hash1, mdlen1);
	memcpy(buf+mdlen1, magic, mlen);
	HMAC(EVP_sha1(), (unsigned char*)key, klen, buf, mlen+mdlen1, hash2, &mdlen2);
	HMAC(EVP_sha1(), (unsigned char*)key, klen, hash1, mdlen1, hash3, &mdlen3);
	memcpy(buf, hash3, mdlen3);
	memcpy(buf+mdlen3, magic, mlen);
	HMAC(EVP_sha1(), (unsigned char*)key, klen, buf, mdlen3+mlen, hash4, &mdlen4);
	memcpy(ret, hash2, 20);
	memcpy(ret+20, hash4, 4);
	memcpy(result,ret, 24);
	return ret;
}/*}}}*/
int _NS_initial_ADL(NS *ns)/*{{{*/
{
	char *adl;
	int count = 0;
	int len = 0;

	if(!ns->contacts)
	{
		fprintf(stderr, "NS NULL contacts\n");
		return 0;
	}
	
	DMSG(stderr, "sending initial ADLs\n");
	do
	{
		adl = cl_generate_ADL_list(ns->contacts, &count, &len);
		_NS_send_payload(ns, "ADL", "", adl, len, TRUE);
		DMSG(stderr, adl);
		xfree(adl);
	}while(count >= 140);
	return 0;
}/*}}}*/
int _NS_disp_GCF(NS *ns, char* command)/*{{{*/
{
	int size;
	char *pl = NULL;

	DMSG(stderr, "GCF: %s\n", command);
	if(sscanf(command, "0 %d", &size) == 1)
	{
		_NS_read_payload(ns, &pl, size);
		xfree(pl);
	}
	return 1;
}/*}}}*/
int _NS_disp_NLN(NS *ns, char *command)/*{{{*/
{
	//NLN status email@addr.ess networkid nickname clientid dpobj
	char status[4];
	char email[64];
	int nid;
	char nick[512];
	int clientid;

	DMSG(stderr, "NLN: %s\n", command);
	/* FIXME currently ignoring dpobj */
	if(sscanf(command, "%s %s %d %s %d", status, email, &nid, nick, &clientid) == 5)
	{
		Contact *c = cl_get_contact_by_email(ns->contacts, email);
		xfree(c->nick);
		c->nick = STRDUP(nick);
		c->status = strtoStatus(status);
	}

	return 1;
}/*}}}*/
int _NS_disp_CHG(NS *ns, char *command) /* change state {{{*/
{
	DMSG(stderr, "CHG: %s\n", command);
	return 1;
}/*}}}*/
int _NS_disp_CHL(NS *ns, char *command) /* challenge {{{*/
{
	char challenge[32] = {0};
	char response[33];

	DMSG(stderr, "CHL: %s\n", command);
	sscanf(command, "0 %s", challenge);
	_NS_calculate_chl(challenge, response);
	DMSG(stderr, "challenge : %s\n", challenge);
	DMSG(stderr, "resposne : %s\n", response);
	return _NS_send_payload(ns, "QRY", PID, response, 32, TRUE);
}/*}}}*/
int _NS_disp_SBS(NS *ns, char *command) /* Unknown null command {{{*/
{
	return 1;
}/*}}}*/
int _NS_disp_MSG(NS *ns, char *command)/*{{{*/
{
	int length = 0;
	char *pl = NULL;
	DMSG(stderr, "MSG: %s\n", command);
	if(sscanf(command, "%*s %*s %d", &length) == 1)
	{
		length = _NS_read_payload(ns, &pl, length);
		DMSG(stderr, "msg read len: %d\n", length);
		xfree(pl);
		if(!(ns->flag & NS_CONNECTED))
		{
			char buf[128];
			char psm[] = "<Data><PSM>TESTING...</PSM><CurrentMedia></CurrentMedia></Data>";

			if(ns->contacts)
				length = cl_retrive(ns->contacts);
			else
				fprintf(stderr, "error: contactlist is not initialized!\n");

			_NS_send_command(ns, "BLP", "BL", TRUE);
			DMSG(stderr, "contact len: %d\n", length);
			if(length > 0)
			{
				_NS_initial_ADL(ns);
			}

			_NS_send_command(ns, "CHG", "HDN 0", TRUE);
			_NS_send_payload(ns, "UUX", "", psm, strlen(psm), TRUE);
			
			sprintf(buf, "MFN %s", ns->account->nick);
			_NS_send_command(ns, "PRP", buf, TRUE);
			ns->olist = oimlist_getlist(ns->oticket);
			ns->flag |= NS_CONNECTED;
			ns->nextping = time(NULL)+50;
		}
	}
	return 1;
}/*}}}*/
int _NS_disp_VER(NS *ns, char* command) /* version {{{*/
{
	char msg[128];
	int len;
	/* TODO: get account name here */
	//sprintf(msg, "CVR 2 0x0409 win 4.10 i386 MSNMSGR 5.0.0544 MSMSGS %s\r\n", ns->account->username);
	DMSG(stderr, "VER: %s\n", command);
	len = sprintf(msg, "CVR 2 0x0409 winnt 5.1 i386 MSMSGS 8.1.0178 msmsgs %s\r\n", ns->account->username);
	len = tcpclient_send(ns->tclient, msg, len);
	DMSG(stderr, "VER: sent %d\n", len);
	return 1;
}/*}}}*/
int _NS_disp_BLP(NS *ns, char *command) /* response to default list setting {{{*/
{
	return 1;
}/*}}}*/
int _NS_disp_CVR(NS *ns, char* command)/*{{{*/
{
	char msg[128];
	int len;

	len = sprintf(msg, "USR 3 SSO I %s\r\n", ns->account->username);
	len = tcpclient_send(ns->tclient, msg, len);
	return len;
}/*}}}*/
int _NS_disp_XFR(NS * ns, char* command) /* transfer {{{*/
{
	char server[64];
	char host[32];
	int port;
	int tid;
	char *tok;
	char ticket[32];

	if(!(ns->flag & NS_CONNECTED) && sscanf(command, "%*d NS %s 0", server) == 1)
	{
		char hello[] = "VER 1 MSNP15 CVR0\r\n";
		tok = strtok(server, ":");
		strncpy(host, server, 32);
		tok = strtok(NULL, ":");
		port = atoi(tok);
		DMSG(stderr, "XFR new server: %s:%d\n", host, port);
		
		tcpclient_destroy(ns->tclient);
		ns->tclient = tcpclient_new(host, port);
		tcpclient_connect(ns->tclient);
		tcpclient_send(ns->tclient, hello, sizeof(hello)-1);
	}
	else if(sscanf(command, "%d SB %[^:]:%d CKI %s", &tid, server, &port, ticket)==4)
	{
		Command *c;
		SBNotifyData *data;
		//XFR 15 SB 207.46.108.37:1863 CKI 17262740.1050826919.32308\r\n
		SB *sb = _NS_get_SB_by_tid(ns, tid);
		if(!sb)
		{
			DMSG(stderr, "ERROR: no matching SB found\n");
			return 0;
		}
		SB_connect(sb, server, port, ticket);
		data = SB_notify_data_new(sb, SB_NOTIFY_REQSB);
		c = command_new(CMD_SB_NOTIFY, data, SB_notify_data_destroy);
		cmdqueue_push(ns->notifications, c);
	}
	else
	{
		fprintf(stderr, "%s\n", command);
	}
	return 1;
}/*}}}*/
int _NS_disp_UUX(NS *ns, char* command) /* personal status {{{*/
{
	return 1;
}/*}}}*/
int _NS_disp_USR(NS *ns, char* command) /* login {{{*/
{
	int verified;
	char policy[64];
	char nonce[128];
	DMSG(stderr, "command: %s\n", command);
	if(sscanf(command, "%*d SSO S %s %s", policy, nonce) == 2)
	{
		DMSG(stderr,"SSO validation\n");
		/* validation using SSO */
		_NS_do_ssoreq(ns, policy, nonce);
		return 1;
	}
	else if(sscanf(command, "%*d OK %*s %d 0", &verified) == 1)
	{
		DMSG(stderr,"validation done\n");
		if(verified == 1)
		{
			ns->verified = 1;
		}
		return 1;
	}
	else
		return 0;
}/*}}}*/
int _NS_disp_FLN(NS *ns, char* command) /* buddy goes offline {{{*/
{
	char buddy[64];
	int nid;
	if(sscanf(command, "%s %d", buddy, &nid) == 2)
	{
		DMSG(stderr, "%s:%d goes offline\n", buddy, nid);
	}
	return 1;
}/*}}}*/
int _NS_disp_UBX(NS *ns, char *command) /* buddy status changes {{{*/
{
	int length = 0;
	char *pl = NULL;
	char user[64];
	int nid;
	/* UBX source@mail.addr.ess networkid length */
	if(sscanf(command, "%s %d %d", user, &nid, &length) == 3)
	{
		Contact *c;
		xmlNodePtr node;
		xmlDocPtr doc;
		DMSG(stderr, "UBX: %s : %d\n", user, nid);
		_NS_read_payload(ns, &pl, length);
		/* <Data><PSM></PSM><CurrentMedia></CurrentMedia><MachineGuid>{F26D1F07-95E2-403C-BC18-D4BFED493428}</MachineGuid></Data> */
		doc = xmlReadMemory(pl, length, "UBX.xml", NULL, 0);
		if(!doc)
		{
			fprintf(stderr, "bad UBX\n");
			xfree(pl);
			return 1;
		}
		c = cl_get_contact_by_email(ns->contacts, user);
		node = findNode(doc->children, "PSM", 3);
		if(node)
		{
			xmlChar *content = xmlNodeGetContent(node);
			DMSG(stderr, "%s changed his PSM to %s\n", c->nick?c->nick:c->name, content);
			xfree(c->PSM);
			c->PSM = STRDUP((char*)content);
			xmlFree(content);
		}
		xmlFreeDoc(doc);
		xmlCleanupParser();
		xfree(pl);
	}
	return 1;
}/*}}}*/
int _NS_disp_PRP(NS *ns, char *command) /* PRP {{{*/
{
	DMSG(stderr, "PRP: %s\n",command);
	return 1;
}/*}}}*/
int _NS_disp_QRY(NS *ns, char *command) /* confirm of challenge {{{*/
{
	return 1;
}/*}}}*/
int _NS_disp_ILN(NS *ns, char *command) /* initial contract {{{*/
{
	//ILN trid status email@addr.ess networkid nickname clientid dpobj
	char status[4];
	char email[64];
	int nid;
	char nick[512];
	int cid;
	/* FIXME: currently ignore dpobj */
	if(sscanf(command, "%*d %s %s %d %s %d", status, email, &nid, nick, &cid) == 5)
	{
		Contact *c = cl_get_contact_by_email(ns->contacts, email);
		xfree(c->nick);
		c->nick = STRDUP(nick);
		c->status = strtoStatus(status);
		DMSG(stderr, "ILN: %s: %s is now Online\n", c->nick, email);
		DMSG(stderr, "%s\n", command);
	}
	return 1;
}/*}}}*/
int _NS_disp_ADL(NS *ns, char *command) /* add list response {{{*/
{
	return 1;
}/*}}}*/
int _NS_disp_RNG(NS *ns, char* command) /* ringring {{{*/
{
	/* RNG sessid address authtype ticket invitepassport invitename */
	int sesid;
	char server[64];
	int port;
	char ticket[32];
	char email[64];
	char nick[256];
	if(sscanf(command, "%d %[^:]:%d CKI %s %s %s", &sesid, server, &port, ticket, email, nick) == 6)
	{
		Command *c;
		SBNotifyData *data;
		SB *sb = SB_new(ns->account, 0, sesid);
		sb->next = ns->sblist;
		ns->sblist = sb;
		SB_connect(sb, server, port, ticket);
		data = SB_notify_data_new(sb, SB_NOTIFY_NEWSB);
		c = command_new(CMD_SB_NOTIFY, data, SB_notify_data_destroy);
		cmdqueue_push(ns->notifications, c);
	}
	return 1;
}/*}}}*/
int _NS_disp_QNG(NS *ns, char *command) /* end of ping {{{*/
{
	int second;
	DMSG(stderr, "QNG %s\n", command);
	if(sscanf(command, "%d", &second) == 1)
	{
		ns->nextping = time(0)+second;
	}
	return 1;
}/*}}}*/
int _NS_disp_OUT(NS *ns, char *command) /* kicked {{{ */
{
	NS_destroy(ns);
	return 1;
}/* }}} */

INLINE unsigned int endian_swap(unsigned int x)/*{{{*/
{
	x = (x>>24) |
		((x<<8) & 0x00FF0000) |
		((x>>8) & 0x0000FF00) |
		(x<<24);
	return x;
}/*}}}*/
void _NS_calculate_chl(char *input, char *output)/*{{{*/
{
#define FILTER (0x7FFFFFFF)
#define MAGIC (0x0E79A9C1)
	int bigendian = (BYTE_ORDER == BIG_ENDIAN);
	char buf[256];
	int len;
	int i;
	typedef unsigned char uch;
	uch md5hash[17] = {0};
	uint md5values[4];
	int strValLen;
	uint *pVal;
	unsigned long long high, low;
	typedef long long ll;

	/* STEP 1: MD5 */
	len = sprintf(buf, "%s%s", input, PKEY);
	MD5((uch*)buf, len, md5hash);

	pVal = (uint*)md5hash;
	for(i=0;i<4;i++)
	{
		if(bigendian) pVal[i] = endian_swap(pVal[i]);
		md5values[i] = pVal[i] & 0x7FFFFFFF;
	}
	len = sprintf(buf, "%s%s00000000", input, PID) - 8;
	len = len+(8-(len%8));
	buf[len]='\0';
	pVal = (uint*)buf;
	strValLen = (len/4);
#define POS (i*4)
	for(i=0;i<strValLen;i++)
	{
		if(bigendian) *(pVal) = endian_swap(*pVal);
		pVal++;
	}
	pVal = (uint*)buf;
#undef POS
	
	high = low = 0;
	for(i=0;i<strValLen;i+=2)
	{
		long long tmp;
		tmp = (MAGIC * (ll)pVal[i]) % FILTER;
		tmp += high;
		tmp = (md5values[0] * tmp + md5values[1]) % FILTER;

		high = ((ll)pVal[i+1]+tmp) % FILTER;
		high = (md5values[2] * high + md5values[3]) % FILTER;
		low = low + high + tmp;
	}
	high = (high + md5values[1]) % FILTER;
	low = (low + md5values[3]) % FILTER;
	pVal = (uint*)md5hash;
	pVal[0] ^= high;
	pVal[1] ^= low;
	pVal[2] ^= high;
	pVal[3] ^= low;
	if(bigendian)
	{
		for(i=0;i<4;i++)
			pVal[0] = endian_swap(pVal[0]);
	}
	for(i=0;i<16;i++)
		output += sprintf(output, "%02x", md5hash[i]);

#undef FILTER
#undef MAGIC

} /* }}} */
NSNotifyData *NS_notify_data_new(NSNotify notify)/*{{{*/
{
	NSNotifyData *data;
	data = (NSNotifyData*)xmalloc(sizeof(*data));
	data->type = notify;
	return data;
}/*}}}*/
void NS_notify_data_destroy(void *notifydata)/*{{{*/
{
	xfree(notifydata);
}/*}}}*/
