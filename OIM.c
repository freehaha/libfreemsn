#include "OIM.h"
#include <string.h>
#include <libxml/HTMLparser.h>

/* local functions {{{ */
int _oim_loadreq(char **req, char *filename);
int _oim_do_fetch(OIMList *list);
int _oim_parse_maildata(OL *ol, xmlDocPtr doc);

const char oim_getmd_req_header[] = 
"POST /rsi/rsi.asmx HTTP/1.1\r\n"
"Accept: */*\r\n"
"SOAPAction: \"http://www.hotmail.msn.com/ws/2004/09/oim/rsi/GetMetadata\"\r\n"
"Content-Type: text/xml; charset=utf-8\r\n"
"Content-Length: %d\r\n"
"User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 1.1.4322; .NET CLR 2.0.50727; Windows Live Messenger 8.0.0812)\r\n"
"Host: rsi.hotmail.com\r\n"
"Connection: Keep-Alive\r\n"
"Cache-Control: no-cache\r\n\r\n";



const char oim_getmd_req[] = "<?xml version=\"1.0\" encoding=\"utf-8\"?>" /* {{{ */
"<soap:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\""
               " xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\""
               " xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">"
"<soap:Header>"
  "<PassportCookie xmlns=\"http://www.hotmail.msn.com/ws/2004/09/oim/rsi\">"
    "<t>%s</t>"
    "<p>%s</p>"
  "</PassportCookie>"
"</soap:Header>"
"<soap:Body>"
  "<GetMetadata xmlns=\"http://www.hotmail.msn.com/ws/2004/09/oim/rsi\" />"
"</soap:Body>"
"</soap:Envelope>";/*}}}*/

const char oim_getm_req_header[] = 
"POST /rsi/rsi.asmx HTTP/1.1\r\n"
"Accept: */*\r\n"
"SOAPAction: \"http://www.hotmail.msn.com/ws/2004/09/oim/rsi/GetMessage\"\r\n"
"Content-Type: text/xml; charset=utf-8\r\n"
"Content-Length: %d\r\n"
"User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; Messenger (BETA) 8.0.0328)\r\n"
"Host: rsi.hotmail.com\r\n"
"Connection: Keep-Alive\r\n"
"Cache-Control: no-cache\r\n\r\n";

const char oim_getm_req[] = 
"<?xmlversion=\"1.0\"encoding=\"utf-8\"?>"
"<soap:Envelopexmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\"xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">"
"<soap:Header>"
"<PassportCookiexmlns=\"http://www.hotmail.msn.com/ws/2004/09/oim/rsi\">"
"<t>%s</t>"
"<p>%s</p>"
"</PassportCookie>"
"</soap:Header>"
"<soap:Body>"
"<GetMessagexmlns=\"http://www.hotmail.msn.com/ws/2004/09/oim/rsi\">"
"<messageId>%s</messageId>"
"<alsoMarkAsRead>false</alsoMarkAsRead>"
"</GetMessage>"
"</soap:Body>"
"</soap:Envelope>";

/* }}} */

OIMList *oimlist_getlist(const char* oticket)
{
	OL *ol = oimlist_new();
	DMSG(stderr, "ticket str: %s\n", oticket);
	char *tok;
	/* get p and t */
	tok = strstr(oticket, "&p=");
	int inlen = (tok-oticket-2);
	int outlen = inlen * 2;
	ol->t = xmalloc(outlen);
	memset(ol->t, 0, outlen);
	if(htmlEncodeEntities((xmlChar*)ol->t, &outlen, (xmlChar*)oticket+2, &inlen, 0))
	{
		fprintf(stderr, "error encoding entities ...\n");
		xfree(ol->t);
		oimlist_destroy(ol);
		return NULL;
	}
	tok += 3;
	inlen = strlen(tok);
	outlen = inlen * 2;
	ol->p = xmalloc(outlen);
	memset(ol->p, 0, outlen);
	if(htmlEncodeEntities((xmlChar*)ol->p, &outlen, (xmlChar*)tok, &inlen, 0))
	{
		fprintf(stderr, "error encoding entities ...\n");
		xfree(ol->p);
		xfree(ol->t);
		oimlist_destroy(ol);
		return NULL;
	}

	/* send soap request */
	SSLClient *client;	
	client = sslclient_new("rsi.hotmail.com", 443);
	DMSG(stderr, "connecting to OIM server ...\n");
	if(!sslclient_connect(client))
	{
		fprintf(stderr, "error connecting to the oim server\n");
		oimlist_destroy(ol);
		return NULL;
	}
	int rlen, hlen;
	char buf[512];
	char *hdr = xmalloc(sizeof(oim_getmd_req_header) + 20);
	char *req = xmalloc(strlen(oticket) + sizeof(oim_getmd_req));
	DMSG(stderr, "sending OIM mail data request ..\n");
	rlen = sprintf(req, oim_getmd_req, ol->t, ol->p);
	hlen = sprintf(hdr, oim_getmd_req_header, rlen);
	sslclient_send(client, hdr, hlen);
	sslclient_send(client, req, rlen);
	xfree(hdr);
	xfree(req);
	FILE *fp;
	sslclient_recv_header(client, &hdr);
	HTTPHeader *header = http_parse_header(hdr);
	rlen = header->content_length;
	http_header_destroy(header);
	fp = fopen("oim.xml", "w");
	memset(buf, 0, sizeof(buf));
	xmlDocPtr doc;
	xmlParserCtxtPtr ctxt;
	rlen -= (hlen = sslclient_recv(client, buf, sizeof(buf)-1));
	fprintf(fp, buf);
	ctxt = xmlCreatePushParserCtxt(NULL, NULL, buf, hlen, "oim.xml");
	if(ctxt == NULL)
	{
		fprintf(stderr, "failed to create parser context");
		return 0;
	}
	while(rlen > 0)
	{
		memset(buf, 0, sizeof(buf));
		rlen -= (hlen=sslclient_recv(client, buf, sizeof(buf)-1));
		xmlParseChunk(ctxt, buf, hlen, 0);
		fprintf(fp, buf);
	}	
	fflush(fp);
	fclose(fp);

	xmlParseChunk(ctxt, buf, 0, 1);
	sslclient_destroy(client, FALSE);
	client = NULL;
	doc = ctxt->myDoc;
	hlen = ctxt->wellFormed;
	if(hlen)
	{
		_oim_parse_maildata(ol, doc);
	}
	xmlFreeParserCtxt(ctxt);
	xmlFreeDoc(doc);
	xmlCleanupParser();
	DMSG(stderr, "contact xml parsing done: %s\n", hlen?"good":"malformed");
	return ol;
}
OIMList *oimlist_new()
{
	OL *ol = xmalloc(sizeof(OL));
	memset(ol, 0, sizeof(OL));
	return ol;
}
void oimlist_destroy(OIMList *olist)
{
	OIM *o;
	while(olist->list)
	{
		o = olist->list->next;
		oim_destroy(olist->list);
		olist->list = o;
	}
	xfree(olist->t);
	xfree(olist->p);
	xfree(olist);
}
void oimlist_append(OIMList *olist, OIM *oim)
{
	if(!oim) return;
	oim->next = olist->list;
	olist->list = oim;
	olist->count++;
}

char *oim_fetch(OIM *o)
{
	if(o->text) return o->text;
	/* TODO: fetch oim */
	return o->text;
}
OIM *oim_new(const char *email, const char *nick, const char *id)
{
	OIM *o = xmalloc(sizeof(*o));
	o->from = strdup(email);
	o->nick = strdup(nick);
	o->id = strdup(id);
	o->text = NULL;
	return o;
}
void oim_destroy(OIM *oim)
{
	xfree(oim->from);
	xfree(oim->nick);
	xfree(oim->id);
	xfree(oim->text);
	xfree(oim);
}

int _oim_parse_maildata(OL *ol, xmlDocPtr doc)
{
	xmlNodePtr node, md, m;
	node = xmlDocGetRootElement(doc);
	md = findNode(doc->children, "MD", 4); 
	xmlNodePtr Email, Id, Nick;
	xmlChar *cEmail, *cId, *cNick;
	OIM *oim;
	for(m=md->children;m;m=m->next)
	{
		if(!m->name || m->name[0] != 'M') break;
		Email = findNode(m->children, "E", 2);
		Id = findNode(m->children, "I", 2);
		Nick = findNode(m->children, "N", 2);
		cEmail = xmlNodeGetContent(Email);
		cId = xmlNodeGetContent(Id);
		cNick = xmlNodeGetContent(Nick);
		char *tmp = xmalloc(strlen((char*)cNick));
		char *nick;
		if(sscanf((char*)cNick, "=?%*[^?]?B?%[^? ]?=", tmp) == 1)
		{
			nick = (char*)unbase64((unsigned char*)tmp, strlen(tmp));
		}

		oim = oim_new((char*)cEmail, (char*)nick, (char*)cId);
		oimlist_append(ol, oim);

		xfree(nick);
		xfree(tmp);
		xmlFree(cEmail);
		xmlFree(cId);
		xmlFree(cNick);
	}
	return 0;
}
