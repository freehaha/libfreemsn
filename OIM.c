#include "OIM.h"
#include <string.h>
#include <libxml/HTMLparser.h>

/* local functions {{{ */
int _oim_loadreq(char **req, char *filename);
int _oim_do_fetch(OIMList *list);
int _oim_parse_maildata(OL *ol, xmlDocPtr doc);
int _oim_parse_message(OIM *o, xmlDocPtr doc);

const char oim_getmd_req_header[] = /*{{{*/
"POST /rsi/rsi.asmx HTTP/1.1\r\n"
"Accept: */*\r\n"
"SOAPAction: \"http://www.hotmail.msn.com/ws/2004/09/oim/rsi/GetMetadata\"\r\n"
"Content-Type: text/xml; charset=utf-8\r\n"
"Content-Length: %d\r\n"
"User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 1.1.4322; .NET CLR 2.0.50727; Windows Live Messenger 8.0.0812)\r\n"
"Host: rsi.hotmail.com\r\n"
"Connection: Keep-Alive\r\n"
"Cache-Control: no-cache\r\n\r\n";/*}}}*/
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
const char oim_getm_req_header[] = /* {{{*/
"POST /rsi/rsi.asmx HTTP/1.1\r\n"
"Accept: */*\r\n"
"SOAPAction: \"http://www.hotmail.msn.com/ws/2004/09/oim/rsi/GetMessage\"\r\n"
"Content-Type: text/xml; charset=utf-8\r\n"
"Content-Length: %d\r\n"
"User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; Messenger (BETA) 8.0.0328)\r\n"
"Host: rsi.hotmail.com\r\n"
"Connection: Keep-Alive\r\n"
"Cache-Control: no-cache\r\n\r\n";/*}}}*/
const char oim_getm_req[] = /*{{{*/
"<?xml version=\"1.0\" encoding=\"utf-8\"?>"
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
"<GetMessage xmlns=\"http://www.hotmail.msn.com/ws/2004/09/oim/rsi\">"
"<messageId>%s</messageId>"
"<alsoMarkAsRead>false</alsoMarkAsRead>"
"</GetMessage>"
"</soap:Body>"
"</soap:Envelope>";
/* }}} */
const char oim_delm_req_header[]=/*{{{*/
"POST /rsi/rsi.asmx HTTP/1.1\r\n"
"Accept: */*\r\n"
"SOAPAction: \"http://www.hotmail.msn.com/ws/2004/09/oim/rsi/DeleteMessages\"\r\n"
"Content-Type: text/xml; charset=utf-8\r\n"
"Content-Length: %d\r\n"
"User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; Messenger (BETA) 8.0.0328)\r\n"
"Host: rsi.hotmail.com\r\n"
"Connection: Keep-Alive\r\n"
"Cache-Control: no-cache\r\n\r\n";/*}}}*/
const char oim_delm_req[] = /*{{{*/
"<?xml version=\"1.0\" encoding=\"utf-8\"?>"
"<soap:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">"
  "<soap:Header>"
    "<PassportCookie xmlns=\"http://www.hotmail.msn.com/ws/2004/09/oim/rsi\">"
      "<t>%s</t>"
      "<p>%s</p>"
    "</PassportCookie>"
  "</soap:Header>"
  "<soap:Body>"
    "<DeleteMessages xmlns=\"http://www.hotmail.msn.com/ws/2004/09/oim/rsi\">"
      "<messageIds>"
        "<messageId>%s</messageId>"
      "</messageIds>"
    "</DeleteMessages>"
  "</soap:Body>"
"</soap:Envelope>";/*}}}*/
/* }}} */
OIMList *oimlist_getlist(const char* oticket)/*{{{*/
{
	OL *ol = oimlist_new();
	char *tok;
	/* get p and t {{{*/
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
	}/*}}}*/
	/* send soap request {{{*/
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
	/* }}} */
	/* response from server {{{ */
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
	/* }}} */
	return ol;
}/*}}}*/
OIMList *oimlist_new()/*{{{*/
{
	OL *ol = xmalloc(sizeof(OL));
	memset(ol, 0, sizeof(OL));
	return ol;
}/*}}}*/
void oimlist_destroy(OIMList *olist)/*{{{*/
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
}/*}}}*/
void oimlist_append(OIMList *olist, OIM *oim)/*{{{*/
{
	if(!oim) return;
	oim->next = olist->list;
	olist->list = oim;
	olist->count++;
}/*}}}*/
char *oim_fetch(OL *ol, OIM *o)/*{{{*/
{
	if(o->text) return o->text;
	/* TODO: fetch oim */
	SSLClient *client;
	client = sslclient_new("rsi.hotmail.com", 443);
	sslclient_connect(client);
	char *hdr, *req;
	int hlen, rlen;
	char buf[512];
	xmlDocPtr doc;
	xmlParserCtxtPtr ctxt;
	hdr = xmalloc(sizeof(oim_getm_req_header)+32);
	req = xmalloc(sizeof(oim_getm_req)+ strlen(ol->t) + strlen(ol->p) + strlen(o->id) + 64);
	rlen = sprintf(req, oim_getm_req, ol->t, ol->p, o->id);
	hlen = sprintf(hdr, oim_getm_req_header, rlen);
	DMSG(stderr, "sending oim fetching request...\n");
	hlen = sslclient_send(client, hdr, hlen);
	rlen = sslclient_send(client, req, rlen);
	xfree(hdr);
	xfree(req);
	DMSG(stderr, "parsing response header... \n");
	sslclient_recv_header(client, &hdr);
	HTTPHeader *header = http_parse_header(hdr);
	hlen = header->content_length;
	http_header_destroy(header);
	DMSG(stderr, "parsing response body ... \n");
	memset(buf, 0, sizeof(buf));
	hlen -= (rlen = sslclient_recv(client, buf, sizeof(buf)-1));
	ctxt = xmlCreatePushParserCtxt(NULL, NULL, buf, rlen, "oim.xml");
	if(ctxt == NULL)
	{
		fprintf(stderr, "failed to create parser context");
		return 0;
	}
	while(hlen > 0)
	{
		memset(buf, 0, sizeof(buf));
		hlen -= (rlen = sslclient_recv(client, buf, sizeof(buf)-1));
		xmlParseChunk(ctxt, buf, rlen, 0);
	}
	/* end of parsing */
	xmlParseChunk(ctxt, buf, 0, 1);
	sslclient_destroy(client, FALSE);
	client = NULL;
	doc = ctxt->myDoc;
	if(ctxt->wellFormed)
	{
		DMSG(stderr, "parseing message...\n");
		_oim_parse_message(o, doc);
	}

	xmlFreeParserCtxt(ctxt);
	xmlFreeDoc(doc);
	xmlCleanupParser();
	return o->text;
}/*}}}*/
OIM *oim_new(const char *email, const char *nick, const char *id)/*{{{*/
{
	OIM *o = xmalloc(sizeof(*o));
	o->from = strdup(email);
	o->nick = strdup(nick);
	o->id = strdup(id);
	o->text = NULL;
	return o;
}/*}}}*/
void oim_destroy(OIM *oim)/*{{{*/
{
	xfree(oim->from);
	xfree(oim->nick);
	xfree(oim->id);
	xfree(oim->text);
	xfree(oim);
}/*}}}*/
int _oim_parse_maildata(OL *ol, xmlDocPtr doc)/*{{{*/
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
}/*}}}*/
int _oim_parse_message(OIM *o, xmlDocPtr doc)/*{{{*/
{
	xmlNodePtr node = xmlDocGetRootElement(doc);
	node = findNode(node->children, "GetMessageResult", 3);
	char line[256];
	int size;
	if(!node) return 0;
	char *content = (char*)xmlNodeGetContent(node);
	const char *ptr = content;
	int sid = 0;
	while(ptr && *ptr)
	{
		size = 256;
		ptr = get_one_line(ptr, line, &size);	
		if(line[0] == '\0') /* header ends here */
		{
			break;
		}
		else if(sscanf(line, "X-OIM-Sequence-Num: %d", &sid) == 1)
			o->sid = sid;
	}
	if(!ptr || !*ptr) fprintf(stderr, "OIM: no oim content!\n");
	else
	{
		o->text = unbase64((unsigned char*)ptr, strlen(ptr));
		DMSG(stderr, "got oim: %s\n", o->text);
	}
	xmlFree((xmlChar*)content);
	return 0;
}/*}}}*/
void oim_delete(OL *ol, OIM *o)/*{{{*/
{
	char *hdr, *req;
	int hlen, rlen;
	char buf[512];
	SSLClient *client;
	hdr = xmalloc(sizeof(oim_delm_req_header) + 32);
	req = xmalloc(sizeof(oim_delm_req)+strlen(ol->t)+strlen(ol->p)+strlen(o->id)+32);

	rlen = sprintf(req, oim_delm_req, ol->t, ol->p, o->id);
	hlen = sprintf(hdr, oim_delm_req_header, rlen);

	client = sslclient_new("rsi.hotmail.com", 443);
	sslclient_connect(client);
	DMSG(stderr, "sending oim fetching request...\n");
	hlen = sslclient_send(client, hdr, hlen);
	rlen = sslclient_send(client, req, rlen);
	xfree(hdr);
	xfree(req);
	DMSG(stderr, "parsing response header... \n");
	sslclient_recv_header(client, &hdr);
	HTTPHeader *header = http_parse_header(hdr);
	hlen = header->content_length;
	DMSG(stderr, "return code: %d\n", header->code);
	if(header->code == 200) /* success */
	{
		DMSG(stderr, "OIM deleted\n");
	}
	http_header_destroy(header);
	while(hlen > 0)
	{
		memset(buf, 0, sizeof(buf));
		hlen -= (rlen = sslclient_recv(client, buf, sizeof(buf)-1));
	}
}/*}}}*/
void oimlist_remove(OL *ol, OIM *o)/*{{{*/
{
	OIM *prev;
	if(ol->list == o)
	{
		ol->list = o->next;
	}
	else
	{
		for(prev=ol->list;prev->next;prev=prev->next)
		{
			if(prev->next == o)
			{
				prev->next = o->next;
				break;
			}
		}
	}
	oim_destroy(o);
}/*}}}*/
