#include "ContactList.h"
#include "xmalloc.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/HTMLparser.h>
#include <openssl/md5.h>

const char *ms_soapreqheader = "POST /abservice/SharingService.asmx HTTP/1.1\r\n"
"SOAPAction: http://www.msn.com/webservices/AddressBook/FindMembership\r\n"
"Content-Type: text/xml; charset=utf-8\r\n"
"Host: contacts.msn.com\r\n"
"Content-Length: ";

const char *ab_soapreqheader = "POST /abservice/abservice.asmx HTTP/1.1\r\n"
"SOAPAction: http://www.msn.com/webservices/AddressBook/ABFindAll\r\n"
"Content-Type: text/xml; charset=utf-8\r\n"
"Host: contacts.msn.com\r\n"
"Content-Length: ";

int _cl_load_soapreq_ms(CL *cl, const char *filename, const char *lastchange, char **req);
int _cl_do_soapreq_ms(CL *cl);
int _cl_do_soapreq_ab(CL *cl);
int _cl_parse_contacts(CL *cl, xmlDocPtr doc);
void _cl_contact_hashdumper(void *payload, void *data, xmlChar *domain);
void _cl_free_table(void *payload, xmlChar *name);
void _cl_sort_contacts(CL *cl);
void cl_save(CL *cl, const char *filename);

ContactList *cl_new(Account *ac, const char *ticket)/*{{{*/
{
	CL *cl;
	cl = xmalloc(sizeof(CL));
	memset(cl, 0, sizeof(CL));
	cl->account = ac;
	cl->ticket = xmalloc(strlen(ticket));
	strcpy(cl->ticket, ticket);
	cl->table = xmlHashCreate(30);
	cl->emailtable = xmlHashCreate(250);

	return cl;
}/*}}}*/
void _cl_free_table(void *payload, xmlChar *name)/*{{{*/
{
}/*}}}*/
void _cl_free_emailtable(void *payload, xmlChar *name)/*{{{*/
{
}/*}}}*/
void cl_destroy(CL *cl)/*{{{*/
{
	char filename[64];
	MD5((unsigned char*)cl->account->username, strlen(cl->account->username), (unsigned char*)filename);
	sprintf(filename, "%x%x.xml", (unsigned char)filename[0], (unsigned char)filename[1]);
	cl_save(cl, filename);
	xmlHashFree(cl->table, _cl_free_table);
	xmlHashFree(cl->emailtable, _cl_free_emailtable);
	Contact *tmp;
	char *dn = NULL;
	while(cl->list)
	{
		if(cl->list->domain != dn)
		{
			dn = cl->list->domain;
			xfree(cl->list->domain);
		}
		tmp = cl->list->g_next;
		contact_destroy(cl->list);
		cl->list = tmp;
	}
	xfree(cl->lastchange);
	xfree(cl->ticket);
	xfree(cl);
}/*}}}*/
int cl_retrive(CL *cl)/*{{{*/
{
	int ret;
	ret = _cl_do_soapreq_ms(cl);
	//_cl_do_soapreq_ab(cl);
	return ret;
}/*}}}*/
int cl_append_contact(CL *cl, Contact *c, const char *name, const char *domain)/*{{{*/
{
	Contact *list;
	char email[64];
	sprintf(email, "%s@%s", name, domain);

	list = xmlHashLookup(cl->emailtable, (xmlChar*)email);
	if(list) /* already exists */
	{
		/* delete from domain list */
		list = xmlHashLookup(cl->table, (xmlChar*)domain);
		if(!strcmp(list->name, name))
		{
			xmlHashUpdateEntry(cl->table, (xmlChar*)domain, list->d_next, NULL);
		}
		else
		{
			Contact *prev;
			for(prev=list;prev->d_next;prev=prev->d_next)
			{
				if(!strcmp(prev->d_next->name, name))
				{
					prev->d_next = prev->d_next->d_next;
					break;
				}
			}
		}

		/* delete from global list */
		if(!strcmp(name, cl->list->name))
		{
			cl->list = cl->list->g_next;
		}
		else
		{
			Contact *prev;
			for(prev=cl->list;prev->g_next;prev=prev->g_next)
			{
				if(!strcmp(prev->g_next->name, name))
				{
					prev->g_next = prev->g_next->g_next;
					break;
				}
			}
		}
		list = xmlHashLookup(cl->emailtable, (xmlChar*)email);
		contact_destroy(list);
	}
	else
	{
		list = xmlHashLookup(cl->table, (xmlChar*)domain);
		c->d_next = list;
		xmlHashUpdateEntry(cl->table, (xmlChar*)domain, c, NULL);
		c->g_next = cl->list;
		cl->list = c;
	}
	xmlHashUpdateEntry(cl->emailtable, (xmlChar*)email, c, NULL);
	if(! cl->flag & CL_INITLIST) /* reorder when new contact added */
		_cl_sort_contacts(cl);
	return 1;
}/*}}}*/
Contact *cl_get_contact_by_email(CL *cl, const char *email)/*{{{*/
{
	return xmlHashLookup(cl->emailtable, (xmlChar*)email);
}/*}}}*/
int _cl_parse_contacts(CL *cl, xmlDocPtr doc)/*{{{*/
{
	xmlNodePtr node;
	node = xmlDocGetRootElement(doc);
	xmlNodePtr services;
	xmlNodePtr service;
	int count = 0;
	services = findNode(node, "Services", 5);
	if(!services)
	{
		fprintf(stderr, "cannot find <Services>\n"); 
		goto cleanup;
	}
	cl->flag |= CL_INITLIST;
	for(service=services->children;service;service=service->next)/*{{{*/
	{
		xmlNodePtr info = findNode(service->children, "Info",1);
		if(!info)
		{
			fprintf(stderr, "cannot find <Info> in <Service>\n");
			count = 0;
			goto cleanup;
		}

		xmlNodePtr type = findNode(info->children, "Type", 3);
		if(!type || !type->children)
		{
			fprintf(stderr, "NULL Type\n");
			count = 0;
			goto cleanup;
		}
		if(xmlStrEqual(type->children->content, (xmlChar*)"Messenger"))
			break;
	}/*}}}*/
	/* parsing lists {{{*/
	if(service)
	{
		xmlNodePtr memberships = findNode(service->children, "Memberships", 1);
		xmlNodePtr ms;
		xmlNodePtr role;
		xmlNodePtr members, member;
		xmlNodePtr pname;
		xmlNodePtr type;
		xmlNodePtr lastchange;
		xmlChar *content;
		lastchange = findNode(service->children, "LastChange", 1);
		content = xmlNodeGetContent(lastchange);
		cl->lastchange = strdup((char*)content);
		DMSG(stderr, "Contact: lastchange = %s\n", cl->lastchange);
		if(!memberships)
		{
			fprintf(stderr, "NULL membership\n");
			count = 0;
			goto cleanup;
		}
		for(ms=memberships->children;ms;ms=ms->next)
		{
			if(!ms->children) continue;
			role = findNode(ms->children, "MemberRole", 1);
			if(!role)
			{
				fprintf(stderr, "Null role\n");
				count = 0;
				goto cleanup;
			}
			members = findNode(role, "Members", 1);
			if(!members) continue;
			int flag = 0;

			if(xmlStrEqual(role->children->content, (xmlChar*)"Allow"))
				flag = 3;
			else if(xmlStrEqual(role->children->content, (xmlChar*)"Block"))
				flag = 4;
			else
				continue;

			int ctype = 1;
			for(member=members->children;member;member=member->next)
			{
				type = findNode(member->children, "Type", 1);
				content = xmlNodeGetContent(type);
				if(!content)
				{
					fprintf(stderr, "NULL Type\n");
					continue;
				}
				Contact *c;
				if(xmlStrEqual(content, (xmlChar*)"Passport"))
				{
					pname = findNode(member->children, "PassportName", 1);
					ctype = 1;
				}
				else if(xmlStrEqual(content, (xmlChar*)"Email"))
				{
					pname = findNode(member->children, "Email", 1);
					ctype = 32;
				}
				else
					continue;

				xmlFree(content);
				if(!pname) 
				{
					fprintf(stderr, "NULL PassportName or Email\n");
					continue;
				}
				content = xmlNodeGetContent(pname);
				if(content)
				{
					char name[32];
					char domain[32];
					if(sscanf((char*)content, "%[^@]@%s", name, domain) != 2)
					{
						fprintf(stderr, "parse contact: malformed email: %s\n", content);
						continue;
					}
					c = contact_new((char*)content);
					c->name = strdup(name);
					c->type = ctype;
					c->status = NA;
					c->inlist |= flag;
					c->domain = NULL; /* should be filled during sort */
					cl_append_contact(cl, c, name, domain);
					xmlFree(content);
					count++;
				}
			}
		}
	}/*}}}*/
	DMSG(stderr, "parsed contact count: %d\n", count);

cleanup:
	cl->flag &= ~CL_INITLIST;
	return count;

}/*}}}*/
int _cl_do_soapreq_ab(CL *cl)/*{{{*/
{
	TCPClient *client;
	client = tcpclient_new("contacts.msn.com", 80);
	char *req = NULL;
	char *header;
	char buf[512];
	int ret, len;
	ret = _cl_load_soapreq_ms(cl, ABXML, cl->ablastchange, &req);
	if(ret)
	{
		tcpclient_connect(client);
		header = xmalloc(strlen(ab_soapreqheader) + 32);
		DMSG(stderr, "sending ab request\n");
		len = sprintf(header, "%s%d\r\n\r\n", ab_soapreqheader, ret);
		if(tcpclient_send(client, header, len) <= 0) goto cleanup;
		if(tcpclient_send(client, req, ret) <= 0) goto cleanup;

		char *ptr = NULL;
		len = tcpclient_recv_header(client, &ptr); /* header */
		if(ptr)
		{
			DMSG(stderr, "AB response header:\n%s", ptr);
			HTTPHeader *header = http_parse_header(ptr);
			len = header->content_length;
			DMSG(stderr, "Length: %d\n", len);
			http_header_destroy(header);
			memset(buf, 0, sizeof(buf));
			xmlDocPtr doc;
			xmlParserCtxtPtr ctxt;
			FILE *fp = fopen("addressbook.xml", "w");
			fprintf(fp, buf);
			len -= (ret = tcpclient_recv(client, buf, sizeof(buf)-1));
			ctxt = xmlCreatePushParserCtxt(NULL, NULL, buf, ret, "addressbook.xml");
			fprintf(fp, buf);
			if(ctxt == NULL)
			{
				fprintf(stderr, "failed to create parser context");
				return 0;
			}

			while(len > 0)
			{
				memset(buf, 0, sizeof(buf));
				len -= (ret=tcpclient_recv(client, buf, sizeof(buf)-1));
				fprintf(fp, buf);
				xmlParseChunk(ctxt, buf, ret, 0);
			}
			fclose(fp);
			xmlParseChunk(ctxt, buf, 0, 1);
			tcpclient_destroy(client);
			client = NULL;
			doc = ctxt->myDoc;
			len = ctxt->wellFormed;
			xmlFreeParserCtxt(ctxt);
			//count += _cl_parse_contacts(cl, doc);
			xmlFreeDoc(doc);
			xmlCleanupParser();
			DMSG(stderr, "addressbook xml parsing done: %s\n", len?"good":"malformed");
			xfree(ptr);
		}
		else
		{
			DMSG(stderr, "ab: no header found\n\r");
		}
	}
	else
	{
		fprintf(stderr, "failed to load abreq\n");
	}
cleanup:
	xfree(header);
	return 0;
}/*}}}*/
int cl_load_contacts(CL *cl, const char* file)/*{{{*/
{
	int ret;
	xmlDocPtr doc;
	doc = xmlReadFile(file, NULL, 0);
	if (doc == NULL)
	{
		fprintf(stderr, "Failed to parse %s\n", file);
		return 0;
	}
	ret = 0;
	xmlNodePtr root;
	xmlNodePtr contact;
	xmlNodePtr node;
	xmlChar *content;
	root = xmlDocGetRootElement(doc);
	contact = findNode(root->children, "contact", 3);
#define READSTR(dst,elem)  node = findNode(contact->children, elem, 1); \
	content = xmlNodeGetContent(node); \
	dst = strdup((char*)content); \
	xmlFree(content)

#define READINT(dst, elem) node = findNode(contact->children, elem, 1); \
		content = xmlNodeGetContent(node); \
		dst = atoi((char*)content); \
		xmlFree(content)
	for(;contact;contact=contact->next)
	{
		node = findNode(contact->children, "nick", 1);
		content = xmlNodeGetContent(node);
		Contact *c = contact_new((char*)content);
		xmlFree(content);
		READSTR(c->name, "name");
		READSTR(c->PSM, "PSM");
		READINT(c->inlist, "inlist");
		READINT(c->type, "type");
		c->status = NA;

		node = findNode(contact->children, "domain", 1);
		content = xmlNodeGetContent(node);
		c->domain = NULL; /* should be filled during sort */
		cl_append_contact(cl, c, c->name, (char*)content);
		xmlFree(content);
		ret++;
	}
	node = findNode(root->children, "lastchange", 3);
	if(node)
	{
		content = xmlNodeGetContent(node);
		cl->lastchange = strdup((char*)content);
		xmlFree(content);
	}
	xmlFreeDoc(doc);
	return ret;
}/*}}}*/
void cl_save(CL *cl, const char *filename)/*{{{*/
{
	FILE *fp = fopen(filename, "w");
	if(!fp) return;
	fprintf(fp, "<?xml version=\"1.0\" encoding=\"utf-8\"?>");
	fprintf(fp, "<contactinfo>");
	fprintf(fp, "<contacts>");
	Contact *c;
	for(c=cl->list;c;c=c->g_next)
	{
		fprintf(fp, "<contact>");
		fprintf(fp, "<name>%s</name>", c->name);
		fprintf(fp, "<nick>%s</nick>", c->nick);
		fprintf(fp, "<PSM>%s</PSM>", c->PSM?c->PSM:"");
		fprintf(fp, "<domain>%s</domain>", c->domain);
		fprintf(fp, "<inlist>%d</inlist>", c->inlist);
		fprintf(fp, "<type>%d</type>", c->type);
		fprintf(fp, "</contact>");
	}
	fprintf(fp, "</contacts>");
	if(cl->lastchange)
		fprintf(fp,"<lastchange>%s</lastchange>", cl->lastchange);
	if(cl->ablastchange)
		fprintf(fp,"<ablastchange>%s</ablastchange>", cl->ablastchange);
	fprintf(fp, "</contactinfo>");
	fflush(fp);
	fclose(fp);
}/*}}}*/
int _cl_do_soapreq_ms(CL *cl)/*{{{*/
{
	SSLClient *client;
	int ret;
	int len;
	int count = 0;
	char *req = NULL;
	char *header;
	header = xmalloc(strlen(ms_soapreqheader) + 32);

	client = sslclient_new(DEFAULTSERVER, 443);
	if(!sslclient_connect(client))
		return 0;
	/* connected */
	char contactfile[64];
	MD5((unsigned char*)cl->account->username, strlen(cl->account->username), (unsigned char*)contactfile);
	sprintf(contactfile, "%x%x.xml", (unsigned char)contactfile[0], (unsigned char)contactfile[1]);
	FILE *fp;
	if((fp=fopen(contactfile, "r")))
	{
		DMSG(stderr, "loading cached contacts...\n");
		if((count = cl_load_contacts(cl, contactfile)))
			ret = _cl_load_soapreq_ms(cl, CONXML, cl->lastchange, &req);
		else
			ret = _cl_load_soapreq_ms(cl, CONXML_FULL, cl->lastchange, &req);
		DMSG(stderr, "%d contacts loaded from cache...\n", count);

		fclose(fp);
	}
	else
		ret = _cl_load_soapreq_ms(cl, CONXML_FULL, cl->lastchange, &req);
	if(ret)
	{
		DMSG(stderr, "sending cl request\n");
		/* send request */
		len = sprintf(header, "%s%d\r\n\r\n", ms_soapreqheader, ret);
		if(sslclient_send(client, header, len) <= 0) goto cleanup;
		if(sslclient_send(client, req, ret) <= 0) goto cleanup;

		DMSG(stderr, "getting cl response\n");
		/* get response */
		char buf[512] = {0};
		char *ptr = NULL;
		DMSG(stderr, "HEADER:\n");
		len = sslclient_recv_header(client, &ptr); /* header */
		if(ptr)
		{
			DMSG(stderr, ptr);
			HTTPHeader *header = http_parse_header(ptr);
			len = header->content_length;
			DMSG(stderr, "content length: %d\n", len);
			http_header_destroy(header);
			xfree(ptr);
		}
		else
		{
			DMSG(stderr, "no header found\n\r");
		}

		memset(buf, 0, sizeof(buf));
		xmlDocPtr doc;
		xmlParserCtxtPtr ctxt;
		FILE *fp = fopen("contacts.xml", "w");
		len -= (ret = sslclient_recv(client, buf, sizeof(buf)-1));
		ctxt = xmlCreatePushParserCtxt(NULL, NULL, buf, ret, "contacts.xml");
		DMSG(stderr, "RESPONSE:\n");
		fprintf(fp, buf);
		if(ctxt == NULL)
		{
			fprintf(stderr, "failed to create parser context");
			return 0;
		}

		while(len > 0)
		{
			memset(buf, 0, sizeof(buf));
			len -= (ret=sslclient_recv(client, buf, sizeof(buf)-1));
			fprintf(fp, buf);
			xmlParseChunk(ctxt, buf, ret, 0);
		}
		fclose(fp);
		xmlParseChunk(ctxt, buf, 0, 1);
		sslclient_destroy(client, FALSE);
		client = NULL;
		doc = ctxt->myDoc;
		len = ctxt->wellFormed;
		xmlFreeParserCtxt(ctxt);
		count += _cl_parse_contacts(cl, doc);
		xmlFreeDoc(doc);
		xmlCleanupParser();
		DMSG(stderr, "contact xml parsing done: %s\n", len?"good":"malformed");
	}
	_cl_sort_contacts(cl);
	cl_save(cl, contactfile);
cleanup:
	xfree(req);
	xfree(header);
	return count;
}/*}}}*/
int _cl_load_soapreq_ms(CL *cl, const char *filename, const char *lastchange, char **req)/*{{{*/
{
	FILE *fp;
	char *buf;
	char line[512];
	int size;
	int ret;
	int len;
	fp = fopen(filename, "r");
	if(!fp)
	{
		fprintf(stderr, "error opening file %s\n", filename);
	   	return 0;
	}
	xfree(*req);
	size = 1024;
	*req = xmalloc(size);
	if(*req == NULL)
	{
		fprintf(stderr, "load_soapreq: bad xmalloc\n");
		fclose(fp);
		return 0;
	}
	memset(*req, 0, size);
	buf = *req;
	ret = 0;
	len = strlen(cl->ticket);
	ret = len*2;
	char *encticket = xmalloc(ret);
	memset(encticket, 0, ret);
	htmlEncodeEntities((unsigned char*)encticket, &ret, (unsigned char*)cl->ticket, &len, 0);
	ret = 0;
	char flag = 0;
	while(fgets(line, 512, fp))
	{
		if(!strncmp(line, "###TICKET", 9))
		{
			flag = 1;
			len = strlen(encticket)+32;
		}
		else if(!strncmp(line, "###DATE", 7))
		{
			flag = 2;
			len = strlen(cl->lastchange)+128;
		}
		else
			len = strlen(line);

		if(ret + len > size)
		{
			size *= 2;
			*req = xrealloc(*req, size);
			buf = *req + strlen(*req);
		}

		if(flag == 1)
		{
			buf += (len = sprintf(buf,"<TicketToken>%s</TicketToken>\r\n", encticket));
			xfree(encticket);
			flag = 0;
		}
		else if (flag == 2)
		{

			buf += (len = sprintf(buf,"<lastChange xmlns=\"http://www.msn.com/webservices/AddressBook\">"
						"%s</lastChange>", cl->lastchange));
			xfree(encticket);
			flag = 0;
		}
		else
		{
			buf +=  sprintf(buf, "%s", line);
		}
		ret += len;
	}
	
	fclose(fp);
	return ret;
}/*}}}*/
/* _cl_contact_sorter: re-construct the contact list in domain order {{{*/
void _cl_contact_sorter(void *payload, void *data, xmlChar *domain)
{
	Contact *c;
	CL *cl = data;
	char *dn; 

	/* if it is sorted before, that is, the domain is filled
	 * we have to free the domain names and reset then.
	 * this should happened ONLY once per scan or we're in trouble
	 */
	if(cl->flag & CL_SORTED)
	{
		dn = NULL;
		for(c=cl->list;c;c=c->g_next)
		{
			if(c->domain && c->domain != dn)
			{
				dn = c->domain; /* keep the address for identification*/
				xfree(c->domain);
				c->domain = NULL;
			}
		}
		cl->flag &= ~CL_SORTED;
	}
	/* put them back to list, and fill the domain */
	dn = strdup((char*)domain);
	for(c=payload;c;c=c->d_next)
	{
		c->domain = dn;
		c->g_next = cl->list;
		cl->list = c;
	}
}/*}}}*/
void _cl_sort_contacts(CL *cl)/*{{{*/
{
	cl->list = NULL;
	xmlHashScan(cl->table, _cl_contact_sorter, cl);	
	cl->flag |= CL_SORTED;
}/*}}}*/
char *cl_generate_ADL_list(CL *cl, int *count, int *sz)/*{{{*/
{
	static Contact *leftoff = NULL;
	char *list = NULL;
	char *plist;
	Contact *c;
	char *dn;
	int size = 512;
	int len = 0;
	int cnt = 0;
	int ret;
	char buf[128] = {0};

	if(!cl->list) /* empty list */
	{
		*count = 0;
		return NULL;
	}

	if(!leftoff) _cl_sort_contacts(cl);

	list = xmalloc(size);
	list[0] = '\0';
	plist = list;

	if(!leftoff)
		leftoff = cl->list;

	c = leftoff;

	ret = sprintf(buf, "<ml l=\"1\">");
	strcat(plist, buf);
	plist += ret;
	len+=ret;
	while(c && cnt < 140)
	{
		dn = c->domain;
		ret = sprintf(buf, "<d n=\"%s\">", dn);
		if(len + ret > size)
		{
			size += 512;
			list = xrealloc(list, size);
			plist = list+len;
		}
		strcat(plist, buf);
		len += ret;
		plist += ret;
		for(;c;c=c->g_next)
		{
			if(dn != c->domain)
				break;

			ret = sprintf(buf, "<c n=\"%s\" l=\"%d\" t=\"%d\" />", c->name, c->inlist, c->type);
			if(len + ret > size)
			{
				size += 512;
				list = xrealloc(list, size);
				plist = list+len;
			}
			strcat(plist, buf);
			len += ret;
			plist += ret;
			cnt++;
			if(cnt >= 140)
			{
				leftoff = c->g_next;
				break;
			}
		}
		if(len + 5 > size)
		{
			size += 16;
			list = xrealloc(list, size);
			plist = list+len;
		}
		len += sprintf(plist, "</d>");
		plist = list+len;
	}
	if(len + 5 > size)
	{
		size += 16;
		list = xrealloc(list, size);
		plist = list+len;
	}
	ret = sprintf(buf, "</ml>");
	strcat(plist, buf);
	len += ret;
	
	*sz = len;
	*count = cnt;
	return list;
}/*}}}*/
Contact *contact_new(const char *nick)/*{{{*/
{
	Contact *c;
	c = xmalloc(sizeof(Contact));
	memset(c, 0, sizeof(Contact));
	c->PSM = NULL;
	c->type = 0;
	c->inlist = 0;
	c->status = NA;
	if(nick && *nick)
		c->nick = strdup(nick);

	return c;
}/*}}}*/
void contact_destroy(Contact *c)/*{{{*/
{
	xfree(c->name);
	xfree(c->nick);
	xfree(c->PSM);
	xfree(c);
}/*}}}*/
Status strtoStatus(const char* status)/*{{{*/
{
	if(!strncmp(status, "NLN", 3)) return NLN;
	else if(!strncmp(status, "BSY", 3)) return BSY;
	else if(!strncmp(status, "BRB", 3)) return BRB;
	else if(!strncmp(status, "AWY", 3)) return AWY;
	else if(!strncmp(status, "IDL", 3)) return IDL;
	else if(!strncmp(status, "PHN", 3)) return PHN;
	else if(!strncmp(status, "LUN", 3)) return LUN;
	else if(!strncmp(status, "HDN", 3)) return HDN;
	else return NA;
}/*}}}*/
