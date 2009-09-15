#ifndef CONTACTSERVICE_8J4XHV59
#define CONTACTSERVICE_8J4XHV59

#include "SSLClient.h"
#include "msnlib.h"
#include "Account.h"

#define CONXML "contactreq.xml"
#define CONXML_FULL "contactreq_full.xml"
#define ABXML "abreq.xml"
#define ABXML_FULL "abreq_full.xml"
#define DEFAULTSERVER "contacts.msn.com"

enum _status
{
	NLN, BSY, BRB, AWY, IDL, PHN, LUN, HDN, NA
};
struct _contact
{
	char *name;
	char *domain;
	int inlist;
	int type;
	char *nick;
	Status status;
	char *PSM;
	Contact *d_next; /* next in domain table */
	Contact *g_next;
};

struct _contactlist
{
	Account *account;
	char *ticket;
	Contact *list;
	char *lastchange;
	char *ablastchange;
	xmlHashTablePtr table;
	xmlHashTablePtr emailtable;
	unsigned int count;
	int flag;
};

#define CL_SORTED 1
#define CL_INITLIST 2
ContactList *cl_new(Account *ac, const char *ticket);
char *cl_generate_ADL_list(CL *cl, int *count, int *len);
void cl_destroy(CL *cl);
int cl_retrive(CL *cl);
int cl_append_contact(CL *cl, Contact *c, const char *name, const char *domain);
Contact *cl_get_contact_by_email(CL *cl, const char *email);
void contact_destroy(Contact *c);
Contact *contact_new(const char *nick);
Status strtoStatus(const char* status);
#endif /* end of include guard: CONTACTSERVICE_8J4XHV59 */
