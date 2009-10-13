#ifndef OIM_PS9P51FM
#define OIM_PS9P51FM

#include "msnlib.h"
#include "SSLClient.h"
#include "Account.h"

typedef unsigned int uint;

struct _OIMList_t
{
	uint count;
	char *p;
	char *t;
	OIM *list;
};
struct _OIM_t
{
	char *from;
	char *nick;
	char *id;
	char *text;
	uint sid;
	OIM *next;
};
typedef OIMList OL;

OIMList *oimlist_getlist(const char* oticket);
OIMList *oimlist_new();
void oimlist_destroy(OIMList *olist);
void oimlist_append(OIMList *olist, OIM *oim);
void oimlist_remove(OL *ol, OIM *o);
void oimlist_save(OL *ol, const char *filename);

char *oim_fetch(OL *ol, OIM *o);
void oim_delete(OL *ol, OIM *o);
OIM *oim_new(const char *email, const char *nick, const char *id);
void oim_destroy(OIM *oim);

#endif /* end of include guard: OIM_PS9P51FM */
