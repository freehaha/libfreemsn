#include "CmdQueue.h"

CQ cmdqueue_new()
{
	CQ q;
	q = (CQ)xmalloc(sizeof(*q));
	memset(q, 0, sizeof(*q));
	pthread_mutex_init(&(q->lock), NULL);
	return q;
}
void cmdqueue_destroy(CQ q)
{
	Command *c, *c_next;
	for(c=q->front;c;c=c_next)
	{
		c_next = c->next;
		xfree(c);
	}
	pthread_mutex_destroy(&(q->lock));
	xfree(q);
}
INLINE bool cmdqueue_empty(CQ q)
{
	return q->size == 0;
}
void cmdqueue_push(CQ q, Command *cmd)
{
	if(!cmd) return;
	pthread_mutex_lock(&q->lock);
	cmd->next = NULL;

	if(cmdqueue_empty(q))
		q->front = cmd;
	else
		q->rear->next = cmd;

	q->rear = cmd;
	q->size++;
	pthread_mutex_unlock(&q->lock);
}
Command *cmdqueue_pop(CQ q)
{
	Command *c;
	pthread_mutex_lock(&q->lock);
	if(cmdqueue_empty(q))
	{
		pthread_mutex_unlock(&q->lock);
		return NULL;
	}
	c = q->front;
	q->front = c->next;
	q->size--;
	pthread_mutex_unlock(&q->lock);
	return c;
}
Command *command_new(CmdType type, void *data, CmdDestroyFunc desfunc)
{
	Command *c;
	if(data && !desfunc)
	{
		fprintf(stderr, "new Command data doesn't have destroy function\n");
		return NULL;
	}
	c = (Command*)xmalloc(sizeof(Command));
	c->type = type;
	c->data = data;
	c->desfunc = desfunc;
	return c;
}
void command_destroy(Command *c)
{
	if(c->data) c->desfunc(c->data);
	xfree(c);
}
