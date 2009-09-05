#include <stdlib.h>
#include <stdio.h>
void *xmalloc(size_t size)
{
	void *ptr;
	ptr = malloc(size);
	if(ptr == 0)
		fprintf(stderr, "malloc failed, size: %d\n", size);

	return ptr;
}
void _xfree(void *ptr)
{
	if(ptr) free(ptr);
}
void *xrealloc(void *ptr, size_t size)
{
	void *newptr;
	newptr = ptr?realloc(ptr, size):malloc(size);

	if(newptr == 0)
		fprintf(stderr, "realloc failed, size %d\n", size);

	return newptr;
}
