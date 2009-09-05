#ifndef XMALLOC_UEQWPAI6
#define XMALLOC_UEQWPAI6

void *xmalloc(size_t size);
#define xfree(x) (_xfree(x), x=NULL)
void _xfree(void *ptr);
void *xrealloc(void *ptr, size_t size);

#endif /* end of include guard: XMALLOC_UEQWPAI6 */
