#include <stdlib.h>
#include <unistd.h>
#include <sys/queue.h>
#include <evldns.h>

static TAILQ_HEAD(fbq, fb_function)	funcs;

struct fb_function {
	TAILQ_ENTRY(fb_function)	 next;
	const char			*name;
	evldns_callback			 func;
};
typedef struct fb_function fb_function;

void evldns_init(void)
{
	TAILQ_INIT(&funcs);
}

void evldns_add_function(const char *name, evldns_callback func)
{
	fb_function *f = (fb_function *)malloc(sizeof(fb_function));
	memset(f, 0, sizeof(fb_function));
	f->name = strdup(name);
	f->func = func;
	TAILQ_INSERT_TAIL(&funcs, f, next);
}

evldns_callback evldns_get_function(const char *name)
{
	fb_function *func;
	TAILQ_FOREACH(func, &funcs, next) {
		if (strcmp(func->name, name) == 0) {
			return func->func;
		}
	}
	return NULL;
}
