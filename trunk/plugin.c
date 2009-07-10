#include <dlfcn.h>
#include <evldns.h>

int evldns_load_plugin(struct evldns_server_port *p, const char *plugin)
{
	char *err;
	dlerror();
	void *handle = dlopen(plugin, RTLD_NOW);
	if ((err = dlerror()) != NULL) {
		fprintf(stderr, "dlopen: %s\n", err);
		return -1;
	}

	evldns_plugin_init init = dlsym(handle, "init");
	if ((err = dlerror()) != NULL) {
		fprintf(stderr, "dlopen: %s\n", err);
		return -1;
	}

	return init(p);
}
