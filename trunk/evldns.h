#ifndef EVLDNS_H
#define EVLDNS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <event.h>
#include <ldns/ldns.h>

/* forward declarations */
struct evldns_server_port;
struct evldns_server_request;

/* type declarations */

struct evldns_server_request {

	struct evldns_server_request	*next_pending;
	struct evldns_server_request	*prev_pending;

	struct evldns_server_port	*port;
	struct sockaddr_storage		 addr;
	socklen_t			 addrlen;

	ldns_pkt			*request;
	ldns_pkt			*response;

	uint8_t				*wire_response;
	size_t				 wire_len;
};
typedef struct evldns_server_request evldns_server_request;

typedef void (*evldns_callback)(evldns_server_request *request, void *data);
typedef int (*evldns_plugin_init)(struct evldns_server_port *p);

/*
 * exported functions
 */

/* core evdns clone functions */
struct evldns_server_port *evldns_add_server_port(int socket);
void evldns_server_close(struct evldns_server_port *port);
void evldns_add_callback(struct evldns_server_port *port, const char *dname, ldns_rr_class rr_class, ldns_rr_type rr_type, evldns_callback callback, void *data);
ldns_pkt *evldns_response(const ldns_pkt *request, ldns_pkt_rcode rcode);

/* plugin and function handling functions */
extern void evldns_init(void);
extern int evldns_load_plugin(struct evldns_server_port *p, const char *plugin);
extern void evldns_add_function(const char *name, evldns_callback func);
extern evldns_callback evldns_get_function(const char *name);

/* miscellaneous utility functions */
extern int bind_to_udp4_port(int port);

#ifdef __cplusplus
}
#endif

#endif /* EVLDNS_H */
