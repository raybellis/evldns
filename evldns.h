/*
 * $Id$
 *
 * Copyright (c) 2009, Nominet UK.
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of Nominet UK nor the names of its contributors may
 *       be used to endorse or promote products derived from this software
 *       without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY Nominet UK ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL Nominet UK BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef EVLDNS_H
#define EVLDNS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <event.h>
#include <ldns/ldns.h>

/* forward declarations */
struct evldns_server;
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
typedef int (*evldns_plugin_init)(struct evldns_server *p);

/*
 * exported functions
 */

/* core evdns sort-of-clone functions */
struct evldns_server *evldns_add_server();
struct evldns_server_port *evldns_add_server_port(struct evldns_server *, int socket);
void evldns_server_close(struct evldns_server_port *port);
void evldns_add_callback(struct evldns_server *server, const char *dname, ldns_rr_class rr_class, ldns_rr_type rr_type, evldns_callback callback, void *data);
ldns_pkt *evldns_response(const ldns_pkt *request, ldns_pkt_rcode rcode);

/* plugin and function handling functions */
extern void evldns_init(void);
extern int evldns_load_plugin(struct evldns_server *server, const char *plugin);
extern void evldns_add_function(const char *name, evldns_callback func);
extern evldns_callback evldns_get_function(const char *name);

/* miscellaneous utility functions */
extern int bind_to_udp4_port(int port);

#ifdef __cplusplus
}
#endif

#endif /* EVLDNS_H */
