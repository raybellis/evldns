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
 * This source file is derived from 'evdns.c' from libevent, originally
 * developed by Adam Langley <agl@imperialviolet.org>
 *
 */

#include <stdlib.h>
#include <unistd.h>
#include <sys/queue.h>

#include <evldns.h>

struct evldns_server {
	TAILQ_HEAD(evldnsfdq, evldns_server_port) ports;
	TAILQ_HEAD(evldnscbq, evldns_cb) callbacks;
};
typedef struct evldns_server evldns_server;

struct evldns_server_port {
	TAILQ_ENTRY(evldns_server_port)	 next;
	evldns_server			*server;
	int				 socket;
	int				 refcnt;
	char				 is_tcp;
	char				 closing;
	struct event			*event;
	TAILQ_HEAD(evldnssrq, evldns_server_request) pending;
};
typedef struct evldns_server_port evldns_server_port;

struct evldns_cb {
	TAILQ_ENTRY(evldns_cb)		 next;
	ldns_rdf			*rdf;
	ldns_rr_type			 rr_type;
	ldns_rr_class			 rr_class;
	evldns_callback			 callback;
	void				*data;
};
typedef struct evldns_cb evldns_cb;

/* forward declarations */
static void server_port_tcp_accept_callback(int fd, short events, void *arg);
static void server_port_tcp_read_callback(int fd, short events, void *arg);

static void server_port_udp_callback(int fd, short events, void *arg);
static void server_port_udp_read_callback(evldns_server_port *port);
static void server_port_udp_write_callback(evldns_server_port *port);

static void server_port_free(evldns_server_port *port);
static int server_request_free(evldns_server_request *req);

static void dispatch_callbacks(struct evldnscbq *callbacks, evldns_server_request *req);

/* exported function */
struct evldns_server *evldns_add_server()
{
	evldns_server *server;
	if (!(server = malloc(sizeof(*server)))) {
		return NULL;
	}
	memset(server, 0, sizeof(*server));

	TAILQ_INIT(&server->ports);
	TAILQ_INIT(&server->callbacks);

	return server;
}

struct evldns_server_port *
evldns_add_server_port(struct evldns_server *server, int socket)
{
	evldns_server_port *port;
	int type;
	socklen_t typelen = sizeof(type);

	/* don't add bad sockets */
	if (socket < 0) return NULL;

	/* create and populate the evldns_server_port structure */
	if (!(port = calloc(1, sizeof(*port)))) {
		return NULL;
	}
	memset(port, 0, sizeof(*port));
	port->server = server;
	port->socket = socket;
	port->event = calloc(1, sizeof(struct event)); // TODO: errorcheck
	port->refcnt = 1;

	/* find out if it's TCP or not */
	getsockopt(socket, SOL_SOCKET, SO_TYPE, &type, &typelen);
	port->is_tcp = (type == SOCK_STREAM);

	/* add this to the server's list of ports */
	TAILQ_INSERT_TAIL(&server->ports, port, next);

	/* and set it up for libevent */
	if (port->is_tcp) {
		event_set(port->event, port->socket, EV_READ | EV_PERSIST,
			server_port_tcp_accept_callback, port);
	} else {
		TAILQ_INIT(&port->pending);
		event_set(port->event, port->socket, EV_READ | EV_PERSIST,
			server_port_udp_callback, port);
	}
	event_add(port->event, NULL);

	return port;
}

void
evldns_close_server_port(evldns_server_port *port)
{
	if (--port->refcnt == 0) {
		server_port_free(port);
	}
	port->closing = 1;
}

static int
server_process_packet(uint8_t *buffer, size_t buflen, evldns_server_port *port, evldns_server_request *req)
{
	req->port = port;
	port->refcnt++;

	if (ldns_wire2pkt(&req->request, buffer, buflen) != LDNS_STATUS_OK) {
		return -1;
	}

	dispatch_callbacks(&port->server->callbacks, req);

	if (!req->wire_response) {

		if (!req->response) {
			req->response = evldns_response(req->request,
				LDNS_RCODE_REFUSED);
		}

		ldns_status status = ldns_pkt2wire(&req->wire_response,
			req->response, &req->wire_resplen);
		if (status != LDNS_STATUS_OK) {
			return -1;
		}
	}

	return 0;
}

/*
 * This callback is only used for TCP sockets when a connection is first accepted
 */
static void
server_port_tcp_accept_callback(int fd, short events, void *arg)
{
	evldns_server_port *port = (evldns_server_port *)arg;
	evldns_server_request *req = calloc(1, sizeof(evldns_server_request)); // TODO: error check

	req->addrlen = sizeof(struct sockaddr_storage);
	req->socket = accept(fd, (struct sockaddr *)&req->addr, &req->addrlen);

	/* create event on new socket and register that event */
	req->event = calloc(1, sizeof(struct event)); // TODO: error check
	event_set(req->event, req->socket, EV_READ | EV_PERSIST,
			server_port_tcp_read_callback, port);
	event_add(req->event, NULL);
}

static void
server_port_tcp_read_callback(int fd, short events, void *arg)
{
}

/*-------------------------------------------------------------------*/

static void
server_port_udp_callback(int fd, short events, void *arg)
{
	evldns_server_port *port = (evldns_server_port *)arg;

	if (events & EV_READ) {
		server_port_udp_read_callback(port);
	}
	if (events & EV_WRITE) {
		server_port_udp_write_callback(port);
	}
}

static int
evldns_server_udp_write_queue(evldns_server_request *req)
{
	evldns_server_port *port = req->port;
	int		r;

	r = sendto(req->socket, req->wire_response, req->wire_resplen, MSG_DONTWAIT,
		   (struct sockaddr *) &req->addr, req->addrlen);

	if (r < 0) {
		if (errno != EAGAIN) {
			perror("sendto");
			return -1;
		}

		TAILQ_INSERT_TAIL(&port->pending, req, next);
		if (TAILQ_FIRST(&port->pending) == req) {
			(void)event_del(port->event);
			event_set(port->event, port->socket,
				  (port->closing ? 0 : EV_READ) | EV_WRITE | EV_PERSIST,
				  server_port_udp_callback, port);
			if (event_add(port->event, NULL) < 0) {
				// TODO: warn
			}
		}

		return 1;
	}

	if (server_request_free(req)) {
		return 0;
	}

	if (!TAILQ_EMPTY(&port->pending)) {
		server_port_udp_write_callback(port);
	}

	return 0;
}

static void
server_port_udp_read_callback(evldns_server_port *port)
{
	uint8_t buffer[LDNS_MAX_PACKETLEN];
	while (1) {
		evldns_server_request *req = calloc(1, sizeof(evldns_server_request)); // TODO: malloc check
		req->addrlen = sizeof(struct sockaddr_storage);
		req->socket = port->socket;

		int buflen = recvfrom(req->socket, buffer, sizeof(buffer), MSG_DONTWAIT,
				(struct sockaddr *)&req->addr, &req->addrlen);
		if (buflen < 0) {
			if (errno != EAGAIN) {
				perror("recvfrom");
			}
			free(req);
			return;
		}

		if (server_process_packet(buffer, buflen, port, req) >= 0) {
			evldns_server_udp_write_queue(req);
		}
	}
}

static void
server_port_udp_write_callback(evldns_server_port *port)
{
	struct evldns_server_request *req;
	TAILQ_FOREACH(req, &port->pending, next) {

		int r = sendto(port->socket, req->wire_response, req->wire_resplen,
			MSG_DONTWAIT,
			(struct sockaddr *)&req->addr, req->addrlen);

		if (r < 0) {
			if (errno == EAGAIN) {
				return;
			}
			perror("sendto");
		}

		TAILQ_REMOVE(&port->pending, req, next);
		if (server_request_free(req)) {
			return;
		}
	}

	/* no more write events pending - go back to read-only mode */
	(void)event_del(port->event);
	event_set(port->event, port->socket, EV_READ | EV_PERSIST,
		server_port_udp_callback, port);
	if (event_add(port->event, NULL) < 0) {
		// TODO: warn
	}
}

/*-------------------------------------------------------------------*/

ldns_pkt *
evldns_response(const ldns_pkt *req, ldns_pkt_rcode rcode)
{
	ldns_pkt *p = ldns_pkt_new();
	ldns_rr_list *q = ldns_rr_list_clone(ldns_pkt_question(req));

	ldns_pkt_set_id(p, ldns_pkt_id(req));		/* copy ID field */
	ldns_pkt_set_cd(p, ldns_pkt_cd(req));		/* copy CD bit */
	ldns_pkt_set_rd(p, ldns_pkt_rd(req));		/* copy RD bit */
	ldns_pkt_set_qr(p, true);			/* this is a response */
	ldns_pkt_set_opcode(p, LDNS_PACKET_QUERY);	/* to a query */
	ldns_pkt_set_rcode(p, rcode);			/* with this rcode */

	ldns_rr_list_deep_free(p->_question);
	ldns_pkt_set_question(p, q);
	ldns_pkt_set_qdcount(p, ldns_rr_list_rr_count(q));

	return p;
}

/*-------------------------------------------------------------------*/

static void
server_port_free(evldns_server_port *port)
{
	// TODO
	free(port);
}

static int
server_request_free(evldns_server_request *req)
{
	req->port->refcnt--;

	ldns_pkt_free(req->request);
	ldns_pkt_free(req->response);

	free(req->wire_request);
	free(req->wire_response);
	free(req->event);
	free(req);

	return 0;
}

void evldns_add_callback(evldns_server *server, const char *dname, ldns_rr_class rr_class, ldns_rr_type rr_type, evldns_callback callback, void *data)
{
	evldns_cb *cb = (evldns_cb *)malloc(sizeof(evldns_cb));
	// TODO: error check
	memset(cb, 0, sizeof(evldns_cb));
	if (dname != NULL) {
		cb->rdf = ldns_dname_new_frm_str(dname);
		ldns_dname2canonical(cb->rdf);
	}
	cb->rr_class = rr_class;
	cb->rr_type = rr_type;
	cb->callback = callback;
	cb->data = data;
	TAILQ_INSERT_TAIL(&server->callbacks, cb, next);
}

static void
dispatch_callbacks(struct evldnscbq *callbacks, evldns_server_request *req)
{
	evldns_cb *cb;
	ldns_pkt *pkt = req->request;
	ldns_rr *q = ldns_rr_list_rr(ldns_pkt_question(pkt), 0);
	ldns_rdf *owner = ldns_dname_clone_from(ldns_rr_owner(q), 0);
	ldns_dname2canonical(owner);

	TAILQ_FOREACH(cb, callbacks, next) {
		if ((cb->rr_class != LDNS_RR_CLASS_ANY) &&
		    (cb->rr_class != ldns_rr_get_class(q)))
		{
			continue;
		}

		/* TODO: dispatch if request QTYPE == ANY? */
		if ((cb->rr_type != LDNS_RR_TYPE_ANY) &&
		    (cb->rr_type != ldns_rr_get_type(q)))
		{
			continue;
		}

		if (cb->rdf) {
			if (!ldns_dname_match_wildcard(owner, cb->rdf)) {
				continue;
			}
		}

		(*cb->callback)(req, cb->data);

		if (req->response || req->wire_response) {
			break;
		}
	}

	ldns_rdf_deep_free(owner);
}
