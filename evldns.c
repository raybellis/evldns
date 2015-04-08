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
#include <sys/uio.h>
#include <sys/queue.h>
#include <arpa/inet.h>

#include <evldns.h>

struct evldns_server {
	struct event_base				*base;
	TAILQ_HEAD(evldnscbq, evldns_cb) callbacks;
};
typedef struct evldns_server evldns_server;

struct evldns_server_port {
	TAILQ_ENTRY(evldns_server_port)	 next;
	evldns_server					*server;
	int								 socket;
	int								 refcnt;
	struct event					*event;
	TAILQ_HEAD(evldnssrq, evldns_server_request) pending;
	int								 is_tcp:1;
	int								 closing:1;
};
typedef struct evldns_server_port evldns_server_port;

struct evldns_cb {
	TAILQ_ENTRY(evldns_cb)			 next;
	ldns_rdf						*rdf;
	ldns_rr_type					 rr_type;
	ldns_rr_class					 rr_class;
	evldns_callback					 callback;
	void							*data;
};
typedef struct evldns_cb evldns_cb;

/* forward declarations */
static void evldns_tcp_accept_callback(int fd, short events, void *arg);
static void evldns_tcp_read_callback(int fd, short events, void *arg);
static void evldns_tcp_write_callback(int fd, short events, void *arg);

static void evldns_udp_callback(int fd, short events, void *arg);
static void evldns_udp_read_callback(evldns_server_port *port);
static void evldns_udp_write_callback(evldns_server_port *port);

static void server_port_free(evldns_server_port *port);
static int server_request_free(evldns_server_request *req);
static int server_process_packet(evldns_server_request *req, uint8_t *buffer, size_t buflen);

/* exported function */
struct evldns_server *evldns_add_server(struct event_base *base)
{
	evldns_server *server;
	if (!(server = calloc(1, sizeof(*server)))) {
		return NULL;
	}
	server->base = base;
	TAILQ_INIT(&server->callbacks);

	return server;
}

struct evldns_server_port *
evldns_add_server_port(struct evldns_server *server, int socket)
{
	evldns_server_port *port;
	void (*callback)(int, short, void *);

	/* don't add bad sockets */
	if (socket < 0) return NULL;

	/* create the evldns_server_port structure */
	if (!(port = calloc(1, sizeof(*port)))) {
		return NULL;
	}

	/* and populate it */
	port->server = server;
	port->socket = socket;
	port->refcnt = 1;
	port->is_tcp = socket_is_tcp(socket);

	/* and set it up for libevent */
	if (port->is_tcp) {
		callback = evldns_tcp_accept_callback;
	} else {
		callback = evldns_udp_callback;
		TAILQ_INIT(&port->pending);		// only needed for UDP
	}

	port->event = event_new(port->server->base, port->socket,
		EV_READ | EV_PERSIST, callback, port);
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

/*-------------------------------------------------------------------*/

static void
evldns_tcp_accept_callback(int fd, short events, void *arg)
{
	struct timeval tv = { 120, 0 };
	evldns_server_port *port = (evldns_server_port *)arg;
	evldns_server_request *req = calloc(1, sizeof(evldns_server_request)); // TODO: error check

	req->port = port;
	req->addrlen = sizeof(struct sockaddr_storage);
	req->socket = accept(fd, (struct sockaddr *)&req->addr, &req->addrlen);
	req->is_tcp = 1;

	/* create event on new socket and register that event */
	req->event = event_new(req->port->server->base, req->socket, EV_READ | EV_PERSIST,
			evldns_tcp_read_callback, req);
	event_add(req->event, &tv);
}

/*-------------------------------------------------------------------*/

static void evldns_tcp_cleanup(evldns_server_request *req)
{
	event_del(req->event);
	shutdown(req->socket, SHUT_RDWR);
	close(req->socket);
	server_request_free(req);
}

static int
evldns_tcp_write_packet(evldns_server_request *req)
{
	int		r;

	/*
	 * send the two byte header coalesced with data if possible
	 */
	if (req->wire_resphead < 2) {
		struct iovec iov[2];
		uint16_t len = htons(req->wire_resplen);

		iov[0].iov_base = &len + req->wire_resphead;
		iov[0].iov_len = sizeof(len) - req->wire_resphead;

		iov[1].iov_base = req->wire_response;
		iov[1].iov_len = req->wire_resplen;

		r = writev(req->socket, &iov[0], 2);
		if (r < 0) {
			if (errno == EAGAIN || errno == EINTR) {
				return 0;
			} else {
				perror("writev");
				return -1;
			}
		} else if (r == 0) {
			return 0;
		} else if (r == 1) {
			req->wire_resphead = 1;
		} else if (r >= 2) {
			req->wire_resphead = 2;
			req->wire_respdone = req->wire_resplen - r - 2;
		}
	}

	/*
	 * send as much of the rest of the packet as possible
	 */
	while (req->wire_respdone < req->wire_resplen) {
		r = write(req->socket, req->wire_response + req->wire_respdone,
		     	req->wire_resplen - req->wire_respdone);
		if (r < 0) {
			if (errno == EAGAIN || errno == EINTR) {
				return 0;
			} else {
				perror("write");
				return -1;
			}
		} else if (r == 0) {
			return 0;
		} else {
			req->wire_respdone += r;
		}
	}

	/*
  	 * if the whole packet has been sent without any errors set the
  	 * socket back to read-only mode so that more requests can be
  	 * received
  	 */
	if (req->wire_respdone >= req->wire_resplen) {

		/*
		 * set up the request object reader to receive another
		 * request - without this it'll loop
		 */
		ldns_pkt_free(req->response);
		if (req->wire_response) {
			free(req->wire_response);
		}
		req->response = 0;
		req->wire_response = 0;
		req->wire_reqdone = 0;
		req->wire_reqlen = 0;

		struct timeval tv = { 120, 0 };
		(void)event_del(req->event);
		(void)event_assign(req->event, req->port->server->base, req->socket,
			EV_READ | EV_PERSIST, evldns_tcp_read_callback, req);
		if (event_add(req->event, &tv) < 0) {
			// TODO: warn
		}

		return 1;
	} else {
		return 0;
	}
}

static void
evldns_tcp_write_queue(evldns_server_request *req)
{
	int		r;

	/*
	 * first time we've seen this packet, wire_resphead == 0
	 * indicates that the two byte header needs to be written
	 */
	req->wire_resphead = 0;
	req->wire_respdone = 0;

	/*
	 * send the packet, and leave libevent expecting more write events
	 * if the whole packet wasn't sent
	 */
	r = evldns_tcp_write_packet(req);
	if (r == 0) {
		struct timeval tv = { 120, 0 };
		(void)event_del(req->event);
		(void)event_assign(req->event, req->port->server->base, req->socket,
			EV_WRITE | EV_PERSIST, evldns_tcp_write_callback, req);
		if (event_add(req->event, &tv) < 0) {
			// TODO: warn
		}
	} else if (r < 0) {
		evldns_tcp_cleanup(req);
	}
}

static int
evldns_tcp_read_packet(evldns_server_request *req)
{
	int			 r;

	/*
	 * if this is a new message - read the two byte message header
	 */
	if (!req->wire_reqlen) {
		uint16_t len = 0;

		r = recv(req->socket, &len, sizeof(len), 0);
		if (r < 0) {
			if (errno == EAGAIN || errno == EINTR) {
				return 0;
			} else {
				perror("recv");
				return -1;
			}
		} else if (r == 0) {
			return -1;
		} else {
			if (!len) return 1;	/* zero-length request */
			/* get rid of any previous buffer */
			free(req->wire_request);

			/* set up the new buffers */
			req->wire_reqlen = len = ntohs(len);
			req->wire_reqdone = 0;
			req->wire_request = malloc(len);
			if (!req->wire_request) {
				perror("malloc");
				return -1;
			}
		}
	}

	/*
	 * the rest of the message might be available
	 */
	while (req->wire_reqdone < req->wire_reqlen) {
		r = recv(req->socket, req->wire_request + req->wire_reqdone,
		 	req->wire_reqlen - req->wire_reqdone, 0);
		if (r < 0) {
			if (errno == EAGAIN || errno == EINTR) {
				return 0;
			} else {
				perror("recv");
				return -1;
			}
		} else if (r == 0) {
			return -1;
		} else {
			req->wire_reqdone += r;
		}
	}

	/*
	 * see if we've got the whole request now
	 */
	return (req->wire_reqdone >= req->wire_reqlen) ? 1 : 0;
}

static void
evldns_tcp_read_callback(int fd, short events, void *arg)
{
	evldns_server_request *req = (evldns_server_request *)arg;
	if (events == EV_TIMEOUT) {
		evldns_tcp_cleanup(req);
	} else if (events & EV_READ) {
		int r = evldns_tcp_read_packet(req);
		if (r < 0) {
			evldns_tcp_cleanup(req);
		} else if (r == 1) {
			if (server_process_packet(req, req->wire_request, req->wire_reqlen) >= 0) {
				evldns_tcp_write_queue(req);
			}
		}
	}
}

static void
evldns_tcp_write_callback(int fd, short events, void *arg)
{
	evldns_server_request *req = (evldns_server_request *)arg;
	if (events == EV_TIMEOUT) {
		evldns_tcp_cleanup(req);
	} else if (events & EV_WRITE) {
		if (evldns_tcp_write_packet(req) < 0) {
			evldns_tcp_cleanup(req);
		}
	}
}

/*-------------------------------------------------------------------*/

static void
evldns_udp_callback(int fd, short events, void *arg)
{
	evldns_server_port *port = (evldns_server_port *)arg;

	if (events & EV_READ) {
		evldns_udp_read_callback(port);
	}
	if (events & EV_WRITE) {
		evldns_udp_write_callback(port);
	}
}

static int
evldns_server_udp_write_queue(evldns_server_request *req)
{
	evldns_server_port *port = req->port;
	int		r;

	/*
	 * try and send the datagram immediately
	 */
	r = sendto(req->socket, req->wire_response, req->wire_resplen, 0,
		   (struct sockaddr *) &req->addr, req->addrlen);

	/*
	 * if it failed, queue it for later
	 */
	if (r < 0) {
		if (errno != EAGAIN) {
			perror("sendto");
			return -1;
		}

		TAILQ_INSERT_TAIL(&port->pending, req, next);
		if (TAILQ_FIRST(&port->pending) == req) {
			(void)event_del(port->event);
			(void)event_assign(port->event, port->server->base, port->socket,
				  (port->closing ? 0 : EV_READ) | EV_WRITE | EV_PERSIST,
				  evldns_udp_callback, port);
			if (event_add(port->event, NULL) < 0) {
				// TODO: warn
			}
		}

		return 1;
	}

	/*
	 * dispose of the current request - only reached if the original send succeeds
	 */
	if (server_request_free(req)) {
		return 0;
	}

	/*
	 * and send anything else that happens to be in the queue
	 */
	if (!TAILQ_EMPTY(&port->pending)) {
		evldns_udp_write_callback(port);
	}

	return 0;
}

static void
evldns_udp_read_callback(evldns_server_port *port)
{
	uint8_t buffer[LDNS_MAX_PACKETLEN];
	while (1) {
		evldns_server_request *req = calloc(1, sizeof(evldns_server_request)); // TODO: alloc check
		req->addrlen = sizeof(struct sockaddr_storage);
		req->socket = port->socket;
		req->port = port;

		int buflen = recvfrom(req->socket, buffer, sizeof(buffer), 0,
				(struct sockaddr *)&req->addr, &req->addrlen);
		if (buflen < 0) {
			if (errno != EAGAIN) {
				perror("recvfrom");
			}
			free(req);
			return;
		}

		if (server_process_packet(req, buffer, buflen) >= 0) {
			evldns_server_udp_write_queue(req);
		}
	}
}

static void
evldns_udp_write_callback(evldns_server_port *port)
{
	struct evldns_server_request *req;
	TAILQ_FOREACH(req, &port->pending, next) {

		int r = sendto(port->socket, req->wire_response, req->wire_resplen, 0,
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
	(void)event_assign(port->event, port->server->base, port->socket,
		EV_READ | EV_PERSIST, evldns_udp_callback, port);
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

	// TODO: free port structure on refcnt == 0?

	return 0;
}

void evldns_add_callback(evldns_server *server, const char *dname, ldns_rr_class rr_class, ldns_rr_type rr_type, evldns_callback callback, void *data)
{
	evldns_cb *cb = (evldns_cb *)calloc(1, sizeof(evldns_cb));
	// TODO: error check
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
	ldns_rdf *qname = ldns_dname_clone_from(ldns_rr_owner(q), 0);
	ldns_dname2canonical(qname);
	ldns_rr_type qtype = ldns_rr_get_type(q);
	ldns_rr_class qclass = ldns_rr_get_class(q);

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
			if (!ldns_dname_match_wildcard(qname, cb->rdf)) {
				continue;
			}
		}

		(*cb->callback)(req, cb->data, qname, qtype, qclass);

		if (req->response || req->wire_response) {
			break;
		}
	}

	ldns_rdf_deep_free(qname);
}

static int
server_process_packet(evldns_server_request *req, uint8_t *buffer, size_t buflen)
{
	req->port->refcnt++;

	/*
	 * dispose of the previous packet buffers if they're still around
	 */
	if (req->request) {
		ldns_pkt_free(req->request);
		req->request = 0;
	}

	/*
	 * convert the received packet into ldns format
	 */
	if (ldns_wire2pkt(&req->request, buffer, buflen) != LDNS_STATUS_OK) {
		return -1;
	}

	/*
	 * don't respond to responses
	 */
	if (ldns_pkt_qr(req->request)) {
		return -1;
	}

	/*
	 * send it to the callback chain
	 */
	dispatch_callbacks(&req->port->server->callbacks, req);

	/*
	 * if the callbacks didn't generate a wire-format response
	 * then do the necessary stuff here
	 */
	if (!req->wire_response) {

		/*
		 * if the callbacks didn't even create an ldns format
		 * response then return a default (REFUSED) ldns response
		 */
		if (!req->response) {
			req->response = evldns_response(req->request,
				LDNS_RCODE_REFUSED);
		}

		/*
		 * convert from ldns format to wire format
		 */
		ldns_status status = ldns_pkt2wire(&req->wire_response,
			req->response, &req->wire_resplen);
		if (status != LDNS_STATUS_OK) {
			return -1;
		}
	}

	return 0;
}
