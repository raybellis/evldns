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
	char				 choked;
	char				 closing;
	struct event			 event;
	struct evldns_server_request	*pending_replies;
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
static void server_port_ready_callback(int fd, short events, void *arg);
static void server_port_read(evldns_server_port *port);
static void server_port_free(evldns_server_port *port);
static void server_port_flush(evldns_server_port *port);

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
	if (!(port = malloc(sizeof(*port)))) {
		return NULL;
	}
	memset(port, 0, sizeof(*port));

	port->server = server;
	port->socket = socket;
	port->refcnt = 1;
	port->closing = 0;
	TAILQ_INSERT_TAIL(&server->ports, port, next);

	event_set(&port->event, port->socket, EV_READ | EV_PERSIST,
		server_port_ready_callback, port);
	event_add(&port->event, NULL);

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
evldns_server_request_respond(evldns_server_request *req)
{
	evldns_server_port *port = req->port;
	int		r;

	if (!req->wire_response) {

		if (!req->response) {
			req->response = evldns_response(req->request,
				LDNS_RCODE_REFUSED);
		}

		ldns_status status = ldns_pkt2wire(&req->wire_response,
			req->response, &req->wire_len);
		if (status != LDNS_STATUS_OK) {
			return -1;
		}
	}

	r = sendto(port->socket, req->wire_response, req->wire_len,
		   MSG_DONTWAIT,
		   (struct sockaddr *) &req->addr, req->addrlen);

	if (r < 0) {
		if (errno != EAGAIN) {
			return -1;
		}

		if (port->pending_replies) {
			req->prev_pending = port->pending_replies->prev_pending;
			req->next_pending = port->pending_replies;
			req->prev_pending->next_pending =
				req->next_pending->prev_pending = req;
		} else {
			req->prev_pending = req->next_pending = req;
			port->pending_replies = req;
			port->choked = 1;

			(void)event_del(&port->event);
			event_set(&port->event, port->socket, (port->closing ? 0 : EV_READ) | EV_WRITE | EV_PERSIST, server_port_ready_callback, port);
			if (event_add(&port->event, NULL) < 0) {
				// TODO: warn
			}
		}

		return 1;
	}

	if (server_request_free(req)) {
		return 0;
	}

	if (port->pending_replies) {
		server_port_flush(port);
	}

	return 0;
}

static int
handle_packet(uint8_t *buffer, size_t buflen, evldns_server_port *port, struct sockaddr *addr, socklen_t addrlen)
{
	evldns_server_request *req = NULL;
	ldns_status status;

	req = malloc(sizeof(evldns_server_request));
	if (req == NULL) {
		return -1;
	}

	memset(req, 0, sizeof(evldns_server_request));

	memcpy(&req->addr, addr, addrlen);
	req->addrlen = addrlen;
	req->port = port;
	port->refcnt++;

	status = ldns_wire2pkt(&req->request, buffer, buflen);
	if (status != LDNS_STATUS_OK) {
		return -1;
	}

	dispatch_callbacks(&port->server->callbacks, req);

	evldns_server_request_respond(req);

	return 0;
}

static void
server_port_ready_callback(int fd, short events, void *arg)
{
	evldns_server_port *port = (evldns_server_port *)arg;

	if (events & EV_WRITE) {
		port->choked = 0;
		server_port_flush(port);
	}
	if (events & EV_READ) {
		server_port_read(port);
	}
}

static void server_port_read(evldns_server_port *port)
{
	uint8_t buffer[LDNS_MAX_PACKETLEN];
	struct sockaddr_storage addr;
	socklen_t addrlen;

	while (1) {
		addrlen = sizeof(struct sockaddr_storage);
		int r = recvfrom(port->socket, buffer, sizeof(buffer),
				MSG_DONTWAIT,
				(struct sockaddr *) &addr, &addrlen);
		if (r < 0) {
			if (errno == EAGAIN) {
				return;
			}
			perror("recvfrom");
			return;
		}

		handle_packet(buffer, r, port, (struct sockaddr *) &addr, addrlen);
	}
}

static void
server_port_flush(evldns_server_port *port)
{
	while (port->pending_replies) {
		evldns_server_request *req = port->pending_replies;
		int r = sendto(port->socket, req->wire_response, req->wire_len,
			MSG_DONTWAIT,
			(struct sockaddr *)&req->addr, req->addrlen);
		if (r < 0) {
			if (errno == EAGAIN) {
				return;
			}
			// TODO: warn
		}

		if (server_request_free(req)) {
			return;
		}

		(void)event_del(&port->event);
		event_set(&port->event, port->socket, EV_READ | EV_PERSIST,
			server_port_ready_callback, port);
		if (event_add(&port->event, NULL) < 0) {
			// TODO: warn
		}
	}
}

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

static void
server_port_free(evldns_server_port *port)
{
	// TODO
	free(port);
}

static int
server_request_free(evldns_server_request *req)
{
	int rc = 1;

	if (req->port) {
		if (req->port->pending_replies == req) {
			if (req->next_pending) {
				req->port->pending_replies = req->next_pending;
			} else {
				req->port->pending_replies = NULL;
			}
		}
		rc = --req->port->refcnt;
	}

	ldns_pkt_free(req->request);
	ldns_pkt_free(req->response);
	free(req->wire_response);

	if (req->next_pending && req->next_pending != req) {
		req->next_pending->prev_pending = req->prev_pending;
		req->prev_pending->next_pending = req->next_pending;
	}

	if (rc == 0) {
		server_port_free(req->port);
		free(req);
		return 1;
	}

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
