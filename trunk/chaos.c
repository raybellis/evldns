#include <stdlib.h>
#include <stdio.h>
#include <evldns.h>

void nxdomain(evldns_server_request *srq, void *user_data)
{
	ldns_pkt *req = srq->request;
	srq->response = evldns_response(req, LDNS_RCODE_NXDOMAIN);
}

/* rejects packets that arrive with QR=1, or OPCODE != QUERY, or QDCOUNT != 1 */
void query_only(evldns_server_request *srq, void *user_data)
{
	ldns_pkt *req = srq->request;

	if (ldns_pkt_get_opcode(req) != LDNS_PACKET_QUERY) {
		srq->response = evldns_response(req, LDNS_RCODE_NOTIMPL);
	}

	if (ldns_pkt_qr(req) || ldns_pkt_qdcount(req) != 1) {
		srq->response = evldns_response(req, LDNS_RCODE_FORMERR);
	}
}

int main(int argc, char *argv[])
{
	int				 s;
	struct evldns_server_port	*p;

	event_init();
	evldns_init();

	if ((s = bind_to_udp4_port(5053)) < 0) {
		return EXIT_FAILURE;
	}

	p = evldns_add_server_port(s);
	evldns_add_callback(p, NULL, LDNS_RR_CLASS_ANY, LDNS_RR_TYPE_ANY, query_only, NULL);
	evldns_load_plugin(p, ".libs/mod_mangler.so");
	evldns_load_plugin(p, ".libs/mod_version.so");
	evldns_add_callback(p, "*", LDNS_RR_CLASS_ANY, LDNS_RR_TYPE_ANY, nxdomain, NULL);
	event_dispatch();

	return EXIT_SUCCESS;
}
