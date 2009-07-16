#include <netinet/in.h>
#include <arpa/inet.h>
#include <evldns.h>

/*
 * this callback function returns the IP(v4) address of
 * the DNS client that sent the request
 *
 * If the question is "qname IN TXT" or "qname CH TXT"
 * then a TXT record containing the address is returned.
 *
 * If the question is "qname IN A" then an A record is
 * returned instead.
 *
 * If the question is "qname IN ANY" then both the TXT
 * and A records are returned.
 */
static void myip_callback(evldns_server_request *srq, void *user_data)
{
	ldns_pkt *req = srq->request;
	ldns_pkt *resp = evldns_response(req, LDNS_RCODE_NOERROR);
	ldns_rr *question = ldns_rr_list_rr(ldns_pkt_question(req), 0);
	ldns_rr_type qtype = ldns_rr_get_type(question);
	ldns_rr_type qclass = ldns_rr_get_class(question);
	ldns_rr_list *answer = ldns_pkt_answer(resp);

	if (qtype == LDNS_RR_TYPE_TXT || qtype == LDNS_RR_TYPE_ANY) {
		char *txt = NULL;
		ldns_rr *rr = NULL;
		if (srq->addr.ss_family == AF_INET) {
			struct sockaddr_in *p = (struct sockaddr_in *)&srq->addr;
			txt = inet_ntoa(p->sin_addr);
		} else if (srq->addr.ss_family == AF_INET6) {
			/* TODO - IPv6 AAAA records */
		}

		if (txt) {
			ldns_rr *rr = ldns_rr_clone(question);
			ldns_rr_push_rdf(rr, ldns_rdf_new_frm_str(LDNS_RDF_TYPE_STR, txt));
			ldns_rr_set_type(rr, LDNS_RR_TYPE_TXT);
			ldns_rr_set_ttl(rr, 0L);
			ldns_rr_list_push_rr(answer, rr);
		}
	}

	if (qclass == LDNS_RR_CLASS_IN && srq->addr.ss_family == AF_INET &&
	    (qtype == LDNS_RR_TYPE_A || qtype == LDNS_RR_TYPE_ANY)) {
		struct sockaddr_in *p = (struct sockaddr_in *)&srq->addr;
		ldns_rr *rr = ldns_rr_clone(question);
		ldns_rdf *rdf = ldns_rdf_new_frm_data(LDNS_RDF_TYPE_A, 4,
				&p->sin_addr.s_addr);
		ldns_rr_push_rdf(rr, rdf);
		ldns_rr_set_type(rr, LDNS_RR_TYPE_A);
		ldns_rr_set_ttl(rr, 0L);
		ldns_rr_list_push_rr(answer, rr);
	}

	ldns_pkt_set_ancount(resp, ldns_rr_list_rr_count(answer));
	srq->response = resp;
}

int init(struct evldns_server_port *p)
{
	evldns_add_function("myip", myip_callback);

	return 0;
}
