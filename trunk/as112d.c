#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <evldns.h>

static char *t_soa = "@ SOA prisoner.iana.org. hostmaster.root-servers.org. 2002040800 1800 900 0604800 604800";
static char *t_ns1 = "@ NS blackhole-1.iana.org.";
static char *t_ns2 = "@ NS blackhole-2.iana.org.";

typedef struct as112_zone {
	ldns_rdf	*origin;
	ldns_rr		*soa;
	ldns_rr		*ns1;
	ldns_rr		*ns2;
} as112_zone;

as112_zone zones[19];

/*
 * following two functions pre-create a set of standard RRs
 * (SOA and NS) for each of the recognised zones
 */
void create_zone(const char *origin, as112_zone *zone)
{
	zone->origin = ldns_dname_new_frm_str(origin);
	ldns_rr_new_frm_str(&zone->soa, t_soa, 300, zone->origin, NULL);
	ldns_rr_new_frm_str(&zone->ns1, t_ns1, 300, zone->origin, NULL);
	ldns_rr_new_frm_str(&zone->ns2, t_ns2, 300, zone->origin, NULL);
}

void create_zones()
{
	as112_zone *p = &zones[0];
	create_zone("10.in-addr.arpa", p++);
	create_zone("254.169.in-addr.arpa", p++);
	create_zone("168.192.in-addr.arpa", p++);
	create_zone("16.172.in-addr.arpa", p++);
	create_zone("17.172.in-addr.arpa", p++);
	create_zone("18.172.in-addr.arpa", p++);
	create_zone("19.172.in-addr.arpa", p++);
	create_zone("20.172.in-addr.arpa", p++);
	create_zone("21.172.in-addr.arpa", p++);
	create_zone("22.172.in-addr.arpa", p++);
	create_zone("23.172.in-addr.arpa", p++);
	create_zone("24.172.in-addr.arpa", p++);
	create_zone("25.172.in-addr.arpa", p++);
	create_zone("26.172.in-addr.arpa", p++);
	create_zone("27.172.in-addr.arpa", p++);
	create_zone("28.172.in-addr.arpa", p++);
	create_zone("29.172.in-addr.arpa", p++);
	create_zone("30.172.in-addr.arpa", p++);
	create_zone("31.172.in-addr.arpa", p++);
}

/*
 * given an query, strips it to the relevant portion of the
 * in-addr.arpa namespace and uses hard-coded logic to figure
 * out which of the pre-created elements of the 'zones' array
 * contains the RRs for it
 */
as112_zone *search_zones(ldns_rdf *qname, int *count)
{
	int n = 0, slash8;
	*count = ldns_dname_label_count(qname);
	while (*count > 0 && n < 4) {
		int octet;

		(*count)--;
		if (n < 2) {
			/* do nothing for in-addr. and arpa. */
		} else {
			/* attempt to parse the numeric labels */
			ldns_rdf *label = ldns_dname_label(qname, *count);
			char *ptr, *data = ldns_rdf_data(label);
			char *str = data + 1, c1 = *str, c2;
			octet = strtol(str, &ptr, 10);
			c2 = *ptr;
			ldns_rdf_deep_free(label);
			if (!isdigit(c1) || c2 != '\0') return NULL;
			if (n == 2) {
				slash8 = octet;
				if (slash8 == 10) { /* shortcut here for 10.0.0.0/8 */
					return &zones[0];
				}
			}
		}

		/* if it wasn't 10.0.0.0/8 then check at the /16 boundary */
		if (n == 3) {
			if (slash8 == 169 && octet == 254) {
				return &zones[1];
			} else if (slash8 == 192 && octet == 168) {
				return &zones[2];
			} else if (slash8 == 172 && (octet >= 16 && octet < 32)) {
				return &zones[3 + octet - 16];
			} else {
				return NULL;
			}
		}
		n++;
	}
	return NULL;
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

void as112_callback(evldns_server_request *srq, void *user_data)
{
	/* copy the question and determine qtype and qname */
	ldns_pkt *req = srq->request;
	ldns_pkt *resp = srq->response = evldns_response(req, LDNS_RCODE_REFUSED);
	ldns_rr *question = ldns_rr_list_rr(ldns_pkt_question(req), 0);
	ldns_rr_type qtype = ldns_rr_get_type(question);
	ldns_rdf *qname = ldns_rr_owner(question);

	/* misc local variables */
	ldns_rr_list *answer = ldns_pkt_answer(resp);
	ldns_rr *soa, *ns1, *ns2;
	int lcount;

	/* figure out what zone we're handling */
	as112_zone *zone = search_zones(qname, &lcount);
	if (!zone) {
		return;
	}

	if (lcount == 0) {	/* no more sub-domain labels found */
		/* SOA */
		if (qtype == LDNS_RR_TYPE_ANY || qtype == LDNS_RR_TYPE_SOA) {
			ldns_rr_list_push_rr(answer, ldns_rr_clone(zone->soa));
		}

		/* NS */
		if (qtype == LDNS_RR_TYPE_ANY || qtype == LDNS_RR_TYPE_NS) {
			ldns_rr_list_push_rr(answer, ldns_rr_clone(zone->ns1));
			ldns_rr_list_push_rr(answer, ldns_rr_clone(zone->ns2));
		}
		ldns_pkt_set_rcode(resp, LDNS_RCODE_NOERROR);
	} else {		/* more labels, left - no good */
		ldns_pkt_set_rcode(resp, LDNS_RCODE_NXDOMAIN);
	}

	/* fill authority section if NODATA */
	ldns_pkt_set_ancount(resp, ldns_rr_list_rr_count(answer));
	if (!ldns_rr_list_rr_count(answer)) {
		ldns_rr_list_push_rr(ldns_pkt_authority(resp), ldns_rr_clone(zone->soa));
		ldns_pkt_set_nscount(resp, 1);
	}

	/* update packet header */
	ldns_pkt_set_aa(resp, 1);
}
int main(int argc, char *argv[])
{
	int				 s;
	struct evldns_server_port	*p;

	if ((s = bind_to_udp4_port(5053)) < 0) {
		return EXIT_FAILURE;
	}

	create_zones();
	event_init();
	p = evldns_add_server_port(s);
	evldns_add_callback(p, NULL, LDNS_RR_CLASS_ANY, LDNS_RR_TYPE_ANY, query_only, NULL);
	evldns_add_callback(p, "*.in-addr.arpa.", LDNS_RR_CLASS_ANY, LDNS_RR_TYPE_ANY, as112_callback, NULL);
	event_dispatch();

	return EXIT_SUCCESS;
}
