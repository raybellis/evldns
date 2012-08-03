/*
 * $Id: as112d.c 29 2010-01-15 11:54:55Z ray.bellis $
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

#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <evldns.h>

static char *t_soa = "@ SOA a.as112.net. hostmaster.root-servers.org. 2002040800 1800 900 0604800 604800";
static char *t_ns1 = "@ NS b.as112.net.";
static char *t_ns2 = "@ NS c.as112.net.";

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
	ldns_rr *soa, *ns1, *ns2;
	int ancount = 0;

	/* misc local variables */
	ldns_rr_list *answer = ldns_pkt_answer(resp);

	ldns_rr_new_frm_str(&soa, t_soa, 300, qname, NULL);
	ldns_rr_new_frm_str(&ns1, t_ns1, 300, qname, NULL);
	ldns_rr_new_frm_str(&ns2, t_ns2, 300, qname, NULL);

	/* SOA */
	if (qtype == LDNS_RR_TYPE_ANY || qtype == LDNS_RR_TYPE_SOA) {
		ldns_rr_list_push_rr(answer, ldns_rr_clone(soa));
	}

	/* NS */
	if (qtype == LDNS_RR_TYPE_ANY || qtype == LDNS_RR_TYPE_NS) {
		ldns_rr_list_push_rr(answer, ldns_rr_clone(ns1));
		ldns_rr_list_push_rr(answer, ldns_rr_clone(ns2));
	}

	ancount = ldns_rr_list_rr_count(answer);
	if (ancount) {
		ldns_pkt_set_rcode(resp, LDNS_RCODE_NOERROR);
	} else {
		ldns_pkt_set_rcode(resp, LDNS_RCODE_NXDOMAIN);
	}

	/* fill authority section if NODATA */
	ldns_pkt_set_ancount(resp, ancount);
	if (!ancount) {
		ldns_rr_list_push_rr(ldns_pkt_authority(resp), ldns_rr_clone(soa));
		ldns_pkt_set_nscount(resp, 1);
	}

	ldns_rr_free(soa);
	ldns_rr_free(ns1);
	ldns_rr_free(ns2);

	/* update packet header */
	ldns_pkt_set_aa(resp, 1);
}
int main(int argc, char *argv[])
{
	struct evldns_server		*p;

	event_init();
	p = evldns_add_server();
	evldns_add_server_port(p, bind_to_udp4_port(5053));
	evldns_add_server_port(p, bind_to_tcp4_port(5053, 10));
	evldns_add_callback(p, NULL, LDNS_RR_CLASS_ANY, LDNS_RR_TYPE_ANY, query_only, NULL);
	evldns_add_callback(p, NULL, LDNS_RR_CLASS_ANY, LDNS_RR_TYPE_ANY, as112_callback, NULL);
	event_dispatch();

	return EXIT_SUCCESS;
}
