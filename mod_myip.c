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

#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
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
static void myip_callback(evldns_server_request *srq, void *user_data, ldns_rdf *qname, ldns_rr_type qtype, ldns_rr_class qclass)
{
	ldns_pkt *req = srq->request;
	ldns_pkt *resp = evldns_response(req, LDNS_RCODE_NOERROR);
	ldns_rr *question = ldns_rr_list_rr(ldns_pkt_question(req), 0);
	ldns_rr_list *answer = ldns_pkt_answer(resp);

	/* generate TXT records for client address */
	if ((qclass == LDNS_RR_CLASS_IN || qclass == LDNS_RR_CLASS_CH) &&
	     (qtype == LDNS_RR_TYPE_TXT ||  qtype == LDNS_RR_TYPE_ANY))
	{
		char nbuf[NI_MAXHOST];

		if (getnameinfo((struct sockaddr *)&srq->addr, srq->addrlen,
				nbuf, sizeof(nbuf), NULL, 0,
				NI_NUMERICHOST) == 0)
		{
			ldns_rr *rr = ldns_rr_clone(question);
			ldns_rr_push_rdf(rr, ldns_rdf_new_frm_str(LDNS_RDF_TYPE_STR, nbuf));
			ldns_rr_set_type(rr, LDNS_RR_TYPE_TXT);
			ldns_rr_set_ttl(rr, 0L);
			ldns_rr_list_push_rr(answer, rr);
		}
	}

	/* generate A records for client address, if the query arrived on IPv4 */
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

	/* generate AAAA records for client address, if the query arrived on IPv6 */
	if (qclass == LDNS_RR_CLASS_IN && srq->addr.ss_family == AF_INET6 &&
	    (qtype == LDNS_RR_TYPE_AAAA || qtype == LDNS_RR_TYPE_ANY)) {
		struct sockaddr_in6 *p = (struct sockaddr_in6 *)&srq->addr;
		ldns_rr *rr = ldns_rr_clone(question);
		ldns_rdf *rdf = ldns_rdf_new_frm_data(LDNS_RDF_TYPE_AAAA, 16,
				&p->sin6_addr.s6_addr);
		ldns_rr_push_rdf(rr, rdf);
		ldns_rr_set_type(rr, LDNS_RR_TYPE_AAAA);
		ldns_rr_set_ttl(rr, 0L);
		ldns_rr_list_push_rr(answer, rr);
	}

	/* update packet header */
	ldns_pkt_set_ancount(resp, ldns_rr_list_rr_count(answer));
	srq->response = resp;
}

int init(struct evldns_server *p)
{
	evldns_add_function("myip", myip_callback);

	return 0;
}
