/*
 * $Id: $
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
#include <evldns.h>

/* rejects packets that arrive with OPCODE != QUERY, or QDCOUNT != 1 */
void query_only(evldns_server_request *srq, void *user_data, ldns_rdf *qname, ldns_rr_type qtype, ldns_rr_class qclass)
{
	ldns_pkt *req = srq->request;

	if (ldns_pkt_get_opcode(req) != LDNS_PACKET_QUERY) {
		srq->response = evldns_response(req, LDNS_RCODE_NOTIMPL);
	}

	if (ldns_pkt_qdcount(req) != 1) {
		srq->response = evldns_response(req, LDNS_RCODE_FORMERR);
	}
}

int main(int argc, char *argv[])
{
	struct event_base			*base;
	struct evldns_server		*p;
	evldns_callback				 arec;

	base = event_base_new();

	/* create an evldns server context */
	evldns_init();
	p = evldns_add_server(base);

	/* create sockets and add them to the context */
	evldns_add_server_ports(p, bind_to_all(NULL, 0, "5053", 10));

	/* load a couple of plugins */
	evldns_load_plugin(p, ".libs/mod_arec.so");

	/* get plugin defined functions */
	arec = evldns_get_function("a");

	/* register a list of callbacks */
	evldns_add_callback(p, NULL, LDNS_RR_CLASS_ANY, LDNS_RR_TYPE_ANY, query_only, NULL);
	evldns_add_callback(p, "*", LDNS_RR_CLASS_IN, LDNS_RR_TYPE_A, arec, "192.168.1.1");

	/* and set it running */
	event_base_dispatch(base);

	return EXIT_SUCCESS;
}
