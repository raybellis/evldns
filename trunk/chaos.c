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
	struct evldns_server		*p;
	evldns_callback			 myip, txt;

	event_init();
	evldns_init();

	/* create an evldns server context */
	p = evldns_add_server();

	/* create sockets and add them to the context */
	evldns_add_server_port(p, bind_to_udp4_port(5053), 0);
	evldns_add_server_port(p, bind_to_udp6_port(5053), 0);

	/* load a couple of plugins */
	evldns_load_plugin(p, ".libs/mod_myip.so");
	evldns_load_plugin(p, ".libs/mod_txtrec.so");

	/* get plugin defined functions */
	myip = evldns_get_function("myip");
	txt = evldns_get_function("txt");

	/* register a list of callbacks */
	evldns_add_callback(p, NULL, LDNS_RR_CLASS_ANY, LDNS_RR_TYPE_ANY, query_only, NULL);
	evldns_add_callback(p, "client.bind", LDNS_RR_CLASS_ANY, LDNS_RR_TYPE_ANY, myip, NULL);
	evldns_add_callback(p, "version.bind", LDNS_RR_CLASS_CH, LDNS_RR_TYPE_TXT, txt, "evldns-0.1");
	evldns_add_callback(p, "author.bind", LDNS_RR_CLASS_CH, LDNS_RR_TYPE_TXT, txt, "Ray Bellis, Advanced Projects, Nominet UK");
	evldns_add_callback(p, "*", LDNS_RR_CLASS_ANY, LDNS_RR_TYPE_ANY, nxdomain, NULL);

	/* and set it running */
	event_dispatch();

	return EXIT_SUCCESS;
}
