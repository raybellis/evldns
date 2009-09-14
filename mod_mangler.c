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
#include <evldns.h>

/*
 * This function is not actually a callback, although it has
 * the same parameter signature as a callback
 *
 * Given an 'evldns_server_request' that has _already_ been
 * populated, it randomly flips bits in the output buffer
 * based on the value supplied in 'user_data'
 *
 * NB: user_data should be passed directly as an integer,
 * not as a pointer to an integer
 */
static void bitflip(evldns_server_request *srq, void *user_data)
{
	int		n_bits = (int)(long)user_data;
	int		i;

	/* can't mangle an empty packet */
	if (!srq->response && !srq->wire_response) {
		return;
	}

	/* convert LDNS packet to wire format if necessary */
	if (!srq->wire_response) {
		ldns_status status = ldns_pkt2wire(&srq->wire_response,
			srq->response, &srq->wire_resplen);
		if (status != LDNS_STATUS_OK) {
			return;
		}
	}

	if (n_bits < 1) {
		n_bits = 1;
	}

	/* randomly flip n_bits bits */
	for (i = 0; i < n_bits; ++i) {
		int offset = random() % srq->wire_resplen;
		int bit = random() % 8;
		srq->wire_response[offset] ^= (1 << bit);
	}
}

int init(struct evldns_server *p)
{
	evldns_add_function("bitflip", bitflip);

	return 0;
}
