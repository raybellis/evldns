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
			srq->response, &srq->wire_len);
		if (status != LDNS_STATUS_OK) {
			return;
		}
	}

	if (n_bits < 1) {
		n_bits = 1;
	}

	/* randomly flip n_bits bits */
	for (i = 0; i < n_bits; ++i) {
		int offset = random() % srq->wire_len;
		int bit = random() % 8;
		srq->wire_response[offset] ^= (1 << bit);
	}
}

int init(struct evldns_server *p)
{
	evldns_add_function("bitflip", bitflip);

	return 0;
}
