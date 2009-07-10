#include <evldns.h>

/* TXT record lookup in - result is in user_data */
static void txt_callback(evldns_server_request *srq, void *user_data)
{
	ldns_pkt *req = srq->request;
	ldns_pkt *resp = evldns_response(req, LDNS_RCODE_NOERROR);
	ldns_rr *question = ldns_rr_list_rr(ldns_pkt_question(req), 0);
	ldns_rr *rr = ldns_rr_clone(question);

	ldns_rr_set_ttl(rr, 0L);
	ldns_rr_push_rdf(rr, ldns_rdf_new_frm_str(LDNS_RDF_TYPE_STR, user_data));
	ldns_rr_list_push_rr(ldns_pkt_answer(resp), rr);
	ldns_pkt_set_ancount(resp, 1);

	srq->response = resp;
}

static void add_txt_record(struct evldns_server_port *p, const char *label, void *value)
{
	evldns_add_callback(p, label, LDNS_RR_CLASS_CH, LDNS_RR_TYPE_TXT, txt_callback, value);
}

int init(struct evldns_server_port *p)
{
	evldns_add_function("txt_callback", txt_callback);

	add_txt_record(p, "version.bind", "evldns-0.1");
	add_txt_record(p, "author.bind",  "Ray Bellis");

	return 0;
}
