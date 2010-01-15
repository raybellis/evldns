#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <netinet/in.h>
#include <ldns/ldns.h>

void usage()
{
	fprintf(stderr, "usage: testtcp <host> <port>\n");
	exit(EXIT_FAILURE);
}

int test(struct sockaddr_in *addr, void *out, size_t outlen, void *in, size_t *inlen)
{
	int reuse = 1;
	int done = 0;
	uint16_t msglen = htons(outlen);
#if 0
	int delay = 1;
	struct iovec vec[2] = {
		{ &msglen, sizeof (msglen) },
		{ out, outlen }
	};
#endif

	int s = socket(PF_INET, SOCK_STREAM, 0);
	if (s < 0) {
		perror("socket");
		return -1;
	}

	/* allow socket re-use */
	if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse))) {
		perror("setsockopt");
	}

	if (connect(s, (struct sockaddr *)addr, sizeof(*addr)) < 0) {
		perror("connect");
		return -1;
	}

#if 0
	/* write packet length and output buffer */
	if (writev(s, vec, 2) < 0) {
		perror("writev");
		return -1;
	}

	/* flush socket */
	if (setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &delay, sizeof(delay))) {
		perror("setsockopt");
	}
#else
	if (write(s, &msglen, sizeof(msglen)) < 0) {
		perror("write");
		return -1;
	}

	done = 0;
	while (done < outlen) {
		int r = write(s, out + done, outlen - done);
		if (r < 0) {
			perror("write");
			return -1;
		}
		done += r;
	}
#endif

	/* read returned packet length */
	if (read(s, &msglen, sizeof(msglen)) < 0) {
		perror("read");
		return -1;
	}

	/* read the rest of the packet */
	*inlen = ntohs(msglen);
	done = 0;
	while (done < *inlen) {
		int r = read(s, in + done, *inlen - done);
		if (r < 0) {
			perror("read");
			return -1;
		}
		done += r;
	}

	shutdown(s, SHUT_RDWR);
	close(s);

	return 0;
}

void loop(struct sockaddr_in *addr)
{
	int		 i = 1;
	size_t		 outlen, inlen;
	uint8_t		*outbuf;
	uint8_t		 inbuf[LDNS_MAX_PACKETLEN];
	struct timeval	 tv1, tv2;
	ldns_pkt	*outpkt;

	gettimeofday(&tv1, NULL);

	ldns_pkt_query_new_frm_str(&outpkt, "www.google.co.uk",
				   LDNS_RR_TYPE_A, LDNS_RR_CLASS_IN, 0);

	while (1) {

		ldns_pkt_set_id(outpkt, rand());
		ldns_pkt2wire(&outbuf, outpkt, &outlen);

		if (test(addr, outbuf, outlen, inbuf, &inlen) < 0) {
			return ;
		}
		i++;

		free(outbuf);

		gettimeofday(&tv2, NULL);
		if (tv2.tv_sec - tv1.tv_sec == 5 &&
		    tv2.tv_usec > tv1.tv_usec) {
			break;
		}
	}

	ldns_pkt_free(outpkt);

	fprintf(stdout, "%5d packets handled\n", i++);
	fprintf(stdout, "rate = %d\n", i / 5);
}

int main(int argc, char *argv[])
{
	char			*host;
	int			 port;
	struct hostent		*hostent;
	struct sockaddr_in	 addr;

	if (argc != 3) {
		usage();
	}

	host = argv[1];
	port = atoi(argv[2]);

	if ((hostent = gethostbyname(host)) == NULL) {
		herror("gethostbyname");
		return EXIT_FAILURE;
	}

	memset(&addr, 0, sizeof(addr));
	memcpy(&addr.sin_addr, hostent->h_addr, sizeof(addr.sin_addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);

	loop(&addr);

	return EXIT_SUCCESS;
}
