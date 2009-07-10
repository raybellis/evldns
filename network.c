#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netdb.h>

int bind_to_udp4_port(int port)
{
	int			r, s;
	struct sockaddr_in	addr;

	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 0) {
		perror("socket");
		return s;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(port);
	if ((r = bind(s, (struct sockaddr *)&addr, sizeof(addr))) < 0) {
		perror("bind");
		return r;
	}

	return s;
}
