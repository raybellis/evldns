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
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netdb.h>

/*--------------------------------------------------------------------*/

static int bind_to_port(int port, int domain, int family, int type, int backlog)
{
	int			 r, s;
	struct sockaddr_in	 addr4;
	struct sockaddr_in6	 addr6;
	struct sockaddr		*addr;
	socklen_t		 addrlen;

	/* make the actual socket */
	s = socket(domain, type, 0);
	if (s < 0) {
		perror("socket");
		return s;
	}

	/* disable automatic 6to4 if necessary */
	if (domain == PF_INET6) {
		int v6only = 1;
		if (setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only))) {
			perror("setsockopt");
		}
	}

	/* set up the local address (protocol specific) */
	if (family == AF_INET) {
		addrlen = sizeof(addr4);
		addr = (struct sockaddr *)&addr4;
		memset(addr, 0, addrlen);

		addr4.sin_family = family;
		addr4.sin_addr.s_addr = INADDR_ANY;
		addr4.sin_port = htons(port);
	} else if (family == AF_INET6) {
		addrlen = sizeof(addr6);
		addr = (struct sockaddr *)&addr6;
		memset(addr, 0, addrlen);

		addr6.sin6_family = AF_INET6;
		addr6.sin6_addr = in6addr_any;
		addr6.sin6_port = htons(port);
	} else {
		fprintf(stderr, "address family not recognized\n");
		close(s);
		return -1;
	}


	/* bind to that local address */
	if ((r = bind(s, addr, addrlen)) < 0) {
		perror("bind");
		close(s);
		return r;
	}

	/* if it's TCP, listen */
	if (type == SOCK_STREAM) {
		if ((r = listen(s, backlog)) < 0) {
			perror("listen");
			close(s);
			return r;
		}
	}

	/* make the socket non-blocking */
	if (fcntl(s, F_SETFL, O_NONBLOCK) < 0) {
		perror("fcntl");
	}

	return s;
}

/*--------------------------------------------------------------------*/

int bind_to_udp4_port(int port)
{
	return bind_to_port(port, PF_INET, AF_INET, SOCK_DGRAM, 0);
}

int bind_to_tcp4_port(int port, int backlog)
{
	return bind_to_port(port, PF_INET, AF_INET, SOCK_STREAM, backlog);
}

/*--------------------------------------------------------------------*/

int bind_to_udp6_port(int port)
{
	return bind_to_port(port, PF_INET6, AF_INET6, SOCK_DGRAM, 0);
}

int bind_to_tcp6_port(int port, int backlog)
{
	return bind_to_port(port, PF_INET6, AF_INET6, SOCK_STREAM, backlog);
}

/*--------------------------------------------------------------------*/
