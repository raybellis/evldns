/*
 * $Id$
 *
 * Copyright (c) 2009-2014, Nominet UK.
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
#include <netinet/in.h>
#include <netdb.h>
#include <netinet/in.h>
#include <syslog.h>
#include <evldns.h>
#include <syslog.h>

/*--------------------------------------------------------------------*/

int bind_to_sockaddr(struct sockaddr* addr, socklen_t addrlen, int type, int backlog)
{
	int					 r, s;
	int					 reuse = 1;
	char				 nbuf[NI_MAXHOST];

	/* make the actual socket */
	s = socket(addr->sa_family, type, 0);
	if (s < 0) {
		perror("socket");
		return s;
	}

	/* disable automatic 6to4 if necessary */
	if (addr->sa_family == AF_INET6) {
		int v6only = 1;
		if (setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only))) {
			perror("setsockopt(IPV6_ONLY)");
		}
	}

	/* allow socket re-use */
	if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse))) {
		perror("setsockopt(SO_REUSEADDR)");
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

	/* log the result of the 'bind' call (non-fatal) */
	if ((r = getnameinfo(addr, addrlen, nbuf, sizeof(nbuf), NULL, 0, NI_NUMERICHOST)) == 0) {
		syslog(LOG_INFO, "bound %s fd#%d to %s", (type == SOCK_STREAM) ? "TCP" : "UDP", s, nbuf);
	} else {
		fprintf(stderr, "getnameinfo: %s\n",  gai_strerror(r));
	}

	return s;
}

int bind_to_port(int port, int family, int type, int backlog)
{
	/* set up the local address (protocol specific) */
	if (family == AF_INET) {
		struct sockaddr_in		addr;
		memset(&addr, 0, sizeof(addr));

		addr.sin_family = family;
		addr.sin_addr.s_addr = INADDR_ANY;
		addr.sin_port = htons(port);
		return bind_to_sockaddr((struct sockaddr *)&addr, sizeof(addr), type, backlog);
	} else if (family == AF_INET6) {
		struct sockaddr_in6		addr;
		memset(&addr, 0, sizeof(addr));

		addr.sin6_family = AF_INET6;
		addr.sin6_addr = in6addr_any;
		addr.sin6_port = htons(port);
		return bind_to_sockaddr((struct sockaddr *)&addr, sizeof(addr), type, backlog);
	} else {
		fprintf(stderr, "address family %d not recognized\n", family);
		return -1;
	}
}

int bind_to_address(const char *ipaddr, const char *port, int type, int backlog)
{
	struct sockaddr_storage	addr;
	int						addrlen;
	struct addrinfo			hints, *ai;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_flags = AI_PASSIVE;

	int res = getaddrinfo(ipaddr, port, &hints, &ai);
	if (res) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(res));
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addrlen = ai->ai_addrlen;
	memcpy(&addr, ai->ai_addr, addrlen);
	freeaddrinfo(ai);

	return bind_to_sockaddr((struct sockaddr  *)&addr, addrlen, type, backlog);
}

/*--------------------------------------------------------------------*/

int bind_to_udp_address(const char *ipaddr, const char *port)
{
	return bind_to_address(ipaddr, port, SOCK_DGRAM, 0);
}

int bind_to_tcp_address(const char *ipaddr, const char *port, int backlog)
{
	return bind_to_address(ipaddr, port, SOCK_STREAM, backlog);
}

/*--------------------------------------------------------------------*/

int bind_to_udp4_port(int port)
{
	return bind_to_port(port, AF_INET, SOCK_DGRAM, 0);
}

int bind_to_tcp4_port(int port, int backlog)
{
	return bind_to_port(port, AF_INET, SOCK_STREAM, backlog);
}

/*--------------------------------------------------------------------*/

int bind_to_udp6_port(int port)
{
	return bind_to_port(port, AF_INET6, SOCK_DGRAM, 0);
}

int bind_to_tcp6_port(int port, int backlog)
{
	return bind_to_port(port, AF_INET6, SOCK_STREAM, backlog);
}

/*--------------------------------------------------------------------*/

int *bind_to_all(const char **ipaddr, int num_ip, const char *port, int backlog)
{
	struct sockaddr_storage	addr;
	struct addrinfo			hints, *ai;
	struct addrinfo *ai0[10]={0,};
	int						*result = 0;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_flags = AI_ADDRCONFIG | AI_PASSIVE;

	int count = 0;
	int i;
	for (i=0; i < num_ip; i++) {
		int res = getaddrinfo(ipaddr[i], port, &hints, &ai);
		if (res) {
			fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(res));
			return NULL;
		}
		ai0[i] = ai;

		/* count the addrinfo objects */
		while (ai) {
			++count; // for each object derived from each ipaddr[] element
			ai = ai->ai_next;
		}    
	}

	/* make some memory for FDs */
	result = (int *)calloc(count + 1, sizeof(int));
	int current = 0;
  
	for (i=0; i < num_ip; i++) {
		for (ai = ai0[i] ; ai; ai = ai->ai_next) {
			if (ai->ai_socktype != SOCK_DGRAM && ai->ai_socktype != SOCK_STREAM) continue;

			int addrlen = ai->ai_addrlen;
			memset(&addr, 0, sizeof(addr));
			memcpy(&addr, ai->ai_addr, addrlen);

			int fd = bind_to_sockaddr((struct sockaddr *)&addr, addrlen, ai->ai_socktype, backlog);
			if (fd >= 0) {
				if (addr.ss_family == AF_INET) {
					struct sockaddr_in *sin = (struct sockaddr_in *)&addr;
					unsigned char *ip = (unsigned char *)&sin->sin_addr.s_addr;
					syslog(LOG_INFO,"Binding to IPv4: %d.%d.%d.%d, File descriptor:%d \n", ip[0], ip[1], ip[2], ip[3], fd);
				} else if (addr.ss_family == AF_INET6) {
					char buffer[INET6_ADDRSTRLEN];
					int err=getnameinfo((struct sockaddr*)&addr,addrlen,buffer,sizeof(buffer),0,0,NI_NUMERICHOST);
					if (err!=0) {
						syslog(LOG_INFO, "Failed to convert address to string (errno=%d)",errno);
						exit(1);
					} else {
						syslog(LOG_INFO,"Binding to IPv6: %s, File descriptor:%d \n", buffer, fd);
					}
				}
				result[current++] = fd;
			}
		}

		/* clean up and terminate */
		freeaddrinfo(ai0[i]);
	}
	result[current] = -1;
	return result;
}

/*--------------------------------------------------------------------*/

int socket_is_tcp(int fd)
{
	int		type;
	socklen_t	typelen = sizeof(type);

	getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &typelen);

	return (type == SOCK_STREAM);
}
