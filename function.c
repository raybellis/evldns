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
#include <unistd.h>
#include <sys/queue.h>
#include <evldns.h>

static TAILQ_HEAD(fbq, fb_function)	funcs;

struct fb_function {
	TAILQ_ENTRY(fb_function)	 next;
	const char			*name;
	evldns_callback			 func;
};
typedef struct fb_function fb_function;

void evldns_init(void)
{
	TAILQ_INIT(&funcs);
}

void evldns_add_function(const char *name, evldns_callback func)
{
	fb_function *f = (fb_function *)malloc(sizeof(fb_function));
	memset(f, 0, sizeof(fb_function));
	f->name = strdup(name);
	f->func = func;
	TAILQ_INSERT_TAIL(&funcs, f, next);
}

evldns_callback evldns_get_function(const char *name)
{
	fb_function *func;
	TAILQ_FOREACH(func, &funcs, next) {
		if (strcmp(func->name, name) == 0) {
			return func->func;
		}
	}
	return NULL;
}
