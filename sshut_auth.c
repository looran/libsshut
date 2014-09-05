/* libsshut - ssh utility library */
/* Copyright (c) 2014 Laurent Ghigonis <laurent@gouloum.fr>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

#include "sshut.h"

static void _creds_free(struct sshut_creds *);

struct sshut_auth *
sshut_auth_new(void)
{
	struct sshut_auth *auth;

	auth = calloc(1, sizeof(struct sshut_auth));
	return auth;
}

void
sshut_auth_free(struct sshut_auth *auth)
{
	struct sshut_creds *creds, *credst;

	LIST_FOREACH_SAFE(creds, &auth->creds, entry, credst) {
		_creds_free(creds);
	}
	free(auth);
}

int
sshut_auth_add_userpass(struct sshut_auth *auth, char *user, char *pass)
{
	struct sshut_creds *creds;

	creds = calloc(1, sizeof(struct sshut_creds));
	creds->type = SSHUT_CREDSTYPE_USERPASS;
	creds->dat.userpass.user = strdup(user);
	creds->dat.userpass.pass = strdup(pass);
	LIST_INSERT_HEAD(&auth->creds, creds, entry);
	return 1;
}

struct sshut_creds *
sshut_auth_getcreds(struct sshut_auth *auth)
{
	struct sshut_creds *creds;
	int n;

	n = 0;
	LIST_FOREACH(creds, &auth->creds, entry) {
		if (auth->nextcreds == n) {
			auth->nextcreds++;
			return creds;
		}
	}
	auth->nextcreds = 0;
	return NULL;
}

void
sshut_auth_rewind(struct sshut_auth *auth)
{
	auth->nextcreds = 0;
}

static void
_creds_free(struct sshut_creds *creds)
{
	switch(creds->type) {
	case SSHUT_CREDSTYPE_USERPASS:
		free(creds->dat.userpass.user);
		free(creds->dat.userpass.pass);
	}
	free(creds);
}
