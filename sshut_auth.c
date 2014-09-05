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
