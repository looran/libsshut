#include <stdio.h>
#include <event.h>
#include <sshut.h>

static void
_cb_push(struct sshut_action *action, enum sshut_error error, void *arg)
{
	if (error != SSHUT_NOERROR)
		sshut_err_print(error);
	else
		printf("Copy done\n");
	event_base_loopbreak(action->ssh->evb);
}

static void
_cb_connect(struct sshut *ssh, void *arg)
{
	printf("Connected !\n");
	sshut_push(ssh, "/etc/issue", "/tmp/pushedissue", _cb_push, NULL);
}

static void
_cb_disconnect(struct sshut *ssh, enum sshut_error error, void *arg)
{
	if (error != SSHUT_NOERROR)
		sshut_err_print(error);
	event_base_loopbreak(ssh->evb);
}

int
main(void)
{
	struct event_base *evb;
	struct sshut_auth *auth;
	struct sshut *ssh;

	evb = event_base_new();

	auth = sshut_auth_new();
	sshut_auth_add_userpass(auth, "login", "password");
	ssh = sshut_new(evb, "127.0.0.1", 22, auth, SSHUT_NORECONNECT, SSHUT_NOVERBOSE,
		_cb_connect, _cb_disconnect, NULL);
	event_base_dispatch(evb);

	sshut_auth_free(auth);
	sshut_free(ssh);
	return 0;
}
