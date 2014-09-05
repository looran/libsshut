#include <stdio.h>
#include <event.h>
#include <sshut.h>

static void
_cb_exec(struct sshut_action *action, char *cmd, char *output, int output_len, void *arg)
{
	printf("> %s\n", cmd);
	printf("%s\n", output);
	event_base_loopbreak(action->ssh->evb);
}

static void
_cb_connect(struct sshut *ssh, void *arg)
{
	printf("Connected !\n");
	sshut_exec(ssh, "uname -ap", _cb_exec, NULL);
}

static void
_cb_disconnect(struct sshut *ssh, enum sshut_error error, void *arg)
{
	if (error)
		sshut_err_print(ssh, error);
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
