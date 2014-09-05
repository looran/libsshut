#include <stdlib.h>
#include <unistd.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <event.h>


#include "sshut.h"

static void _state(struct sshut *, enum sshut_state);
static void _handshake(struct sshut *);
static void _authentication(struct sshut *);
static void _state_again(struct sshut *);
static void _state_next(struct sshut *, enum sshut_state);
static void _cb_state(int, short, void *);

struct sshut *
sshut_new(struct event_base *evb, char *ip, int port, struct sshut_auth *auth, enum sshut_reconnect reconnect, int verbose,
	void (*cbusr_connect)(struct sshut *, void *),
	void (*cbusr_disconnect)(struct sshut *, enum sshut_error, void *), void *arg)
{
	struct sshut *ssh;

	if (libssh2_init(0))
		return NULL;

	ssh = calloc(1, sizeof(struct sshut));
	ssh->evb = evb;
	ssh->state = SSHUT_STATE_UNINITIALIZED;
	ssh->ev_wait = evtimer_new(evb, _cb_state, ssh);
	ssh->tv_wait.tv_sec = 0;
	//ssh->tv_wait.tv_usec = 100000;
	ssh->tv_wait.tv_usec = 50000;
	ssh->conf.ip = strdup(ip);
	ssh->conf.port = port;
	ssh->conf.auth = auth;
	ssh->conf.reconnect = reconnect;
	ssh->conf.verbose = verbose;
	ssh->cbusr_connect = cbusr_connect;
	ssh->cbusr_disconnect = cbusr_disconnect;
	ssh->cbusr_arg = arg;
	sshut_connect(ssh);

	return ssh;
}

void
sshut_free(struct sshut *ssh)
{
	free(ssh);
}

int
sshut_connect(struct sshut *ssh)
{
	unsigned long hostaddr;
	struct sockaddr_in sin;
	
	ssh->state = SSHUT_STATE_CONNECTING_SOCKET;
	ssh->conn.sock = socket(AF_INET, SOCK_STREAM, 0);
	hostaddr = inet_addr(ssh->conf.ip);
	sin.sin_family = AF_INET;
	sin.sin_port = htons(ssh->conf.port);
	sin.sin_addr.s_addr = hostaddr;
	// XXX async connect
	if (connect(ssh->conn.sock, (struct sockaddr*)(&sin),
				sizeof(struct sockaddr_in)) != 0) {
		sshut_disconnect(ssh, SSHUT_ERROR_CONNECTION);
		return -1;
	}
	ssh->conn.session = libssh2_session_init();
	libssh2_session_set_blocking(ssh->conn.session, 0);
	if (ssh->conf.verbose)
		libssh2_trace(ssh->conn.session, LIBSSH2_TRACE_KEX|LIBSSH2_TRACE_AUTH);
	_state_next(ssh, SSHUT_STATE_CONNECTING_HANDSHAKE);
	return 0;
}

void
sshut_disconnect(struct sshut *ssh, enum sshut_error error)
{
	close(ssh->conn.sock);
	ssh->cbusr_disconnect(ssh, error, ssh->cbusr_arg);
}

void
sshut_err_print(struct sshut *ssh, enum sshut_error error)
{
	printf("sshut error: %d\n", error);
}

static void
_state(struct sshut *ssh, enum sshut_state state)
{
	ssh->state = state;

	switch (state) {
	case SSHUT_STATE_CONNECTING_HANDSHAKE:
		_handshake(ssh);
		break;
	case SSHUT_STATE_CONNECTING_AUTHENTICATION:
		_authentication(ssh);
		break;
	case SSHUT_STATE_CONNECTED:
		ssh->cbusr_connect(ssh, ssh->cbusr_arg);
		break;
	case SSHUT_STATE_UNINITIALIZED:
	case SSHUT_STATE_DISCONNECTED:
	case SSHUT_STATE_CONNECTING_SOCKET:
		sshut_disconnect(ssh, SSHUT_ERROR_UNKNOWN_STATE);
		break;
	}
}

static void
_handshake(struct sshut *ssh)
{
	int rc;

	rc = libssh2_session_handshake(ssh->conn.session, ssh->conn.sock);
	if (!rc)
		_state_next(ssh, SSHUT_STATE_CONNECTING_AUTHENTICATION);
	else if (rc == LIBSSH2_ERROR_EAGAIN)
		_state_again(ssh);
	else
		sshut_disconnect(ssh, SSHUT_ERROR_HANDSHAKE);
		
}

static void
_authentication(struct sshut *ssh)
{
	struct sshut_creds *creds;
	int rc;

	creds = ssh->conn.creds_cur;
	if (!creds) {
		creds = sshut_auth_getcreds(ssh->conf.auth);
		if (!creds) {
			sshut_disconnect(ssh, SSHUT_ERROR_AUTHENTICATION);
			return;
		}
	}
	switch (creds->type) {
	case SSHUT_CREDSTYPE_USERPASS:
		rc = libssh2_userauth_password(ssh->conn.session, creds->dat.userpass.user, creds->dat.userpass.pass);
		break;
	}
	ssh->conn.creds_cur = creds;
	if (!rc)
		_state_next(ssh, SSHUT_STATE_CONNECTED);
	else if (rc == LIBSSH2_ERROR_EAGAIN)
		_state_again(ssh);
	else {
		/* next auth */
		ssh->conn.creds_cur = NULL;
		_state_again(ssh);
	}
}

static void
_state_again(struct sshut *ssh)
{
	evtimer_add(ssh->ev_wait, &ssh->tv_wait);
}

static void
_state_next(struct sshut *ssh, enum sshut_state state)
{
	ssh->state = state;
	evtimer_add(ssh->ev_wait, &ssh->tv_wait);
}

static void
_cb_state(int fd, short why, void *data)
{
	struct sshut *ssh;

	ssh = data;
	_state(ssh, ssh->state);
}

