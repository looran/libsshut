#include <stdlib.h>
#include <event.h>

#include "sshut.h"

int actionstates[1][6] = 
{
	/* SSHUT_ACTION_EXEC */
	{SSHUT_ACTIONSTATE_UNINITIALIZED,
	 SSHUT_ACTIONSTATE_CHANNEL_OPEN,
	 SSHUT_ACTIONSTATE_CHANNEL_EXEC,
	 SSHUT_ACTIONSTATE_CHANNEL_READ,
	 SSHUT_ACTIONSTATE_CHANNEL_CLOSE,
	 SSHUT_ACTIONSTATE_DONE}
};

static void _state(struct sshut_action *, enum sshut_actionstate);
static void _channel_open(struct sshut_action *);
static void _channel_exec(struct sshut_action *);
static void _channel_read(struct sshut_action *);
static void _channel_close(struct sshut_action *);
static void _done(struct sshut_action *);
static void _state_again(struct sshut_action *);
static void _state_again_waitsocket(struct sshut_action *);
static void _state_next(struct sshut_action *);
static enum sshut_actionstate _state_next_get(enum sshut_actiontype, enum sshut_actionstate);
static void _cb_state(int, short, void *);

struct sshut_action *
sshut_exec(struct sshut *ssh, char *cmd, 
	void (*cbusr_done)(struct sshut_action *, char *, char *, int, void *), void *arg)
{
	struct sshut_action *action;

	action = calloc(1, sizeof(struct sshut_action));
	action->ssh = ssh;
	action->type = SSHUT_ACTION_EXEC;
	action->state = SSHUT_ACTIONSTATE_UNINITIALIZED;
	action->ev_sleep = evtimer_new(ssh->evb, _cb_state, action);
	action->tv_sleep.tv_sec = 0;
	//action->tv_sleep.tv_usec = 100000;
	action->tv_sleep.tv_usec = 50000;
	action->tv_timeout.tv_sec = 10;
	action->tv_timeout.tv_usec = 0;
	action->t.exec.cmd = strdup(cmd);
	action->t.exec.cbusr_done = cbusr_done;
	action->cbusr_arg = arg;
	_state_next(action);
	return action;
}

void
sshut_action_close(struct sshut_action *action)
{
	
}

static void
_state(struct sshut_action *action, enum sshut_actionstate state)
{
	action->state = state;

	switch (state) {
	case SSHUT_ACTIONSTATE_UNINITIALIZED:
		sshut_disconnect(action->ssh, SSHUT_ERROR_UNKNOWN_STATE);
		break;
	case SSHUT_ACTIONSTATE_CHANNEL_OPEN:
		_channel_open(action);
		break;
	case SSHUT_ACTIONSTATE_CHANNEL_EXEC:
		_channel_exec(action);
		break;
	case SSHUT_ACTIONSTATE_CHANNEL_READ:
		_channel_read(action);
		break;
	case SSHUT_ACTIONSTATE_CHANNEL_CLOSE:
		_channel_close(action);
		break;
	case SSHUT_ACTIONSTATE_DONE:
		_done(action);
		break;
	}
}

static void
_channel_open(struct sshut_action *action)
{
	int rc;

	action->channel = libssh2_channel_open_session(action->ssh->conn.session);
	rc = libssh2_session_last_error(action->ssh->conn.session,NULL,NULL,0);
	if (!rc || action->channel)
		_state_next(action);
	else if (rc == LIBSSH2_ERROR_EAGAIN)
		_state_again_waitsocket(action);
	else
		sshut_disconnect(action->ssh, SSHUT_ERROR_CHANNEL_OPEN);
}

static void
_channel_exec(struct sshut_action *action)
{
	int rc;

	rc = libssh2_channel_exec(action->channel, action->t.exec.cmd);
	if (!rc)
		_state_next(action);
	else if (rc == LIBSSH2_ERROR_EAGAIN)
		_state_again_waitsocket(action);
	else
		sshut_disconnect(action->ssh, SSHUT_ERROR_EXEC);
}

static void
_channel_read(struct sshut_action *action)
{
	char buf[0x1000];
	int rc, newlen;

	rc = libssh2_channel_read(action->channel, buf, sizeof(buf));
	if (rc > 0) {
		newlen = action->t.exec.output_len + rc;
		action->t.exec.output = realloc(action->t.exec.output, newlen);
		memcpy(action->t.exec.output + action->t.exec.output_len, buf, rc);
		action->t.exec.output_len = newlen;
		_state_again(action);
	}
	else if (!rc)
		_state_next(action);
	else if (rc == LIBSSH2_ERROR_EAGAIN)
		_state_again_waitsocket(action);
	else
		sshut_disconnect(action->ssh, SSHUT_ERROR_READ);
}

static void
_channel_close(struct sshut_action *action)
{
	int rc;

	rc = libssh2_channel_close(action->channel);
	if (!rc)
		_state_next(action);
	else if (rc == LIBSSH2_ERROR_EAGAIN)
		_state_again_waitsocket(action);
	else
		sshut_disconnect(action->ssh, SSHUT_ERROR_CHANNEL_CLOSE);
}

static void
_done(struct sshut_action *action)
{
	switch(action->type) {
	case SSHUT_ACTION_EXEC:
		action->t.exec.cbusr_done(action, action->t.exec.cmd,
			action->t.exec.output, action->t.exec.output_len,
			action->cbusr_arg);
		sshut_action_close(action);
		break;
	}
}

static void
_state_again(struct sshut_action *action)
{
	evtimer_add(action->ev_sleep, &action->tv_sleep);
}

static void
_state_again_waitsocket(struct sshut_action *action)
{
	int dir, flags;

	flags = 0;
	dir = libssh2_session_block_directions(action->ssh->conn.session);
	if (dir & LIBSSH2_SESSION_BLOCK_INBOUND)
		flags = flags | EV_READ;
	if (dir & LIBSSH2_SESSION_BLOCK_OUTBOUND)
		flags = flags | EV_WRITE;

	//printf("_state_again_waitsocket %d %d (channel=%p)\n", dir, flags, action->channel);
	action->ev_waitsocket = event_new(action->ssh->evb,
		action->ssh->conn.sock, flags, _cb_state, action);
	event_add(action->ev_waitsocket, &action->tv_timeout);
}

static void
_state_next(struct sshut_action *action)
{
	action->state = _state_next_get(action->type, action->state);
	//printf("_state_next: %d\n", action->state);
	evtimer_add(action->ev_sleep, &action->tv_sleep);
}

static enum sshut_actionstate
_state_next_get(enum sshut_actiontype type, enum sshut_actionstate state)
{
	enum sshut_actionstate s;
	int i;

	i = 0;
	do {
		s = actionstates[type][i];
		if (s == state)
			return actionstates[type][i+1];
		i++;
	} while (s != SSHUT_ACTIONSTATE_DONE);

	return SSHUT_ACTIONSTATE_DONE;
}

static void
_cb_state(int fd, short why, void *data)
{
	struct sshut_action *action;

	action = data;
	_state(action, action->state);
}

