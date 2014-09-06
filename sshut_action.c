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
#include <event.h>

#include "sshut.h"

#define LOG_VERBOSE(parg, ...) if (action->ssh->conf.verbose) { printf("sshut_action: " parg, ##__VA_ARGS__); }

int actionstates[2][7] = 
{
	/* SSHUT_ACTION_EXEC */
	{SSHUT_ACTIONSTATE_UNINITIALIZED,
	 SSHUT_ACTIONSTATE_CHANNEL_OPEN,
	 SSHUT_ACTIONSTATE_CHANNEL_EXEC,
	 SSHUT_ACTIONSTATE_CHANNEL_READ,
	 SSHUT_ACTIONSTATE_CHANNEL_CLOSE,
	 SSHUT_ACTIONSTATE_DONE},
	/* SSHUT_ACTION_PUSH */
	{SSHUT_ACTIONSTATE_UNINITIALIZED,
	 SSHUT_ACTIONSTATE_CHANNEL_OPEN_SCP_SEND,
	 SSHUT_ACTIONSTATE_CHANNEL_WRITE_FROMFILE,
	 SSHUT_ACTIONSTATE_CHANNEL_SEND_EOF,
	 SSHUT_ACTIONSTATE_CHANNEL_WAIT_EOF,
	 SSHUT_ACTIONSTATE_CHANNEL_WAIT_CLOSED,
	 SSHUT_ACTIONSTATE_DONE}
};

struct sshut_action *_new(struct sshut *, enum sshut_actiontype);
static void _state(struct sshut_action *, enum sshut_actionstate);
static void _channel_open(struct sshut_action *);
static void _channel_open_scp_send(struct sshut_action *);
static void _channel_open_scp_recv(struct sshut_action *);
static void _channel_exec(struct sshut_action *);
static void _channel_read(struct sshut_action *);
static void _channel_write_fromfile(struct sshut_action *);
static void _channel_send_eof(struct sshut_action *);
static void _channel_wait_eof(struct sshut_action *);
static void _channel_wait_closed(struct sshut_action *);
static void _channel_close(struct sshut_action *);
static void _done(struct sshut_action *);
static void _error(struct sshut_action *, enum sshut_error);
static void _state_again(struct sshut_action *);
static void _state_again_waitsocket(struct sshut_action *);
static void _state_next(struct sshut_action *);
static enum sshut_actionstate _state_next_get(enum sshut_actiontype, enum sshut_actionstate);
static void _cb_state(int, short, void *);

struct sshut_action *
sshut_exec(struct sshut *ssh, char *cmd, 
	void (*cbusr_done)(struct sshut_action *, enum sshut_error, char *, char *, int, void *), void *arg)
{
	struct sshut_action *action;

	action = _new(ssh, SSHUT_ACTION_EXEC);
	action->t.exec.cmd = strdup(cmd);
	action->t.exec.cbusr_done = cbusr_done;
	action->cbusr_arg = arg;

	_state_next(action);
	return action;
}

struct sshut_action *
sshut_push(struct sshut *ssh, char *path_local, char *path_remote,
	void (*cbusr_done)(struct sshut_action *, enum sshut_error, void *), void *arg)
{
	struct sshut_action *action;

	action = _new(ssh, SSHUT_ACTION_PUSH);
	action->t.push.path_local = strdup(path_local);
	action->t.push.path_remote = strdup(path_remote);
	action->t.push.cbusr_done = cbusr_done;
	action->cbusr_arg = arg;

	action->t.push.file = fopen(path_local, "rb");
	if (!action->t.push.file) {
		sshut_action_close(action);
		return NULL;
	}
	stat(action->t.push.path_local, &action->t.push.fileinfo);
	action->t.push.filebuf = malloc(SSHUT_FILEBUF_SIZE * sizeof(char));

	_state_next(action);
	return action;
}

void
sshut_action_close(struct sshut_action *action)
{
	switch(action->type) {
	case SSHUT_ACTION_EXEC:
		action->t.exec.cbusr_done(action, action->error, action->t.exec.cmd,
			action->t.exec.output, action->t.exec.output_len,
			action->cbusr_arg);
		break;
	case SSHUT_ACTION_PUSH:
		action->t.push.cbusr_done(action, action->error, action->cbusr_arg);
		if (action->t.push.file)
			fclose(action->t.push.file);
		if (action->t.push.filebuf)
			free(action->t.push.filebuf);
		break;
	}
}

struct sshut_action *
_new(struct sshut *ssh, enum sshut_actiontype type)
{
	struct sshut_action *action;

	action = calloc(1, sizeof(struct sshut_action));
	action->ssh = ssh;
	action->type = type;
	action->state = SSHUT_ACTIONSTATE_UNINITIALIZED;
	action->error = SSHUT_NOERROR;
	action->ev_sleep = evtimer_new(ssh->evb, _cb_state, action);
	action->tv_sleep.tv_sec = 0;
	//action->tv_sleep.tv_usec = 100000;
	action->tv_sleep.tv_usec = 50000;
	action->tv_timeout.tv_sec = 10;
	action->tv_timeout.tv_usec = 0;
	return action;
}

static void
_state(struct sshut_action *action, enum sshut_actionstate state)
{
	action->state = state;

	switch (state) {
	case SSHUT_ACTIONSTATE_UNINITIALIZED: _error(action, SSHUT_ERROR_UNKNOWN_STATE); break;
	case SSHUT_ACTIONSTATE_CHANNEL_OPEN: _channel_open(action); break;
	case SSHUT_ACTIONSTATE_CHANNEL_OPEN_SCP_SEND: _channel_open_scp_send(action); break;
	case SSHUT_ACTIONSTATE_CHANNEL_OPEN_SCP_RECV: _channel_open_scp_recv(action); break;
	case SSHUT_ACTIONSTATE_CHANNEL_EXEC: _channel_exec(action); break;
	case SSHUT_ACTIONSTATE_CHANNEL_READ: _channel_read(action); break;
	case SSHUT_ACTIONSTATE_CHANNEL_WRITE_FROMFILE: _channel_write_fromfile(action); break;
	case SSHUT_ACTIONSTATE_CHANNEL_SEND_EOF: _channel_send_eof(action); break;
	case SSHUT_ACTIONSTATE_CHANNEL_WAIT_EOF: _channel_wait_eof(action); break;
	case SSHUT_ACTIONSTATE_CHANNEL_WAIT_CLOSED: _channel_wait_closed(action); break;
	case SSHUT_ACTIONSTATE_CHANNEL_CLOSE: _channel_close(action); break;
	case SSHUT_ACTIONSTATE_DONE: _done(action); break;
	}
}

static void
_channel_open(struct sshut_action *action)
{
	int rc;

	action->channel = libssh2_channel_open_session(action->ssh->conn.session);
	rc = libssh2_session_last_error(action->ssh->conn.session, NULL, NULL, 0);
	if (!rc || action->channel)
		_state_next(action);
	else if (rc == LIBSSH2_ERROR_EAGAIN)
		_state_again_waitsocket(action);
	else
		_error(action, SSHUT_ERROR_CHANNEL_OPEN);
}

static void
_channel_open_scp_send(struct sshut_action *action)
{
	int rc;

	action->channel = libssh2_scp_send(action->ssh->conn.session, action->t.push.path_remote,
		action->t.push.fileinfo.st_mode & 0777, (unsigned long)action->t.push.fileinfo.st_size);
	rc = libssh2_session_last_error(action->ssh->conn.session, NULL, NULL, 0);
	if (!rc || action->channel)
		_state_next(action);
	else if (rc == LIBSSH2_ERROR_EAGAIN)
		_state_again_waitsocket(action);
	else
		_error(action, SSHUT_ERROR_CHANNEL_OPEN_SCP_SEND);
}

static void
_channel_open_scp_recv(struct sshut_action *action)
{

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
		_error(action, SSHUT_ERROR_EXEC);
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
		_error(action, SSHUT_ERROR_READ);
}

static void
_channel_write_fromfile(struct sshut_action *action)
{
	int rc;
	char *filebuf_start;

	//printf("_channel_write_fromfile\n");
	if (!action->t.push.filebuf_remaining) {
		action->t.push.filebuf_size = fread(action->t.push.filebuf, 1, SSHUT_FILEBUF_SIZE,
							action->t.push.file); // XXX sizeof(buf), 1 ???
		action->t.push.filebuf_remaining = action->t.push.filebuf_size;
	}
	if (action->t.push.filebuf_remaining <= 0) {
		_state_next(action); /* EOF */
		return;
	}
	filebuf_start = (action->t.push.filebuf + action->t.push.filebuf_size) - action->t.push.filebuf_remaining;
	//printf("filebuf_start=%p filebuf=%p filebuf_size=%d filebuf_remaining=%d\n", filebuf_start, action->t.push.filebuf, action->t.push.filebuf_size, action->t.push.filebuf_remaining);
	rc = libssh2_channel_write(action->channel, filebuf_start, action->t.push.filebuf_remaining);
	//printf("rc = %d\n", rc);
	if (rc >= 0) {
		action->t.push.filebuf_remaining -= rc;
		_state_again(action);
	}
	else if (rc == LIBSSH2_ERROR_EAGAIN)
		_state_again_waitsocket(action);
	else
		_error(action, SSHUT_ERROR_WRITE_FROMFILE);
}

static void
_channel_send_eof(struct sshut_action *action)
{
	int rc;

	rc = libssh2_channel_send_eof(action->channel);
	if (!rc)
		_state_next(action);
	else if (rc == LIBSSH2_ERROR_EAGAIN)
		_state_again(action);
	else
		_error(action, SSHUT_ERROR_SEND_EOF);
}

static void
_channel_wait_eof(struct sshut_action *action)
{
	int rc;

	rc = libssh2_channel_wait_eof(action->channel);
	if (!rc)
		_state_next(action);
	else if (rc == LIBSSH2_ERROR_EAGAIN)
		_state_again(action);
	else
		_error(action, SSHUT_ERROR_WAIT_EOF);
}

static void
_channel_wait_closed(struct sshut_action *action)
{
	int rc;

	rc = libssh2_channel_wait_closed(action->channel);
	if (!rc)
		_state_next(action);
	else if (rc == LIBSSH2_ERROR_EAGAIN)
		_state_again(action);
	else
		_error(action, SSHUT_ERROR_WAIT_CLOSED);
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
		_error(action, SSHUT_ERROR_CHANNEL_CLOSE);
}

static void
_done(struct sshut_action *action)
{
	sshut_action_close(action);
}

static void
_error(struct sshut_action *action, enum sshut_error error)
{
	action->error = error;
	_done(action);
}

static void
_state_again(struct sshut_action *action)
{
	LOG_VERBOSE("_state_again\n");
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

	LOG_VERBOSE("_state_again_waitsocket %d %d (channel=%p)\n", dir, flags, action->channel);
	action->ev_waitsocket = event_new(action->ssh->evb,
		action->ssh->conn.sock, flags, _cb_state, action);
	event_add(action->ev_waitsocket, &action->tv_timeout);
}

static void
_state_next(struct sshut_action *action)
{
	action->state = _state_next_get(action->type, action->state);
	LOG_VERBOSE("_state_next: %d\n", action->state);
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
		if (s == state) return actionstates[type][i+1];
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

