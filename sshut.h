#include <bsd/sys/queue.h>
#include <libssh2.h>

#define SSHUT_NOVERBOSE 0
#define SSHUT_VERBOSE 1

enum sshut_reconnect {
	SSHUT_NORECONNECT,
	SSHUT_RECONNECT_3TIMES,
	SSHUT_RECONNECT_INFINITE
};

enum sshut_state {
	SSHUT_STATE_UNINITIALIZED,
	SSHUT_STATE_DISCONNECTED,
	SSHUT_STATE_CONNECTING_SOCKET,
	SSHUT_STATE_CONNECTING_HANDSHAKE,
	SSHUT_STATE_CONNECTING_AUTHENTICATION,
	SSHUT_STATE_CONNECTED,
};

enum sshut_error {
	SSHUT_ERROR_UNKNOWN_STATE,
	SSHUT_ERROR_CONNECTION,
	SSHUT_ERROR_HANDSHAKE,
	SSHUT_ERROR_AUTHENTICATION,
	SSHUT_ERROR_CONNECTION_CLOSED,
	SSHUT_ERROR_CHANNEL_OPEN,
	SSHUT_ERROR_EXEC,
	SSHUT_ERROR_READ,
	SSHUT_ERROR_CHANNEL_CLOSE,
};

enum sshut_actiontype {
	SSHUT_ACTION_EXEC,
};

enum sshut_actionstate {
	SSHUT_ACTIONSTATE_UNINITIALIZED,
	SSHUT_ACTIONSTATE_CHANNEL_OPEN,
	SSHUT_ACTIONSTATE_CHANNEL_EXEC,
	SSHUT_ACTIONSTATE_CHANNEL_READ,
	SSHUT_ACTIONSTATE_CHANNEL_CLOSE,
	SSHUT_ACTIONSTATE_DONE,
};

enum sshut_credstype {
	SSHUT_CREDSTYPE_USERPASS,
};

struct sshut_creds {
	LIST_ENTRY(sshut_creds) entry;
	enum sshut_credstype type;
	union {
		struct {
			char *user;
			char *pass;
		} userpass;
	} dat;
};

struct sshut_auth {
	LIST_HEAD(, sshut_creds) creds;
	int nextcreds;
};

struct sshut_action {
	LIST_ENTRY(sshut_action) entry;
	struct sshut *ssh;
	enum sshut_actiontype type;
	enum sshut_actionstate state;
	struct event *ev_waitsocket;
	struct event *ev_sleep;
	struct timeval tv_sleep;
	struct timeval tv_timeout;
	union {
		struct {
			char *cmd;
			char *output;
			int output_len;
			void (*cbusr_done)(struct sshut_action *, char *, char *, int, void *);
		} exec;
	} t;
	void *cbusr_arg;
	LIBSSH2_CHANNEL *channel;
};

struct sshut {
	struct event_base *evb;
	enum sshut_state state;
	struct event *ev_wait;
	struct timeval tv_wait;
	struct {
		char *ip;
		int port;
		struct sshut_auth *auth;
		enum sshut_reconnect reconnect;
		int verbose;
	} conf;
	struct {
		int sock;
		LIBSSH2_SESSION *session;
		struct sshut_creds *creds_cur;
	} conn;
	LIST_HEAD (, sshut_action) actions;
	void (*cbusr_connect)(struct sshut *, void *);
	void (*cbusr_disconnect)(struct sshut *, enum sshut_error, void *);
	void *cbusr_arg;
};

/* sshut.c */

struct sshut *sshut_new(struct event_base *evb, char *ip, int port, struct sshut_auth *auth, enum sshut_reconnect reconnect, int verbose,
	void (*cbusr_connect)(struct sshut *, void *),
	void (*cbusr_disconnect)(struct sshut *, enum sshut_error, void *), void *arg);
void sshut_free(struct sshut *ssh);

int  sshut_connect(struct sshut *ssh);
void sshut_disconnect(struct sshut *ssh, enum sshut_error error);

void sshut_err_print(struct sshut *ssh, enum sshut_error error);

/* sshut_action.c */

struct sshut_action *sshut_exec(struct sshut *ssh, char *cmd, 
	void (*cbusr_done)(struct sshut_action *, char *, char *, int, void *), void *arg);
/*struct sshut_action *sshut_push(struct sshut *ssh, char *path_local, char *path_remote,
	void (*cb)(struct sshut *, int, void *), void *arg);
struct sshut_action *sshut_pull(struct sshut *ssh, char *path_remote, char *path_local, int flags,
	void (*cb)(struct sshut *, int, void *), void *arg);*/
void sshut_action_close(struct sshut_action *action);

/* sshut_auth.c */

struct sshut_auth *sshut_auth_new(void);
void sshut_auth_free(struct sshut_auth *auth);
int sshut_auth_add_userpass(struct sshut_auth *auth, char *user, char *pass);
struct sshut_creds *sshut_auth_getcreds(struct sshut_auth *auth);
void sshut_auth_rewind(struct sshut_auth *auth);
