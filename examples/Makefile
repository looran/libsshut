LD_LIBRARY_PATH = $(LD_LIBRARY_PATH):../

all:
	$(CC) -I../ -L../ -o exec exec.c -lsshut -levent -lssh2
	$(CC) -I../ -L../ -o push push.c -lsshut -levent -lssh2

