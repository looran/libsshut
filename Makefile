CFLAGS += -Wall -fPIC

PREFIX=/usr/local
INCLUDEDIR=$(PREFIX)/include
LIBDIR=$(PREFIX)/lib
LIBNAME=libsshut

TARGET  = ${LIBNAME}.so
SOURCES = sshut.c sshut_action.c sshut_auth.c
HEADERS = sshut.h
OBJECTS = $(SOURCES:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) -fPIC -shared -o $(TARGET) $(OBJECTS)

install:
	@echo "installation of $(LIBNAME)"
	mkdir -p $(LIBDIR)
	mkdir -p $(INCLUDEDIR)
	install -m 0644 $(TARGET) $(LIBDIR)
	install -m 0644 $(HEADERS) $(INCLUDEDIR)

clean:
	rm -f $(TARGET) $(OBJECTS)

