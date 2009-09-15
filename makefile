CC=gcc
SRC=SSLClient.c TCPClient.c Messenger.c Account.c ContactList.c msnlib.c SwitchBoard.c xmalloc.c CmdQueue.c NS.c OIM.c
OBJ=$(SRC:.c=.o)
LIBRARY=libfreemsn.so
CFLAGS=-fPIC -Wall -g3 -DDEBUG -I/usr/include/libxml2
LFLAGS=-lssl -lxml2 -lpthread
TESTS=account.test

all: $(TESTS) $(LIBRARY)

$(LIBRARY): $(OBJ)
	$(CC) -shared -Wl,-soname,libfreemsn.so -o $(LIBRARY) $(OBJ) $(CFLAGS) $(LFLAGS)

account.test: $(LIBRARY) test.c
	$(CC) -o account.test -Wl,--rpath=./ -L./ -lfreemsn test.c $(CFLAGS) $(LFLAGS)

.SUFFIXES: .c .cpp

.c.o:
	$(CC) $(CFLAGS) -c $<

clean:
	rm -rf *.o

