CC=gcc
SRC=SSLClient.c TCPClient.c Messenger.c Account.c ContactList.c msnlib.c SwitchBoard.c xmalloc.c CmdQueue.c NS.c
OBJ=$(SRC:.c=.o)
LIBRARY=libfreemsn.so
CFLAGS=-fPIC -Wall -g3 -DDEBUG -I/usr/include/libxml2
LFLAGS=-lssl -lxml2 -lpthread
TEST_O=test.o NS.o SSLClient.o TCPClient.o msnlib.o ContactList.o xmalloc.o Account.o SwitchBoard.o CmdQueue.o
TESTS=account.test

all: $(TESTS) $(LIBRARY)

$(LIBRARY): $(OBJ)
	$(CC) -shared -Wl,-soname,libfreemsn.so -o $(LIBRARY) $(OBJ) $(CFLAGS) $(LFLAGS)

account.test: $(TEST_O)
	$(CC) -o account.test $(TEST_O) $(CFLAGS) $(LFLAGS) 

.SUFFIXES: .c .cpp

.c.o:
	$(CC) $(CFLAGS) -c $<

clean:
	rm -rf *.o

