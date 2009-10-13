CC=gcc
SRC=sendmsg.c sendmsg_callback.c
OBJ=$(SRC:.c=.o)
PROGRAM=sendmsg sendmsg_callback
CFLAGS=-I../ `pkg-config --cflags libxml-2.0 openssl` -g3
LFLAGS=-L../ -Wl,--rpath=../
LIBS=-lfreemsn `pkg-config --libs libxml-2.0 openssl`

all: $(PROGRAM)

sendmsg: sendmsg.o
	$(CC) -o sendmsg sendmsg.o $(CFLAGS) $(LFLAGS) $(LIBS)

sendmsg_callback: sendmsg_callback.o
	$(CC) -o sendmsg_callback sendmsg_callback.o $(CFLAGS) $(LFLAGS) $(LIBS)

.SUFFIXES: .c .cpp

.cpp.o:
	$(CC) $(CFLAGS) -c $<

clean:
	rm -rf *.o

