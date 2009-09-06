CC=gcc
SRC=sendmsg.c
OBJ=$(SRC:.c=.o)
PROGRAM=sendmsg
CFLAGS=-I../ `pkg-config --cflags libxml-2.0 openssl` -g3
LFLAGS=-L../ -Wl,--rpath=../
LIBS=-lfreemsn `pkg-config --libs libxml-2.0 openssl`

all: $(PROGRAM)

$(PROGRAM): $(OBJ)
	$(CC) -o $(PROGRAM) $(OBJ) $(CFLAGS) $(LFLAGS) $(LIBS)

.SUFFIXES: .c .cpp

.cpp.o:
	$(CC) $(CFLAGS) -c $<

clean:
	rm -rf *.o

