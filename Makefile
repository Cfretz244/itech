ARRAY = array.o
LIST = list.o
LIB = sock352.o
CLIENT = client
SERVER = server

CC = gcc
CFLAGS = -I. -I./include -lm -g -lssl -lcrypto -O0 -pthread

all: $(CLIENT) $(SERVER)

$(CLIENT): $(LIB) client.c
	$(CC) $(CFLAGS) -o client client.c $(LIB) $(ARRAY)

$(SERVER): $(LIB) server.c
	$(CC) $(CFLAGS) -o server server.c $(LIB) $(ARRAY)

$(LIB): $(ARRAY) $(LIST) sock352.c sock352.h
	$(CC) $(CFLAGS) -c sock352.c -o sock352.o

$(ARRAY): array.c array.h
	$(CC) $(CFLAGS) -c array.c -o array.o

$(LIST): list.c list.h
	$(CC) $(CFLAGS) -c list.c -o list.o

clean:
	rm *.o
	rm $(CLIENT)
	rm $(SERVER)
