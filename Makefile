ARRAY = array.o
QUEUE = queue.o
LIB = sock352lib.o
CLIENT = client
SERVER = server

CC = gcc
CFLAGS = -I. -I./include -lm -g -lssl -lcrypto -O0 -pthread

all: $(CLIENT) $(SERVER)

$(CLIENT): $(LIB) client.c
	$(CC) $(CFLAGS) -o $(CLIENT) client.c $(LIB) $(ARRAY) $(QUEUE)

$(SERVER): $(LIB) server.c
	$(CC) $(CFLAGS) -o $(SERVER) server.c $(LIB) $(ARRAY) $(QUEUE)

$(LIB): $(ARRAY) $(QUEUE) sock352.c sock352.h
	$(CC) $(CFLAGS) -c sock352.c -o $(LIB)

$(ARRAY): array.c array.h
	$(CC) $(CFLAGS) -c array.c -o $(ARRAY)

$(QUEUE): queue.c queue.h
	$(CC) $(CFLAGS) -c queue.c -o $(QUEUE)

clean:
	rm *.o
	rm $(CLIENT)
	rm $(SERVER)
