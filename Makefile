ARRAY = array.o
QUEUE = queue.o
LIB = sock352lib.o
CLIENT = client
CLIENT2 = client2
SERVER = server
SERVER2 = server2

CC = gcc
CFLAGS = -I. -I./include -lm -g -lssl -lcrypto -O0 -pthread

all: $(CLIENT) $(SERVER) $(CLIENT2) $(SERVER2)

$(CLIENT): $(LIB) client.c
	$(CC) $(CFLAGS) -o $(CLIENT) client.c $(LIB) $(ARRAY) $(QUEUE)

$(CLIENT2): $(LIB) client2.c
	$(CC) $(CFLAGS) -o $(CLIENT2) client2.c $(LIB) $(ARRAY) $(QUEUE)

$(SERVER): $(LIB) server.c
	$(CC) $(CFLAGS) -o $(SERVER) server.c $(LIB) $(ARRAY) $(QUEUE)

$(SERVER2): $(LIB) server2.c
	$(CC) $(CFLAGS) -o $(SERVER2) server2.c $(LIB) $(ARRAY) $(QUEUE)

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
	rm $(CLIENT2)
	rm $(SERVER2)
