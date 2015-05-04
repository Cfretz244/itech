ARRAY = array.o
QUEUE = queue.o
LIBS = sock352lib.o libsodium.a
CLIENT = client
CLIENT2 = client2
SERVER = server
SERVER2 = server2
CLIENTSEC = client_crypto
SERVERSEC = server_crypto

CC = gcc
CFLAGS = -I. -I./include -I sodium -lm -g -lssl -lcrypto -O0 -pthread

all: $(CLIENT) $(SERVER) $(CLIENT2) $(SERVER2) $(CLIENTSEC) $(SERVERSEC)

$(CLIENT): $(LIBS) client.c
	$(CC) $(CFLAGS) -o $(CLIENT) client.c $(LIBS) $(ARRAY) $(QUEUE)

$(CLIENT2): $(LIBS) client2.c
	$(CC) $(CFLAGS) -o $(CLIENT2) client2.c $(LIBS) $(ARRAY) $(QUEUE)

$(CLIENTSEC): $(LIBS) client_crypto.c
	$(CC) $(CFLAGS) -o $(CLIENTSEC) client_crypto.c $(LIBS) $(ARRAY) $(QUEUE)

$(SERVER): $(LIBS) server.c
	$(CC) $(CFLAGS) -o $(SERVER) server.c $(LIBS) $(ARRAY) $(QUEUE)

$(SERVER2): $(LIBS) server2.c
	$(CC) $(CFLAGS) -o $(SERVER2) server2.c $(LIBS) $(ARRAY) $(QUEUE)

$(SERVERSEC): $(LIBS) server_crypto.c
	$(CC) $(CFLAGS) -o $(SERVERSEC) server_crypto.c $(LIBS) $(ARRAY) $(QUEUE)

$(LIBS): $(ARRAY) $(QUEUE) sock352.c sock352.h
	$(CC) $(CFLAGS) -c sock352.c -o $(LIBS)

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
	rm $(CLIENTSEC)
	rm $(SERVERSEC)
