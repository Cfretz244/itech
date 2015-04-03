#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/select.h>
#include <pthread.h>
#include <sys/time.h>
#include <endian.h>
#include "sock352.h"
#include "array.h"
#include "queue.h"

/*---- Private Constants -----*/

#define MAX_UDP_PACKET 65535
#define MAX_WINDOW_SIZE 8
#define RECEIVE_TIMEOUT 200000

/*----- Private Struct Declarations -----*/

typedef enum sock352_types {
    SOCK352_UNSET,
    SOCK352_LISTEN,
    SOCK352_ACCEPT,
    SOCK352_CLIENT
} sock352_types_t;

// Struct represents a packet to be sent, acknowledged, or read.
typedef struct sock352_chunk {
    sock352_pkt_hdr_t header;
    void *data;
    int size;
    struct timeval time;
} sock352_chunk_t;

// Struct maintains state for a single connection.
typedef struct sock352_socket {
    int fd, bound, lfin, rfin, lport, rport, lacked, lack_no, bad_acks;
    uint64_t lseq_num, rseq_num, last_ack;
    sock352_types_t type;
    sockaddr_sock352_t laddr, raddr;
    queue_t *send_queue, *recv_queue;
    pthread_t *send_thread, *recv_thread;
    socklen_t len;
} sock352_socket_t;

/*----- Socket Manipulation Function Declarations -----*/

sock352_socket_t *create_352socket(int fd);
sock352_socket_t *copysock(sock352_socket_t *socket);
void *send_queue(void *sock);
void *recv_queue(void *sock);
void destroy_352socket(sock352_socket_t *socket);

/*----- Queue Manipulation Function Declarations -----*/

void queue_send(queue_t *q, sock352_pkt_hdr_t *header, void *data);
int queue_recv(queue_t *q, void *data, int size);

/*----- Packet Manipulation Function Declarations -----*/

int send_packet(sock352_pkt_hdr_t *header, void *data, int nbytes, sock352_socket_t *socket);
int recv_packet(sock352_pkt_hdr_t *header, void *data, sock352_socket_t *socket, int timeout, int save_addr);
int valid_packet(sock352_pkt_hdr_t *header, void *data, int flags);
int valid_sequence(sock352_pkt_hdr_t *header, sock352_socket_t *socket);
int valid_ack(sock352_pkt_hdr_t *header, int expected, int exact);

/*----- Header Manipulation Function Declarations -----*/

void create_header(sock352_pkt_hdr_t *header, uint64_t sequence_num, uint64_t ack_num, uint8_t flags, uint16_t checksum, uint32_t len);
void encode_header(sock352_pkt_hdr_t *header);
void decode_header(sock352_pkt_hdr_t *header);
void setup_sockaddr(sockaddr_sock352_t *addr, struct sockaddr_in *udp_addr);

/*----- Misc. Utility Function Declarations -----*/

sock352_chunk_t *create_chunk(sock352_pkt_hdr_t *header, void *data);
void destroy_chunk(sock352_chunk_t *chunk);

/*----- Globals -----*/

int uport = -1, ruport = -1, luport = -1, fd_counter = 0;
array *sockets;

/*----- Socket API Function Implementations -----*/

// Function is responsible for initializing the library.
int sock352_init(int udp_port) {
    if (udp_port <= 0 || uport >= 0) return SOCK352_FAILURE;
    puts("sock352_init: Starting...");

    uport = udp_port;
    sockets = create_array();
    return SOCK352_SUCCESS;
}

// Function is responsible for initializing the library when running both client and server on the same machine.
int sock352_init2(int remote_port, int local_port) {
    if (remote_port <= 0 || local_port <= 0 || luport >= 0 || ruport >= 0) return SOCK352_FAILURE;
    puts("sock352_init2: Starting...");

    ruport = remote_port;
    luport = local_port;
    sockets = create_array();
    return SOCK352_SUCCESS;
}

int sock352_init3(int remote_port, int local_port, char **envp) {
    puts("sock352_init3: Starting...");
    return sock352_init2(remote_port, local_port);
}

// Function is responsible for returning a socket for the given configuration.
int sock352_socket(int domain, int type, int protocol) {
    if (domain != AF_CS352 || type != SOCK_STREAM || protocol != 0) {
        return SOCK352_FAILURE;
    }
    puts("sock352_socket: Starting...");

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return SOCK352_FAILURE;
    int fd_352 = fd_counter++;
    insert(sockets, fd_352, create_352socket(fd));

    return fd_352;
}

// Function is responsible for binding to the given local port.
int sock352_bind(int fd, sockaddr_sock352_t *addr, socklen_t len) {
    sock352_socket_t *socket = retrieve(sockets, fd);
    memcpy(&socket->laddr, addr, sizeof(sockaddr_sock352_t));
    puts("sock352_bind: Starting...");

    struct sockaddr_in udp_addr;
    udp_addr.sin_family = AF_INET;
    udp_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    if (uport > 0) {
        udp_addr.sin_port = htons((short) uport);
    } else {
        udp_addr.sin_port = htons((short) luport);
    }

    puts("sock352_bind: Calling bind...");
    return bind(socket->fd, (struct sockaddr *) &udp_addr, len);
}

// Function is responsible for the client's half of the 3 way TCP connection handshake.
int sock352_connect(int fd, sockaddr_sock352_t *addr, socklen_t len) {
    int e_count = 0;
    sock352_socket_t *socket = retrieve(sockets, fd);
    memcpy(&socket->raddr, addr, sizeof(sockaddr_sock352_t));
    socket->type = SOCK352_CLIENT;
    puts("sock352_connect: Starting...");

    // Bind to local port.
    sockaddr_sock352_t laddr;
    laddr.sin_addr.s_addr = htonl(INADDR_ANY);
    if (uport > 0) {
        laddr.sin_port = htons((short) uport);
    } else {
        laddr.sin_port = htons((short) luport);
    }
    int status = sock352_bind(fd, &laddr, len);
    if (status) return SOCK352_FAILURE;

    // Send SYN.
    sock352_pkt_hdr_t header;
    create_header(&header, socket->lseq_num, 0, SOCK352_SYN, 0, 0);
    printf("sock352_connect: Sending SYN packet with initial sequence number %ld...\n", header.sequence_no);
    encode_header(&header);
    status = send_packet(&header, NULL, 0, socket);
    if (status < 0) return SOCK352_FAILURE;

    // Receive SYN/ACK.
    sock352_pkt_hdr_t resp_header;
    status = recv_packet(&resp_header, NULL, socket, 1, 0);
    while (!valid_packet(&resp_header, NULL, SOCK352_SYN | SOCK352_ACK) || !valid_ack(&resp_header, socket->lseq_num, 1) || status == SOCK352_FAILURE) {
        if (++e_count > 5) return SOCK352_FAILURE;
        send_packet(&header, NULL, 0, socket);
        recv_packet(&resp_header, NULL, socket, 1, 0);
    }
    printf("sock352_connect: Received SYN/ACK with sequence number %ld and ACK number %ld...\n", resp_header.sequence_no, resp_header.ack_no);
    puts("sock352_connect: Received SYN/ACK...");
    e_count = 0;
    socket->last_ack = resp_header.ack_no;
    socket->lseq_num++;
    socket->rseq_num = resp_header.sequence_no;

    // Send ACK.
    create_header(&header, socket->lseq_num, socket->rseq_num + 1, SOCK352_ACK, 0, 0);
    printf("sock352_connect: Sending ACK number %ld...\n", header.ack_no);
    encode_header(&header);
    puts("sock352_connect: Sending ACK...");
    send_packet(&header, NULL, 0, socket);

    // Technically speaking it never received this ACK, but it makes the logic less complex later if I can
    // assume that the ACK counter should always be one more than the sequence number.
    socket->last_ack++;

    // Start send and receive queue threads.
    pthread_create(socket->send_thread, NULL, send_queue, socket);
    pthread_create(socket->recv_thread, NULL, recv_queue, socket);

    // Connected!
    puts("sock352_connect: Connected...");
    return SOCK352_SUCCESS;
}

// Function doesn't do much right now. Just marks the socket as a listening socket.
int sock352_listen(int fd, int n) {
    puts("sock352_listen: Starting...");
    sock352_socket_t *socket = retrieve(sockets, fd);
    socket->type = SOCK352_LISTEN;

    return SOCK352_SUCCESS;
}

// Function is responsible for the server's half of the TCP 3-way handshake.
int sock352_accept(int _fd, sockaddr_sock352_t *addr, int *len) {
    sock352_socket_t *socket = retrieve(sockets, _fd);
    puts("sock352_accept: Starting...");

    if (uport > 0) {
        socket->raddr.sin_port = htons((short) uport);
    } else {
        socket->raddr.sin_port = htons((short) ruport);
    }

    while (1) {
        // Wait for SYN.
        int e_count = 0, status = SOCK352_FAILURE;
        sock352_pkt_hdr_t header;
        status = recv_packet(&header, NULL, socket, 0, 1);
        while (!valid_packet(&header, NULL, SOCK352_SYN) || status == SOCK352_FAILURE) {
            status = recv_packet(&header, NULL, socket, 0, 1);
        }
        printf("sock352_accept: Received SYN with initial sequence number %ld...\n", header.sequence_no);
        socket->rseq_num = header.sequence_no;

        // Send SYN/ACK.
        sock352_pkt_hdr_t resp_header;
        create_header(&resp_header, socket->lseq_num, socket->rseq_num + 1, SOCK352_SYN | SOCK352_ACK, 0, 0);
        printf("sock352_accpept: Sending SYN/ACK with sequence number %ld and ACK number %ld...\n", resp_header.sequence_no, resp_header.ack_no);
        encode_header(&resp_header);
        send_packet(&resp_header, NULL, 0, socket);

        // Receive ACK.
        int valid = 1;
        status = recv_packet(&header, NULL, socket, 1, 0);
        while (!valid_packet(&header, NULL, SOCK352_ACK) || !valid_ack(&header, socket->lseq_num, 1) || status == SOCK352_FAILURE) {
            if (++e_count > 5) {
                valid = 0;
                break;
            }
            send_packet(&resp_header, NULL, 0, socket);
            status = recv_packet(&header, NULL, socket, 1, 0);
        }
        printf("sock352_accept: Received an ACK with ACK number %ld...\n", header.ack_no);
        socket->last_ack = header.ack_no;
        socket->lseq_num++;
        socket->rseq_num = header.sequence_no;

        // Either return new socket for connection, or give up and start over.
        if (valid) {
            // Connected!
            puts("sock352_accept: Connected...");
            int fd = fd_counter++;
            sock352_socket_t *copy = copysock(socket);
            copy->type = SOCK352_ACCEPT;
            pthread_create(copy->send_thread, NULL, send_queue, copy);
            pthread_create(copy->recv_thread, NULL, recv_queue, copy);
            insert(sockets, fd, copy);
            return fd;
        }
    }
}

// Function is responsible for dequeuing a received packet, or blocking until one arrives.
int sock352_read(int fd, void *buf, int count) {
    if (count <= 0 || !buf) {
        return 0;
    }
    puts("sock352_read: Starting...");

    // Get the socket, then get the data.
    sock352_socket_t *socket = retrieve(sockets, fd);
    if (!socket) return SOCK352_FAILURE;
    puts("sock352_read: About to dequeue data...");
    int read = queue_recv(socket->recv_queue, buf, count);
    puts("sock352_read: Returning data...");

    return read;
}

// Function is responsible for breaking up the given data into packet sized chunks, and enqueuing it to be sent.
int sock352_write(int fd, void *buf, int count) {
    if (count <= 0 || !buf) {
        return 0;
    }
    puts("sock352_write: Starting...");

    // Get the socket and set up some initial state.
    sock352_socket_t *socket = retrieve(sockets, fd);
    if (!socket) return SOCK352_FAILURE;
    int current = count, remaining = count;
    char *ptr = buf;

    while (remaining > 0) {
        if (current > MAX_UDP_PACKET) current = MAX_UDP_PACKET;

        // Create the header and enqueue it with the data.
        sock352_pkt_hdr_t header;
        socket->lseq_num += current;
        create_header(&header, socket->lseq_num, socket->rseq_num + 1, 0, 0, current);
        puts("sock352_write: About to queue data...");
        queue_send(socket->send_queue, &header, ptr);

        // Increase our counters.
        ptr += current;
        remaining -= current;
        current = remaining;
    }

    return count;
}

// Function is responsible for handling the 4-way TCP closing handshake.
int sock352_close(int fd) {
    sock352_socket_t *socket = retrieve(sockets, fd);
    int e_count = 0, status;
    puts("sock352_close: Starting...");

    if (socket->type == SOCK352_CLIENT || socket->type == SOCK352_ACCEPT) {
        // Wait until sending queue is empty so that we know all data has been set and ACKd.
        puts("sock352_close: Waiting for send queue to empty...");
        block_until_empty(socket->send_queue);
        puts("sock352_close: Send queue is empty...");

        // Give the sending thread our FIN packet as a final packet, and set the halting
        // flag.
        sock352_pkt_hdr_t header, resp_header;
        create_header(&header, ++socket->lseq_num, socket->rseq_num + 1, SOCK352_FIN, 0, 0);
        socket->lack_no = socket->lseq_num + 1;
        socket->lfin = 1;
        printf("sock352_close: Queuing FIN packet with sequence number %ld...\n", header.sequence_no);
        queue_send(socket->send_queue, &header, NULL);

        // Join with the sending thread so that everything is cleaned up nicely.
        puts("sock352_close: Joining send thread...");
        pthread_join(*socket->send_thread, NULL);
        empty(socket->send_queue);

        // Wait until the receive thread has received the last ACK.
        struct timeval time;
        time.tv_sec = 0;
        time.tv_usec = RECEIVE_TIMEOUT;
        puts("sock352_close: Waiting to receive last ACK...");
        select(0, NULL, NULL, NULL, &time);
        while (!socket->lacked) {
            puts("sock352_close: Did not receive last ACK, trying again...");
            if (++e_count > 5) return SOCK352_FAILURE;
            if (e_count == 1) encode_header(&header);
            send_packet(&header, NULL, 0, socket);
            time.tv_sec = 0;
            time.tv_usec = RECEIVE_TIMEOUT;
            select(0, NULL, NULL, NULL, &time);
        }
        puts("sock352_close: Received last ACK...");
        e_count = 0;
        socket->last_ack = resp_header.ack_no;
        socket->rseq_num = resp_header.sequence_no;

        // The remote end will eventually send a FIN, which the receive thread will ACK, and then exit.
        // Wait until that happens.
        puts("sock352_close: Joining receive thread...");
        pthread_join(*socket->recv_thread, NULL);
        puts("sock352_close: Joined receive thread. Other side must have sent a FIN...");

        // Wait one full timeout to make sure the ACK was received.
        status = recv_packet(&resp_header, NULL, socket, 1, 0);
        while (status != SOCK352_FAILURE) {
            puts("sock352_close: Received another packet, resending ACK...");
            if (++e_count > 5) return SOCK352_FAILURE;
            send_packet(&header, NULL, 0, socket);
            status = recv_packet(&resp_header, NULL, socket, 1, 0);
        }

        // Connection is closed!
        puts("sock352_close: Connection closed.");
        destroy_352socket(socket);
        return SOCK352_SUCCESS;
    } else if (socket->type == SOCK352_LISTEN) {
        puts("sock352_close: Closing listen socket...");
        destroy_352socket(socket);
        puts("sock352_close: Closed.");
        return SOCK352_SUCCESS;
    } else {
        puts("sock352_close: Invalid file descriptor, returning error code.");
        return SOCK352_FAILURE;
    }
}

/*----- Socket Manipulation Function Implementations -----*/

// Function is responsible for allocating and initializing a socket.
sock352_socket_t *create_352socket(int fd) {
    sock352_socket_t *socket = calloc(1, sizeof(sock352_socket_t));

    if (socket) {
        socket->fd = fd;

        socket->send_queue = create_queue(KEEP, MAX_WINDOW_SIZE);
        socket->recv_queue = create_queue(DUMP, MAX_WINDOW_SIZE);

        socket->send_thread = malloc(sizeof(pthread_t));
        socket->recv_thread = malloc(sizeof(pthread_t));
    }

    return socket;
}

// Function is responsible for duplicating a socket.
sock352_socket_t *copysock(sock352_socket_t *socket) {
    sock352_socket_t *copy = create_352socket(socket->fd);

    if (copy) {
        copy->bound = socket->bound;
        copy->lseq_num = socket->lseq_num;
        copy->rseq_num = socket->rseq_num;
        copy->last_ack = socket->last_ack;
        copy->type = socket->type;
        copy->laddr = socket->laddr;
        copy->raddr = socket->raddr;
        copy->len = socket->len;
    }

    return copy;
}

// Function is responsible for destroying a socket.
void destroy_352socket(sock352_socket_t *socket) {
    destroy_queue(socket->send_queue);
    destroy_queue(socket->recv_queue);
    free(socket->send_thread);
    free(socket->recv_thread);
    free(socket);
}

// Function is responsible for sending any packets in the send queue.
void *send_queue(void *sock) {
    sock352_socket_t *socket = sock;

    while (!socket->lfin) {
        sock352_chunk_t *chunk = dequeue(socket->send_queue);
        sock352_pkt_hdr_t header;
        memcpy(&header, &chunk->header, sizeof(sock352_pkt_hdr_t));
        int len = header.payload_len;
        encode_header(&header);
        void *data = chunk->data;
        gettimeofday(&chunk->time, NULL);
        printf("send_queue: About to send sequence number %ld...\n", chunk->header.sequence_no);
        send_packet(&header, data, len, socket);
    }

    return NULL;
}

// Function takes care of everything related to receiving data. It's grown a little wild and out of control, so I'll
// probably split it up at some point if I have time.
void *recv_queue(void *sock) {
    sock352_socket_t *socket = sock;
    sock352_pkt_hdr_t header, resp_header;
    char buffer[MAX_UDP_PACKET];

    while (!socket->lfin || !socket->rfin || !socket->lacked) {
        puts("recv_queue: About to receive a packet...");
        int status = recv_packet(&header, buffer, socket, 1, 0);

        if (valid_packet(&header, buffer, SOCK352_ACK) && !socket->lacked && status != SOCK352_FAILURE) {
            // We've received an ACK! Time to check if it's valid.
            if (valid_ack(&header, socket->last_ack, 0)) {
                // We've received a valid ACK! Time to remove all corresponding packets (at least one, maybe more) from the yet-to-be-acknowledged part of
                // the send queue.
                printf("recv_queue: Received a valid ACK, number %ld. Updating send queue...\n", header.ack_no);
                sock352_chunk_t *chunk = peek_head(socket->send_queue, 0);

                // Keep dropping packets from the unacknowledged, but sent, end of the queue until we reach the ACK number.
                while (chunk && chunk->header.sequence_no < header.ack_no) {
                    puts("recv_queue: Dropping a chunk from the send queue...");
                    drop(socket->send_queue);
                    destroy_chunk(chunk);
                    chunk = peek_head(socket->send_queue, 0);
                }

                // Update our last_ack and remote sequence numbers, and reset the invalid ack counter.
                socket->last_ack = header.ack_no;
                socket->rseq_num = header.sequence_no;
                socket->bad_acks = 0;
                if (socket->lfin && header.ack_no == socket->lack_no) {
                    puts("recv_queue: Local FIN flag is set, and ACK number matches predicted last ACK. Setting last ACK flag...");
                    socket->lacked = 1;
                }
            } else {
                // We've received a duplicate ACK. Increase the counter, and reset if need be.
                puts("recv_queue: Received an invalid ACK. Assuming duplication...");
                socket->bad_acks++;
                if (socket->bad_acks > 3) {
                    puts("recv_queue: Received 3 invalid ACKs. Resetting send queue...");
                    socket->bad_acks = 0;
                    reset(socket->send_queue);
                }
            }
        } else if (valid_packet(&header, buffer, SOCK352_SYN | SOCK352_ACK) && !socket->lfin && status != SOCK352_FAILURE) {
            // The last ACK in the handshake failed to arrive at the server side. Resend and reset.
            sock352_chunk_t *chunk = peek_head(socket->send_queue, 1);
            sock352_pkt_hdr_t header;

            create_header(&header, chunk->header.sequence_no - chunk->header.payload_len - 1, socket->rseq_num, SOCK352_ACK, 0, 0);
            encode_header(&header);
            puts("recv_queue: Oddly enough, last ACK from handshake must have been lost. Resending and resetting...");
            send_packet(&header, NULL, 0, socket);
            reset(socket->send_queue);
        } else if (header.payload_len > 0 && status != SOCK352_FAILURE) {
            // We've received a data packet. Validate it, and add it to the read queue.
            if ((valid_packet(&header, buffer, 0) || valid_packet(&header, buffer, SOCK352_FIN)) && valid_sequence(&header, socket) && status != SOCK352_FAILURE) {
                printf("recv_queue: Received a data packet with sequence number %ld...\n", header.sequence_no);
                if (header.flags == SOCK352_FIN) {
                    // We have a FIN packet. Mark that the remote host is finished.
                    puts("recv_queue: FIN bit is set. Marking remote FIN flag...");
                    socket->rfin = 1;
                }

                // The packet was valid! Enqueue its data into the receive queue and send back an ACK.
                socket->rseq_num = header.sequence_no;
                sock352_chunk_t *chunk = create_chunk(&header, buffer);
                enqueue(socket->recv_queue, chunk);
                create_header(&resp_header, socket->lseq_num, socket->rseq_num + 1, SOCK352_ACK, 0, 0);
                printf("recv_queue: Sending ACK number %ld...\n", resp_header.ack_no);
                encode_header(&resp_header);
                send_packet(&resp_header, NULL, 0, socket);
            } else {
                puts("recv_queue: Received an out of order data packet, sending duplicate ACK...");

                create_header(&resp_header, socket->lseq_num, socket->rseq_num + 1, SOCK352_ACK, 0, 0);
                encode_header(&resp_header);
                send_packet(&resp_header, NULL, 0, socket);
            }
        } else if (valid_packet(&header, buffer, SOCK352_FIN) && status != SOCK352_FAILURE) {
            printf("recv_queue: FIN bit is set on non-data packet with sequence number %ld. Marking remote FIN flag and ACKing...\n", header.sequence_no);

            socket->rfin = 1;
            socket->rseq_num = header.sequence_no;
            create_header(&resp_header, socket->lseq_num, socket->rseq_num + 1, SOCK352_ACK, 0, 0);
            printf("recv_queue: Sending ACK number %ld...\n", resp_header.ack_no);
            encode_header(&resp_header);
            send_packet(&resp_header, NULL, 0, socket);
        } else if (status == SOCK352_FAILURE && !socket->lfin) {
            puts("recv_queue: Timeout. Resetting send_queue...");
            reset(socket->send_queue);
        }
    }
    puts("recv_queue: Both local and remote FIN flags are set, and the last ACK has been received. Exiting...");

    return NULL;
}

/*----- Queue Manipulation Function Declarations -----*/

// Function is responsible for wrapping a packet into a chunk, and enqueuing it for sending.
void queue_send(queue_t *q, sock352_pkt_hdr_t *header, void *data) {
    sock352_chunk_t *chunk = create_chunk(header, data);
    enqueue(q, chunk);
}

// Function is responsible for dequeuing received data, or blocking until there is some.
int queue_recv(queue_t *q, void *data, int size) {
    int read;
    sock352_chunk_t *chunk = peek(q, 1);
    sock352_pkt_hdr_t *header = &chunk->header;

    if (size >= header->payload_len) {
        memcpy(data, chunk->data, header->payload_len);
        read = header->payload_len;
        destroy_chunk(dequeue(q));
    } else {
        int difference = header->payload_len - size;
        memcpy(data, chunk->data, size);
        memcpy(chunk->data, ((char *) chunk->data) + size, difference);
        header->payload_len = difference;
        read = size;
    }

    return read;
}

/*----- Packet Manipulation Function Implementations -----*/

// Function is responsible for actually sending the given header and data.
int send_packet(sock352_pkt_hdr_t *header, void *data, int nbytes, sock352_socket_t *socket) {
    struct sockaddr_in udp_addr;
    setup_sockaddr(&socket->raddr, &udp_addr);
    char packet[sizeof(sock352_pkt_hdr_t) + nbytes];

    // Copy the data into the buffer.
    memcpy(packet, header, sizeof(sock352_pkt_hdr_t));
    if (data) memcpy(packet + sizeof(sock352_pkt_hdr_t), data, nbytes);
    int num_bytes = data ? sizeof(packet) : sizeof(sock352_pkt_hdr_t);

    // Send the data.
    return sendto(socket->fd, packet, num_bytes, 0, (struct sockaddr *) &udp_addr, sizeof(udp_addr));
}

// Function is responsible for receiving a packet into the given header and buffer.
int recv_packet(sock352_pkt_hdr_t *header, void *data, sock352_socket_t *socket, int timeout, int save_addr) {
    char response[MAX_UDP_PACKET];
    int header_size = sizeof(sock352_pkt_hdr_t), status;
    struct sockaddr_in sender;
    socklen_t addr_len = sizeof(struct sockaddr_in);
    memset(header, 0, sizeof(sock352_pkt_hdr_t));

    // Setup timeout structure.
    struct timeval time;
    time.tv_sec = 0;
    time.tv_usec = RECEIVE_TIMEOUT;

    // Set up the file descriptor set for the select call.
    fd_set to_read;
    FD_ZERO(&to_read);
    FD_SET(socket->fd, &to_read);

    // Wait (or not) until the data is ready.
    if (timeout) {
        if (timeout != 1) time.tv_usec = timeout * 1000;
        status = select(socket->fd + 1, &to_read, NULL, NULL, &time);
    } else {
        status = select(socket->fd + 1, &to_read, NULL, NULL, NULL);
    }

    // Receive the data, or return a failure.
    if (FD_ISSET(socket->fd, &to_read)) {
        recvfrom(socket->fd, response, sizeof(response), 0, (struct sockaddr *) &sender, &addr_len);
    } else {
        return SOCK352_FAILURE;
    }

    // This is ugly, but when the server first receives data, it needs to save the address of the host that sent it,
    // which gets done here.
    if (save_addr) {
        socket->raddr.sin_addr = sender.sin_addr;
    }

    // Copy data the received data into the provided buffers.
    memcpy(header, response, sizeof(sock352_pkt_hdr_t));
    decode_header(header);
    if (data) memcpy(data, response + header_size, header->payload_len);

    return SOCK352_SUCCESS;
}

// Function is responsible for checking if the packet is valid. Currently only checks flags.
int valid_packet(sock352_pkt_hdr_t *header, void *data, int flags) {
    int flag_check = header->flags == flags;

    // TODO: Add checksum validation here.
    int sum_check = 1;
    return flag_check && sum_check;
}

// Function is responsible for checking if the received packet has the correct sequence number.
int valid_sequence(sock352_pkt_hdr_t *header, sock352_socket_t *socket) {
    if (header->payload_len > 0) {
        return header->sequence_no == socket->rseq_num + header->payload_len;
    } else {
        return header->sequence_no == socket->rseq_num + 1;
    }
}

// Function checks if the received packet has the correct ACK number.
int valid_ack(sock352_pkt_hdr_t *header, int expected, int exact) {
    if (exact) {
        return header->ack_no == expected + 1;
    } else {
        return header->ack_no > expected;
    }
}

/*----- Header Manipulation Function Implementations -----*/

// Function is responsible for creating a header with the given properties.
void create_header(sock352_pkt_hdr_t *header, uint64_t sequence_num, uint64_t ack_num, uint8_t flags, uint16_t checksum, uint32_t len) {
    memset(header, 0, sizeof(*header));
    header->version = SOCK352_VER_1;
    header->flags = flags;
    header->protocol = 0;
    header->header_len = sizeof(*header);
    header->checksum = checksum;
    header->source_port = 0;
    header->dest_port = 0;
    header->sequence_no = sequence_num;
    header->ack_no = ack_num;
    header->window = MAX_WINDOW_SIZE;
    header->payload_len = len;
}

// Function is responsible for encoding a header to be sent over the network.
void encode_header(sock352_pkt_hdr_t *header) {
    header->header_len = htons(header->header_len);
    header->checksum = htons(header->checksum);
    header->source_port = htonl(header->source_port);
    header->dest_port = htonl(header->dest_port);
    header->sequence_no = htobe64(header->sequence_no);
    header->ack_no = htobe64(header->ack_no);
    header->window = htonl(header->window);
    header->payload_len = htonl(header->payload_len);
}

// Function is responsible for decoding a header that was received over the network for reading.
void decode_header(sock352_pkt_hdr_t *header) {
    header->header_len = ntohs(header->header_len);
    header->checksum = ntohs(header->checksum);
    header->source_port = ntohl(header->source_port);
    header->dest_port = ntohl(header->dest_port);
    header->sequence_no = be64toh(header->sequence_no);
    header->ack_no = be64toh(header->ack_no);
    header->window = ntohl(header->window);
    header->payload_len = ntohl(header->payload_len);
}

// Function is responsible for configuing a given sockaddr_in structure with the same properties as the given
// sockaddr_sock352_t struct.
void setup_sockaddr(sockaddr_sock352_t *addr, struct sockaddr_in *udp_addr) {
    memset(udp_addr, 0, sizeof(struct sockaddr_in));
    udp_addr->sin_family = AF_INET;
    udp_addr->sin_addr = addr->sin_addr;
    udp_addr->sin_port = addr->sin_port;
}

/*----- Misc. Utility Function Implementations -----*/

// Function is responsible for creating a chunk struct.
sock352_chunk_t *create_chunk(sock352_pkt_hdr_t *header, void *data) {
    sock352_chunk_t *chunk = malloc(sizeof(sock352_chunk_t));

    if (chunk) {
        memcpy(&chunk->header, header, sizeof(sock352_pkt_hdr_t));
        chunk->data = malloc(header->payload_len);
        memcpy(chunk->data, data, header->payload_len);
        chunk->size = header->payload_len;
    }

    return chunk;
}

// Function is responsible for destroying a chunk struct.
void destroy_chunk(sock352_chunk_t *chunk) {
    free(chunk->data);
    free(chunk);
}
