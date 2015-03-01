#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/select.h>
#include <pthread.h>
#include <sys/time.h>
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
    int fd, bound, send_halt, recv_halt, lfin, rfin, lport, rport;
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

void create_header(sock352_pkt_hdr_t *header, int sequence_num, int ack_num, uint8_t flags, uint16_t checksum, uint32_t len);
void encode_header(sock352_pkt_hdr_t *header);
void decode_header(sock352_pkt_hdr_t *header);
void setup_sockaddr(sockaddr_sock352_t *addr, struct sockaddr_in *udp_addr);

/*----- Misc. Utility Function Declarations -----*/

sock352_chunk_t *create_chunk(sock352_pkt_hdr_t *header, void *data);
void destroy_chunk(sock352_chunk_t *chunk);

uint64_t htonll(uint64_t num);
uint64_t ntohll(uint64_t num);
int endian_check();

/*----- Globals -----*/

int uport = -1, ruport = -1, luport = -1, fd_counter = 0;
array *sockets;

/*----- Socket API Function Implementations -----*/

// Function is responsible for initializing the library.
int sock352_init(int udp_port) {
    if (udp_port <= 0 || uport >= 0) return SOCK352_FAILURE;

    uport = udp_port;
    sockets = create_array();
    return SOCK352_SUCCESS;
}

// Function is responsible for initializing the library when running both client and server on the same machine.
int sock352_init2(int remote_port, int local_port) {
    if (remote_port <= 0 || local_port <= 0 || luport >= 0 || ruport >= 0) return SOCK352_FAILURE;

    ruport = remote_port;
    luport = local_port;
    sockets = create_array();
    return SOCK352_SUCCESS;
}

// Function is responsible for returning a socket for the given configuration.
int sock352_socket(int domain, int type, int protocol) {
    if (domain != AF_CS352 || type != SOCK_STREAM || protocol != 0) {
        return SOCK352_FAILURE;
    }

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

    struct sockaddr_in udp_addr;
    udp_addr.sin_family = AF_INET;
    udp_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    if (uport > 0) {
        udp_addr.sin_port = htons((short) uport);
    } else {
        udp_addr.sin_port = htons((short) luport);
    }
    return bind(socket->fd, (struct sockaddr *) &udp_addr, len);
}

// Function is responsible for the client's half of the 3 way TCP connection handshake.
int sock352_connect(int fd, sockaddr_sock352_t *addr, socklen_t len) {
    int e_count = 0;
    sock352_socket_t *socket = retrieve(sockets, fd);
    memcpy(&socket->raddr, addr, sizeof(sockaddr_sock352_t));
    socket->type = SOCK352_CLIENT;

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
    e_count = 0;
    socket->last_ack = resp_header.ack_no;
    socket->lseq_num++;
    socket->rseq_num = resp_header.sequence_no;

    // Send ACK.
    create_header(&header, socket->lseq_num, socket->rseq_num + 1, SOCK352_ACK, 0, 0);
    encode_header(&header);
    send_packet(&header, NULL, 0, socket);

    // Technically speaking it never received this ACK, but it makes the logic less complex later if I can
    // assume that the ACK counter should always be one more than the sequence number.
    socket->last_ack++;

    // Start send and receive queue threads.
    pthread_create(socket->send_thread, NULL, send_queue, socket);
    pthread_create(socket->recv_thread, NULL, recv_queue, socket);

    // Connected!
    return SOCK352_SUCCESS;
}

// Function doesn't do much right now. Just marks the socket as a listening socket.
int sock352_listen(int fd, int n) {

    sock352_socket_t *socket = retrieve(sockets, fd);
    socket->type = SOCK352_LISTEN;

    return SOCK352_SUCCESS;
}

// Function is responsible for the server's half of the TCP 3-way handshake.
int sock352_accept(int _fd, sockaddr_sock352_t *addr, int *len) {
    sock352_socket_t *socket = retrieve(sockets, _fd);

    while (1) {
        // Wait for SYN.
        int e_count = 0, status = SOCK352_FAILURE;
        sock352_pkt_hdr_t header;
        status = recv_packet(&header, NULL, socket, 0, 1);
        while (!valid_packet(&header, NULL, SOCK352_SYN) || status == SOCK352_FAILURE) {
            status = recv_packet(&header, NULL, socket, 0, 1);
        }
        socket->rseq_num = header.sequence_no;

        // Send SYN/ACK.
        sock352_pkt_hdr_t resp_header;
        create_header(&resp_header, socket->lseq_num, socket->rseq_num + 1, SOCK352_SYN | SOCK352_ACK, 0, 0);
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
        socket->last_ack = header.ack_no;
        socket->lseq_num++;
        socket->rseq_num = header.sequence_no;

        // Either return new socket for connection, or give up and start over.
        if (valid) {
            // Connected!
            int fd = fd_counter++;
            sock352_socket_t *copy = copysock(socket);
            copy->type = SOCK352_ACCEPT;
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

    // Get the socket, then get the data.
    sock352_socket_t *socket = retrieve(sockets, fd);
    if (!socket) return SOCK352_FAILURE;
    int read = queue_recv(socket->recv_queue, buf, count);

    return read;
}

// Function is responsible for breaking up the given data into packet sized chunks, and enqueuing it to be sent.
int sock352_write(int fd, void *buf, int count) {
    if (count <= 0 || !buf) {
        return 0;
    }

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

    if (socket->type == SOCK352_CLIENT) {
        // Wait until sending queue is empty so that we know all data has been sent and ACKd.
        block_until_empty(socket->send_queue);

        // We also need to stop the receive thread to make sure it doesn't swallow up the ACK
        // for our FIN packet.
        socket->recv_halt = 1;
        pthread_join(*socket->recv_thread, NULL);

        // Give the sending thread our FIN packet as a final packet, and set the halting
        // flag.
        sock352_pkt_hdr_t header, resp_header;
        create_header(&header, ++socket->lseq_num, socket->rseq_num + 1, SOCK352_FIN, 0, 0);
        socket->send_halt = 1;
        queue_send(socket->send_queue, &header, NULL);

        // Join with the sending thread so that everything is cleaned up nicely.
        pthread_join(*socket->send_thread, NULL);
        empty(socket->send_queue);

        // Receive the ACK packet for our FIN.
        status = recv_packet(&resp_header, NULL, socket, 1, 0);
        while (!valid_packet(&resp_header, NULL, SOCK352_ACK) || !valid_ack(&resp_header, socket->last_ack, 0) || status == SOCK352_FAILURE) {
            if (++e_count > 5) return SOCK352_FAILURE;
            if (e_count == 1) encode_header(&header);
            send_packet(&header, NULL, 0, socket);
            status = recv_packet(&resp_header, NULL, socket, 1, 0);
        }
        e_count = 0;
        socket->last_ack = resp_header.ack_no;
        socket->rseq_num = resp_header.sequence_no;

        // Wait on the server to send a FIN packet.
        status = recv_packet(&header, NULL, socket, 0, 0);
        while (!valid_packet(&header, NULL, SOCK352_FIN) || !valid_sequence(&header, socket) || status == SOCK352_FAILURE) {
            if (++e_count > 5) return SOCK352_FAILURE;
            recv_packet(&header, NULL, socket, 0, 0);
        }
        e_count = 0;
        socket->rseq_num = header.sequence_no;

        // Send ACK in response to the server's FIN.
        create_header(&header, socket->lseq_num++, socket->rseq_num + 1, SOCK352_ACK, 0, 0);
        encode_header(&header);
        send_packet(&header, NULL, 0, socket);

        // Wait one full timeout to make sure the ACK was received.
        status = recv_packet(&resp_header, NULL, socket, 1, 0);
        while (status != SOCK352_FAILURE) {
            if (++e_count > 5) return SOCK352_FAILURE;
            send_packet(&header, NULL, 0, socket);
            status = recv_packet(&resp_header, NULL, socket, 1, 0);
        }

        // Connection is closed!
        destroy_352socket(socket);
        return SOCK352_SUCCESS;
    } else if (socket->type == SOCK352_ACCEPT) {
        // Stop the receive thread so that it doesn't interfere with our closing the connection.
        socket->recv_halt = 1;
        pthread_join(*socket->recv_thread, NULL);

        sock352_pkt_hdr_t header, resp_header;

        // We have not yet received the client's FIN.
        if (!socket->rfin) {

            // Receive the FIN.
            recv_packet(&header, NULL, socket, 0, 0);
            while (!valid_packet(&header, NULL, SOCK352_FIN) || !valid_sequence(&header, socket) || status == SOCK352_FAILURE) {
                if (++e_count > 5) return SOCK352_FAILURE;
                recv_packet(&header, NULL, socket, 0, 0);
            }
            socket->rseq_num = header.sequence_no;
            e_count = 0;

            // Send an ACK for the FIN.
            create_header(&resp_header, socket->lseq_num, socket->rseq_num + 1, SOCK352_ACK, 0, 0);
            encode_header(&resp_header);
            send_packet(&resp_header, NULL, 0, socket);

            // Make sure ACK was received.
            status = recv_packet(&header, NULL, socket, 1, 0);
            while (status != SOCK352_FAILURE) {
                if (++e_count > 5) return SOCK352_FAILURE;
                send_packet(&resp_header, NULL, 0, socket);
                status = recv_packet(&resp_header, NULL, socket, 1, 0);
            }
            e_count = 0;
        }

        // Send FIN to client.
        create_header(&header, ++socket->lseq_num, socket->rseq_num + 1, SOCK352_FIN, 0, 0);
        encode_header(&header);
        send_packet(&header, NULL, 0, socket);

        // Receive ACK from client.
        status = recv_packet(&resp_header, NULL, socket, 1, 0);
        while (!valid_packet(&resp_header, NULL, SOCK352_ACK) || !valid_ack(&resp_header, socket->last_ack, 0) || status == SOCK352_FAILURE) {
            if (++e_count > 5) return SOCK352_FAILURE;
            send_packet(&header, NULL, 0, socket);
            status = recv_packet(&resp_header, NULL, socket, 1, 0);
        }

        destroy_352socket(socket);

        // Connection is closed!
        return SOCK352_SUCCESS;
    } else if (socket->type == SOCK352_LISTEN) {
        destroy_352socket(socket);

        return SOCK352_SUCCESS;
    } else {
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

    while (!socket->send_halt) {
        sock352_chunk_t *chunk = dequeue(socket->send_queue);
        sock352_pkt_hdr_t header;
        memcpy(&header, &chunk->header, sizeof(sock352_pkt_hdr_t));
        int len = header.payload_len;
        encode_header(&header);
        void *data = chunk->data;
        gettimeofday(&chunk->time, NULL);
        send_packet(&header, data, len, socket);
    }
    socket->send_halt = 0;

    return NULL;
}

// Function does double duty. On the client side, it handles receiving ACKS and rewinding the queue on a timeout,
// and on the server side it handles sending ACKs.
void *recv_queue(void *sock) {
    sock352_socket_t *socket = sock;
    sock352_pkt_hdr_t header, resp_header;
    char buffer[MAX_UDP_PACKET];

    while (!socket->recv_halt) {
        int status = recv_packet(&header, buffer, socket, 1, 0);

        if (socket->type == SOCK352_CLIENT && !socket->recv_halt) {
            if (valid_packet(&header, buffer, SOCK352_ACK) && valid_ack(&header, socket->last_ack, 0) && status != SOCK352_FAILURE) {
                // We've received a valid ACK! Time to remove all corresponding packets (at least one, maybe more) from the yet-to-be-acknowledged part of
                // the send queue.
                sock352_chunk_t *chunk = peek_head(socket->send_queue, 1);

                // Keep dropping packets from the unacknowledged, but sent, end of the queue until we reach the ACK number.
                while (chunk && chunk->header.sequence_no < header.ack_no) {
                    drop(socket->send_queue);
                    destroy_chunk(chunk);
                    chunk = peek_head(socket->send_queue, 0);
                }

                // Update our last_ack and remote sequence numbers.
                socket->last_ack = header.ack_no;
                socket->rseq_num = header.sequence_no;
            } else if (valid_packet(&header, buffer, SOCK352_SYN | SOCK352_ACK)) {
                // The last ACK in the handshake failed to arrive at the server side. Resend and reset.
                sock352_chunk_t *chunk = peek_head(socket->send_queue, 1);
                sock352_pkt_hdr_t header;

                create_header(&header, chunk->header.sequence_no - chunk->header.payload_len - 1, socket->rseq_num, SOCK352_ACK, 0, 0);
                encode_header(&header);
                send_packet(&header, NULL, 0, socket);
                reset(socket->send_queue);
            } else if (status == SOCK352_FAILURE) {
                // We've had a timeout, so reset the current pointer on the send queue back to the first unacknowledged packet.
                reset(socket->send_queue);
            }
        } else if (!socket->recv_halt) {
            // Check if the data packet we received is the correct sequence. The valid_packet call doesn't really do too much here as we haven't added checksum
            // checking yet.
            if ((valid_packet(&header, buffer, 0) || valid_packet(&header, buffer, SOCK352_FIN)) && valid_sequence(&header, socket) && status != SOCK352_FAILURE) {
                if (header.flags == SOCK352_FIN) {
                    // We have a FIN packet. Mark that the remote host is finished.
                    socket->rfin = 1;
                }

                // The packet was valid! Enqueue its data into the receive queue and send back an ACK.
                socket->rseq_num = header.sequence_no;
                sock352_chunk_t *chunk = create_chunk(&header, buffer);
                enqueue(socket->recv_queue, chunk);
                create_header(&resp_header, socket->lseq_num, socket->rseq_num + 1, SOCK352_ACK, 0, 0);
                encode_header(&resp_header);
                send_packet(&resp_header, NULL, 0, socket);
            } else {
                // FIXME: Need to resend old data.
            }
        }
    }
    socket->recv_halt = 0;

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
        socket->raddr.sin_port = sender.sin_port;
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
void create_header(sock352_pkt_hdr_t *header, int sequence_num, int ack_num, uint8_t flags, uint16_t checksum, uint32_t len) {
    memset(header, 0, sizeof(header));
    header->version = SOCK352_VER_1;
    header->flags = flags;
    header->protocol = 0;
    header->header_len = sizeof(header);
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
    header->sequence_no = htonll(header->sequence_no);
    header->ack_no = htonll(header->ack_no);
    header->window = htonl(header->window);
    header->payload_len = htonl(header->payload_len);
}

// Function is responsible for decoding a header that was received over the network for reading.
void decode_header(sock352_pkt_hdr_t *header) {
    header->header_len = ntohs(header->header_len);
    header->checksum = ntohs(header->checksum);
    header->source_port = ntohl(header->source_port);
    header->dest_port = ntohl(header->dest_port);
    header->sequence_no = ntohll(header->sequence_no);
    header->ack_no = ntohll(header->ack_no);
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

// Function is responsible for rearranging 8 bytes of data into network format.
uint64_t htonll(uint64_t num) {
    if (endian_check()) {
        uint32_t *f_half = (uint32_t *) &num, tmp;
        uint32_t *s_half = f_half + 1;
        *f_half = htonl(*f_half);
        *s_half = htonl(*s_half);
        tmp = *f_half;
        memcpy(f_half, s_half, sizeof(uint32_t));
        memcpy(s_half, &tmp, sizeof(uint32_t));
    }
    return num;
}

// Function is responsible for rearranging 8 bytes of data to local format.
uint64_t ntohll(uint64_t num) {
    return htonll(num);
}

// Function is responsible for discerning if the current machine is little endian.
int endian_check() {
    int num = 42;
    return *((char *) &num) == 42;
}
