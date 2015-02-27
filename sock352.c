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

typedef struct sock352_chunk {
    sock352_pkt_hdr_t header;
    void *data;
    int size;
    struct timeval time;
} sock352_chunk_t;

typedef struct sock352_socket {
    int fd, bound, send_halt, recv_halt, lfin, rfin;
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
int valid_sequence(sock352_pkt_hdr_t *header, int expected);
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

int uport = -1, fd_counter = 0;
array *sockets;

/*----- Socket API Function Implementations -----*/

int sock352_init(int udp_port) {
    puts("Sock352_Init: Starting...");
    if (udp_port <= 0 || uport >= 0) return SOCK352_FAILURE;

    uport = udp_port;
    sockets = create_array();
}

int sock352_socket(int domain, int type, int protocol) {
    puts("Sock352_Socket: Starting...");
    if (domain != AF_CS352 || type != SOCK_STREAM || protocol != 0) {
        return SOCK352_FAILURE;
    }

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return SOCK352_FAILURE;
    int fd_352 = fd_counter++;
    insert(sockets, fd_352, create_352socket(fd));

    return fd_352;
}

int sock352_bind(int fd, sockaddr_sock352_t *addr, socklen_t len) {
    puts("Sock352_Bind: Starting...");
    sock352_socket_t *socket = retrieve(sockets, fd);
    memcpy(&socket->laddr, addr, sizeof(sockaddr_sock352_t));

    struct sockaddr_in udp_addr;
    setup_sockaddr(addr, &udp_addr);
    return bind(socket->fd, (struct sockaddr *) &udp_addr, len);
}

int sock352_connect(int fd, sockaddr_sock352_t *addr, socklen_t len) {
    puts("Sock352_Connect: Starting...");
    int e_count = 0;
    sock352_socket_t *socket = retrieve(sockets, fd);
    memcpy(&socket->raddr, addr, sizeof(sockaddr_sock352_t));
    socket->type = SOCK352_CLIENT;

    // Bind to local port.
    puts("Sock352_Connect: Binding to local port...");
    sockaddr_sock352_t laddr;
    laddr.sin_addr.s_addr = htonl(INADDR_ANY);
    laddr.sin_port = htons((short) uport);
    int status = sock352_bind(fd, &laddr, len);
    if (status) return SOCK352_FAILURE;

    // Send SYN.
    puts("Sock352_Connect: Sending SYN packet...");
    sock352_pkt_hdr_t header;
    create_header(&header, socket->lseq_num, 0, SOCK352_SYN, 0, 0);
    encode_header(&header);
    status = send_packet(&header, NULL, 0, socket);
    if (status < 0) return SOCK352_FAILURE;

    // Receive SYN/ACK.
    sock352_pkt_hdr_t resp_header;
    puts("Sock352_Connect: Receiving SYN/ACK, cross your fingers...");
    status = recv_packet(&resp_header, NULL, socket, 1, 0);
    puts("Sock352_Connect: About to validate a packet...");
    while (!valid_packet(&resp_header, NULL, SOCK352_SYN | SOCK352_ACK) || !valid_ack(&resp_header, socket->lseq_num, 1) || status == SOCK352_FAILURE) {
        if (++e_count > 5) return SOCK352_FAILURE;
        printf("Sock352_Connect: Receive failure #%d...\n", e_count);
        send_packet(&header, NULL, 0, socket);
        recv_packet(&resp_header, NULL, socket, 1, 0);
    }
    puts("Sock352_Connect: Successfully received SYN/ACK!");
    e_count = 0;
    socket->last_ack = resp_header.ack_no;
    socket->lseq_num++;
    socket->rseq_num = resp_header.sequence_no;

    // Send ACK.
    puts("Sock352_Connect: Sending ACK...");
    create_header(&header, socket->lseq_num, socket->rseq_num + 1, SOCK352_SYN | SOCK352_ACK, 0, 0);
    encode_header(&header);
    send_packet(&header, NULL, 0, socket);

    // Make sure ACK was received, and increment remote sequence number if so.
    puts("Sock352_Connect: Making sure ACK was received...");
    while (recv_packet(&resp_header, NULL, socket, 1, 0) != SOCK352_FAILURE) {
        if (++e_count > 5) return SOCK352_FAILURE;
        printf("Sock352_Connect: ACK was not received. Try #%d...\n", e_count);
        send_packet(&header, NULL, 0, socket);
    }
    socket->rseq_num++;
    socket->lseq_num++;

    // Technically speaking it never received this ACK, but it makes the logic less complex later if I can
    // assume that the ACK counter should always be one more than the sequence number.
    socket->last_ack++;

    pthread_create(socket->send_thread, NULL, send_queue, socket);
    pthread_create(socket->recv_thread, NULL, recv_queue, socket);

    // Praise the gods!
    puts("Sock352_Connect: CONNECTED!!!");
    return SOCK352_SUCCESS;
}

int sock352_listen(int fd, int n) {
    puts("Sock352_Listen: Starting...");

    sock352_socket_t *socket = retrieve(sockets, fd);
    socket->type = SOCK352_LISTEN;

    return SOCK352_SUCCESS;
}

int sock352_accept(int _fd, sockaddr_sock352_t *addr, int *len) {
    puts("Sock352_Accept: Starting...");
    sock352_socket_t *socket = retrieve(sockets, _fd);

    while (1) {
        // Wait for SYN.
        int e_count = 0, status = SOCK352_FAILURE;
        puts("Sock352_Accept: Waiting for initial SYN, fingers crossed...");
        sock352_pkt_hdr_t header;
        status = recv_packet(&header, NULL, socket, 0, 1);
        puts("Sock352_Accept: About to validate a packet...");
        while (!valid_packet(&header, NULL, SOCK352_SYN) || status == SOCK352_FAILURE) {
            puts("Sock352_Accept: Received packet was invalid, trying again");
            status = recv_packet(&header, NULL, socket, 0, 1);
        }
        puts("Sock352_Accept: Received initial SYN!");
        socket->rseq_num = header.sequence_no;

        // Send SYN/ACK.
        sock352_pkt_hdr_t resp_header;
        create_header(&resp_header, socket->lseq_num, socket->rseq_num + 1, SOCK352_SYN | SOCK352_ACK, 0, 0);
        encode_header(&resp_header);
        puts("Sock352_Accept: Sending SYN/ACK...");
        send_packet(&resp_header, NULL, 0, socket);

        // Receive ACK.
        int valid = 1;
        puts("Sock352_Accept: Waiting for ACK...");
        status = recv_packet(&header, NULL, socket, 1, 0);
        puts("Sock352_Accept: About to validate a packet...");
        while (!valid_packet(&header, NULL, SOCK352_SYN | SOCK352_ACK) || !valid_ack(&header, socket->lseq_num, 1) || status == SOCK352_FAILURE) {
            if (++e_count > 5) {
                valid = 0;
                break;
            }
            printf("Sock352_Accept: Receive failure #%d...\n", e_count);
            send_packet(&resp_header, NULL, 0, socket);
            status = recv_packet(&header, NULL, socket, 1, 0);
        }
        socket->last_ack = header.ack_no;
        socket->lseq_num++;
        socket->rseq_num = header.sequence_no;

        // Either return new socket for connection, or give up and start over.
        if (valid) {
            int fd = fd_counter++;
            sock352_socket_t *copy = copysock(socket);
            copy->type = SOCK352_ACCEPT;
            pthread_create(copy->recv_thread, NULL, recv_queue, copy);
            insert(sockets, fd, copy);
            puts("Sock352_Accept: CONNECTED!!!");
            return fd;
        }
    }
}

int sock352_read(int fd, void *buf, int count) {
    if (count <= 0 || !buf) {
        return 0;
    }
    puts("Sock352_Read: Starting...");

    sock352_socket_t *socket = retrieve(sockets, fd);
    puts("Sock352_Read: Attempting to dequeue a packet...");
    int read = queue_recv(socket->recv_queue, buf, count);

    return read;
}

int sock352_write(int fd, void *buf, int count) {
    if (count <= 0 || !buf) {
        return 0;
    }
    puts("Sock352_Write: Starting...");

    sock352_socket_t *socket = retrieve(sockets, fd);
    if (!socket) return SOCK352_FAILURE;
    int current = count, remaining = count;
    char *ptr = buf;
    while (remaining > 0) {
        if (current > MAX_UDP_PACKET) current = MAX_UDP_PACKET;

        sock352_pkt_hdr_t header;
        create_header(&header, socket->lseq_num++, socket->rseq_num + 1, 0, 0, current);
        queue_send(socket->send_queue, &header, ptr);
        puts("Sock352_Write: Queued a packet to be sent...");

        ptr += current;
        remaining -= current;
        current = remaining;
    }

    return count;
}

int sock352_close(int fd) {
    sock352_socket_t *socket = retrieve(sockets, fd);
    int e_count = 0, status;
    puts("Sock352_Close: Starting...");

    if (socket->type == SOCK352_CLIENT) {
        // Wait until sending queue is empty so that we know all data has been sent and ACKd.
        puts("Sock352_Close: About to block to allow the send queue to empty...");
        block_until_empty(socket->send_queue);

        // We also need to stop the receive thread to make sure it doesn't swallow up the ACK
        // for our FIN packet.
        puts("Sock352_Close: About to block to allow receive queue to exit...");
        socket->recv_halt = 1;
        pthread_join(*socket->recv_thread, NULL);

        // Give the sending thread our FIN packet as a final packet, and set the halting
        // flag.
        puts("Sock352_Close: Queuing intial FIN packet...");
        sock352_pkt_hdr_t header, resp_header;
        create_header(&header, socket->lseq_num++, socket->rseq_num + 1, SOCK352_FIN, 0, 0);
        socket->send_halt = 1;
        queue_send(socket->send_queue, &header, NULL);

        // Join with the sending thread so that everything is cleaned up nicely.
        puts("Sock352_Close: About to block to allow send queue to exit...");
        pthread_join(*socket->send_thread, NULL);
        empty(socket->send_queue);

        // Receive the ACK packet for our FIN.
        puts("Sock352_Close: Receiving ACK...");
        status = recv_packet(&resp_header, NULL, socket, 1, 0);
        puts("Sock352_Close: About to validate a packet...");
        while (!valid_packet(&resp_header, NULL, SOCK352_ACK) || !valid_ack(&resp_header, socket->last_ack, 0) || status == SOCK352_FAILURE) {
            if (++e_count > 5) return SOCK352_FAILURE;
            if (e_count == 1) encode_header(&header);
            puts("Sock352_Close: ACK was invalid...");
            send_packet(&header, NULL, 0, socket);
            status = recv_packet(&resp_header, NULL, socket, 1, 0);
        }
        e_count = 0;
        socket->last_ack = resp_header.ack_no;
        socket->rseq_num = resp_header.sequence_no;

        // Wait on the server to send a FIN packet.
        puts("Sock352_Close: Waiting on a FIN...");
        status = recv_packet(&header, NULL, socket, 0, 0);
        puts("Sock352_Close: About to validate a packet...");
        while (!valid_packet(&header, NULL, SOCK352_FIN) || !valid_sequence(&header, socket->rseq_num + 1) || status == SOCK352_FAILURE) {
            if (++e_count > 5) return SOCK352_FAILURE;
            puts("Sock352_Close: FIN was invalid...");
            recv_packet(&header, NULL, socket, 0, 0);
        }
        e_count = 0;
        socket->rseq_num = header.sequence_no;

        // Send ACK in response to the server's FIN.
        puts("Sock352_Close: Sending final ACK...");
        create_header(&header, socket->lseq_num++, socket->rseq_num + 1, SOCK352_ACK, 0, 0);
        encode_header(&header);
        send_packet(&header, NULL, 0, socket);

        // Wait one full timeout to make sure the ACK was received.
        status = recv_packet(&resp_header, NULL, socket, 1, 0);
        while (status != SOCK352_FAILURE) {
            if (++e_count > 5) return SOCK352_FAILURE;
            puts("Sock352_Close: Last ACK must have been lost, received another packet...");
            send_packet(&header, NULL, 0, socket);
            status = recv_packet(&resp_header, NULL, socket, 1, 0);
        }

        // Connection is closed!
        puts("Sock352_Close: CONNECTION CLOSED!");
        return SOCK352_SUCCESS;
    } else if (socket->type == SOCK352_ACCEPT) {
        // Stop the receive thread so that it doesn't interfere with our closing the connection.
        puts("Sock352_Close: About to block to allow the receive queue to exit...");
        socket->recv_halt = 1;
        pthread_join(*socket->recv_thread, NULL);

        sock352_pkt_hdr_t header, resp_header;

        // We have not yet received the client's FIN.
        if (!socket->rfin) {
            puts("Sock352_Close: Waiting to receive client FIN...");

            // Receive the FIN.
            recv_packet(&header, NULL, socket, 0, 0);
            while (!valid_packet(&header, NULL, SOCK352_FIN) || !valid_sequence(&header, socket->rseq_num + 1) || status == SOCK352_FAILURE) {
                if (++e_count > 5) return SOCK352_FAILURE;
                printf("Sock352_Close: Receive failure #%d...\n", e_count);
                recv_packet(&header, NULL, socket, 0, 0);
            }
            socket->rseq_num = header.sequence_no;
            e_count = 0;
            puts("Sock352_Close: Successfully received FIN, sending ACK...");

            // Send an ACK for the FIN.
            create_header(&resp_header, socket->lseq_num, socket->rseq_num + 1, SOCK352_ACK, 0, 0);
            encode_header(&resp_header);
            send_packet(&resp_header, NULL, 0, socket);

            // Make sure ACK was received.
            puts("Sock352_Close: Making sure ACK was received...");
            status = recv_packet(&header, NULL, socket, 1, 0);
            while (status != SOCK352_FAILURE) {
                if (++e_count > 5) return SOCK352_FAILURE;
                printf("Sock352_Close: ACK was not received. Try #%d...\n", e_count);
                send_packet(&resp_header, NULL, 0, socket);
                status = recv_packet(&resp_header, NULL, socket, 1, 0);
            }
            e_count = 0;
        }

        // Send FIN to client.
        puts("Sock352_Close: Sending FIN to client...");
        create_header(&header, ++socket->lseq_num, socket->rseq_num + 1, SOCK352_FIN, 0, 0);
        encode_header(&header);
        send_packet(&header, NULL, 0, socket);

        // Receive ACK from client.
        puts("Sock352_Close: Receiving ACK...");
        status = recv_packet(&resp_header, NULL, socket, 1, 0);
        while (!valid_packet(&resp_header, NULL, SOCK352_ACK) || !valid_ack(&resp_header, socket->last_ack, 0) || status == SOCK352_FAILURE) {
            if (++e_count > 5) return SOCK352_FAILURE;
            puts("Sock352_Close: ACK was invalid...");
            send_packet(&header, NULL, 0, socket);
            status = recv_packet(&resp_header, NULL, socket, 1, 0);
        }

        // Connection is closed!
        puts("Sock352_Close: CONNECTION CLOSED!");
        return SOCK352_SUCCESS;
    } else if (socket->type == SOCK352_LISTEN) {
        return SOCK352_SUCCESS;
    } else {
        return SOCK352_FAILURE;
    }
}

/*----- Socket Manipulation Function Implementations -----*/

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

void *send_queue(void *sock) {
    puts("Send_Queue: Starting...");
    sock352_socket_t *socket = sock;

    while (!socket->send_halt) {
        puts("Send_Queue: About to block to dequeue a packet...");
        sock352_chunk_t *chunk = dequeue(socket->send_queue);
        puts("Send_Queue: Got a packet...");
        sock352_pkt_hdr_t header;
        memcpy(&header, &chunk->header, sizeof(sock352_pkt_hdr_t));
        int len = header.payload_len;
        encode_header(&header);
        void *data = chunk->data;
        gettimeofday(&chunk->time, NULL);
        send_packet(&header, data, len, socket);
        puts("Send_Queue: Sent a packet...");
    }
    socket->send_halt = 0;
    puts("Send_Queue: About to exit...");

    return NULL;
}

void *recv_queue(void *sock) {
    puts("Recv_Queue: Starting...");
    sock352_socket_t *socket = sock;
    sock352_pkt_hdr_t header, resp_header;
    char buffer[MAX_UDP_PACKET];

    while (!socket->recv_halt) {
        puts("Recv_Queue: About to block to receive a packet...");
        int status = recv_packet(&header, buffer, socket, 1, 0);
        if (socket->type == SOCK352_CLIENT && !socket->recv_halt) {
            puts("Recv_Queue: About to validate a packet...");
            if (valid_packet(&header, buffer, SOCK352_ACK) && valid_ack(&header, socket->last_ack, 0) && status != SOCK352_FAILURE) {
                puts("Recv_Queue: Received a valid ACK, clearing out send queue...");
                sock352_chunk_t *chunk = peek_head(socket->send_queue, 1);
                while (chunk && chunk->header.sequence_no < header.ack_no) {
                    puts("Recv_Queue: About to drop a packet from the send queue...");
                    drop(socket->send_queue);
                    destroy_chunk(chunk);
                    chunk = peek_head(socket->send_queue, 0);
                }
                printf("Recv_Queue: After clearing, length of queue is: %d\n", socket->send_queue->count);
                socket->last_ack = header.ack_no;
                socket->rseq_num = header.sequence_no;
            } else if (status == SOCK352_FAILURE) {
                puts("Recv_Queue: Time out, resetting send queue...");
                printf("Recv_Queue: Current length of the queue is: %d\n", socket->send_queue->count);
                reset(socket->send_queue);
            } else {
                puts("Recv_Queue: Packet was invalid...");
            }
        } else if (!socket->recv_halt) {
            puts("Recv_Queue: About to validate a packet...");
            if ((valid_packet(&header, buffer, 0) || valid_packet(&header, buffer, SOCK352_FIN)) && valid_sequence(&header, socket->rseq_num + 1) && status != SOCK352_FAILURE) {
                puts("Recv_Queue: Received a valid data packet, sending ACK...");
                if (header.flags == SOCK352_FIN) {
                    puts("Recv_Queue: Received packet was a FIN, marked remote side as closed...");
                    socket->rfin = 1;
                }
                socket->rseq_num = header.sequence_no;
                sock352_chunk_t *chunk = create_chunk(&header, buffer);
                enqueue(socket->recv_queue, chunk);
                create_header(&resp_header, socket->lseq_num, socket->rseq_num + 1, SOCK352_ACK, 0, 0);
                encode_header(&resp_header);
                send_packet(&resp_header, NULL, 0, socket);
            }
        }
    }
    socket->recv_halt = 0;
    puts("Recv_Queue: Exiting...");

    return NULL;
}

void destroy_352socket(sock352_socket_t *socket) {
    free(socket);
}

/*----- Queue Manipulation Function Declarations -----*/

void queue_send(queue_t *q, sock352_pkt_hdr_t *header, void *data) {
    sock352_chunk_t *chunk = create_chunk(header, data);
    enqueue(q, chunk);
}

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

int send_packet(sock352_pkt_hdr_t *header, void *data, int nbytes, sock352_socket_t *socket) {
    struct sockaddr_in udp_addr;
    setup_sockaddr(&socket->raddr, &udp_addr);
    char packet[sizeof(sock352_pkt_hdr_t) + nbytes];

    memcpy(packet, header, sizeof(sock352_pkt_hdr_t));
    if (data) memcpy(packet + sizeof(sock352_pkt_hdr_t), data, nbytes);
    int num_bytes = data ? sizeof(packet) : sizeof(sock352_pkt_hdr_t);

    return sendto(socket->fd, packet, num_bytes, 0, (struct sockaddr *) &udp_addr, sizeof(udp_addr));
}

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

    fd_set to_read;
    FD_ZERO(&to_read);
    FD_SET(socket->fd, &to_read);
    if (timeout) {
        if (timeout != 1) time.tv_usec = timeout * 1000;
        status = select(socket->fd + 1, &to_read, NULL, NULL, &time);
    } else {
        status = select(socket->fd + 1, &to_read, NULL, NULL, NULL);
    }
    if (FD_ISSET(socket->fd, &to_read)) {
        recvfrom(socket->fd, response, sizeof(response), 0, (struct sockaddr *) &sender, &addr_len);
    } else {
        return SOCK352_FAILURE;
    }
    if (save_addr) {
        socket->raddr.sin_port = sender.sin_port;
        socket->raddr.sin_addr = sender.sin_addr;
    }

    memcpy(header, response, sizeof(sock352_pkt_hdr_t));
    decode_header(header);
    if (data) memcpy(data, response + header_size, header->payload_len);

    return SOCK352_SUCCESS;
}

int valid_packet(sock352_pkt_hdr_t *header, void *data, int flags) {
    printf("Valid_Packet: Expected flags: %d...\n", flags);
    printf("Valid_Packet: Received flags: %d...\n", header->flags);
    int flag_check = header->flags == flags;

    // TODO: Add checksum validation here.
    int sum_check = 1;
    return flag_check && sum_check;
}

int valid_sequence(sock352_pkt_hdr_t *header, int expected) {
    printf("Valid_Sequence: Expected Sequence: %d...\n", expected);
    printf("Valid_Sequence: Received Sequence: %d...\n", header->sequence_no);
    return header->sequence_no == expected;
}

int valid_ack(sock352_pkt_hdr_t *header, int expected, int exact) {
    printf("Valid_Ack: Expecting ACK to be larger than: %d...\n", expected);
    printf("Valid_ack: Received ACK: %d...\n", header->ack_no);
    if (exact) {
        return header->ack_no == expected + 1;
    } else {
        return header->ack_no > expected;
    }
}

/*----- Header Manipulation Function Implementations -----*/

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

void setup_sockaddr(sockaddr_sock352_t *addr, struct sockaddr_in *udp_addr) {
    memset(udp_addr, 0, sizeof(struct sockaddr_in));
    udp_addr->sin_family = AF_INET;
    udp_addr->sin_addr = addr->sin_addr;
    udp_addr->sin_port = addr->sin_port;
}

/*----- Misc. Utility Function Implementations -----*/

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

void destroy_chunk(sock352_chunk_t *chunk) {
    free(chunk->data);
    free(chunk);
}

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

uint64_t ntohll(uint64_t num) {
    return htonll(num);
}

int endian_check() {
    int num = 42;
    return *((char *) &num) == 42;
}
