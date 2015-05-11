
/* Copyright (c) 2015 Rutgers University and Richard P. Martin.
 * All rights reserved.
 *
 * Permission to use, copy, modify, and distribute this software and its
 * documentation for any purpose, without fee, and without written agreement is
 * hereby granted, provided that the following conditions are met:
 *
 *    1. Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *
 *    2. Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *
 *    3. Neither the name of the University nor the names of its
 *       contributors may be used to endorse or promote products derived from
 *       this software without specific prior written permission.
 *
 * IN NO EVENT SHALL RUTGERS UNIVERSITY BE LIABLE TO ANY PARTY FOR DIRECT,
 * INDIRECT, SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES ARISING OUT
 * OF THE USE OF THIS SOFTWARE AND ITS DOCUMENTATION, EVEN IF RUTGERS
 * UNIVERSITY HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * RUTGERS UNIVERSITY SPECIFICALLY DISCLAIMS ANY WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE.  THE SOFTWARE PROVIDED HEREUNDER IS
 * ON AN "AS IS" BASIS, AND RUTGERS UNIVERSITY HAS NO OBLIGATION TO
 * PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR MODIFICATIONS.
 *
 *
 * Author:                      Richard P. Martin
 * Version:                     1
 * Creation Date:				Tue Apr 28 16:57:43 EDT 2015
 * Filename:					server4.c
 */

/* this is the CS 352 spring 2015 server program for the bandwidth challenge test
 * Students must complete the sock352 calls for this library for this server to work
 * with the corresponding client. See sock352.h for the definition
 */
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <math.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <openssl/md5.h>

#include "sock352.h"

#define BUFFER_SIZE 65536
#define MAX_ZERO_BYTE_READS 1000000

void usage() {
		printf("server4: usage: -n -u <udp-port> -l <local-port> -r <remote-port> \n");
}

/* this returns the lapsed number of micro-seconds given timestamps since epoch
 * (epoch is Jan 1, 1970 */
uint64_t lapsed_usec(struct timeval * start, struct timeval *end){
	uint64_t bt, be;  /* start, end times as 64 bit integers */

	bt =  (uint64_t) start->tv_sec *  (uint64_t)(1000000) + (uint64_t )start->tv_usec;
	be =  (uint64_t) end->tv_sec *  (uint64_t)(1000000) + (uint64_t ) end->tv_usec;

	if (be >= bt) { /* make sure we don't return a negative time */
		return (be-bt);
	}
	else {
		printf("server4 lapsed_usec: warning, negative time interval\n");
		return 0;
	}
}

int main(int argc, char *argv[], char *envp) {
		uint32_t input_size;
		uint32_t input_size_network;

		sockaddr_sock352_t server_addr,client_addr; /*  address of the server and client*/
		uint32_t cs352_port;
		uint32_t udp_port,local_port,remote_port;  /* ports used for remote library */
		int retval;  /* return code */
		int listen_fd, connection_fd;

		char buffer[BUFFER_SIZE]; /* read/write buffer */
		int end_of_file, total_bytes, bytes_read; /* for reading the input file */
		int client_addr_len;
		int socket_closed;
		int zero_bytes,bw;
		struct timeval begin_time, end_time; /* start, end time to compute bandwidth */
		uint64_t lapsed_useconds;
		double lapsed_seconds;
		MD5_CTX md5_context;
		int compute_checksum; /* compute the checksum or not */
		unsigned char md5_out[MD5_DIGEST_LENGTH];
		int c,i; /* index counters */

		/* set defaults */
		udp_port = SOCK352_DEFAULT_UDP_PORT;
		local_port = remote_port = 0 ;
		compute_checksum = 1;
		/* Parse the arguments to get: */
		opterr = 0;

		while ((c = getopt (argc, argv, "c:u:l:r:n")) != -1) {
			switch (c) {
		      case 'c':
		        cs352_port = atoi(optarg);
		        break;
		      case 'u':
		        udp_port = atoi(optarg);
		        break;
		      case 'l':
		    	  local_port =  atoi(optarg);
		    	  break;
		      case 'r':
		    	  remote_port =  atoi(optarg);
		    	  break;
		      case 'n':
		    	  compute_checksum =0;
		    	  break;
		      case '?':
		    	  usage();
		    	  exit(-1);
		    	  break;
		      default:
		        printf("server4 unknown option: ");
		        usage();
		        exit(-1);
		        break;
			}
		}

		/* change which init function to use based on the arguments */
		/* if BOTH the local and remote ports are set, use the init2 function */

		if ( (remote_port > 0) && (local_port > 0) ) {
			retval =  sock352_init2(remote_port, local_port);
		} else {
			retval = sock352_init(udp_port);
		}
		if (retval != SOCK352_SUCCESS < 0) {
			printf("server4 initialization of 352 sockets on UDP port %d failed\n",udp_port);
			exit(-1);
		}
		listen_fd = sock352_socket(AF_CS352,SOCK_STREAM,0);

		/* the destination port overrides the udp port setting */
		if (remote_port != 0) {
			udp_port = remote_port;
		}

		memset(&server_addr,0,sizeof(server_addr));
		server_addr.sin_family = AF_CS352;
		server_addr.sin_addr.s_addr=htonl(INADDR_ANY);
		server_addr.sin_port=htons(udp_port);

		if ( sock352_bind(listen_fd,(sockaddr_sock352_t *) &server_addr,
				sizeof(server_addr)) != SOCK352_SUCCESS) {
			printf("server4 bind failed \n");
			exit(-1);
		}

		if ( (sock352_listen(listen_fd,5)) != SOCK352_SUCCESS) {
			printf("server4 listen failed \n");
			exit(-1);
		}
		client_addr_len = sizeof(client_addr);
		connection_fd  = sock352_accept(listen_fd,(sockaddr_sock352_t *)&client_addr,
										&client_addr_len);

		if (connection_fd == SOCK352_FAILURE) {
			printf("server4 accept failed");
			exit(-1);
		}

		socket_closed = zero_bytes = total_bytes = 0;
		if (compute_checksum) MD5_Init(&md5_context);
		gettimeofday(&begin_time, (struct timezone *) NULL);

		/* the first 4 bytes are the file size in network byte order */
		bytes_read = sock352_read(connection_fd,&input_size_network,sizeof(input_size_network));
		if (bytes_read != sizeof(input_size_network)) {
			printf("server4 read of file size failed \n");
			exit(-1);
		}
		input_size = ntohl(input_size_network); /* size of the file */

		/* initialize text variables correctly */
		total_bytes = zero_bytes = socket_closed = 0;
		/* loop until we either get the whole file or there is an error */

		while ( (total_bytes < input_size) &&
				(! socket_closed)) {
			bytes_read = sock352_read(connection_fd,buffer,BUFFER_SIZE);
			if (bytes_read > 0) {
				total_bytes += bytes_read;
				if (compute_checksum)  MD5_Update(&md5_context, buffer, bytes_read);
			} else {
				if (bytes_read == 0) {
					zero_bytes++;
				} else {
					if (bytes_read < 0 ){
						socket_closed = 1;
					}
				}
			}
			if (zero_bytes > MAX_ZERO_BYTE_READS) {
				printf("server4: too many zero byte returns, closing connection\n");
				socket_closed = 1;
			}
		} /* end while socket not closed */
		/* printf("zero byte calls is %d \n",zero_bytes); */
		gettimeofday(&end_time, (struct timezone *) NULL);
		if (compute_checksum) MD5_Final(md5_out, &md5_context);

		/* make sure to clean up! */
		sock352_close(connection_fd);
		sock352_close(listen_fd);

		lapsed_useconds = lapsed_usec(&begin_time, &end_time);
		lapsed_seconds = (double) lapsed_useconds / (double) 1000000;
		printf("server4 received %d bytes in %lf sec, bandwidth %8.4lf Mb/s \n", total_bytes,lapsed_seconds,
				( (double) total_bytes/ (double) (1048576*8)) /lapsed_seconds );
		if (compute_checksum) {
			printf("server4 MD5-checksum: ");
			for(i=0; i < MD5_DIGEST_LENGTH; i++)
				printf("%02x", md5_out[i]);
			printf("\n");
		}

return 0;

}
