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
 * Creation Date:				Wed Jan 28 15:39:42 EST 2015
 * Filename:					sock352lib.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
#include "uthash.h"
#include "utlist.h"

#include "sock352.h"
#include "sock352lib.h"

int sock352_init(int port) {
	return SOCK352_SUCCESS;
}
int sock352_init2(int remote_port,int local_port) {
	return SOCK352_SUCCESS;
}

int sock352_init3(int remote_port,int local_port, char *envp[] ) {
	return SOCK352_SUCCESS;
}

int sock352_socket(int domain, int type, int protocol) {

}
int sock352_bind (int fd, struct sockaddr_sock352 *addr, socklen_t len){

	return SOCK352_SUCCESS;

}

int sock352_listen (int fd, int n){

	return SOCK352_SUCCESS;
}

int sock352_accept (int fd, sockaddr_sock352_t *addr, int *len) {

	return SOCK352_SUCCESS;
}

int sock352_connect(int fd, sockaddr_sock352_t *addr, socklen_t len) {

	return SOCK352_SUCCESS;;
}

extern int sock352_close(int fd) {

	return SOCK352_SUCCESS;
}

int sock352_read(int fd, void *buf, int count) {

	return count;
}

int sock352_write(int fd, void *buf, int count){

	return count;

}

