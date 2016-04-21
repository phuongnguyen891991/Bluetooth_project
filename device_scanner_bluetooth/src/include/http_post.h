#ifndef HTTP_POST_H
#define HTTP_POST_H

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>

#define SA      struct sockaddr
#define MAXLINE 4096
#define MAXSUB  200

int setup_http_request();

int process_post(char *params);

#endif