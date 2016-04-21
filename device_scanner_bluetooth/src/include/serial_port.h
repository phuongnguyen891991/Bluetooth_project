#ifndef SERIAL_PORT_H
#define SERIAL_PORT_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <termios.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>
#include <signal.h>
#include "http_post.h"

#define SPEED B115200
#define FLAG_LENGTH 6
#define EVENT_INDEX_1 3
#define EVENT_INDEX_2 4
#define STATUS_INDEX 5
#define SUCCESS 0x00
#define REQUEST_DISCOVERY 0
#define REQUEST_CONNECT 1
#define REQUEST_DISCONNECT 2
#define REQUEST_PAIRING 3
#define REQUEST_PAIRING_REGISTER 4
#define REQUEST_SCAN 5

int init_port(char *port);

int set_interface_attribs (int fd, int speed, int parity);

int set_blocking (int fd, int should_block);

int init_hci(int fd);

int send_request(int fd, int request, char *mac_address, char *handle);

void listen_serial_port(int fd, int request, char *mac_address, char *handle);

void process_receive_data(int request, int len, unsigned char buf[]);

void is_discovery_done(int len, unsigned char buf[]);

void is_connection_done(int len, unsigned char buf[]);

void is_disconnection_done(int len, unsigned char buf[]);

void is_pair_done(int len, unsigned char buf[], int need_register);

void is_scan_done(int len, unsigned char buf[]);

#endif