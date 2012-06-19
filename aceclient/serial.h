#ifndef __MYSERIAL_PORT_H
#define __MYSERIAL_PORT_H

int open_port(int port);
int close_port(int fd);
int setup_port(int fd, int speed, int data_bits, int parity, int stop_bits);

#endif

