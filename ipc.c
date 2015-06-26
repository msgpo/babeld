#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>
#include <time.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/un.h>

#include "babeld.h"
#include "util.h"
#include "interface.h"
#include "ipc.h"

char* socket_file = "/tmp/babeld.sock";

struct uclient* uclients = NULL;
int uclient_count = 0;

int usock;

struct uclient* add_uclient(int fd) {

  struct uclient *cur;

  struct uclient *ucl = malloc(sizeof(struct uclient));
  if(!ucl) {
    return NULL;
  }
  
  ucl->fd = fd;
  ucl->next = NULL;
  ucl->msg = malloc(MAX_UCLIENT_MSG_SIZE+1);
  if(!(ucl->msg)) {
    return NULL;
  }

  ucl->msg_len = 0;  

  if(!uclients) {
    uclients = ucl;
    uclient_count++;
    return ucl;
  }
  
  cur = uclients;
  while(cur->next) {
    cur = cur->next;
  }

  cur->next = ucl;
  uclient_count++;
  return ucl;
}

int remove_uclient(struct uclient* ucl) {

  struct uclient *cur;
  struct uclient *prev = NULL;

  if(!ucl || !uclients)
    return -1;
  
  if(uclients == ucl) {
    uclients = ucl->next;
    close(ucl->fd);
    free(ucl->msg);
    free(ucl);
    uclient_count--;
    return 0;
  }

  for(cur = uclients; cur->next; cur = cur->next) {
    if(cur == ucl) {
      prev->next = cur->next;
      close(ucl->fd);
      free(ucl->msg);
      free(ucl);
      uclient_count--;
      return 0;
    }
    prev = cur;
  }
  return -1;
}

// check if fd is a uclient fd
// and return its uclient struct
struct uclient* is_uclient_fd(int fd) {

  struct uclient *cur;

  if(!uclients)
    return NULL;
  
  for(cur = uclients; cur->next; cur = cur->next) {
    if(cur->fd == fd) {
      return cur;
    }
  }
  return NULL;
}

void handle_uclient_msg(struct uclient* ucl) {

  char cmd;
  char* arg;

  cmd = (ucl->msg)[0];
  arg = (ucl->msg)+1;

  printf("Got command: '%c' with argument: %s\n", cmd, arg);

  // TODO verify that this is an interface name

  switch(cmd) {

  case 'a':
    manage_interface(arg);
    break;

  case 'x':
    unmanage_interface(arg);
    break;
  }

  remove_uclient(ucl);
}

void receive_uclient_msg(struct uclient* ucl) {
  int num_bytes = read(ucl->fd, ucl->msg + ucl->msg_len, MAX_UCLIENT_MSG_SIZE - ucl->msg_len);

  if(num_bytes < 0) {
    fprintf(stderr, "Error reading from socket %s: %s\n", socket_file, strerror(errno));
    return;
  } else if(num_bytes == 0) {
    ucl->msg[ucl->msg_len] = '\0';
    handle_uclient_msg(ucl);
    return;
  }
  ucl->msg_len += num_bytes;
}

int send_uclient_msg(char cmd, char* arg) {

  int sock;
  size_t cmd_len;
  int bytes_written;
  int ret;
  char* full_cmd;
  struct sockaddr_un addr;
	
  cmd_len = strlen(arg) + 2; // one for leading cmd and one for trailing \0
  if(cmd_len > MAX_UCLIENT_MSG_SIZE) {
    fprintf(stderr, "Command too long (max %d bytes)\n", MAX_UCLIENT_MSG_SIZE);
    return -1;
  }

  full_cmd = malloc(cmd_len);
  if(!full_cmd) {
    return -1;
  }

  snprintf(full_cmd, cmd_len, "%c%s", cmd, arg);

  memset(&addr, 0, sizeof(struct sockaddr_un));
  addr.sun_family = AF_LOCAL;
  strcpy(addr.sun_path, socket_file);

  sock = socket(AF_LOCAL, SOCK_STREAM, 0);
			
  if(connect(sock, (struct sockaddr*) &addr, sizeof(struct sockaddr_un)) < 0) {
    fprintf(stderr, "Connect failed to %s: %s\n", socket_file, strerror(errno));
    fprintf(stderr, "Are you sure you have a running babeld instance?\n");
    close(sock);
    return -1;
  }

  bytes_written = 0;
			
  while(bytes_written < cmd_len) {
    ret = write(sock, full_cmd+bytes_written, cmd_len-bytes_written);
    if(ret < 0)  {
      fprintf(stderr, "Write failed to %s: %s\n", socket_file, strerror(errno));
      return -1;
    }
    bytes_written += ret;
  }

  close(sock);
  return 0;
}

int open_ipc_socket() {

  struct sockaddr_un addr;
  int usock_opts;
  int ret;

  memset(&addr, 0, sizeof(struct sockaddr_un));
  addr.sun_family = AF_LOCAL;
  strcpy(addr.sun_path, socket_file);

  usock = socket(AF_LOCAL, SOCK_STREAM, 0);
			
  usock_opts = fcntl(usock, F_GETFL, 0);
  ret = fcntl(usock, F_SETFL, usock_opts | O_NONBLOCK);
  if(ret == -1) {
    return ret;
  }

  if(connect(usock, (struct sockaddr*) &addr, sizeof(struct sockaddr_un)) < 0) {
    if(errno != ENOENT) {
      close(usock);
      unlink(socket_file);
      usock = socket(AF_LOCAL, SOCK_STREAM, 0);
    }
    //    printf("connect() error: %d | %s\n", errno, strerror(errno));
  } else {
    fprintf(stderr, "Looks like babeld is already running.\nUse '-a devname' to add a device.");
    return 1;
  }

  if(bind(usock, (struct sockaddr*) &addr, sizeof(struct sockaddr_un)) < 0) {
    fprintf(stderr, "Failed to bind socket %s: %s\n", socket_file, strerror(errno));
    return 1;
  }

  if(listen(usock, 10) < 0) {
    fprintf(stderr, "Listen failed on socket %s: %s\n", socket_file, strerror(errno));
    return 1;
  }

  return 0;
}


void accept_ipc_connection() {

	struct sockaddr addr;
	socklen_t addr_size = sizeof(struct sockaddr);
  int fd;

  if(uclient_count >= MAX_UCLIENTS) {
    fprintf(stderr, "Client connection limit reached (%d)\n", MAX_UCLIENTS);
    return;
  }

	fd = accept(usock, (struct sockaddr *)&addr, &addr_size);

	if(fd < 0) {
    fprintf(stderr, "Accept failed on socket %s: %s\n", socket_file, strerror(errno));
    return;
  }

  add_uclient(fd);

  return;
}

// returns the new maxfd
int add_uclients_to_fd_set(fd_set* readfds, int maxfd) {
  struct uclient* ucl;

  // add unix ipc socket to set
  FD_SET(usock, readfds);
  maxfd = MAX(maxfd, usock);

  FOR_ALL_UCLIENTS(ucl) {
    FD_SET(ucl->fd, readfds);
    maxfd = MAX(maxfd, ucl->fd);
  }
  return maxfd;
}

void handle_uclient_connections(fd_set* readfds) {
  struct uclient* ucl;

  if(FD_ISSET(usock, readfds)) {
    accept_ipc_connection();
  }

  FOR_ALL_UCLIENTS(ucl) {
    if(FD_ISSET(ucl->fd, readfds)) {
      receive_uclient_msg(ucl);
    }
  }
}
