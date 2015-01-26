
#define MAX_UCLIENTS (100)
#define MAX_UCLIENT_MSG_SIZE (100)

struct uclient {
  int fd;
  char* msg;
  unsigned int msg_len;
  struct uclient* next;
};

#define FOR_ALL_UCLIENTS(_ucl) for(_ucl = uclients; _ucl; _ucl = _ucl->next)

int send_uclient_msg(char* cmd);
struct uclient* add_uclient(int fd);
int remove_uclient(struct uclient* ucl);
struct uclient* is_uclient_fd(int fd);
void handle_uclient_msg(struct uclient* ucl);
void receive_uclient_msg(struct uclient* ucl);
int send_uclient_msg(char* cmd);
int open_ipc_socket();
void accept_ipc_connection();
void handle_uclient_connections(fd_set* readfds);
int add_uclients_to_fd_set(fd_set* readfds, int maxfd);
