#include "../include/utils.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstring>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <thread>

void print_addrinfo(struct addrinfo *res) {
  struct addrinfo *p;
  char ipstr[INET6_ADDRSTRLEN];

  for (p = res; p != NULL; p = p->ai_next) {
    void *addr;
    const char *ipver;

    if (p->ai_family == AF_INET) {  // IPv4
      struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
      addr = &(ipv4->sin_addr);
      ipver = "IPv4";
    } else {  // IPv6
      struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)p->ai_addr;
      addr = &(ipv6->sin6_addr);
      ipver = "IPv6";
    }

    inet_ntop(p->ai_family, addr, ipstr, sizeof ipstr);

    printf("--- Result Node ---\n");
    printf("  Family:     %s (%d)\n", ipver, p->ai_family);
    printf("  Socktype:   %s (%d)\n",
           (p->ai_socktype == SOCK_STREAM ? "Stream/TCP" : "Datagram/UDP"),
           p->ai_socktype);
    printf("  Protocol:   %d\n", p->ai_protocol);
    printf("  Address:    %s\n", ipstr);
    printf("  Addr Len:   %d bytes\n", (int)p->ai_addrlen);

    if (p->ai_canonname) {
      printf("  Canon Name: %s\n", p->ai_canonname);
    }
    printf("\n");
  }
}

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa) {
  if (sa->sa_family == AF_INET) {
    return &(((struct sockaddr_in *)sa)->sin_addr);
  }

  return &(((struct sockaddr_in6 *)sa)->sin6_addr);
}

int main_server_listner() {
  int sockfd, connfd;
  struct addrinfo *server_info, hints, *list_ptr;
  struct sockaddr_storage conn_addr;
  socklen_t conn_addr_size;
  int rv = 0;
  int yes = 1;
  char s[INET6_ADDRSTRLEN];
  char recv_buff[MAX_BUFF_LEN];

  memset(&hints, 0, sizeof hints);

  hints.ai_flags = AI_PASSIVE;
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;

  if ((rv = getaddrinfo(NULL, PORT, &hints, &server_info) != 0)) {
    fprintf(stderr, "getaddrinfo error: %s", gai_strerror(rv));
    return 1;
  }

  for (list_ptr = server_info; list_ptr != nullptr;
       list_ptr = list_ptr->ai_next) {
    sockfd = socket(list_ptr->ai_family, list_ptr->ai_socktype,
                    list_ptr->ai_protocol);
    if (sockfd == -1) {
      LOG_INFO("Unable to get valid sock fd for current addr, trying next.");
      continue;
    }

    fcntl(sockfd, F_SETFL, O_NONBLOCK);

    // Resuse same socket if program restarts.
    auto set_sock_res =
        setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));
    CHECK_ERR(set_sock_res, -1);

    auto bind_res = bind(sockfd, list_ptr->ai_addr, list_ptr->ai_addrlen);
    if (bind_res == -1) {
      close(sockfd);
      LOG_INFO("Unable to bind sockfd.");
      continue;
    }

    break;
  }

  freeaddrinfo(server_info);

  if (list_ptr == nullptr) {
    LOG_ERR("Unable to bind sockfd for all of the provided addresses.");
    LOG_ERR("Closing listner.");
    return 1;
  }

  if (listen(sockfd, BACKLOG) == -1) {
    LOG_ERR("Unable to listen for connections.");
    LOG_ERR("Closing listner.");
    return 1;
  }
  std::cout << "Listening for connections on port: " << PORT << std::endl;

  while (!shutdown_requested) {
    conn_addr_size = sizeof(conn_addr);
    connfd = accept(sockfd, (struct sockaddr *)&conn_addr, &conn_addr_size);

    if (connfd == -1) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        continue;
      } else {
        perror("accept");
        continue;
      }
    }
    inet_ntop(conn_addr.ss_family, get_in_addr((struct sockaddr *)&conn_addr),
              s, sizeof s);
    printf("server: got connection from %s\n", s);

    std::thread conn_th(handle_connection, connfd);
    conn_th.detach();
  }
  close(sockfd);
  return 0;
}

int get_server_req_str(std::string &client_req_str, std::string &req_str,
                       HttpRequest &http_req) {
  http_req.parse(client_req_str);
  req_str = http_req.modifyRequest();
  return 0;
}

int get_addr_info_node_ptr(std::string host, std::string &port,
                           struct addrinfo *&server_addr) {
  struct addrinfo hints;

  std::memset(&hints, 0, sizeof hints);

  hints.ai_flags = AI_PASSIVE;
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;

  int rv = getaddrinfo(host.c_str(), "80", &hints, &server_addr);
  return rv;
}

int send_req(std::string &host, std::string &port, std::string &msg,
             std::string &server_res, int conn_fd) {
  struct addrinfo *server_info, *node;
  char s[INET6_ADDRSTRLEN];

  auto addr_res = get_addr_info_node_ptr(host, port, server_info);
  CHECK_ERR(addr_res, -1);
  int sockfd;
  int yes = 1;

  for (node = server_info; node != nullptr; node = node->ai_next) {
    sockfd = socket(node->ai_family, node->ai_socktype, node->ai_protocol);
    if (sockfd == -1) {
      LOG_INFO("Unable to get valid sock fd for current addr, trying next.");
      continue;
    }

    inet_ntop(node->ai_family, get_in_addr((struct sockaddr *)node->ai_addr), s,
              sizeof(s));

    if (connect(sockfd, node->ai_addr, node->ai_addrlen) == -1) {
      perror("connect");
      close(sockfd);
      continue;
    }
    break;
  }

  if (node == nullptr) {
    fprintf(stderr, "Unable to get any valid addrinfo struct.");
    return -1;
  }

  inet_ntop(node->ai_family, get_in_addr((struct sockaddr *)node->ai_addr), s,
            sizeof(s));
  printf("Connected to %s.\n", s);

  freeaddrinfo(server_info);

  LOG_INFO("Conn. established with destination server.");

  auto status = send_msg(sockfd, msg);
  if (status != 0) {
    LOG_ERR("Error while sendign data.")
    close(sockfd);
    return -1;
  }

  LOG_INFO("Req sent to destination server.");

  status = recv_res_from_server(sockfd, server_res);
  if (status != 0) {
    LOG_ERR("Failed to receive data from server.")
    close(sockfd);
    return -1;
  }

  std::cout << '\n';
  std::cout << "Received response : " << server_res << '\n';
  std::cout << '\n';

  close(sockfd);

  return 0;
}

int send_msg(int sockfd, std::string &msg) {
  auto sent_msg_len = 0;
  while (sent_msg_len < msg.size()) {
    auto curr_msg_len = msg.size() - sent_msg_len;
    auto curr_msg_ptr = msg.c_str() + sent_msg_len;

    auto send_res = send(sockfd, curr_msg_ptr, curr_msg_len, 0);

    if (sockfd == -1) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        continue;
      } else {
        perror("Error while sending req to destination server.");
        close(sockfd);
        return -1;
      }
    }
    sent_msg_len += send_res;
  }
  return 0;
}

int recv_res_from_server(int sockfd, std::string &server_res) {
  auto recv_msg_len = 1;
  char res[MAX_BUFF_LEN];
  while (recv_msg_len > 0) {
    // TODO: polling can be used?!
    recv_msg_len = recv(sockfd, res, MAX_BUFF_LEN, 0);

    if (recv_msg_len == -1) {
      // Signal Interruption
      if (errno == EINTR) {
        continue;
      }

      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        continue;
      }

      LOG_ERR("Failed to receive msg from destination server.");
      close(sockfd);
      return -1;
    }

    server_res.append(res, recv_msg_len);
  }
  return 0;
}

void handle_connection(int connfd) {
  char recv_buff[MAX_BUFF_LEN];

  LOG_INFO("Waiting to recv data from client.");
  int recv_bytes = recv(connfd, recv_buff, MAX_BUFF_LEN - 1, 0);
  if (recv_bytes == 0) {
    LOG_ERR("Connection closed, could not recv data.\n");
    close(connfd);
    return;
  }

  recv_buff[recv_bytes] = '\0';
  printf("Received client req buffer: %s\n", recv_buff);

  // Form server req string from the req recived from client.
  // This req will be relayed to the original destination.
  std::string req_str_;
  std::string client_req_str_(recv_buff, recv_bytes);
  HttpRequest http_req_;
  auto status = get_server_req_str(client_req_str_, req_str_, http_req_);
  if (status != 0) {
    LOG_ERR("Closing connection, could not retrieve requested string.\n");
    close(connfd);
    return;
  }

  std::string server_res;
  auto host = http_req_.getHostname();
  std::string port_str = http_req_.getPortStr();

  // sends request to server and receives response.
  // TODO: Response reception step can be seperated.
  status = send_req(host, port_str, req_str_, server_res);
  if (status != 0) {
    LOG_ERR("Error during communication with server.\n");
    close(connfd);
    return;
  }

  LOG_INFO("Sending response back to client.");
  status = send_msg(connfd, server_res);
  if (status != 0) {
    LOG_ERR("Error during communication with server.\n");
    close(connfd);
    return;
  }

  LOG_INFO("Closing connection.")
  close(connfd);
}
