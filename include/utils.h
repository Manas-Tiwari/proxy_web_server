#pragma once

#include <netdb.h>

#include <atomic>
#include <cstdio>

#include "http_req.h"

#define CHECK_ERR(var, val)                                                  \
  {                                                                          \
    if (var == val) {                                                        \
      fprintf(stderr, "%s:%d: %s err: %d\n", __FILE__, __LINE__, #var, val); \
    }                                                                        \
  }

#define LOG_INFO(msg)                                             \
  {                                                               \
    printf("[%s][%d][INFO]: %s\n", __FILE_NAME__, __LINE__, msg); \
  }

#define LOG_ERR(msg)                                               \
  {                                                                \
    printf("[%s][%d][ERROR]: %s\n", __FILE_NAME__, __LINE__, msg); \
  }

#define PORT "8080"

#define BACKLOG 10
#define MAX_BUFF_LEN 4096

// Flag used to shutdown server when abort signal is received.
inline std::atomic<bool> shutdown_requested(false);

// Utility function to print address info.
void print_addrinfo(struct addrinfo *res);

// Get sock addr for IPv4 or IPv6.
void *get_in_addr(struct sockaddr *sa);

// Handles incoming request from clients.
// Main entrypoint for each connections received.
// A new thread is created for each req.
void handle_connection(int);

// Starts the main listner sever.
int main_server_listner();

// Handles conneciton with destination server.
// Send modifed req. and receives the resource requested by client.
int send_req(std::string &host, std::string &port, std::string &msg,
             std::string &server_res, int conn_fd = -1);

// Recv response from destination server.
// Called/Used by send_req() func.
int recv_res_from_server(int sockfd, std::string &server_res);

// Get address info pointer for the given host and port.
int get_addr_info_node_ptr(std::string host, std::string &port,
                           struct addrinfo *&server_addr);

// Returns request string made from the request received from the clinet.
int get_server_req_str(std::string &client_req_str, std::string &req_str,
                       HttpRequest &http_req);

// Cusotm send() impl to send msg string.
int send_msg(int fd, std::string &msg);
