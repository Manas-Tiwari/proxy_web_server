#include <arpa/inet.h>
#include <errno.h>
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
#include <csignal>
#include <cstddef>
#include <cstring>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <thread>

#include "../include/utils.h"

void signal_handler(int signal) {
  if (signal == SIGINT || signal == SIGTERM) {
    std::cout << "\nShutdown signal received (signal " << signal << ")"
              << std::endl;
    shutdown_requested = true;
  }
}

int main() {
  signal(SIGINT, signal_handler);
  signal(SIGTERM, signal_handler);

  auto res = main_server_listner();
  if (res != 0) {
    LOG_ERR("Error encountered while listening for connections.");
  }

  LOG_INFO("Wait for 2 sec before shutting down server.");
  std::this_thread::sleep_for(std::chrono::seconds(2));

  return 0;
}
