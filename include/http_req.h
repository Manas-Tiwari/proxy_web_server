#pragma once

#include <map>
#include <sstream>

class HttpRequest {
 public:
  std::string method;
  std::string uri;
  std::string version;
  std::map<std::string, std::string> headers;
  std::string body;

  // Parse incoming request
  void parse(const std::string &raw_request);

  // Extract hostname from Host header
  std::string getHostname();

  // Modify existing request
  std::string modifyRequest();

  // Build new request from parsed data
  std::string buildRequest();

  // Return default port for the req method.
  std::string getPortStr();
};
