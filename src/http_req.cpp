#include "../include/http_req.h"

#include <map>
#include <sstream>

// Parse incoming request
void HttpRequest::parse(const std::string &raw_request) {
  std::istringstream stream(raw_request);

  stream >> method >> uri >> version;
  stream.ignore();  // Skip newline

  // Parse headers
  std::string line;
  while (std::getline(stream, line) && line != "\r") {
    size_t colon = line.find(':');
    if (colon != std::string::npos) {
      std::string key = line.substr(0, colon);
      std::string value = line.substr(colon + 2);  // Skip ": "
      // Remove \r if present
      if (!value.empty() && value.back() == '\r') {
        value.pop_back();
      }
      headers[key] = value;
    }
  }

  // Read body (remaining content)
  std::string body_line;
  while (std::getline(stream, body_line)) {
    body += body_line + "\n";
  }
}

// Extract hostname from Host header
std::string HttpRequest::getHostname() {
  // Find Host header
  auto it = headers.find("Host");
  if (it == headers.end()) {
    return "";  // No Host header found
  }

  std::string host = it->second;

  size_t colon_pos = host.find(':');
  if (colon_pos != std::string::npos) {
    return host.substr(0, colon_pos);
  }

  return host;
}

// Modify existing request
std::string HttpRequest::modifyRequest() {
  headers.erase("Proxy-Connection");
  headers["Connection"] = "close";

  return buildRequest();
}

// Build new request from parsed data
std::string HttpRequest::buildRequest() {
  std::ostringstream request;
  request << method << " " << uri << " " << version << "\r\n";

  for (const auto &header : headers) {
    request << header.first << ": " << header.second << "\r\n";
  }

  request << "\r\n";

  if (!body.empty()) {
    request << body;
  }

  return request.str();
}

// Return default port for the req method.
std::string HttpRequest::getPortStr() {
  if (method == "GET")
    return "80";
  else if (method == "CONNECT")
    return "443";
  else
    return "80";
}
