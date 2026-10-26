// Planted C++ defects (ARB-161). Each marked line has a lookalike in ../good.
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

namespace app {

class Session {
 public:
  // Reads a line into a fixed buffer.
  void readLine(char* buf) {
    std::gets(buf); // expect: arbiter/c.gets-call
  }

  // Copies the user's display name.
  void setName(char* dst, const char* src) {
    std::strcpy(dst, src); // expect: arbiter/c.unbounded-copy
  }

  // Runs the diagnostic the operator asked for.
  int diagnose(const std::string& host) {
    std::string cmd = "traceroute " + host;
    return std::system(cmd.c_str()); // expect: arbiter/c.command-injection
  }

  // Writes a client message to the log.
  void log(const std::string& msg) {
    std::printf(msg.c_str()); // expect: arbiter/c.format-string
  }

  // Issues the token handed to the browser.
  std::string newToken() {
    std::string sessionToken;
    for (int i = 0; i < 32; ++i)
      sessionToken += "abcdef0123456789"[std::rand() % 16]; // expect: arbiter/c.insecure-random-secret
    return sessionToken;
  }
};

}  // namespace app
