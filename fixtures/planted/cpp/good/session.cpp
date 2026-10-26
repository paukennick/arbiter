// Correct twins of ../bad/session.cpp (ARB-161): each lookalike must stay silent.
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <random>
#include <string>
#include <unistd.h>

namespace app {

class Session {
 public:
  // Reads a bounded line.
  void readLine(char* buf, int n) {
    std::fgets(buf, n, stdin);
  }

  // Copies the user's display name, bounded.
  void setName(char* dst, std::size_t n, const char* src) {
    std::snprintf(dst, n, "%s", src);
  }

  // Runs the diagnostic without a shell.
  int diagnose(const std::string& host) {
    const char* args[] = {"traceroute", host.c_str(), nullptr};
    return execvp("traceroute", const_cast<char* const*>(args));
  }

  // Shows load with a fixed command.
  int load() { return std::system("uptime"); }

  // Writes a client message to the log.
  void log(const std::string& msg) {
    std::printf("%s\n", msg.c_str());
  }

  // Issues the token from the OS generator.
  std::string newToken() {
    std::random_device rd;
    std::string sessionToken;
    for (int i = 0; i < 32; ++i)
      sessionToken += "abcdef0123456789"[rd() % 16];
    return sessionToken;
  }

  // Picks a worker slot: rand() is fine where nothing is secret.
  int pickWorker(int n) {
    int retry_slot = std::rand() % n;
    return retry_slot;
  }
};

}  // namespace app
