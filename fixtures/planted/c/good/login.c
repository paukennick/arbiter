/* Correct twins of ../bad/login.c (ARB-161): each lookalike must stay silent. */
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <syslog.h>
#include <unistd.h>

#define BANNER "%s: ready\n"
#define UPTIME "uptime"

static const char *db_dsn_env = "DATABASE_URL";

/* Reads the user name from the terminal, bounded. */
void read_name(char *name, size_t n) {
    if (fgets(name, (int)n, stdin))
        name[strcspn(name, "\n")] = '\0';
}

/* Builds the greeting shown after login, bounded. */
void greet(char *out, size_t n, const char *user) {
    snprintf(out, n, "hello, %s", user);
    strncat(out, "!", n - strlen(out) - 1);
}

/* Pings the host without a shell. */
int ping_host(const char *host) {
    char *const args[] = {"ping", "-c", "1", (char *)host, NULL};
    return execvp("ping", args);
}

/* Fixed commands: a literal-initialised local, a macro and a literal. */
int show_uptime(void) {
    const char *cmd = "date";
    system(cmd);
    system(UPTIME);
    return system("uptime");
}

/* Lists the fixed spool directory through a pipe. */
FILE *list_spool(void) {
    return popen("ls /var/spool/app", "r");
}

/* Echoes and logs a message received from a client. */
void echo_message(const char *msg) {
    printf("%s", msg);
    fprintf(stderr, "%s\n", msg);
    syslog(LOG_WARNING, "%s", msg);
    printf(msg[0] ? "message\n" : "empty\n");
}

/* A printf-style wrapper: the format is the caller's. */
void log_line(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    printf(fmt);
}

/* Formats the audit line, bounded and with a literal format. */
void audit(char *line, size_t n, const char *who) {
    snprintf(line, n, "%s", who);
}

/* Issues a session token from the OS generator. */
void new_session(char *session_token, size_t n) {
    static const char alphabet[] = "abcdefghijklmnopqrstuvwxyz0123456789";
    unsigned char raw[64];
    if (n > sizeof raw || getrandom(raw, n, 0) < 0)
        return;
    for (size_t i = 0; i + 1 < n; i++)
        session_token[i] = alphabet[raw[i] % 36];
    session_token[n - 1] = '\0';
}

/* Retry jitter: rand() is fine where nothing is secret. */
int backoff_ms(int attempt) {
    int jitter_ms = rand() % 100;
    return attempt * 250 + jitter_ms;
}

int main(int argc, char **argv) {
    printf(BANNER, argv[0]);
    const char *dsn = getenv(db_dsn_env);
    (void)dsn;
    return argc > 1 ? ping_host(argv[1]) : 0;
}
