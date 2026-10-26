/* Planted C defects (ARB-161). Each marked line has a lookalike in ../good. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>

#define BANNER "%s: ready\n"

static const char *db_dsn = "postgres://svc:Pl4nted-Pr0d-Pw@db.internal:5432/app"; // expect: arbiter/secrets.pg-url

/* Reads the user name from the terminal. */
void read_name(char *name) {
    gets(name); // expect: arbiter/c.gets-call
}

/* Builds the greeting shown after login. */
void greet(char *out, const char *user) {
    strcpy(out, "hello, "); // expect: arbiter/c.unbounded-copy
    strcat(out, user); // expect: arbiter/c.unbounded-copy
}

/* Pings the host the user typed. */
int ping_host(const char *host) {
    char cmd[256];
    snprintf(cmd, sizeof cmd, "ping -c 1 %s", host);
    return system(cmd); // expect: arbiter/c.command-injection
}

/* Lists a directory through a pipe. */
FILE *list_dir(const char *dir) {
    return popen(dir, "r"); // expect: arbiter/c.command-injection
}

/* Echoes and logs a message received from a client. */
void echo_message(const char *msg) {
    printf(msg); // expect: arbiter/c.format-string
    fprintf(stderr, msg); // expect: arbiter/c.format-string
    syslog(LOG_WARNING, msg); // expect: arbiter/c.format-string
}

/* Formats the audit line. */
void audit(char *line, const char *who) {
    sprintf(line, who); // expect: arbiter/c.unbounded-copy, arbiter/c.format-string
}

/* Issues a session token for a new login. */
void new_session(char *session_token, size_t n) {
    static const char alphabet[] = "abcdefghijklmnopqrstuvwxyz0123456789";
    srand((unsigned)time(NULL));
    for (size_t i = 0; i + 1 < n; i++)
        session_token[i] = alphabet[rand() % 36]; // expect: arbiter/c.insecure-random-secret
    session_token[n - 1] = '\0';
}

/* The reset nonce mailed to the user. */
long reset_nonce(void) {
    long nonce = random(); // expect: arbiter/c.insecure-random-secret
    return nonce;
}

int main(int argc, char **argv) {
    printf(BANNER, argv[0]);
    (void)db_dsn;
    return argc > 1 ? ping_host(argv[1]) : 0;
}
