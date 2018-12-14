#ifndef __LIBCLI_H__
#define __LIBCLI_H__

// vim:sw=4 tw=120 et

#ifdef __cplusplus
extern "C" {
#endif

#include <stdarg.h>
#include <stdio.h>
#include <sys/time.h>
#include <stdbool.h>

#define LIBCLI_VERSION_MAJOR 1
#define LIBCLI_VERISON_MINOR 9
#define LIBCLI_VERISON_REVISION 8
#define LIBCLI_VERSION ((LIBCLI_VERSION_MAJOR << 16) | (LIBCLI_VERSION_MINOR << 8) | LIBCLI_VERSION_REVISION)

#define CLI_OK 0
#define CLI_ERROR -1
#define CLI_QUIT -2
#define CLI_ERROR_ARG -3

#define MAX_HISTORY 256

#define PRIVILEGE_UNPRIVILEGED 0
#define PRIVILEGE_PRIVILEGED 15
#define MODE_ANY -1
#define MODE_EXEC 0
#define MODE_CONFIG 1

#define LIBCLI_HAS_ENABLE 1

#define PRINT_PLAIN 0
#define PRINT_FILTERED 0x01
#define PRINT_BUFFERED 0x02

#define CLI_MAX_LINE_LENGTH 4096
#define CLI_MAX_LINE_WORDS 128

struct cli_def {
  int completion_callback;
  struct cli_command *commands;
  int (*auth_callback)(const char *, const char *);
  int (*regular_callback)(struct cli_def *cli);
  int (*enable_callback)(const char *);
  char *banner;
  struct unp *users;
  char *enable_password;
  char *history[MAX_HISTORY];
  char showprompt;
  char *promptchar;
  char *hostname;
  char *modestring;
  int privilege;
  int mode;
  int state;
  struct cli_filter *filters;
  void (*print_callback)(struct cli_def *cli, const char *string);
  FILE *client;
  /* internal buffers */
  void *conn;
  void *service;
  char *commandname;  // temporary buffer for cli_command_name() to prevent leak
  char *buffer;
  unsigned buf_size;
  struct timeval timeout_tm;
  time_t idle_timeout;
  int (*idle_timeout_callback)(struct cli_def *);
  time_t last_action;
  int telnet_protocol;
  void *user_context;
  struct cli_terminfo *terminfo;
};

struct cli_filter {
  int (*filter)(struct cli_def *cli, const char *string, void *data);
  void *data;
  struct cli_filter *next;
};

struct cli_command {
  char *command;
  int (*callback)(struct cli_def *, const char *, char **, int);
  unsigned int unique_len;
  char *help;
  int privilege;
  int mode;
  struct cli_command *next;
  struct cli_command *children;
  struct cli_command *parent;
};

struct cli_terminfo {
  int detected_terminal_width;
  int detected_terminal_height;
  int user_terminal_width;
  int user_terminal_height;
  int terminal_width;
  int terminal_height;
  bool enabled;
  volatile bool terminal_changed;
};

extern struct cli_def *cli_init();
extern int cli_done(struct cli_def *cli);
extern struct cli_command *cli_register_command(struct cli_def *cli, struct cli_command *parent, const char *command,
                                         int (*callback)(struct cli_def *, const char *, char **, int), int privilege,
                                         int mode, const char *help);
extern int cli_unregister_command(struct cli_def *cli, const char *command);
extern int cli_run_command(struct cli_def *cli, const char *command);
extern int cli_loop(struct cli_def *cli, int sockfd);
extern int cli_file(struct cli_def *cli, FILE *fh, int privilege, int mode);
extern void cli_set_auth_callback(struct cli_def *cli, int (*auth_callback)(const char *, const char *));
extern void cli_set_enable_callback(struct cli_def *cli, int (*enable_callback)(const char *));
extern void cli_allow_user(struct cli_def *cli, const char *username, const char *password);
extern void cli_allow_enable(struct cli_def *cli, const char *password);
extern void cli_deny_user(struct cli_def *cli, const char *username);
extern void cli_set_banner(struct cli_def *cli, const char *banner);
extern void cli_set_hostname(struct cli_def *cli, const char *hostname);
extern void cli_set_promptchar(struct cli_def *cli, const char *promptchar);
extern void cli_set_modestring(struct cli_def *cli, const char *modestring);
extern int cli_set_privilege(struct cli_def *cli, int privilege);
extern int cli_set_configmode(struct cli_def *cli, int mode, const char *config_desc);
extern void cli_reprompt(struct cli_def *cli);
extern void cli_regular(struct cli_def *cli, int (*callback)(struct cli_def *cli));
extern void cli_regular_interval(struct cli_def *cli, int seconds);
extern void cli_print(struct cli_def *cli, const char *format, ...) __attribute__((format(printf, 2, 3)));
extern void cli_bufprint(struct cli_def *cli, const char *format, ...) __attribute__((format(printf, 2, 3)));
extern void cli_vabufprint(struct cli_def *cli, const char *format, va_list ap);
extern void cli_error(struct cli_def *cli, const char *format, ...) __attribute__((format(printf, 2, 3)));
extern void cli_print_callback(struct cli_def *cli, void (*callback)(struct cli_def *, const char *));
extern void cli_free_history(struct cli_def *cli);
extern void cli_set_idle_timeout(struct cli_def *cli, unsigned int seconds);
extern void cli_set_idle_timeout_callback(struct cli_def *cli, unsigned int seconds, int (*callback)(struct cli_def *));

// Enable or disable telnet protocol negotiation.
// Note that this is enabled by default and must be changed before cli_loop() is run.
extern void cli_telnet_protocol(struct cli_def *cli, int telnet_protocol);

// Set/get user context
extern void cli_set_context(struct cli_def *cli, void *context);
extern void *cli_get_context(struct cli_def *cli);

// Set screen size 
extern void cli_set_detected_terminal_size(struct cli_def *cli, int width, int height) ;
extern void cli_set_terminal_size(struct cli_def *cli, int width, int height) ;
void cli_set_terminal_height(struct cli_def *cli, int height);
void cli_set_terminal_width(struct cli_def *cli, int width);
#ifdef __cplusplus
}
#endif

#endif
