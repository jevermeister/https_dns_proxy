#include <sys/stat.h>
#include <sys/types.h>

#include <ctype.h>
#include <fcntl.h>
#ifndef _WIN32
	#include <grp.h>
	#include <pwd.h>
#else
	# define WIN32_LEAN_AND_MEAN
	# include <windows.h>
# endif


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "logging.h"
#include "options.h"

void options_init(struct Options *opt) {
  opt->listen_addr = "127.0.0.1";
  opt->listen_port = 5053;
  opt->edns_client_subnet = "";
  opt->logfile = "-";
  opt->logfd = -1;
  opt->loglevel = LOG_ERROR;
#ifndef _WIN32  
  opt->daemonize = 0;
  opt->user = "nobody";
  opt->group = "nobody";
  opt->uid = -1;
  opt->gid = -1;
#endif
  //new as from https://dnsprivacy.org/wiki/display/DP/DNS+Privacy+Test+Servers
  opt->bootstrap_dns = "8.8.8.8,8.8.4.4,145.100.185.15,145.100.185.16,185.49.141.37,199.58.81.218,80.67.188.188"; 
  opt->curl_proxy = NULL;
  opt->use_http_1_1 = 0;
}

int options_parse_args(struct Options *opt, int argc, char **argv) {
  int c;
  while ((c = getopt(argc, argv, "a:p:e:du:g:b:t:l:vx")) != -1) {
    switch (c) {
    case 'a': // listen_addr
      opt->listen_addr = optarg;
      break;
    case 'p': // listen_port
      opt->listen_port = atoi(optarg);
      break;
    case 'e': // edns_client_subnet
      opt->edns_client_subnet = optarg;
      break;
#ifndef _WIN32	  
    case 'd': // daemonize
      opt->daemonize = 1;
      break;
    case 'u': // user
      opt->user = optarg;
      break;
    case 'g': // group
      opt->group = optarg;
      break;
#endif
    case 'b': // bootstrap dns servers
      opt->bootstrap_dns = optarg;
      break;
    case 't': // curl http proxy
      opt->curl_proxy = optarg;
      break;
    case 'l': // logfile
      opt->logfile = optarg;
      break;
    case 'v': // verbose
      opt->loglevel--;
      break;
    case 'x': // http/1.1
      opt->use_http_1_1 = 1;
      break;
    case '?':
      printf("Unknown option '-%c'", c);
      return -1;
    default:
      printf("Unknown state!");
      exit(EXIT_FAILURE);
    }
  }
#ifndef _WIN32
  if (opt->daemonize) {
    struct passwd *p;
    if (!(p = getpwnam(opt->user)) || !p->pw_uid) {
      printf("Username (%s) invalid.\n", opt->user);
      return -1;
    }
    opt->uid = p->pw_uid;
    struct group *g;
    if (!(g = getgrnam(opt->group)) || !g->gr_gid) {
      printf("Group (%s) invalid.\n", opt->group);
      return -1;
    }
    opt->gid = g->gr_gid;
  }
#endif
  if (!strcmp(opt->logfile, "-")) {
    opt->logfd = STDOUT_FILENO;
  } else if ((opt->logfd = open(opt->logfile, 
#ifndef _WIN32
                                O_CREAT | O_WRONLY | O_APPEND | O_CLOEXEC,
#else
								O_CREAT | O_WRONLY | O_APPEND,
#endif
                                S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP)) <= 0) {
    printf("Logfile '%s' is not writable.\n", opt->logfile);
  }
  return 0;
}

void options_show_usage(int argc, char **argv) {
  struct Options defaults;
  options_init(&defaults);
  printf("Usage: %s [-a <listen_addr>] [-p <listen_port>]\n", argv[0]);
#ifndef _WIN32  
  printf("        [-e <subnet>] [-d] [-u <user>] [-g <group>] [-b <dns_servers>]\n");
  printf("        [-l <logfile>]\n\n");
#else
  printf("        [-e <subnet>] [-b <dns_servers>] [-l <logfile>]\n\n");
#endif

  printf("  -a listen_addr    Local address to bind to. (%s)\n",
         defaults.listen_addr);
  printf("  -p listen_port    Local port to bind to. (%d)\n",
         defaults.listen_port);
  printf("  -e subnet_addr    An edns-client-subnet to use such as "
                             "\"203.31.0.0/16\". (%s)\n",
         defaults.edns_client_subnet);
#ifndef _WIN32		 
  printf("  -d                Daemonize.\n");
  printf("  -u user           User to drop to launched as root. (%s)\n",
         defaults.user);
  printf("  -g group          Group to drop to launched as root. (%s)\n",
         defaults.group);
#endif
  printf("  -b dns_servers    Comma separated IPv4 address of DNS servers\n");
  printf("                    to resolve dns.google.com. (%s)\n",
         defaults.bootstrap_dns);
  printf("  -t proxy_server   Optional HTTP proxy. e.g. socks5://127.0.0.1:1080\n");
  printf("                    Remote name resolution will be used if the protocol\n");
  printf("                    supports it (http, https, socks4a, socks5h), otherwise\n");
  printf("                    initial DNS resolution will still be done via the\n");
  printf("                    bootstrap DNS servers.\n");
  printf("  -l logfile        Path to file to log to. (%s)\n",
         defaults.logfile);
  printf("  -x                Use HTTP/1.1 instead of HTTP/2. Useful with broken\n"
         "                    or limited builds of libcurl (false).\n");
  printf("  -v                Increase logging verbosity. (INFO)\n");
  options_cleanup(&defaults);
}

void options_cleanup(struct Options *opt) {
  if (opt->logfd > 0) {
    close(opt->logfd);
  }
}
