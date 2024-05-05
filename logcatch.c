/* logcatch - run a process with private /dev/log
 *
 * Usage: logcatch [-s] {-t FD | -u PATH} COMMAND ...
 *   -s         strip syslog prefix when used with -t
 *   -t FD      print syslog messages to file descriptor FD
 *   -u PATH    connect /dev/log to the unix domain socket at PATH
 *
 * To the extent possible under law, Leah Neukirchen <leah@vuxu.org>
 * has waived all copyright and related or neighboring rights to this work.
 * https://creativecommons.org/publicdomain/zero/1.0/
 */

/* with "setcap cap_sys_admin,cap_setpcap+ep logcatch" this can be run as
 * ordinary user. */

#define _GNU_SOURCE

#if defined __has_include
  #if __has_include(<sys/capability.h>)
    #include <sys/capability.h>
    #define HAVE_CAPABILITY
  #endif
#endif

#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>

#include <errno.h>
#include <libgen.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <string.h>
#include <unistd.h>

int tflag;
int sflag;
char *uflag;

noreturn static void
fatal(const char *msg)
{
	perror(msg);
	exit(111);
}

int
logsock(int s)
{
#ifdef HAVE_CAPABILITY
	cap_set_mode(CAP_MODE_NOPRIV);  /* drop all capabilities */
#endif

	setsid();

	sigset_t mask;
	sigemptyset(&mask);
	sigaddset(&mask, SIGHUP);
	sigprocmask(SIG_BLOCK, &mask, 0);

	int sighupfd = signalfd(-1, &mask, SFD_CLOEXEC);
	if (sighupfd < 0)
		fatal("signalfd");

	if (prctl(PR_SET_PDEATHSIG, SIGHUP) < 0)
		fatal("prctl");

	char linebuf[4096];

	struct pollfd fds[2] = {
		{ .fd = s, .events = POLLIN },
		{ .fd = sighupfd, .events = POLLIN },
	};

	while (1) {
		int n = poll(fds, sizeof fds / sizeof fds[0], -1);

		if (n < 0)
			fatal("poll");

		if (fds[0].revents & POLLIN) {
			ssize_t len = recv(s, linebuf, sizeof linebuf, 0);
			if (len < 0)
				fatal("recv");

			if (len < (ssize_t)sizeof linebuf) {
				linebuf[len++] = '\n';
			} else {
				len -= 5;
				linebuf[len++] = ' ';
				linebuf[len++] = '.';
				linebuf[len++] = '.';
				linebuf[len++] = '.';
				linebuf[len++] = '\n';
			}

			int offset = 0;

			if (sflag) {
				/* skip syslog prefix */

				/* could start with <D>, <DD>, <DDD> */
				/* followed by 15 chars timestamp and a space */
				if (len > 19 && linebuf[0] == '<') {
					if (linebuf[2] == '>')
						offset = 3 + 15 + 1;
					else if (linebuf[3] == '>')
						offset = 4 + 15 + 1;
					else if (linebuf[4] == '>')
						offset = 5 + 15 + 1;
				}
			}

			ssize_t r = write(tflag, linebuf + offset, len - offset);
			if (r < 0)
				perror("write");

			/* keep draining the socket before handling signal */
			continue;
		}

		if (fds[1].revents & POLLIN)
			break;
	}

	exit(0);
}

int
main(int argc, char *argv[])
{
	int c;
	while ((c = getopt(argc, argv, "+st:u:")) != -1)
		switch (c) {
		case 's': sflag = 1; break;
		case 't': tflag = atoi(optarg); break;
		case 'u': uflag = optarg; break;
		default:
		usage:
			fprintf(stderr,
			    "Usage: %s [-s] {-t FD | -u PATH} COMMAND ...\n",
			    argv[0]);
			exit(1);
		}

	if (argc < optind)
		goto usage;

	if (!tflag == !uflag) {
		fprintf(stderr, "error: need either -t or -u\n");
		goto usage;
	}

	if (tflag) {
		errno = 0;
		fcntl(tflag, F_GETFD);
		if (errno)
			fatal("invalid file descriptor for -t");
	}

	if (unshare(CLONE_NEWNS) < 0)
		fatal("unshare");

	/* Don't let our bind mounts propagate outside, but accept new mounts
	   from outside. */
	if (mount("none", "/", 0, MS_REC | MS_SLAVE, 0) < 0)
		fatal("mount /");

	if (tflag) {
		int s = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
		struct sockaddr_un sa = { 0 };
		sa.sun_family = AF_UNIX;

		/* We cannot remove /dev/log to bind it directly, but only
		   bind-mount over it, so create the socket we listen on in a
		   temporary dir. */

		char path[64] = "/tmp/logcatch.XXXXXX";
		if (!mkdtemp(path))
			fatal("mkdtemp");
		strcat(path, "/log");
		strncpy(sa.sun_path, path, sizeof sa.sun_path - 1);

		int old_umask = umask(0);
		if (bind(s, (struct sockaddr *)&sa, sizeof sa) < 0)
			fatal("bind");
		umask(old_umask);

		pid_t logger = fork();
		if (logger < 0)
			fatal("fork logsock");
		else if (logger == 0)
			logsock(s);

		if (mount(path, "/dev/log", 0, MS_BIND, 0) < 0)
			fatal("bind mount /dev/log");

		unlink(path);
		rmdir(dirname(path));
	}

	if (uflag) {
		if (mount(uflag, "/dev/log", 0, MS_BIND, 0) < 0)
			fatal("bind mount /dev/log");
	}

	execvp(argv[optind], argv + optind);

	fatal("execvp");
}
