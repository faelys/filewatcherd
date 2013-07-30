/* run.c - command execution */

/*
 * Copyright (c) 2013, Natacha Porté
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <spawn.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "log.h"
#include "run.h"

/* run_entry - start the command associated with the given entry */
pid_t
run_entry(struct watch_entry *wentry) {
	char *argv[4];
	size_t i = 0;
	pid_t result;
	int has_delay = (wentry->delay.tv_sec || wentry->delay.tv_nsec);

	/* Create a child process and hand control back to parent */
	result = has_delay ? fork() : vfork();
	if (result == -1) {
		log_fork();
		return 0;
	} else if (result != 0) {
	 	return result;
	}

	/* chroot if requested */
	if (wentry->chroot) {
		if (chroot(wentry->chroot) < 0) {
			log_chroot(wentry->chroot);
			_exit(EXIT_FAILURE);
		}
		if (chdir("/") < 0) {
			log_chdir(wentry->chroot);
			_exit(EXIT_FAILURE);
		}
	}

	/* Set gid and uid if requested */
	if (wentry->gid && setgid(wentry->gid) < 0) {
		log_setgid(wentry->gid);
		_exit(EXIT_FAILURE);
	}
	if (wentry->uid && setuid(wentry->uid) < 0) {
		log_setuid(wentry->uid);
		_exit(EXIT_FAILURE);
	}

	/* Wait for some time if requested */
	if (has_delay)
		nanosleep(&wentry->delay, 0);

	/* Lookup SHELL environment variable */
	argv[0] = 0;
	for (i = 0; wentry->envp[i]; i++) {
		if (strncmp(wentry->envp[i], "SHELL=", 6) == 0) {
			argv[0] = wentry->envp[i] + 6;
			break;
		}
	}

	/* Build argument list */
	if (!argv[0]) argv[0] = "/bin/sh";
	argv[1] = "-c";
	argv[2] = (char *)wentry->command;
	argv[3] = 0;

	/* Handover control to the command */
	execve(argv[0], argv, wentry->envp);

	/* Report error */
	log_exec(wentry);
	_exit(EXIT_FAILURE);
}
