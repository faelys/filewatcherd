/* filewatcherd.c - main function for file watcher daemon */

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

#include <fcntl.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <signal.h>

#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>

#include "log.h"
#include "run.h"
#include "watchtab.h"

/* insert_entry - wait for an event described by the given watchtab entry */
static int
insert_entry(int kq, struct watch_entry *wentry) {
	struct kevent event;
	wentry->fd = open(wentry->path, O_RDONLY | O_CLOEXEC);
	if (wentry->fd < 0) {
		log_open_entry(wentry->path);
		wentry->fd = -1;
		return -1;
	}
	EV_SET(&event, wentry->fd,
	    EVFILT_VNODE,
	    EV_ADD | EV_ONESHOT,
	    wentry->events,
	    0,
	    wentry);
	if (kevent(kq, &event, 1, 0, 0, 0) < 0) {
		log_kevent_entry(wentry->path);
		close(wentry->fd);
		wentry->fd = -1;
		return -1;
	}

	log_entry_wait(wentry);
	return 0;
}



int
main(int argc, char **argv) {
	int kq;			/* file descriptor for the kernel queue */
	int argerr = 0;		/* whether arguments are invalid */
	int help = 0;		/* whether help text should be displayed */
	int daemonize = 1;	/* whether fork to background and use syslog */
	const char *tabpath = 0;/* path to the watchtab file */
	int tab_fd;		/* file descriptor of watchtab */
	FILE *tab_f;		/* file stream of watchtab */
	struct watchtab wtab;	/* current watchtab data */
	intptr_t delay = 100;	/* delay in ms before reloading watchtab */
	int wtab_error = 0;	/* whether watchtab can't be opened */

	struct option longopts[] = {
	    { "foreground", no_argument,       0, 'd' },
	    { "help",       no_argument,       0, 'h' },
	    { "wait",       required_argument, 0, 'w' },
	    { 0,            0,                 0,  0 }
	};

	/* Temporary variables */
	struct kevent event;
	struct watch_entry *wentry;
	pid_t pid;
	char c;
	char *s;


	/***************************
	 * COMMAND LINE PROCESSING *
	 ***************************/

	/* Process options */
	while (!argerr
	    && (c = getopt_long(argc, argv, "dhw:", longopts, 0)) != -1) {
		switch (c) {
		    case 'd':
			daemonize = 0;
			break;
		    case 'h':
			help = 1;
			break;
		    case 'w':
			delay = strtol(optarg, &s, 10);
			if (!s[0]) {
				log_bad_delay(optarg);
				argerr = 1;
			}
			break;
		    default:
			argerr = 1;
		}
	}

	/* Use the first argument as watchtab, discard the reset */
	if (optind < argc)
		tabpath = argv[optind];
	else
		argerr = 1;

	/* Display help text and terminate */
	if (argerr || help) {
		print_usage(!help, argc, argv);
		return help ? EXIT_SUCCESS : EXIT_FAILURE;
	}


	/******************
	 * INITIALIZATION *
	 ******************/

	if (signal(SIGCHLD, SIG_IGN) == SIG_ERR) {
		log_signal(SIGCHLD);
		return EXIT_FAILURE;
	}

	/* Try to open and read the watchtab */
	tab_fd = open(tabpath, O_RDONLY | O_CLOEXEC);
	if (tab_fd < 0) {
		log_open_watchtab(tabpath);
		return EXIT_FAILURE;
	}
	tab_f = fdopen(tab_fd, "r");
	if (!tab_f) {
		log_open_watchtab(tabpath);
		return EXIT_FAILURE;
	}
	SLIST_INIT(&wtab);
	if (wtab_readfile(&wtab, tab_f, tabpath) < 0)
		return EXIT_FAILURE;
	log_watchtab_loaded(tabpath);

	/* Fork to background */
	if (daemonize) {
		daemon(0, 0);
		set_report(&syslog);
	}

	/* Create a kernel queue */
	kq = kqueue();
	if (kq == -1) {
		log_kqueue();
		return EXIT_FAILURE;
	}

	/* Insert config file watcher */
	EV_SET(&event, tab_fd,
	    EVFILT_VNODE,
	    EV_ADD | EV_ONESHOT,
	    NOTE_DELETE | NOTE_WRITE | NOTE_RENAME | NOTE_REVOKE,
	    0, 0);
	if (kevent(kq, &event, 1, 0, 0, 0) < 0) {
		log_kevent_watchtab(tabpath);
		return EXIT_FAILURE;
	}

	/* Insert initial watchers */
	SLIST_FOREACH(wentry, &wtab, next) {
		insert_entry(kq, wentry);
	}


	/*************
	 * MAIN LOOP *
	 *************/

	while (1) {
		/* Wait for a single event */
		if (kevent(kq, 0, 0, &event, 1, 0) < 0) {
			log_kevent_wait();
			break;
		}

		switch (event.filter) {
		    case EVFILT_VNODE:
			if (!event.udata) {
				/*
				 * Something happened on the watchtab:
				 * close everything and start the timer before
				 * reloading it.
				 */
				fclose(tab_f);  /* also closes tab_fd */
				EV_SET(&event, 42,
				    EVFILT_TIMER,
				    EV_ADD,
				    0,
				    delay, /* ms */
				    0);
				if (kevent(kq, &event, 1, 0, 0, 0) < 0) {
					log_kevent_timer();
					exit(EXIT_FAILURE);
				}
				break;
			}

			/* A watchtab entry has been triggered */
			wentry = event.udata;
			if (wentry->fd < 0
			    || (uintptr_t)wentry->fd != event.ident) {
				LOG_ASSERT("wentry->fd");
				exit(EXIT_FAILURE);
			}
			close(wentry->fd);
			wentry->fd = -1;
			pid = run_entry(wentry);
			if (!pid) break;

			/* Wait for the command to finish */
			EV_SET(&event, pid,
			    EVFILT_PROC,
			    EV_ADD | EV_ONESHOT,
			    NOTE_EXIT,
			    0,
			    wentry);
			if (kevent(kq, &event, 1, 0, 0, 0) < 0)
				log_kevent_proc(wentry, pid);
			break;

		    case EVFILT_PROC:
			/*
			 * The command has finished, re-insert the path to
			 * watch it.
			 */
			insert_entry(kq, event.udata);
			break;

		    case EVFILT_TIMER:
			/*
			 * Timer for watchtab reload has expired, try to
			 * reopen and reload it.
			 * When open fails, keep the timer around to try
			 * again after delay (suppressing errors).
			 * When loading fails, keep the old watchtab but add
			 * the event filter anyway to try again on next update.
			 */

			/* Try opening the watchtab file */
			tab_fd = open(tabpath, O_RDONLY | O_CLOEXEC);
			if (tab_fd < 0) {
				if (!wtab_error)
					log_open_watchtab(tabpath);
				wtab_error = 1;
				break;
			}
			tab_f = fdopen(tab_fd, "r");
			if (!tab_f) {
				if (!wtab_error)
					log_open_watchtab(tabpath);
				wtab_error = 1;
				close(tab_fd);
				break;
			}

			/* Delete the timer */
			event.flags = EV_DELETE;
			if (kevent(kq, &event, 1, 0, 0, 0) < 0) {
				log_kevent_timer_off();
				/* timer is still around, close files */
				fclose(tab_f);
				break;
			}

			/* Watch the file for changes */
			EV_SET(&event, tab_fd,
			    EVFILT_VNODE,
			    EV_ADD | EV_ONESHOT,
			    NOTE_DELETE | NOTE_RENAME | NOTE_REVOKE
			      | NOTE_WRITE,
			    0, 0);
			if (kevent(kq, &event, 1, 0, 0, 0) < 0)
				log_kevent_watchtab(tabpath);

			/* Load watchtab contents on a temporary variable */
			/* local */{
				struct watchtab new_wtab
				    = SLIST_HEAD_INITIALIZER(new_wtab);

				if (wtab_readfile(&new_wtab,
				    tab_f, tabpath) < 0) {
					wtab_release(&new_wtab);
					break;
				}

				wtab_release(&wtab);
				wtab = new_wtab;
				SLIST_FOREACH(wentry, &wtab, next) {
					insert_entry(kq, wentry);
				}
			}

			log_watchtab_loaded(tabpath);
			break;
		}
	}

	return EXIT_SUCCESS;
}
