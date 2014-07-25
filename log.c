/* log.c - report errors to the outside world */

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

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>

#include "log.h"

/*************
 * REPORTING *
 *************/

/* report - callback actually used by formatting functions */
static report_fn report = &report_to_stderr;


/* set_report - use the given callback for error reporting */
void
set_report(report_fn callback) {
	report = callback;
}


/* report_to_stderr - wrapper to send the message to standard error output */
void
report_to_stderr(int priority, const char *message, ...) {
	va_list ap;
	(void)priority;

	va_start(ap, message);
	vfprintf(stderr, message, ap);
	va_end(ap);
	fputc('\n', stderr);
}



/*******************
 * ERROR FORMATING *
 *******************/

/* log_alloc - memory allocation failure */
void
log_alloc(const char *subsystem) {
	if (subsystem)
		report(LOG_ERR, "Unable to allocate memory for %s", subsystem);
	else
		report(LOG_ERR, "Unable to allocate memory");
}


/* log_assert - internal inconsistency */
void
log_assert(const char *reason, const char *source, unsigned line) {
	if (reason)
		report(LOG_ERR, "Internal inconsistency at %s:%u (%s)",
		    source, line, reason);
	else
		report(LOG_ERR, "Internal inconsistency at %s:%u",
		    source, line);
}


/* log_bad_delay - invalid string provided for delay value */
void
log_bad_delay(const char *opt) {
	report(LOG_ERR, "Bad value \"%s\" for delay", opt);
}


/* log_chdir - chdir("/") failed after successful chroot() */
void
log_chdir(const char *newroot) {
	report(LOG_ERR, "chdir(\"/\") error after chroot to %s: %s",
	    newroot, strerror(errno));
}


/* log_chroot - chroot() failed */
void
log_chroot(const char *newroot) {
	report(LOG_ERR, "Unable to chroot to %s: %s",
	    newroot, strerror(errno));
}


/* log_entry_wait - watchtab entry successfully inserted in the queue */
void
log_entry_wait(struct watch_entry *wentry) {
	report(LOG_INFO, "Waiting for events on \"%s\"", wentry->path);
}

/* log_exec - execve() failed */
void
log_exec(struct watch_entry *wentry) {
	report(LOG_ERR, "Unable to execute \"%s\": %s",
	    wentry->command, strerror(errno));
}


/* log_fork - fork() failed */
void
log_fork(void) {
	report(LOG_ERR, "Error in fork(): %s", strerror(errno));
}


/* log_kevent_entry - kevent() failed when adding an event for a file entry */
void
log_kevent_entry(const char *path) {
	report(LOG_ERR, "Unable to queue filter for file \"%s\": %s",
	    path, strerror(errno));
}


/* log_kevent_proc - kevent() failed when adding a command watcher */
void
log_kevent_proc(struct watch_entry *wentry, pid_t pid) {
	report(LOG_ERR, "Unable to watch command pid %d (\"%s\"): %s",
	    (int)pid, wentry->command, strerror(errno));
}


/* log_kevent_timer - kevent() failed when adding a timer */
void
log_kevent_timer(void) {
	report(LOG_ERR, "Unable to queue timer for watchtab: %s",
	    strerror(errno));
}


/* log_kevent_timer_off - kevent() failed when removing a timer */
void
log_kevent_timer_off(void) {
	report(LOG_ERR, "Unable to delete timer for watchtab: %s",
	    strerror(errno));
}


/* log_kevent_wait - kevent() failed while waiting for an event */
void
log_kevent_wait(void) {
	report(LOG_ERR, "Error while waiting for a kevent: %s",
	    strerror(errno));
}


/* log_kevent_watchtab - kevent() failed when adding a watchtab event */
void
log_kevent_watchtab(const char *path) {
	report(LOG_ERR, "Unable to queue filter for watchtab \"%s\": %s",
	    path, strerror(errno));
}


/* log_kqueue - report failure in kqueue() call */
void
log_kqueue(void) {
	report(LOG_ERR, "Error in kqueue(): %s", strerror(errno));
}


/* log_lookup_group - getgrnam() failed */
void
log_lookup_group(const char *group) {
	if (errno)
		report(LOG_ERR, "Error while lookup group \"%s\": %s",
		    group, strerror(errno));
	else
		report(LOG_ERR, "Unable to find group \"%s\"", group);
}

/* log_lookup_pw - getpwnam() failed */
void
log_lookup_pw(const char *login) {
	if (errno)
		report(LOG_ERR, "Error while lookup user \"%s\": %s",
		    login, strerror(errno));
	else
		report(LOG_ERR, "Unable to find user \"%s\"", login);
}

/* log_lookup_self - getlogin() or getpwnam() failed */
void
log_lookup_self(void) {
	report(LOG_ERR, "Error while trying to lookup current user login");
}


/* log_open_entry - open() failed on watchtab entry file */
void
log_open_entry(const char *path) {
	report(LOG_ERR, "Unable to open watched file \"%s\": %s",
	    path, strerror(errno));
}


/* log_open_watchtab - watchtab file open() failed */
void
log_open_watchtab(const char *path) {
	report(LOG_ERR, "Unable to open watchtab \"%s\": %s",
	    path, strerror(errno));
}


/* log_running - a watchtab entry has been triggered */
void
log_running(struct watch_entry *wentry) {
	report(LOG_INFO, "Running \"%s\", triggered by \"%s\"",
	    wentry->command, wentry->path);
}


/* log_setgid - setgid() failed */
void
log_setgid(gid_t gid) {
	report(LOG_INFO, "Unable to set gID to %d: %s",
	    (int)gid, strerror(errno));
}


/* log_setuid - setuid() failed */
void
log_setuid(uid_t uid) {
	report(LOG_INFO, "Unable to set uID to %d: %s",
	    (int)uid, strerror(errno));
}


/* log_signal - signal() failed */
void
log_signal(int sig) {
	report(LOG_ERR, "Unable to setup signal handler for \"%s\": %s", 
		strsignal(sig), strerror(errno));
}


/* log_watchtab_invalid_action - invalid action line in watchtab */
void
log_watchtab_invalid_action(const char *filename, unsigned line_no) {
	report(LOG_ERR, "Invalid action line at line %s:%u",
	    filename, line_no);
}


/* log_watchtab_invalid_delay - invalid delay field in watchtab entry */
void
log_watchtab_invalid_delay(const char *filename, unsigned line_no,
    const char *field) {
	report(LOG_ERR, "Invalid delay field \"%s\" at %s:%u",
	    field, filename, line_no);
}


/* log_watchtab_invalid_events - parse error in watchtab event set */
void
log_watchtab_invalid_events(const char *filename, unsigned line_no,
    const char *field, size_t len) {
	report(LOG_ERR, "Invalid event set \"%.*s\" at %s:%u",
	    (int)len, field, filename, line_no);
}


/* log_watchtab_loaded - watchtab has been successfully loaded */
void
log_watchtab_loaded(const char *path) {
	report(LOG_NOTICE, "Watchtab \"%s\" loaded successfully", path);
}


/* log_watchtab_read - read error on watchtab */
void
log_watchtab_read(void) {
	report(LOG_ERR, "Error while reading from watchtab");
}


/* print_usage - output usage text upon request or after argument error */
void
print_usage(int after_error, int argc, char **argv) {
	(void)argc;

	fprintf(after_error ? stderr : stdout,
	    "Usage: %s [-dh] [-f delay_ms] watchtab\n\n"
	    "\t-d, --foreground\n"
	    "\t\tDon't fork to background and log to stderr\n"
	    "\t-h, --help\n"
	    "\t\tDisplay this help text\n"
	    "\t-w, --wait delay_ms\n"
	    "\t\tWait that number of milliseconds after watchtab\n"
	    "\t\tchanges before reloading it\n",
	    argv[0]);
}
