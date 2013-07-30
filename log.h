/* log.h - report errors to the outside world */

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

/*
 * This module gather all error-formating functions, so that all user-facing
 * strings are gathered in one place.
 */

#ifndef FILEWATCHER_LOG_H
#define FILEWATCHER_LOG_H

#include "watchtab.h"


/*************
 * REPORTING *
 *************/

/* report_fn - report callback, same semantics as syslog() */
typedef void (*report_fn)(int priority, const char *message, ...)
    __attribute__((format (printf, 2, 3)));

/* report_to_stderr - wrapper to send the message to standard error output */
void
report_to_stderr(int priority, const char *message, ...);

/* set_report - use the given callback for error reporting */
void
set_report(report_fn callback);

/*******************
 * ERROR FORMATING *
 *******************/

/* log_alloc - memory allocation failure */
void
log_alloc(const char *subsystem);

/* log_assert - internal inconsistency */
void
log_assert(const char *reason, const char *source, unsigned line);
#define LOG_ASSERT(m) log_assert((m), __FILE__, __LINE__)

/* log_bad_delay - invalid string provided for delay value */
void
log_bad_delay(const char *opt);

/* log_chdir - chdir("/") failed after successful chroot() */
void
log_chdir(const char *newroot);

/* log_chroot - chroot() failed */
void
log_chroot(const char *newroot);

/* log_entry_wait - watchtab entry successfully inserted in the queue */
void
log_entry_wait(struct watch_entry *wentry);

/* log_exec - execve() failed */
void
log_exec(struct watch_entry *wentry);

/* log_fork - fork() failed */
void
log_fork(void);

/* log_kevent_entry - kevent() failed when adding an event for a file entry */
void
log_kevent_entry(const char *path);

/* log_kevent_proc - kevent() failed when adding a command watcher */
void
log_kevent_proc(struct watch_entry *wentry, pid_t pid);

/* log_kevent_timer - kevent() failed when adding a timer */
void
log_kevent_timer(void);

/* log_kevent_timer_off - kevent() failed when removing a timer */
void
log_kevent_timer_off(void);

/* log_kevent_wait - kevent() failed while waiting for an event */
void
log_kevent_wait(void);

/* log_kevent_watchtab - kevent() failed when adding a watchtab event */
void
log_kevent_watchtab(const char *path);

/* log_kqueue - kqueue() failed */
void
log_kqueue(void);

/* log_lookup_group - getgrnam() failed */
/* WARNING: errno must explicitly be zeroed before calling getgrnam() */
void
log_lookup_group(const char *group);

/* log_lookup_pw - getpwnam() failed */
/* WARNING: errno must explicitly be zeroed before calling getpwnam() */
void
log_lookup_pw(const char *login);

/* log_lookup_self - getlogin() or getpwnam() failed */
/* WARNING: errno must explicitly be zeroed before calling getpwnam() */
void
log_lookup_self(void);

/* log_open_entry - open() failed on watchtab entry file */
void
log_open_entry(const char *path);

/* log_open_watchtab - watchtab file open() failed */
void
log_open_watchtab(const char *path);

/* log_running - a watchtab entry has been triggered */
void
log_running(struct watch_entry *wentry);

/* log_setgid - setgid() failed */
void
log_setgid(gid_t gid);

/* log_setuid - setuid() failed */
void
log_setuid(uid_t uid);

/* log_watchtab_invalid_action - invalid action line in watchtab */
void
log_watchtab_invalid_action(const char *filename, unsigned line_no);

/* log_watchtab_invalid_delay - invalid delay field in watchtab entry */
void
log_watchtab_invalid_delay(const char *filename, unsigned line_no,
    const char *field);

/* log_watchtab_invalid_events - parse error in watchtab event set */
void
log_watchtab_invalid_events(const char *filename, unsigned line_no,
    const char *field, size_t len);

/* log_watchtab_loaded - watchtab has been successfully loaded */
void
log_watchtab_loaded(const char *path);

/* log_watchtab_read - read error on watchtab */
void
log_watchtab_read(void);

#endif /* ndef FILEWATCHER_LOG_H */
