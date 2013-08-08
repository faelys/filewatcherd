/* watchtab.h - configuration tables for file watches */

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

#ifndef FILEWATCHER_WATCHTAB_H
#define FILEWATCHER_WATCHTAB_H

#include <stdio.h>
#include <sys/queue.h>
#include <sys/types.h>
#include <unistd.h>


/********************
 * TYPE DEFINITIONS *
 ********************/

/* struct watch_entry - a single watch table entry */
struct watch_entry {
	const char	*path;		/* file path to watch */
	u_int		events;		/* vnode event set to watch */
	struct timespec	delay;		/* delay before running command */
	uid_t		uid;		/* uid to set before command */
	gid_t		gid;		/* gid to set before command */
	const char	*chroot;	/* path to chroot before command */
	const char	*command;	/* command to execute */
	char		**envp;		/* environment variables */
	int		fd;		/* file descriptor in kernel queue */
	SLIST_ENTRY(watch_entry) next;
};

/* struct watchtab - list of watchtab entries */
SLIST_HEAD(watchtab, watch_entry);

/* struct watch_env - dynamic table of environment variables */
struct watch_env {
	const char	**environ;	/* environment strings */
	size_t		size;		/* index of the last NULL pointer */
	size_t		capacity;	/* number of string slot available */
};


/********************
 * PUBLIC INTERFACE *
 ********************/

/* wentry_init - initialize a watch_entry with null values */
void
wentry_init(struct watch_entry *wentry);

/* wentry_release - free internal objects from a watch_entry */
void
wentry_release(struct watch_entry *wentry);

/* wentry_free - free a watch_entry and the strinigs it contains */
void
wentry_free(struct watch_entry *wentry);

/* wentry_readline - parse a config file line and fill a struct watch_entry */
int
wentry_readline(struct watch_entry *dest, char *line,
    struct watch_env *base_env, int has_home,
    const char *filename, unsigned line_no);


/* wenv_init - create an empty environment list */
int
wenv_init(struct watch_env *wenv);

/* wenv_release - free string memory in a struct watch_env but not the struct*/
void
wenv_release(struct watch_env *wenv);

/* wenv_add - append a string to an existing struct watch_env */
int
wenv_add(struct watch_env *wenv, const char *env_str);

/* wenv_set - insert or reset an environment variable */
int
wenv_set(struct watch_env *wenv, const char *name, const char *value,
    int overwrite);

/* wenv_get - lookup environment variable */
const char *
wenv_get(struct watch_env *wenv, const char *name);

/* wenv_dup - deep copy environment strings */
char **
wenv_dup(struct watch_env *wenv);


/* wtab_release - release children objects but not the struct watchtab */
void
wtab_release(struct watchtab *tab);

/* wtab_readfile - parse the given file to build a new watchtab */
int
wtab_readfile(struct watchtab *tab, FILE *input, const char *filename);

#endif /* ndef FILEWATCHER_WATCHTAB_H */
