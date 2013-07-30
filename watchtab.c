/* watchtab.c - configuration tables for file watches */

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
#include <grp.h>
#include <pwd.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/event.h>

#include "log.h"
#include "watchtab.h"

/* number of pointers allocated at once in watch_env */
#define WENV_ALLOC_UNIT 16;

/*********************
 * LOCAL SUBPROGRAMS *
 *********************/

/* parse_events - process a configuration string into fflags vnode events */
static u_int
parse_events(const char *line, size_t len) {
	u_int result = 0;
	size_t i = 0;

	/* Check wildcard */
	if (len == 1 && line[0] == '*')
		return NOTE_DELETE | NOTE_WRITE | NOTE_EXTEND | NOTE_ATTRIB
		    | NOTE_LINK | NOTE_RENAME | NOTE_REVOKE;

	/*
	 * Parse entry as a list of token separated by a single
	 * non-letter byte.
	 */
	while (i < len) {
		if (strncmp(line + i, "delete", 6) == 0
		    || strncmp(line + i, "DELETE", 6) == 0) {
			result |= NOTE_DELETE;
			i += 6;
		}
		else if (strncmp(line + i, "write", 5) == 0
		    || strncmp(line + i, "WRITE", 5) == 0) {
			result |= NOTE_WRITE;
			i += 5;
		}
		else if (strncmp(line + i, "extend", 6) == 0
		    || strncmp(line + i, "EXTEND", 6) == 0) {
			result |= NOTE_EXTEND;
			i += 6;
		}
		else if (strncmp(line + i, "attrib", 6) == 0
		    || strncmp(line + i, "ATTRIB", 6) == 0) {
			result |= NOTE_ATTRIB;
			i += 6;
		}
		else if (strncmp(line + i, "link", 4) == 0
		    || strncmp(line + i, "LINK", 4) == 0) {
			result |= NOTE_LINK;
			i += 4;
		}
		else if (strncmp(line + i, "rename", 6) == 0
		    || strncmp(line + i, "RENAME", 6) == 0) {
			result |= NOTE_RENAME;
			i += 6;
		}
		else if (strncmp(line + i, "revoke", 6) == 0
		    || strncmp(line + i, "REVOKE", 6) == 0) {
			result |= NOTE_REVOKE;
			i += 6;
		}
		else return 0;

		if (i < len && ((line[i] >= 'a' && line[i] <= 'z')
		    || (line[i] >= 'A' && line[i] <= 'Z')))
			return 0;
		else
			i++;
	}

	return result;
}


/* strdupesc - duplicate and unescape an input string */
static char *
strdupesc(const char *src, size_t len) {
	size_t s = 0, d = 0;
	char *dest = malloc(len + 1);

	if (!dest) {
		log_alloc("watchtab entry internal string");
		return 0;
	}

	while (src[s] && s < len) {
		if (src[s] != '\\' || (s > 0 && src[s-1] == '\\'))
			dest[d++] = src[s];
		s++;
	}
	dest[d] = 0;
	return dest;
}

/* wenv_resize - preallocate enough storage for new_size pointers */
static int
wenv_resize(struct watch_env *wenv, size_t new_size) {
	size_t new_cap, i;
	const char **new_env;

	/* Initialize if needed */
	if (!wenv->environ && wenv_init(wenv) < 0)
		return -1;

	/* Don't realloc when enough capacity is available */
	if (new_size <= wenv->capacity) return 0;

	/* Actually resize */
	new_cap = wenv->capacity;
	while (new_cap < new_size) new_cap += WENV_ALLOC_UNIT;
	new_env = realloc(wenv->environ, sizeof *wenv->environ * new_cap);
	if (!new_env) {
		log_alloc("environment variables");
		return -1;
	}

	/* Clear new pointers */
	for (i = wenv->capacity; i < new_cap; i++)
		new_env[i] = 0;

	/* Update watch_env */
	wenv->capacity = new_cap;
	wenv->environ = new_env;
	return 0;
}



/********************
 * PUBLIC INTERFACE *
 ********************/

/* wentry_init - initialize a watch_entry with null values */
void
wentry_init(struct watch_entry *wentry) {
	if (!wentry) return;

	wentry->path = 0;
	wentry->events = 0;
	wentry->delay.tv_sec = 0;
	wentry->delay.tv_nsec = 0;
	wentry->uid = 0;
	wentry->gid = 0;
	wentry->chroot = 0;
	wentry->command = 0;
	wentry->envp = 0;
	wentry->fd = -1;
}


/* wentry_release - free internal objects from a watch_entry */
void
wentry_release(struct watch_entry *wentry) {
	if (!wentry) return;

	free((void *)(wentry->path));
	free((void *)(wentry->chroot));
	free((void *)(wentry->command));
	wentry->path = 0;
	wentry->chroot = 0;
	wentry->command = 0;

	if (wentry->envp) {
		size_t i = 0;
		while (wentry->envp[i])
			free(wentry->envp[i++]);
		free(wentry->envp);
	}
	wentry->envp = 0;

	if (wentry->fd != -1)
		close(wentry->fd);
	wentry->fd = -1;
}


/* wentry_free - free a watch_entry and the string it contains */
void
wentry_free(struct watch_entry *wentry) {
	if (!wentry) return;

	wentry_release(wentry);
	free(wentry);
}


/* wentry_readline - parse a config file line and fill a struct watch_entry */
/*   Return 0 on success or -1 on failure. */
int
wentry_readline(struct watch_entry *dest, char *line,
    struct watch_env *base_env, const char *filename, unsigned line_no) {
	size_t path_len = 0;
	size_t event_first = 0, event_len = 0;
	size_t delay_first = 0, delay_len = 0;
	size_t user_first = 0, user_len = 0;
	size_t chroot_first = 0, chroot_len = 0;
	size_t cmd_first = 0, cmd_len = 0;
	struct passwd *pw = 0;
	struct group *grp = 0;
	size_t i = 1;

	/* Sanity checks */
	if (!line || line[0] == 0 || line[0] == '\t') {
		LOG_ASSERT(0);
		return -1;
	}

	/* Look for fields boundaries */
	while (line[i] != 0 && (line[i] != '\t' || line[i-1] == '\\')) i++;
	path_len = i;
	while (line[i] == '\t') i++;
	event_first = i;
	while (line[i] != 0 && (line[i] != '\t' || line[i-1] == '\\')) i++;
	event_len = i - event_first;
	while (line[i] == '\t') i++;
	delay_first = i;
	while (line[i] != 0 && (line[i] != '\t' || line[i-1] == '\\')) i++;
	delay_len = i - delay_first;
	while (line[i] == '\t') i++;
	user_first = i;
	while (line[i] != 0 && (line[i] != '\t' || line[i-1] == '\\')) i++;
	user_len = i - user_first;
	while (line[i] == '\t') i++;
	chroot_first = i;
	while (line[i] != 0 && (line[i] != '\t' || line[i-1] == '\\')) i++;
	chroot_len = i - chroot_first;
	while (line[i] == '\t') i++;
	cmd_first = i;
	while (line[i] != 0) i++;
	cmd_len = i - cmd_first;

	/* Less than 3 fields found is a parse error */
	if (line[delay_first] == 0) {
		log_watchtab_invalid_action(filename, line_no);
		return -1;
	}

	/* Adjust offsets depending on which fields are omitted */
	if (line[user_first] == 0) {
		/* 3-field line: path, events, command */
		cmd_first = delay_first;
		cmd_len = delay_len;
		delay_first = delay_len = 0;
		user_first = user_len = 0;
		chroot_first = chroot_len = 0;
	}
	else if (line[chroot_first] == 0) {
		/* 4-field line: path, events, delay, command */
		cmd_first = user_first;
		cmd_len = user_len;
		user_first = user_len = chroot_first = chroot_len = 0;
	}
	else if (line[cmd_first] == 0) {
		/* 5-field line: path, events, delay, user, command */
		cmd_first = chroot_first;
		cmd_len = chroot_len;
		chroot_first = chroot_len = 0;
	}

	/* Parse event set */
	dest->events = parse_events(line + event_first, event_len);
	if (dest->events == 0) {
		log_watchtab_invalid_events(filename, line_no,
		    line + event_first, event_len);
		return -1;
	}

	/* Parse delay */
	dest->delay.tv_sec = 0;
	dest->delay.tv_nsec = 0;
	if (delay_len > 0
	    && !(delay_len == 1 && line[delay_first] == '*')) {
		char *s;

		/* Decode integer part */
		dest->delay.tv_sec = strtol(line + delay_first, &s, 10);

		/* Decode fractional part if any */
		if (*s == '.') {
			char *ns;
			dest->delay.tv_nsec = strtol(s + 1, &ns, 10);
			while (ns - s <= 9) {
				dest->delay.tv_nsec *= 10;
				s--;
			}
			s = ns;
		}

		/* Check trailing non-digits */
		if (s < line + delay_first + delay_len) {
			line[delay_first + delay_len] = 0;
			log_watchtab_invalid_delay(filename, line_no,
			    line + delay_first);
			return -1;
		}
	}

	/* Process user name and optional group name */
	if (user_len > 0) {
		char *login = line + user_first;
		char *group = 0;

		line[user_len] = 0;

		/* Process group */
		group = strchr(login, ':');
		if (group) {
			*group = 0;
			group++;
			for (i = 0; group[i] >= '0' && group[i] <= '9'; i++);
			errno = 0;
			grp = group[i]
			    ? getgrnam(group)
			    : getgrgid(strtol(group, 0, 10));
			if (!grp) {
				log_lookup_group(group);
				return -1;
			}
		}

		/* Lookup user name */
		for (i = 0; login[i] >= '0' && login[i] <= '9'; i++);
		errno = 0;
		pw = login[i]
		    ? getpwnam(login)
		    : getpwuid(strtol(login, 0, 10));
		if (!pw) {
			log_lookup_pw(login);
			return -1;
		}
	}

	/* Store numeric ids */
	dest->uid = pw ? pw->pw_uid : 0;
	dest->gid = grp ? grp->gr_gid : (pw ? pw->pw_gid : 0);

	/* Lookup self name if not overridden */
	if (!pw) {
		char *login;
		errno = 0;
		login = getlogin();
		pw = login ? getpwnam(login) : 0;
		if (!pw) {
			log_lookup_self();
			return -1;
		}
	}

	/* At this point, no parse error can occur, filling in data */

	/* Clean up destination */
	wentry_release(dest);

	/* Copy string parameters */
	dest->path = strdupesc(line, path_len);
	dest->command = strdupesc(line + cmd_first, cmd_len);

	if (chroot_len > 0)
		dest->chroot = strdupesc(line + chroot_first, chroot_len);
	else
		dest->chroot = 0;

	/* Setup environment */
	wenv_set(base_env, "LOGNAME", pw->pw_name, 1);
	wenv_set(base_env, "USER", pw->pw_name, 1);
	wenv_set(base_env, "HOME", pw->pw_dir, 0);
	wenv_set(base_env, "TRIGGER", dest->path, 1);
	dest->envp = wenv_dup(base_env);

	return 0;
}



/***********************
 * WATCH_ENV INTERFACE *
 ***********************/

/* wenv_init - create an empty environment list */
int
wenv_init(struct watch_env *wenv) {
	if (!wenv) {
		LOG_ASSERT(0);
		return -1;
	}

	wenv->capacity = WENV_ALLOC_UNIT;
	wenv->size = 0;
	wenv->environ = malloc(sizeof *wenv->environ * wenv->capacity);
	if (!wenv->environ) {
		log_alloc("initial environment variables");
		return -1;
	}

	return 0;
}


/* wenv_release - free string memory in a struct watch_env but not the struct*/
void
wenv_release(struct watch_env *wenv) {
	free(wenv->environ);
	wenv->size = 0;
	wenv->environ = 0;
}


/* wenv_add - append a string to an existing struct watch_env */
int
wenv_add(struct watch_env *wenv, const char *env_str) {
	if (!wenv || !env_str) {
		LOG_ASSERT(0);
		return -1;
	}

	/* Increase array size if needed */
	if (wenv_resize(wenv, wenv->size + 2) < 0) return -1;

	/* Store a copy of the provided string */
	wenv->environ[wenv->size] = strdup(env_str);
	wenv->size++;
	return 0;
}

/* wenv_set - insert or reset an environment variable */
int
wenv_set(struct watch_env *wenv, const char *name, const char *value,
    int overwrite) {
	size_t namelen, linelen, i;
	char *line;

	if (!wenv || !name || !value) return -1;

	/* Initialize if needed */
	if (!wenv->environ && wenv_init(wenv) < 0)
		return -1;

	/* Build the environment line */
	namelen = strlen(name);
	linelen = namelen + 1 + strlen(value);
	line = malloc(linelen + 1);
	if (!line) {
		log_alloc("environment variable entry");
		return -1;
	}
	strncpy(line, name, namelen);
	line[namelen] = '=';
	strncpy(line + namelen + 1, value, linelen - (namelen + 1));
	line[linelen] = 0;

	/* Look for an existing entry for the name */
	i = 0;
	while (wenv->environ[i]) {
		if (strncmp(wenv->environ[i], line, namelen + 1) == 0)
			break;
		i++;
	}

	/* If not found, insert the crafted line */
	if (wenv->environ[i] == 0) {
		if (wenv_resize(wenv, wenv->size + 2) < 0) {
			free(line);
			return -1;
		}
		wenv->environ[wenv->size] = line;
		wenv->size++;
		return 0;
	}

	/* Exit when environment variable exist but overwriting is forbidden */
	if (!overwrite) return 0;

	/* Replace found variable with new environment line */
	free((void *)wenv->environ[i]);
	wenv->environ[i] = line;
	return 0;
}

/* wenv_get - lookup environment variable */
const char *
wenv_get(struct watch_env *wenv, const char *name) {
	size_t namelen, i;

	if (!wenv || !wenv->environ || !name) {
		LOG_ASSERT(0);
		return 0;
	}
	namelen = strlen(name);

	for (i = 0; wenv->environ[i]; i++) {
		if (strncmp(wenv->environ[i], name, namelen) == 0
		    && wenv->environ[i][namelen] == '=')
			return wenv->environ[i] + (namelen + 1);
	}

	return 0;
}


/* wenv_dup - deep copy environment strings */
char **
wenv_dup(struct watch_env *wenv) {
	char **result;
	size_t len, i;
	int reported = 0;

	if (!wenv) return 0;
	len = (wenv->environ ? wenv->size : 0);
	result = malloc((len + 1) * sizeof *result);
	if (!result) {
		log_alloc("environment duplicate");
		return 0;
	}

	for (i = 0; i < len; i++) {
		result[i] = strdup(wenv->environ[i]);
		if (!result[i] && !reported) {
			log_alloc("environment item duplication");
			reported = 1;
		}
	}
	result[len] = 0;

	return result;
}



/**********************
 * WATCHTAB INTERFACE *
 **********************/

/* wtab_release - release children objects but not the struct watchtab */
void
wtab_release(struct watchtab *tab) {
	struct watch_entry *entry = 0;

	if (!tab) return;

	while ((entry = SLIST_FIRST(tab)) != 0) {
		SLIST_REMOVE_HEAD(tab, next);
		wentry_free(entry);
	}
}


/* wtab_readfile - parse the given file to build a new watchtab */
int
wtab_readfile(struct watchtab *tab, FILE *input, const char *filename) {
	char *line = 0;
	size_t linecap = 0;
	ssize_t linelen;
	unsigned line_no = 0;
	struct watch_entry *entry = 0;
	int result = 0;
	size_t i, skip;
	struct watch_env env;

	if (!tab) {
		LOG_ASSERT(0);
		return -1;
	}

	/* Setup default environment */
	wenv_init(&env);
	wenv_set(&env, "SHELL", "/bin/sh", 1);
	wenv_set(&env, "PATH", "/usr/bin:/bin", 1);

	/* Read the input data */
	while ((linelen = getdelim(&line, &linecap, '\n', input)) >= 0) {
		line_no++;

		/* Skip leading blanks */
		skip = 0;
		while (line[skip] == ' ' || line[skip] == '\t') skip++;

		/* Trim trailing blanks */
		while ((size_t)linelen > skip && (line[linelen-1] == '\n'
		    || line[linelen-1] == '\r' || line[linelen-1] == ' '
		    || line[linelen-1] == '\t'))
			linelen--;
		line[linelen] = 0;

		/* Ignore empty lines and comments */
		if ((size_t)linelen <= skip || line[skip] == '#')
			continue;

		/*
		 * Define environment lines as lines having an '=' before any
		 * tabulation ('\t') or backslash ('\\').
		 */

		i = skip;
		while (line[i] != 0 && line[i] != '='
		    && line[i] != '\\' && line[i] != '\t')
			i++;

		/* Record an environment variable */
		if (line[i] == '=') {
			/* Compute bounds of variable name */
			size_t j = i - 1;
			while (line[j] == ' ' && j > skip) j--;
			if (j + 1 < i) line[j + 1] = 0;

			/* Compute bounds of variable value */
			j = i + 1;
			while (line[j] == ' ') j++;

			/* Set the variable */
			wenv_set(&env, line + skip, line + j, 1);
			continue;
		}

		/* Parse an entry line */
		entry = malloc(sizeof *entry);
		if (!entry) {
			log_alloc("watchtab entry");
			return -1;
		}
		wentry_init(entry);
		if (wentry_readline(entry, line + skip, &env,
		    filename, line_no) < 0) {
			/* propagate an error but keep parsing */
			result = -1;
			wentry_free(entry);
			continue;
		}

		/* Insert the entry in the list */
		SLIST_INSERT_HEAD(tab, entry, next);
	}

	if (ferror(input)) {
		log_watchtab_read();
		return -1;
	}

	return result;
}
