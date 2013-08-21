# Overview

`filewatcherd` is a daemon inspired by cron, that run commands based on
file changes instead of time.

In principle it is similar to `incron`, but it's simpler, more limited,
and does not depend on anything outside of FreeBSD base.

# Watchtab

Usage of `filewatcherd` is quite straightforward: the daemon has a few
basic command-line options, and takes a _watchtab_ file as main input.

The watchtab is heavily inspired from `crontab`. Blank lines are ignored,
leading and trailing blanks in line are ignored, line starting with a
hash sign (`#`) are ignored as comments.

Environment lines are defined as having an equal sign (`=`) before any
backslash (`\\`) or tabulation character. They represent environment
variables available for commands, and only affect the entries below them.

Entry lines consist of 3 to 6 tabulation-separated fields. A complete line
contains the following fields in respective order:

1. Path of the file to watch
2. Event set to consider
3. Delay between the first triggering event and command run
4. User, and optionally group, to set for the command
5. `chroot` to set for the command
6. The command itself

When only 5 fields are present, `chroot` is skipped. When there are only
4 fields, user is also skipped. When there are only 3 field, delay is
considered 0.

In path, `chroot` and command fields, backslashes (`\\`) act as an escape
character, allowing to embed tabulations, backslashes and/or equal signs
in those fields without misinterpretation.

The event set can be a single star sign (`*`) to mean all available events,
or a list of any number of event names separated by a single non-letter
byte. The available events are `delete`, `write`, `extend`, `attrib`,
`link`, `rename` and `revoke`, with semantics matching those of
similar-named `fflags` for vnode filter.

The delay is given in seconds and can be fractional, up to the nanosecond
(though most system probably do not have such a resolution in
`nanosleep(3)`).

The user can be a login string or a numeric id, and is optionally followed
by a group string or numeric id after a colon (`:`). When specified, those
must exist and have a matching `passwd` or `group` entry.

The command is run in a clean environment, containing only variables
explicitly declared in the watchtab file, and `SHELL`, `PATH`, `HOME`,
`TRIGGER`, `USER`, `LOGNAME`.

  * `SHELL` and `PATH` default respectively to `/bin/sh` and
`/usr/bin:/bin`, but they can be overwritten in the watchtab.
  * `HOME` default to the home directory of the user running the command,
but can be overwritten in the watchtab.
  * `USER` and `LOGNAME` are both forced to the login name of the user
running the command, and values provided in the watchtab are ignored.
  * `TRIGGER` is forced to the path of the file triggering the event
(seen from outside the `chroot`), ignoring any value provided in the
watchtab.

The watchtab is automatically watched by `filewatcherd` itself, and is
automatically reloaded when it changes.

# Internals

## Source organization

`filewatcherd` is split between 4 `.c` modules:

  * `log.c` implements logging functions, which means all user-facing
output
  * `watchtab.c` implements watchtab parsing and upkeep of structures
related to watchtab entries
  * `run.c` implements actual execution of a watchtab entry
  * `filewatcherd.c` implements the event loop directly in `main()`
function

## Event loop overview

### Watchtab entries

Watchtab entries oscillate between two states:

  * waiting for an `EVFILT_VNODE` event described in the watchtab,
which triggers execution of the associated command
  * waiting for an `EVFILT_PROC` event that signals the end of the command
to switch back to `EVFILT_VNODE` wait.

Events are not reused, at each step of cycle a new one is added to the
kernel queue with `EV_ONESHOT` flag.

This architecture guarantees that there cannot be more than one file
descriptor per watchtab entry or more than one process started per watchtab
entry. System resources consumed by `filewatcherd` are therefore bounded
by the watchtab length.

Whenever an error happens, e.g. when spawning the command or opening the
watched path, the cycle is broken and the watchtab entry becomes inactive
until the watchtab is reloaded.

There is currently no way to re-enable a single inactive watchtab entry.

### Watchtab watcher

The watchtab file itself is also watched by `filewatcherd`, in a process
similar to a watchtab entry except that `EVFILT_VNODE` events trigger an
`EVFILT_TIMER` addition before reloading the file.

Errors are handled so that this cycle can only be broken by a failure to
insert an event in the queue:

  * When the watchtab file cannot be opened, the timer event is left in the
kernel queue to trigger another attempt after the delay. To prevent log
spamming, only the first failure is logged, even though subsequent failures
might have other causes.
  * When the watchtab file is opened, the timer event is removed and an
`EVFILT_VNODE` filter is added to track watchtab changes. Should a parse
error occurs, the old watchtab is used instead, and a subsequent change in
the watchtab file will trigger a reload.
