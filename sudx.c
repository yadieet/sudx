/*****************************************************************************
 * File: sudx.c                                                              *
 *   Modified from SU (util-linux)                                           *
 *                                                                           *
 * License: GPLv2 License                                                    *
 *                                                                           *
 * By yadieet <yadieet@gmail.com>                                            *
 *****************************************************************************/

/* SUDX, run bash shell as another user with D-Bus enabled.
   Copyright (C) Free Software Foundation, Inc.
   Copyright (C) 2012 SUSE Linux Products GmbH, Nuernberg

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software Foundation,
   Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA. */

/* Run a shell with the real and effective UID and GID and groups
   of USER (default `root'), with D-Bus enabled.

   If the account has a password, sudx prompts for a password 
   unless run by a user with real UID 0.

   Does not change the current directory.
   Sets `HOME' and `SHELL' from the password entry for USER, and if
   USER is not root, sets `USER' and `LOGNAME' to USER.
   The subshell is not a login shell.

   Modified from SU (util-linux),
   original source code: login-utils/su-common.c 
   Since Nov 2016 */

enum
{
  EXIT_CANNOT_INVOKE = 126,
  EXIT_ENOENT = 127
};

#include <config.h>
#include <stdio.h>
#include <getopt.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <security/pam_appl.h>
#ifdef HAVE_SECURITY_PAM_MISC_H
#include <security/pam_misc.h>
#elif defined(HAVE_SECURITY_OPENPAM_H)
#include <security/openpam.h>
#endif
#include <signal.h>
#include <sys/wait.h>
#include <syslog.h>
#include <utmp.h>
#include "err.h"
#include <stdbool.h>
#include "c.h"
#include "xalloc.h"
#include "nls.h"
#include "pathnames.h"
#include "env.h"
#include "closestream.h"
#include "strutils.h"
#include "ttyutils.h"

#define SUDX_VERSION "2.29.2-1"

/* name of the pam configuration files. separate configs for su and su -  */
#define PAM_SRVNAME_SU_L "su-l"

#define _PATH_LOGINDEFS_SU  "/etc/default/su"
#define is_pam_failure(_rc) ((_rc) != PAM_SUCCESS)

#include "logindefs.h"
#include "su-common.h"

/* The user to become if none is specified */
#define DEFAULT_USER "root"

#ifndef HAVE_ENVIRON_DECL
extern char **environ;
#endif

static bool _pam_session_opened;
static bool _pam_cred_established;
static sig_atomic_t volatile caught_signal = false;
static pam_handle_t *pamh = NULL;

static struct passwd *
current_getpwuid (void)
{
  uid_t ruid;

  /* GNU Hurd implementation has an extension where a process can exist in a
   * non-conforming environment, and thus be outside the realms of POSIX
   * process identifiers; on this platform, getuid() fails with a status of
   * (uid_t)(-1) and sets errno if a program is run from a non-conforming
   * environment.
   *
   * http://austingroupbugs.net/view.php?id=511
   */
  errno = 0;
  ruid = getuid();

  return errno == 0 ? getpwuid(ruid) : NULL;
}

/* Log the fact that someone has run su to the user given by PW;
   if SUCCESSFUL is true, they gave the correct password, etc.  */

static void
log_syslog (struct passwd const *pw, bool successful)
{
  const char *new_user, *old_user, *tty;

  new_user = pw->pw_name;

  /* The utmp entry (via getlogin) is probably the best way to identify
     the user, especially if someone su's from a su-shell.  */
  old_user = getlogin();
  if( !old_user )
  {
    /* getlogin can fail -- usually due to lack of utmp entry.
       Resort to getpwuid.  */
    struct passwd *pwd = current_getpwuid();
    old_user = pwd ? pwd->pw_name : "";
  }

  if( get_terminal_name( NULL, &tty, NULL ) != 0 || !tty )
    tty = "none";

  openlog( program_invocation_short_name, 0, LOG_AUTH );
  syslog( LOG_NOTICE, "%s(to %s) %s on %s",
          successful ? "" : "FAILED SU ",
          new_user, old_user, tty);
  closelog();
}

/* Log failed login attempts in _PATH_BTMP if that exists.  */

static void log_btmp (struct passwd const *pw)
{
  struct utmp ut;
  struct timeval tv;
  const char *tty_name, *tty_num;

  memset( &ut, 0, sizeof(ut) );

  strncpy( ut.ut_user,
           pw && pw->pw_name ? pw->pw_name : "(unknown)",
           sizeof(ut.ut_user) );

  get_terminal_name( NULL, &tty_name, &tty_num );
  if( tty_num )
    xstrncpy( ut.ut_id, tty_num, sizeof(ut.ut_id) );
  if( tty_name )
    xstrncpy( ut.ut_line, tty_name, sizeof(ut.ut_line) );

#if defined(_HAVE_UT_TV)  /* in <utmpbits.h> included by <utmp.h> */
  gettimeofday( &tv, NULL );
  ut.ut_tv.tv_sec = tv.tv_sec;
  ut.ut_tv.tv_usec = tv.tv_usec;
#else
  {
    time_t t;
    time( &t );
    ut.ut_time = t; /* ut_time is not always a time_t */
  }
#endif
  ut.ut_type = LOGIN_PROCESS; /* XXX doesn't matter */
  ut.ut_pid = getpid();

  updwtmp( _PATH_BTMP, &ut );
}


static int su_pam_conv (int num_msg, const struct pam_message **msg,
                        struct pam_response **resp, void *appdata_ptr)
{
#ifdef HAVE_SECURITY_PAM_MISC_H
  return misc_conv( num_msg, msg, resp, appdata_ptr );
#elif defined(HAVE_SECURITY_OPENPAM_H)
  return openpam_ttyconv( num_msg, msg, resp, appdata_ptr );
#endif
}

static struct pam_conv conv =
{
  su_pam_conv,
  NULL
};

static void
cleanup_pam (int retcode)
{
  int saved_errno = errno;

  if( _pam_session_opened )
    pam_close_session( pamh, 0 );

  if( _pam_cred_established )
    pam_setcred( pamh, PAM_DELETE_CRED | PAM_SILENT );

  pam_end( pamh, retcode );
  errno = saved_errno;
}

/* Signal handler for parent process.  */
static void
su_catch_sig (int sig)
{
  caught_signal = sig;
}

/* Export env variables declared by PAM modules.  */
static void
export_pamenv (void)
{
  char **env;

  /* This is a copy but don't care to free as we exec later anyways.  */
  env = pam_getenvlist( pamh );
  while( env && *env )
  {
    if( putenv(*env) != 0 )
      err( EXIT_FAILURE, NULL );

    env++;
  }
}

static void
create_watching_parent (void)
{
  pid_t child;
  sigset_t ourset;
  struct sigaction oldact[3];
  int status = 0;
  int retval;

  retval = pam_open_session( pamh, 0 );
  if( is_pam_failure(retval) )
  {
    cleanup_pam( retval );
    errx( EXIT_FAILURE, _("cannot open session: %s" ),
          pam_strerror(pamh,retval) );
  }
  else
    _pam_session_opened = 1;

  memset( oldact, 0, sizeof(oldact) );

  child = fork();
  if( child == (pid_t) -1 )
  {
    cleanup_pam( PAM_ABORT );
    err( EXIT_FAILURE, _("cannot create child process") );
  }

  /* the child proceeds to run the shell */
  if( child == 0 )
    return;

  /* In the parent watch the child.  */

  /* su without pam support does not have a helper that keeps
     sitting on any directory so let's go to /.  */
  if( chdir("/") != 0 )
    warn( _("cannot change directory to %s"), "/" );

  sigfillset( &ourset );
  if( sigprocmask(SIG_BLOCK, &ourset, NULL) )
  {
    warn( _("cannot block signals") );
    caught_signal = true;
  }
  if( !caught_signal )
  {
    struct sigaction action;
    action.sa_handler = su_catch_sig;
    sigemptyset( &action.sa_mask );
    action.sa_flags = 0;
    sigemptyset( &ourset );
    if( !caught_signal &&
        (
           sigaddset(&ourset, SIGTERM) ||
           sigaddset(&ourset, SIGALRM) ||
           sigaction(SIGTERM, &action, &oldact[0]) ||
           sigprocmask(SIG_UNBLOCK, &ourset, NULL)
        )
      )
    {
      warn( _("cannot set signal handler") );
      caught_signal = true;
    }
  }
  if( !caught_signal )
  {
    pid_t pid;

    for(;;)
    {
      pid = waitpid( child, &status, WUNTRACED );

      if( pid != (pid_t)-1 && WIFSTOPPED(status) )
      {
        kill( getpid(), SIGSTOP );
        /* once we get here, we must have resumed */
        kill( pid, SIGCONT );
      }
      else
        break;
    }
    if( pid != (pid_t)-1 )
    {
      if( WIFSIGNALED(status) )
      {
        fprintf( stderr, "%s%s\n", strsignal( WTERMSIG(status) ),
                 WCOREDUMP(status) ? _(" (core dumped)") : "" );
        status = WTERMSIG(status) + 128;
      }
      else
        status = WEXITSTATUS( status );

      /* child is gone, don't use the PID anymore */
      child = (pid_t) -1;
    }
    else if( caught_signal )
      status = caught_signal + 128;
    else
      status = 1;
  }
  else
    status = 1;

  if( caught_signal && child != (pid_t)-1 )
  {
      fprintf( stderr, _("\nSession terminated, killing shell...") );
      kill( child, SIGTERM );
  }

  cleanup_pam( PAM_SUCCESS );

  if( caught_signal )
  {
    if( child != (pid_t)-1 )
    {
      sleep( 2 );
      kill( child, SIGKILL );
      fprintf( stderr, _(" ...killed.\n") );
    }

    /* Let's terminate itself with the received signal.
     *
     * It seems that shells use WIFSIGNALED() rather than our exit status
     * value to detect situations when is necessary to cleanup (reset)
     * terminal settings (kzak -- Jun 2013).
     */
    switch( caught_signal )
    {
      case SIGTERM:
        sigaction(SIGTERM, &oldact[0], NULL);
        break;
      case SIGINT:
        sigaction(SIGINT, &oldact[1], NULL);
        break;
      case SIGQUIT:
        sigaction(SIGQUIT, &oldact[2], NULL);
        break;
      default:
      /* just in case that signal stuff initialization failed and
       * caught_signal = true */
        caught_signal = SIGKILL;
        break;
    }
    kill( getpid(), caught_signal );
  }
  exit( status );
}

static void
authenticate (const struct passwd *pw)
{
  const struct passwd *lpw = NULL;
  const char *cp, *srvname = NULL;
  int retval;

  srvname = PAM_SRVNAME_SU_L;
  retval = pam_start( srvname, pw->pw_name, &conv, &pamh );
  if( is_pam_failure(retval) )
    goto done;

  if( isatty(0) && (cp = ttyname(0)) != NULL )
  {
    const char *tty;

    if( strncmp(cp, "/dev/", 5) == 0 )
      tty = cp + 5;
    else
      tty = cp;

    retval = pam_set_item( pamh, PAM_TTY, tty );
    if( is_pam_failure(retval) )
      goto done;
  }

  lpw = current_getpwuid();
  if( lpw && lpw->pw_name )
  {
    retval = pam_set_item( pamh, PAM_RUSER, (const void *) lpw->pw_name );
    if( is_pam_failure(retval) )
      goto done;
  }

  retval = pam_authenticate( pamh, 0 );
  if( is_pam_failure(retval) )
    goto done;

  retval = pam_acct_mgmt( pamh, 0 );
  if( retval == PAM_NEW_AUTHTOK_REQD )
  {
    /* Password has expired.  Offer option to change it.  */
    retval = pam_chauthtok( pamh, PAM_CHANGE_EXPIRED_AUTHTOK );
  }

  done:

  log_syslog( pw, !is_pam_failure(retval) );

  if( is_pam_failure(retval) )
  {
    const char *msg;

    log_btmp(pw);

    msg  = pam_strerror( pamh, retval );
    pam_end( pamh, retval );
    sleep( getlogindefs_num("FAIL_DELAY", 1) );
    errx( EXIT_FAILURE, "%s", msg ? msg : _("incorrect password") );
  }
}

static void
set_path (const struct passwd* pw)
{
  int r;

  if( pw->pw_uid )
    r = logindefs_setenv( "PATH", "ENV_PATH", _PATH_DEFPATH );
  else if( ( r = logindefs_setenv("PATH", "ENV_ROOTPATH", NULL) ) != 0)
    r = logindefs_setenv( "PATH", "ENV_SUPATH", _PATH_DEFPATH_ROOT );

  if( r != 0 )
    err( EXIT_FAILURE, _("failed to set the %s environment variable"), "PATH" );
}

/* Update `environ' for the new shell based on PW, with SHELL being
   the value for the SHELL environment variable.  */

static void
modify_environment (const struct passwd *pw, const char *shell)
{
  /* Leave TERM unchanged.  Set HOME, SHELL, USER, LOGNAME, PATH.
     Unset all other environment variables.  */

  char *term = getenv( "TERM" );

  if( term )
    term = xstrdup( term );

  environ = xmalloc( (6 + !!term) * sizeof(char *) );
  environ[0] = NULL;

  if( term )
  {
    xsetenv( "TERM", term, 1 );
    free( term );
  }

  xsetenv( "HOME", pw->pw_dir, 1 );

  if( shell )
    xsetenv( "SHELL", shell, 1 );

  xsetenv( "USER", pw->pw_name, 1 );
  xsetenv( "LOGNAME", pw->pw_name, 1 );
  set_path(pw);

  export_pamenv();
}

/* Become the user and group(s) specified by PW.  */

static void
init_groups (const struct passwd *pw, gid_t *groups, size_t num_groups)
{
  int retval;

  errno = 0;

  if( num_groups )
    retval = setgroups( num_groups, groups );
  else
    retval = initgroups( pw->pw_name, pw->pw_gid );

  if( retval == -1 )
  {
    cleanup_pam( PAM_ABORT );
    err( EXIT_FAILURE, _("cannot set groups") );
  }

  endgrent();

  retval = pam_setcred( pamh, PAM_ESTABLISH_CRED );
  if( is_pam_failure(retval) )
    errx( EXIT_FAILURE, "%s", pam_strerror(pamh, retval) );
  else
    _pam_cred_established = 1;
}

static void
change_identity (const struct passwd *pw)
{
  if( setgid(pw->pw_gid) )
    err( EXIT_FAILURE,  _("cannot set group id") );
  if( setuid(pw->pw_uid) )
    err( EXIT_FAILURE,  _("cannot set user id") );
}

static
void load_config (void)
{
  logindefs_load_file( _PATH_LOGINDEFS_SU );
  logindefs_load_file( _PATH_LOGINDEFS );
}

int
main (int argc, char **argv)
{
  int optc;
  const char *new_user = DEFAULT_USER;
  struct passwd *pw;
  struct passwd pw_copy;

  gid_t *groups = NULL;
  size_t ngroups = 0;

  static const struct option longopts[] = {
    {"help", no_argument, 0, 'h'},
    {"version", no_argument, 0, 'V'},
    {NULL, 0, NULL, 0}
  };

  setlocale( LC_ALL, "" );
  bindtextdomain( PACKAGE, LOCALEDIR );
  textdomain( PACKAGE );
  atexit( close_stdout );

  while( (optc = getopt_long(argc, argv, "hV", longopts, NULL)) != -1 )
  {
    switch( optc )
    {
      case 'h':
        fputs( "\nRun bash shell as another user with D-Bus enabled, "
               "useful for running GUI/X applications that need D-Bus.\n"
               , stdout );
        fputs( USAGE_HEADER, stdout );
        printf( _(" %s <user>\n"), program_invocation_short_name );
        fputs( USAGE_OPTIONS, stdout );
        fputs( USAGE_HELP, stdout );
        fputs( USAGE_VERSION, stdout );
        fputs( "\nThis program is licensed under GPLv2 license.\n"
               "\nhttps://github.com/yadieet/sudx\n",
               stdout );
        exit( EXIT_SUCCESS );

      case 'V':
        fputs( SUDX_VERSION, stdout );
        exit( EXIT_SUCCESS );

      default:
        exit( EXIT_FAILURE );
    }
  }

  if( optind < argc )
      new_user = argv[optind++];

  logindefs_load_defaults = load_config;

  pw = getpwnam( new_user );
  if( !(
         pw && pw->pw_name && pw->pw_name[0] && pw->pw_dir && pw->pw_dir[0]
         && pw->pw_passwd
       )
    )
    errx( EXIT_FAILURE, _("user %s does not exist"), new_user );

  /* Make a copy of the password information and point pw at the local
     copy instead.  Otherwise, some systems (e.g. Linux) would clobber
     the static data through the getlogin call from log_su.
     Also, make sure pw->pw_shell is a nonempty string.
     It may be NULL when NEW_USER is a username that is retrieved via NIS (YP),
     but that doesn't have a default shell listed.  */
  pw_copy = *pw;
  pw = &pw_copy;
  pw->pw_name = xstrdup( pw->pw_name );
  pw->pw_passwd = xstrdup( pw->pw_passwd );
  pw->pw_dir = xstrdup( pw->pw_dir );
  endpwent();

  authenticate( pw );
  init_groups( pw, groups, ngroups );

  create_watching_parent();
  /* Now we're in the child.  */

  change_identity( pw );

  /* Set environment after pam_open_session, which may put KRB5CCNAME
     into the pam_env, etc.  */

  modify_environment( pw, "bash" );

  if( chdir(pw->pw_dir) != 0 )
    warn( _("warning: cannot change directory to %s"), pw->pw_dir );

  {
    char const *args[] = {"-dbus-run-session", "--", "bash", "--login", NULL};
    execv( "/bin/dbus-run-session", (char **) args );
    int exit_status = (errno == ENOENT ? EXIT_ENOENT : EXIT_CANNOT_INVOKE);
    warn( "failed" );
    exit( exit_status );
  }
}
