/*******************************************************************************
*
* MKA daemon.
* SPDX-FileCopyrightText: 2022 Technica Engineering GmbH <macsec@technica-engineering.de>
* SPDX-License-Identifier: GPL-2.0-or-later
* file: main.c
*
* © 2022 Technica Engineering GmbH.
*
* This program is free software: you can redistribute it and/or modify it under
* the terms of the GNU General Public License as published by the Free Software
* Foundation, either version 2 of the License, or (at your option) any later version.
*
* This program is distributed in the hope that it will be useful, but WITHOUT
* ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
* FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License along with
* this program. If not, see https://www.gnu.org/licenses/
*
*******************************************************************************/
/*******************************************************************************
 * @file        main.c
 * @version     1.0.0
 * @author      Jordi Auge
 * @brief       MKA Linux launcher
 *
 * @{
 */

/*******************        Includes        *************************/
#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include <bsd/libutil.h> // pidfile
#include <time.h>
#include <errno.h>
#include <syslog.h>
#include "mka_private.h"
#include "main.h"
#include "mka_phy_driver.h"

#ifdef ENABLE_DBUS
#include "dbus_server.h"
#endif



/*******************        Defines           ***********************/
#define MAIN_LOOP_LOCK() \
    MKA_ASSERT(0 == pthread_mutex_lock(&main_loop_lock), "Thread lock error")

#define MAIN_LOOP_UNLOCK() \
    MKA_ASSERT(0 == pthread_mutex_unlock(&main_loop_lock), "Thread unlock error")

/*******************        Types             ***********************/

/*******************        Variables         ***********************/
static pthread_mutex_t          global_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t          main_loop_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t           main_loop_event = PTHREAD_COND_INITIALIZER;
static int_atomic_t             wakeup_pending = 0;
static int_atomic_t             shutdown_requested = 0;
static struct pidfh             *pidfile_handle = NULL;
static bool                     daemonize = true;
static struct sigaction         default_SIGTERM;
static struct sigaction         default_SIGINT;
char*                           config_file_path = NULL;
int                             verbose = -1;
char*                           pidfile_path = NULL;
int                             child_pipe[2]; // Used to synchronize the parent and child processees when daemonizing
/*******************        Func. prototypes  ***********************/
void mka_main_loop_wakeup(void);
void print_usage();



/*******************        Func. definition  ***********************/

int main( int argc, char *argv[] )
{
    int option;

    for (;;) {
        // Process command line arguments
        option = getopt(argc, argv,
                "hc:v:fp:");
        if (option < 0)
            break;
        switch (option) {
            case 'c':
                config_file_path = optarg;
                break;
            case 'v':
                verbose = atoi(optarg);
                if (verbose < 0 || verbose > 3){
                    fprintf(stderr, "Error: Verbosity must be between 0 and 3\n");
                    exit(EXIT_FAILURE);
                }
                break;
            case 'p':
                pidfile_path = optarg;
                break;
            case 'f':
                daemonize = false;
                break;
            case 'h':
            default:
                print_usage();
                exit(EXIT_SUCCESS);
                break;
        }
    }

    if (config_file_path == NULL){
        fprintf(stderr, "Error: config file is required (use argument -h for help)\n");
        exit(EXIT_FAILURE);
    }

    if (pidfile_path != NULL && daemonize == false){
        fprintf(stderr, "Error: Conflicting options. -p may only be used when daemonizing into background (without -f)\n");
        exit(EXIT_FAILURE);
    }

    setlogmask (LOG_UPTO (LOG_INFO));
    openlog ("mkad", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);

    //TODO: Drop privileges
    //      to drop privileges we still need changes in l2 to open sockets only at init;
    //      although I'm not sure it's possible to open sockets in network interfaces that may be down...?

    if (daemonize == true){
        if (pipe(child_pipe) != 0) {
            fprintf(stderr, "Failed to create pipe");
            exit(EXIT_FAILURE);
        }
        // Start background process
        int pid = fork();
        if (pid == 0) {
            if (pidfile_path != NULL) pidfile_write(pidfile_handle);

            // Close stdin and stdout
            close(0);
            close(1);
            close(2);

            // Run in a new session
            if (setsid() < 0) exit(EXIT_FAILURE);

            daemon_main();
        } else if (pid == -1) {
            // parent but no child has been created.
            fprintf(stderr, "Error when creating background process\n");
            exit(EXIT_FAILURE);
        } else {
            // parent and the child is running.
            char c;
            close(child_pipe[1]);
            int fake_ret =0;
            fake_ret = read(child_pipe[0], &c, 1);
            (void)fake_ret;
            // Launcher has finished, daemon is now running
            exit(EXIT_SUCCESS);
        }
    } else { // daemonize == false
        daemon_main();
    }
}

void write_log(char const* text, unsigned long length)
{
    syslog(LOG_INFO, "%s", text);
    if (!daemonize) (void)(fwrite(text, length, 1, stdout), fflush(stdout));
}

void signalHandlerSIGTERM(int sigio)
{
    // Restore old handler, giving the opportunity of issuing a second Ctl+C / signal
    // that is really is effective, because one never knows...
    (void)sigaction(SIGTERM, &default_SIGTERM, NULL);
    (void)sigaction(SIGINT, &default_SIGINT, NULL);

    shutdown_requested = 1;
    mka_main_loop_wakeup();
}

void daemon_main()
{
    struct sigaction sAction = {0};
    t_MKA_config const* config;
    struct timespec max_wait = {0U, 0U};
    // Read configuration file
    config = mka_config_load(config_file_path);

    if (NULL == config) {
        fprintf(stderr, "ERROR: configuration is invalid, aborting.\n");
        if (pidfile_handle != NULL) pidfile_close(pidfile_handle);
        exit(EXIT_FAILURE);
    }

    if (verbose != -1){
        mka_active_log_level = MKA_LOGLEVEL_DEBUG;
        mka_active_log_verbosity = (uint8_t)verbose;
    }

    if (pidfile_path != NULL){
        pid_t otherpid;
        pidfile_handle = pidfile_open(pidfile_path, 0600, &otherpid);
        if (pidfile_handle == NULL) {
            if (errno == EEXIST) {
                fprintf(stderr, "Error: MKA Daemon already running, pid: %jd.", (intmax_t)otherpid);
                exit(EXIT_FAILURE);
            }
            fprintf(stderr, "Error: Cannot open or create pidfile\n");
            exit(EXIT_FAILURE);
        }
    }

    // Initialize daemon and create virtual interfaces
    if (libnl_init() != MKA_OK){
        if (pidfile_handle != NULL) pidfile_remove(pidfile_handle);
        closelog();
        exit(1);
    }

    // Register DBUS api
#ifdef ENABLE_DBUS
    dbus_server_init(config);
#endif

    MKA_Init(config);

    mka_link_monitor_start();

    // Register signals for clean termination
    sAction.sa_sigaction = NULL;
    sAction.sa_handler = &signalHandlerSIGTERM;
    if(sigaction(SIGTERM, &sAction, &default_SIGTERM) < 0) {
        fprintf(stderr, "Error: Failed to register signal handlers\n");
        if (pidfile_handle != NULL) pidfile_close(pidfile_handle);
        exit(EXIT_FAILURE);
    }
    if(sigaction(SIGINT, &sAction, &default_SIGINT) < 0) {
        fprintf(stderr, "Error: Failed to register signal handlers\n");
        if (pidfile_handle != NULL) pidfile_close(pidfile_handle);
        exit(EXIT_FAILURE);
    }

    // Init done. If we are running in daemon mode, it's now time to release the console, and mark the startup as finished
    if (daemonize == true){
        close(child_pipe[0]);
        close(child_pipe[1]);
    }

    // Main loop
    while(!shutdown_requested){
        MKA_ASSERT(0 == clock_gettime(CLOCK_REALTIME, &max_wait), "Cannot get time");
        if (mka_AddSleepTime(&max_wait)) {
            max_wait.tv_nsec -= max_wait.tv_nsec % 1000000U;

            MAIN_LOOP_LOCK();
            // do not sleep if a frame was received while this thread was running
            if (0 == wakeup_pending) {
                (void)pthread_cond_timedwait(&main_loop_event, &main_loop_lock, &max_wait);
            }
            MAIN_LOOP_UNLOCK();
        }
        wakeup_pending = 0; // atomic op.; clear right before handling all events

        mka_link_monitor_update();
        MKA_MainFunction();
#ifdef ENABLE_DBUS
        dbus_update_status();
#endif
    }
    mka_daemon_exit(0);
}

void mka_daemon_exit(sint_t exit_code)
{
    MKA_LOG_DEBUG1("Cleanly shutting down daemon..");
    libnl_deinit();
    mka_link_monitor_stop();
    if (pidfile_handle != NULL) pidfile_remove(pidfile_handle);
    closelog();
    exit(EXIT_SUCCESS);
}

void print_usage(){
    printf("MKA daemon. Copyright 2021 Technica Engineering GmbH.\n");
    printf("    version: %s\n", DAEMON_VERSION );
    printf("\n");
    printf("Usage: mkad -c <config_file> [-hf] [-v <0-3>] [-p <pidfile>]\n");
    printf("\n");
    printf("    -c    - Configuration file (required)\n");
    printf("            Path to the configuration file. See mkad.conf.example for details.\n");
    printf("\n");
    printf("    -v    - Verbosity\n");
    printf("            Set the verbosity level between 0 and 3.\n");
    printf("            This parameter overrides the level set on the configuration file.\n");
    printf("\n");
    printf("    -f    - Foreground\n");
    printf("            Don't daemonize into background.\n");
    printf("\n");
    printf("    -p    - Pid file\n");
    printf("            Path to a file where to store the daemon's PID.\n");
    printf("            This option will prevent multiple instances from running concurrently with\n");
    printf("            the same pidfile, and is incompatible with the -f option.\n");
    printf("\n");
    printf("    -h    - Help\n");
    printf("            Print this message and exit\n");
    printf("\n");
}

void mka_main_loop_wakeup(void)
{
    // NOTE: signal is not "accumulated" and only has effect if the other thread
    // is in a pthread_cond_*wait, otherwise it's lost!!
    //
    // to avoid losing events, we need a flag, and this flag must:
    //  - be set together with the signal, in an atomic block (mutex)
    //  - be checked right before sleeping, in an atomic block (mutex)

    MAIN_LOOP_LOCK();
    wakeup_pending = 1;
    pthread_cond_signal(&main_loop_event);
    MAIN_LOOP_UNLOCK();
}

void mka_main_global_mutex_lock(void)
{
    MKA_ASSERT(0 == pthread_mutex_lock(&global_lock), "Global lock error");
}

void mka_main_global_mutex_unlock(void)
{
    MKA_ASSERT(0 == pthread_mutex_unlock(&global_lock), "Global lock error");
}
