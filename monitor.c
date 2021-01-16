/*
 * Copyright (C) 2021 SUSE LLC
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 * This file implements a simple monitor for NVMe-related uevents.
 */

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <libudev.h>
#include <signal.h>
#include <time.h>
#include <syslog.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/epoll.h>

#include "util/argconfig.h"
#include "util/cleanup.h"
#include "common.h"
#include "nvme.h"
#include "libnvme.h"
#include "fabrics.h"
#include "monitor.h"
#define LOG_FUNCNAME 1
#include "event/event.h"

static struct monitor_config {
	bool autoconnect;
} mon_cfg = {
	.autoconnect = true,
};

static struct dispatcher *mon_dsp;

static DEFINE_CLEANUP_FUNC(cleanup_monitorp, struct udev_monitor *, udev_monitor_unref);

static int create_udev_monitor(struct udev *udev, struct udev_monitor **pmon)
{
	struct udev_monitor *mon __cleanup__(cleanup_monitorp) = NULL;
	int ret;
	bool use_udev;
	static const char *const monitor_name[] = {
		[false] = "kernel",
		[true]  = "udev",
	};

	/* Check if udevd is running, same test that libudev uses */
	use_udev = access("/run/udev/control", F_OK) >= 0;
	nvme_msg(LOG_DEBUG, "using %s monitor for uevents\n", monitor_name[use_udev]);

	mon = udev_monitor_new_from_netlink(udev, monitor_name[use_udev]);
	if (!mon)
		return errno ? -errno : -ENOMEM;

	/* Add match for NVMe controller devices */
	ret = udev_monitor_filter_add_match_subsystem_devtype(mon, "nvme", NULL);
	/* Add match for fc_udev_device */
	ret = udev_monitor_filter_add_match_subsystem_devtype(mon, "fc", NULL);

	/*
	 * If we use the "udev" monitor, the kernel filters out the interesting
	 * uevents for us using BPF. A single event is normally well below 1kB,
	 * so 1MiB is sufficient for queueing more than 1000 uevents, which
	 * should be plenty for just nvme.
	 *
	 * For "kernel" monitors, the filtering is done by libudev in user space,
	 * thus every device is received in the first place, and a larger
	 * receive buffer is needed. Use the same value as udevd.
	 */
	udev_monitor_set_receive_buffer_size(mon, (use_udev ? 1 : 128) * 1024 * 1024);
	ret = udev_monitor_enable_receiving(mon);
	if (ret < 0)
		return ret;
	*pmon = mon;
	mon = NULL;
	return 0;
}

static sig_atomic_t must_exit;
static sig_atomic_t got_sigchld;
static sigset_t orig_sigmask;

static void monitor_int_handler(int sig)
{
	must_exit = 1;
}

static void monitor_chld_handler(int sig)
{
	got_sigchld = 1;
}

static int monitor_init_signals(sigset_t *wait_mask)
{
	sigset_t mask;
	struct sigaction sa = { .sa_handler = monitor_int_handler, };

	/*
	 * Block all signals. They will be unblocked when we wait
	 * for events.
	 */
	sigfillset(&mask);
	if (sigprocmask(SIG_BLOCK, &mask, &orig_sigmask) == -1)
		return -errno;
	if (sigaction(SIGTERM, &sa, NULL) == -1)
		return -errno;
	if (sigaction(SIGINT, &sa, NULL) == -1)
		return -errno;

	sa.sa_handler = monitor_chld_handler;
	if (sigaction(SIGCHLD, &sa, NULL) == -1)
		return -errno;

	/* signal mask to be used in epoll_pwait() */
	sigfillset(wait_mask);
	sigdelset(wait_mask, SIGTERM);
	sigdelset(wait_mask, SIGINT);
	sigdelset(wait_mask, SIGCHLD);

	return 0;
}

static int child_reset_signals(void)
{
	int err = 0;
	struct sigaction sa = { .sa_handler = SIG_DFL, };

	if (sigaction(SIGTERM, &sa, NULL) == -1)
		err = errno;
	if (sigaction(SIGINT, &sa, NULL) == -1 && !err)
		err = errno;
	if (sigaction(SIGCHLD, &sa, NULL) == -1 && !err)
		err = errno;

	if (sigprocmask(SIG_SETMASK, &orig_sigmask, NULL) == -1 && !err)
		err = errno;

	if (err)
		nvme_msg(LOG_ERR, "error resetting signal handlers and mask\n");
	return -err;
}

static int monitor_get_fc_uev_props(struct udev_device *ud,
				    char *traddr, size_t tra_sz,
				    char *host_traddr, size_t htra_sz)
{
	const char *sysname = udev_device_get_sysname(ud);
	const char *tra = NULL, *host_tra = NULL;
	bool fc_event_seen = false;
	struct udev_list_entry *entry;

	entry = udev_device_get_properties_list_entry(ud);
	if (!entry) {
		nvme_msg(LOG_NOTICE, "%s: emtpy properties list\n", sysname);
		return -ENOENT;
	}

	for (; entry; entry = udev_list_entry_get_next(entry)) {
		const char *name = udev_list_entry_get_name(entry);

		if (!strcmp(name, "FC_EVENT") &&
		    !strcmp(udev_list_entry_get_value(entry), "nvmediscovery"))
				fc_event_seen = true;
		else if (!strcmp(name, "NVMEFC_HOST_TRADDR"))
			host_tra = udev_list_entry_get_value(entry);
		else if (!strcmp(name, "NVMEFC_TRADDR"))
			tra = udev_list_entry_get_value(entry);
	}
	if (!fc_event_seen) {
		nvme_msg(LOG_DEBUG, "%s: FC_EVENT property missing or unsupported\n",
		    sysname);
		return -EINVAL;
	}
	if (!tra || !host_tra) {
		nvme_msg(LOG_WARNING, "%s: transport properties missing\n", sysname);
		return -EINVAL;
	}

	if (!memccpy(traddr, tra, '\0', tra_sz) ||
	    !memccpy(host_traddr, host_tra, '\0', htra_sz)) {
		nvme_msg(LOG_ERR, "traddr (%zu) or host_traddr (%zu) overflow\n",
		    strlen(traddr), strlen(host_traddr));
		return -ENAMETOOLONG;
	}

	return 0;
}

static int monitor_discovery(nvme_host_t h, char *transport,
			     char *traddr, char *host_traddr, char *trsvcid)
{
	pid_t pid;
	int rc;
	nvme_ctrl_t c;
	struct nvme_fabrics_config fabrics_cfg = {
		.tos = -1,
	};

	pid = fork();
	if (pid == -1) {
		nvme_msg(LOG_ERR, "failed to fork discovery task: %m");
		return -errno;
	} else if (pid > 0) {
		nvme_msg(LOG_DEBUG, "started discovery task %ld\n", (long)pid);
		return 0;
	}

	child_reset_signals();
	free_dispatcher(mon_dsp);

	nvme_msg(LOG_NOTICE, "starting discovery\n");
	c = nvme_create_ctrl(NVME_DISC_SUBSYS_NAME, transport, traddr,
			     host_traddr, NULL, trsvcid);
	if (!c) {
		nvme_msg(LOG_ERR, "Failed to allocate discovery controller\n");
		exit(-ENOMEM);
	}
	rc = nvmf_add_ctrl(h, c, &fabrics_cfg, false);
	if (rc) {
		nvme_msg(LOG_ERR, "no controller found\n");
		rc = errno;
	} else {
		rc = nvmf_do_discover(c, &fabrics_cfg, NULL,
				      mon_cfg.autoconnect,
				      true, 0);
		if (rc)
			rc = errno;
	}
	nvme_free_ctrl(c);

	exit(-rc);
	/* not reached */
	return rc;
}

static void monitor_handle_fc_uev(nvme_host_t h, struct udev_device *ud)
{
	const char *action = udev_device_get_action(ud);
	const char *sysname = udev_device_get_sysname(ud);
	char traddr[NVMF_TRADDR_SIZE], host_traddr[NVMF_TRADDR_SIZE];

	if (strcmp(action, "change") || strcmp(sysname, "fc_udev_device"))
		return;

	if (monitor_get_fc_uev_props(ud, traddr, sizeof(traddr),
				     host_traddr, sizeof(host_traddr)))
		return;

	monitor_discovery(h, "fc", traddr, host_traddr, NULL);
}

static int monitor_get_nvme_uev_props(struct udev_device *ud,
				      char *transport, size_t tr_sz,
				      char *traddr, size_t tra_sz,
				      char *trsvcid, size_t trs_sz,
				      char *host_traddr, size_t htra_sz)
{
	const char *sysname = udev_device_get_sysname(ud);
	bool aen_disc = false;
	struct udev_list_entry *entry;

	entry = udev_device_get_properties_list_entry(ud);
	if (!entry) {
		nvme_msg(LOG_NOTICE, "%s: emtpy properties list\n", sysname);
		return -ENOENT;
	}

	*transport = *traddr = *trsvcid = *host_traddr = '\0';
	for (; entry; entry = udev_list_entry_get_next(entry)) {
		const char *name = udev_list_entry_get_name(entry);

		if (!strcmp(name, "NVME_AEN") &&
		    !strcmp(udev_list_entry_get_value(entry), "0x70f002"))
				aen_disc = true;
		else if (!strcmp(name, "NVME_TRTYPE"))
			memccpy(transport, udev_list_entry_get_value(entry),
				'\0', tr_sz);
		else if (!strcmp(name, "NVME_TRADDR"))
			memccpy(traddr, udev_list_entry_get_value(entry),
				'\0', htra_sz);
		else if (!strcmp(name, "NVME_TRSVCID"))
			memccpy(trsvcid, udev_list_entry_get_value(entry),
				'\0', trs_sz);
		else if (!strcmp(name, "NVME_HOST_TRADDR"))
			memccpy(host_traddr, udev_list_entry_get_value(entry),
				'\0', tra_sz);
	}
	if (!aen_disc) {
		nvme_msg(LOG_DEBUG, "%s: not a \"discovery log changed\" AEN, ignoring event\n",
		    sysname);
		return -EINVAL;
	}

	if (!*traddr || !*transport) {
		nvme_msg(LOG_WARNING, "%s: transport properties missing\n", sysname);
		return -EINVAL;
	}

	return 0;
}

static void monitor_handle_nvme_uev(nvme_host_t h, struct udev_device *ud)
{
	char traddr[NVMF_TRADDR_SIZE], host_traddr[NVMF_TRADDR_SIZE];
	char trsvcid[NVMF_TRSVCID_SIZE], transport[5];

	if (strcmp(udev_device_get_action(ud), "change"))
		return;

	if (monitor_get_nvme_uev_props(ud, transport, sizeof(transport),
				       traddr, sizeof(traddr),
				       trsvcid, sizeof(trsvcid),
				       host_traddr, sizeof(host_traddr)))
		return;

	monitor_discovery(h, transport, traddr, host_traddr,
			  strcmp(trsvcid, "none") ? trsvcid : NULL);
}

static void monitor_handle_udevice(nvme_host_t h, struct udev_device *ud)
{
	const char *subsys  = udev_device_get_subsystem(ud);

	if (nvme_log_level >= LOG_INFO) {
		const char *action = udev_device_get_action(ud);
		const char *syspath = udev_device_get_syspath(ud);

		nvme_msg(LOG_INFO, "%s %s\n", action, syspath);
	}
	if (!strcmp(subsys, "fc"))
		monitor_handle_fc_uev(h, ud);
	else if (!strcmp(subsys, "nvme"))
		monitor_handle_nvme_uev(h, ud);
}

struct udev_monitor_event {
	struct event e;
	struct udev_monitor *monitor;
	nvme_host_t host;
};

static int monitor_handle_uevents(struct event *ev,
				  uint32_t __attribute__((unused)) ep_events)
{
	struct udev_monitor_event *udev_event =
		container_of(ev, struct udev_monitor_event, e);
	struct udev_monitor *monitor = udev_event->monitor;
	struct udev_device *ud;

	for (ud = udev_monitor_receive_device(monitor);
	     ud;
	     ud = udev_monitor_receive_device(monitor)) {
		monitor_handle_udevice(udev_event->host, ud);
		udev_device_unref(ud);
	}
	return EVENTCB_CONTINUE;
}

static int handle_epoll_err(int errcode)
{
	if (errcode != -EINTR)
		return errcode;
	else if (must_exit) {
		nvme_msg(LOG_NOTICE, "monitor: exit signal received\n");
		return ELOOP_QUIT;
	} else if (!got_sigchld) {
		nvme_msg(LOG_WARNING, "monitor: unexpected interruption, ignoring\n");
		return ELOOP_CONTINUE;
	}

	got_sigchld = 0;
	while (true) {
		int wstatus;
		pid_t pid;

		pid = waitpid(-1, &wstatus, WNOHANG);
		switch(pid) {
		case -1:
			if (errno != ECHILD)
				nvme_msg(LOG_ERR, "error in waitpid: %m\n");
			goto out;
		case 0:
			goto out;
		default:
			break;
		}
		if (!WIFEXITED(wstatus))
			nvme_msg(LOG_WARNING, "child %ld didn't exit normally\n",
			    (long)pid);
		else if (WEXITSTATUS(wstatus) != 0)
			nvme_msg(LOG_NOTICE, "child %ld exited with status \"%s\"\n",
			    (long)pid, strerror(WEXITSTATUS(wstatus)));
		else
			nvme_msg(LOG_DEBUG, "child %ld exited normally\n", (long)pid);
	};

out:
	/* tell event_loop() to continue */
	return ELOOP_CONTINUE;
}

static DEFINE_CLEANUP_FUNC(cleanup_udevp, struct udev *, udev_unref);

static void cleanup_udev_event(struct event *evt)
{
	struct udev_monitor_event *ue;

	ue = container_of(evt, struct udev_monitor_event, e);
	if (ue->monitor)
		ue->monitor = udev_monitor_unref(ue->monitor);
}

int aen_monitor(const char *desc, int argc, char **argv)
{
	int ret;
	struct udev *udev __cleanup__(cleanup_udevp) = NULL;
	struct udev_monitor *monitor __cleanup__(cleanup_monitorp) = NULL;
	struct udev_monitor_event udev_event = { .e.fd = -1, };
	sigset_t wait_mask;
	bool quiet = false;
	bool verbose = false;
	bool debug = false;
	bool noauto = false;
	bool matching_only = false;
	char *hostnqn = NULL;
	char *hostid = NULL;
	nvme_root_t r;
	nvme_host_t h;
	struct nvme_fabrics_config cfg = {
		.tos = -1,
	};

	OPT_ARGS(opts) = {
		OPT_FLAG("no-connect",     'N', &noauto,          "dry run, do not autoconnect to discovered controllers"),
		OPT_LIST("hostnqn",        'q', &hostnqn,         "user-defined hostnqn (if default not used)"),
		OPT_LIST("hostid",         'I', &hostid,          "user-defined hostid (if default not used)"),
		OPT_INT("keep-alive-tmo",  'k', &cfg.keep_alive_tmo,  "keep alive timeout period in seconds"),
		OPT_INT("reconnect-delay", 'c', &cfg.reconnect_delay, "reconnect timeout period in seconds"),
		OPT_INT("ctrl-loss-tmo",   'l', &cfg.ctrl_loss_tmo,   "controller loss timeout period in seconds"),
		OPT_INT("tos",             'T', &cfg.tos,             "type of service"),
		OPT_FLAG("hdr_digest",     'g', &cfg.hdr_digest,      "enable transport protocol header digest (TCP transport)"),
		OPT_FLAG("data_digest",    'G', &cfg.data_digest,     "enable transport protocol data digest (TCP transport)"),
		OPT_INT("nr-io-queues",    'i', &cfg.nr_io_queues,    "number of io queues to use (default is core count)"),
		OPT_INT("nr-write-queues", 'W', &cfg.nr_write_queues, "number of write queues to use (default 0)"),
		OPT_INT("nr-poll-queues",  'P', &cfg.nr_poll_queues,  "number of poll queues to use (default 0)"),
		OPT_INT("queue-size",      'Q', &cfg.queue_size,      "number of io queue elements to use (default 128)"),
		OPT_FLAG("matching",       'm', &matching_only,   "connect only records matching the traddr"),
		OPT_FLAG("silent",         'S', &quiet,               "log level: silent"),
		OPT_FLAG("verbose",        'v', &verbose,             "log level: verbose"),
		OPT_FLAG("debug",          'D', &debug,               "log level: debug"),
		OPT_FLAG("timestamps",     't', &nvme_log_timestamp,  "print log timestamps"),
		OPT_END()
	};

	nvme_log_pid = true;
	ret = argconfig_parse(argc, argv, desc, opts);
	if (ret)
		return ret;
	if (quiet)
		nvme_log_level = LOG_WARNING;
	if (verbose)
		nvme_log_level = LOG_INFO;
	if (debug)
		nvme_log_level = LOG_DEBUG;
	if (noauto)
		mon_cfg.autoconnect = false;

	ret = monitor_init_signals(&wait_mask);
	if (ret != 0) {
		nvme_msg(LOG_ERR, "monitor: failed to initialize signals: %m\n");
		goto out;
	}

	mon_dsp = new_dispatcher(CLOCK_REALTIME);
	if (!mon_dsp) {
		ret = errno ? -errno : -EIO;
		goto out;
	}

	r = nvme_scan(NULL);
	if (!cfg.keep_alive_tmo)
		cfg.keep_alive_tmo = 30;
	if (!hostnqn)
		hostnqn = nvmf_hostnqn_from_file();
	if (!hostid)
		hostid = nvmf_hostid_from_file();
	h = nvme_lookup_host(r, hostnqn, hostid);
	if (!h) {
		ret = ENOMEM;
		goto out;
	}
	udev = udev_new();
	if (!udev) {
		nvme_msg(LOG_ERR, "failed to create udev object: %m\n");
		ret = errno ? -errno : -ENOMEM;
		goto out;
	}

	ret = create_udev_monitor(udev, &monitor);
	if (ret != 0)
		goto out;

	udev_event.e = EVENT_ON_STACK(monitor_handle_uevents,
				      udev_monitor_get_fd(monitor), EPOLLIN);
	if (udev_event.e.fd == -1)
		goto out;
	udev_event.e.cleanup = cleanup_udev_event;
	udev_event.host = h;
	udev_event.monitor = monitor;
	monitor = NULL;

	if ((ret = event_add(mon_dsp, &udev_event.e)) != 0) {
		nvme_msg(LOG_ERR, "failed to register udev monitor event: %s\n",
			 strerror(-ret));
		goto out;
	}

	ret = event_loop(mon_dsp, &wait_mask, handle_epoll_err);

out:
	free_dispatcher(mon_dsp);
	return nvme_status_to_errno(ret, true);
}
