#include <bcmos_system.h>
#include <bcmcli.h>
#include <bcmolt_daemon.h>
#include <bcm_dev_log.h>
#include <bcm_dev_log_cli.h>
#ifndef BCM_OPEN_SOURCE
#include <bcmolt_host_api.h>
#include <bcmtr_transport_cli.h>
#include <bcmos_cli.h>
#include <bcmtr_interface.h>
#include <bcmtr_debug_cli.h>
#include <onu_mgmt_cli.h>
#include <bcm_api_cli.h>
#include <bcmolt_olt_selector.h>
#endif
#include <bcmolt_netconf_module_init.h>
#include <libyang/libyang.h>
#include <sysrepo.h>
#ifdef NETCONF_MODULE_BBF_POLT_VOMCI
#include <bcm_tr451_polt.h>
#endif

#define BCM_NETCONF_LOG_SIZE               (10*1000*1000)

dev_log_id log_id_netconf;
static dev_log_id log_id_sysrepo;
static sr_conn_ctx_t *sr_conn;
static sr_session_ctx_t *sr_sess;
static struct ly_ctx *ly_ctx;         /**< libyang's context */
static bcmcli_session *current_session;
static nc_startup_options startup_opts;
static bcmos_task netconf_task;

static int print_help(const char *cmd)
{
    const char *p;

    while ((p = strchr(cmd, '/')))
    {
        cmd = p + 1;
    }

    fprintf(stderr,
        "%s"
#ifndef BCM_OPEN_SOURCE
        " -device ip:port"
#endif
#ifdef NETCONF_MODULE_BBF_POLT_VOMCI
        " [-tr451_polt]"
#endif
        " [-d]"
        " [-log level]"
        " [-srlog level]"
#ifdef NETCONF_MODULE_BBF_POLT_VOMCI
        " [-tr451_polt_log level]"
#endif
        " [-syslog]"
        "\n"
        ,cmd);
    fprintf(stderr,
#ifndef BCM_OPEN_SOURCE
            "\t\t -device ip:port - IP address and port OLT is listening on\n"
#endif
            "\t\t -d - debug mode. Stay in the foreground\n"
            "\t\t -syslog - Log to syslog\n"
#ifdef BCM_OPEN_SOURCE
            "\t\t -dummy_tr385 - Dummy TR-385 management. Register for some TR-385 events\n"
#endif
#ifdef NETCONF_MODULE_BBF_POLT_VOMCI
#ifndef BCM_OPEN_SOURCE
            "\t\t -tr451_polt - ONU management is done by TR-451 vOMCI. Enable pOLT support\n"
#endif
            "\t\t -tr451_polt_log error|info|debug TR-451 pOLT log level\n"
#endif
            "\t\t -log error|info|debug - netconf server log level\n"
            "\t\t -srlog error|info|debug - sysrepo log level\n"
            );

    return -EINVAL;

    return -1;
}

#ifndef BCM_OPEN_SOURCE
/* parse ip:port */
static bcmos_errno _parse_ip_port(const char *s, uint32_t *ip, uint16_t *port)
{
    int n;
    uint32_t ip1, ip2, ip3, ip4, pp;

    n = sscanf(s, "%u.%u.%u.%u:%u", &ip1, &ip2, &ip3, &ip4, &pp);
    if (n != 5 || ip1 > 0xff || ip2 > 0xff || ip3 > 0xff || ip4 > 0xff || pp > 0xffff)
    {
        fprintf(stderr, "Can't parse %s. Must be ip_address:port\n", s);
        return BCM_ERR_PARM;
    }
    *ip = (ip1 << 24) | (ip2 << 16) | (ip3 << 8) | ip4;
    *port = pp;
    return BCM_ERR_OK;
}
#endif

// Shutdown server
static void bcm_netconf_shutdown(void)
{
    bcm_netconf_modules_exit(sr_sess, ly_ctx);
    sr_session_stop(sr_sess);
    sr_disconnect(sr_conn);
#ifndef BCM_OPEN_SOURCE
    bcmtr_exit();
#endif
    bcmcli_stop(current_session);
    bcmcli_session_close(current_session);
    bcmcli_token_destroy(NULL);
    bcmos_exit();
}

/* sysrepo log callback */
static void _sr_log_cb(sr_log_level_t level, const char *msg)
{
    bcm_dev_log_level log_level = DEV_LOG_LEVEL_NO_LOG;
    switch(level)
    {
        case SR_LL_NONE:
            log_level = DEV_LOG_LEVEL_NO_LOG;
            break;

        case SR_LL_ERR:   /**< Print only error messages. */
            log_level = DEV_LOG_LEVEL_ERROR;
            break;

        case SR_LL_WRN:   /**< Print error and warning messages. */
            log_level = DEV_LOG_LEVEL_WARNING;
            break;

        case SR_LL_INF:   /**< Besides errors and warnings, print some other informational messages. */
            log_level = DEV_LOG_LEVEL_INFO;
            break;

        case SR_LL_DBG:  /**< Print all messages including some development debug messages. */
            log_level = DEV_LOG_LEVEL_DEBUG;
            break;

        default:
            break;
    }

    /* Log */
#define MAX_LOG_STRING_LEN  (MAX_DEV_LOG_STRING_SIZE - 64)
    if (log_id_sysrepo)
    {
        uint32_t len = strlen(msg);
        const char *p = msg;
        uint32_t flags = BCM_LOG_FLAG_NONE;

        while (len > MAX_LOG_STRING_LEN)
        {
            char buf[MAX_LOG_STRING_LEN];
            memcpy(buf, p, MAX_LOG_STRING_LEN - 1);
            buf[MAX_LOG_STRING_LEN - 1] = 0;
            bcm_dev_log_log(log_id_sysrepo, log_level, flags, "%s", buf);
            p += MAX_LOG_STRING_LEN - 1;
            len -= MAX_LOG_STRING_LEN - 1;
            flags = BCM_LOG_FLAG_NO_HEADER;
        }
        bcm_dev_log_log(log_id_sysrepo, log_level, flags, "%s\n", p);
    }
}

static bcmos_errno _cli_quit(bcmcli_session *session, const bcmcli_cmd_parm parm[], uint16_t n_parms)
{
    bcmcli_print(session, "NETCONF server terminated by CLI command\n");
    bcmcli_stop(session);
    return BCM_ERR_OK;
}

int main(int argc, char *argv[])
{
#ifndef BCM_OPEN_SOURCE
    bcmolt_host_init_parms init_parms = {
        .transport.type = BCM_HOST_API_CONN_LOCAL
    };
    dev_log_init_parms *p_log_parms = &init_parms.log;
#else
    dev_log_init_parms log_parms = {};
    dev_log_init_parms *p_log_parms = &log_parms;
#endif
    bcm_dev_log_level log_level = DEV_LOG_LEVEL_INFO;
    bcm_dev_log_level sr_log_level = DEV_LOG_LEVEL_INFO;
#ifdef NETCONF_MODULE_BBF_POLT_VOMCI
    tr451_polt_init_parms tr451_init_parms = { .log_level = DEV_LOG_LEVEL_INFO };
#endif
    bcmos_bool do_not_daemonize = BCMOS_FALSE;
    bcmolt_daemon_parms daemon_parms = {
        .name = "netconf"
    };
    bcmos_bool log_syslog = BCMOS_FALSE;
    bcmos_task_parm tp = {
        .name = "netconf",
        .priority = TASK_PRIORITY_OLT_AGENT
    };
    bcmos_module_parm mp = {
        .qparm.name = "netconf"
    };
    bcmos_errno rc;
    int i;
    int sr_rc;

    // Parameter validation
    for (i = 1; i < argc; i++)
    {
        if (!strcmp(argv[i], "-log"))
        {
            ++i;
            if (i >= argc)
                return print_help(argv[0]);
            if (!strcmp(argv[i], "debug"))
                log_level = DEV_LOG_LEVEL_DEBUG;
            else if (!strcmp(argv[i], "info"))
                log_level = DEV_LOG_LEVEL_INFO;
            else if (!strcmp(argv[i], "error"))
                log_level = DEV_LOG_LEVEL_ERROR;
            else
                return print_help(argv[0]);
        }
#ifndef BCM_OPEN_SOURCE
        else if (!strcmp(argv[i], "-device"))
        {
            uint32_t remote_ip = 0;
            uint16_t remote_port = 0;
            ++i;
            if (i >= argc)
                return print_help(argv[0]);
            init_parms.transport.type = BCM_HOST_API_CONN_REMOTE;
            if (_parse_ip_port(argv[i], &remote_ip, &remote_port) != BCM_ERR_OK)
                return -1;
            init_parms.transport.addr.ip.u32 = remote_ip;
            init_parms.transport.addr.port = remote_port;
        }
#endif
        else if (!strcmp(argv[i], "-srlog"))
        {
            ++i;
            if (i >= argc)
                return print_help(argv[0]);
            if (!strcmp(argv[i], "debug"))
                sr_log_level = DEV_LOG_LEVEL_DEBUG;
            else if (!strcmp(argv[i], "info"))
                sr_log_level = DEV_LOG_LEVEL_INFO;
            else if (!strcmp(argv[i], "error"))
                sr_log_level = DEV_LOG_LEVEL_ERROR;
            else
                return print_help(argv[0]);
        }
        else if (!strcmp(argv[i], "-d"))
        {
            do_not_daemonize = BCMOS_TRUE;
        }
        else if (!strcmp(argv[i], "-syslog"))
        {
            log_syslog = BCMOS_TRUE;
        }
#ifdef BCM_OPEN_SOURCE
        else if (!strcmp(argv[i], "-dummy_tr385"))
        {
            startup_opts.dummy_tr385_management = BCMOS_TRUE;
        }
#endif
#ifdef NETCONF_MODULE_BBF_POLT_VOMCI
#ifndef BCM_OPEN_SOURCE
        else if (!strcmp(argv[i], "-tr451_polt"))
        {
            startup_opts.tr451_onu_management = BCMOS_TRUE;
        }
#endif
        else if (!strcmp(argv[i], "-tr451_polt_log"))
        {
            ++i;
            if (i >= argc)
                return print_help(argv[0]);
            if (!strcmp(argv[i], "debug"))
                tr451_init_parms.log_level = DEV_LOG_LEVEL_DEBUG;
            else if (!strcmp(argv[i], "info"))
                tr451_init_parms.log_level = DEV_LOG_LEVEL_INFO;
            else if (!strcmp(argv[i], "error"))
                tr451_init_parms.log_level = DEV_LOG_LEVEL_ERROR;
            else
                return print_help(argv[0]);
        }
#endif
        else
        {
            return print_help(argv[0]);
        }
    }

#if defined(NETCONF_MODULE_BBF_POLT_VOMCI) && defined(BCM_OPEN_SOURCE)
    startup_opts.tr451_onu_management = BCMOS_TRUE;
#endif

#if !defined(BCM_OPEN_SOURCE) && !defined(SIMULATION_BUILD)
    if (!init_parms.transport.addr.port)
    {
        fprintf(stderr, "-device parameter is mandatory\n");
        return print_help(argv[0]);
    }
#endif

    /* Daemonize if necessary */
    if (!do_not_daemonize)
    {
        daemon_parms.is_cli_support = BCMOS_TRUE;
        daemon_parms.terminate_cb = bcm_netconf_shutdown;
        //daemon_parms.restart_cb = bcm_netconf_restart;
        rc = bcmolt_daemon_start(&daemon_parms);
        BUG_ON(rc);
        log_syslog = BCMOS_TRUE;
    }
    else
    {
        if (bcmolt_daemon_check_lock(&daemon_parms))
            exit(-1);
    }

    if (!log_syslog)
    {
        p_log_parms->type = BCM_DEV_LOG_FILE_MEMORY;
        p_log_parms->mem_size = BCM_NETCONF_LOG_SIZE;
    }
    else
    {
        p_log_parms->type = BCM_DEV_LOG_FILE_SYSLOG;
    }

#ifndef BCM_OPEN_SOURCE
    /* Initialize host application */
    rc = bcmolt_host_init(&init_parms);
    BUG_ON(rc != BCM_ERR_OK);

#else

    bcmos_trace_level_set(BCMOS_TRACE_LEVEL_INFO);

#ifdef ENABLE_LOG
    /* Initialize logger */
    rc = bcm_log_init(p_log_parms);
    BCMOS_TRACE_CHECK_RETURN(rc, rc, "bcmolt_log_init()\n");
#endif

#endif /* #ifndef BCM_OPEN_SOURCE */

#ifdef ENABLE_LOG
    log_id_netconf = bcm_dev_log_id_register("NETCONF", log_level, DEV_LOG_ID_TYPE_BOTH);
    bcm_dev_log_id_set_level(log_id_netconf, log_level, log_level);
    log_id_sysrepo = bcm_dev_log_id_register("SYSREPO", log_level, DEV_LOG_ID_TYPE_BOTH);
    bcm_dev_log_id_set_level(log_id_sysrepo, sr_log_level, sr_log_level);
#endif

    sr_log_set_cb(_sr_log_cb);

    /* Initialize CLI */
    bcmcli_session_parm mon_session_parm = {};
    /* Create CLI session */
    memset(&mon_session_parm, 0, sizeof(mon_session_parm));
    mon_session_parm.access_right = BCMCLI_ACCESS_ADMIN;

    rc = bcmcli_session_open(&mon_session_parm, &current_session);
    BUG_ON(rc != BCM_ERR_OK);

#ifndef BCM_OPEN_SOURCE
    bcmolt_olt_sel_init(NULL);

    /* API CLI */
    bcm_api_cli_init(NULL, current_session);

    /* ONU management */
    bcmonu_mgmt_cli_init(NULL, current_session);

    /* Transport CLI */
    bcmtr_cli_init();

    /* CLD directory */
    bcmtr_cld_cli_init();

    /* os CLI directory */
    bcmos_cli_init(NULL);
#endif

#ifdef ENABLE_LOG
    /* logger CLI directory */
    bcm_dev_log_cli_init(NULL);
#endif

    /* Create task and module for handling NETCONF events */
    rc = bcmos_task_create(&netconf_task, &tp);
    BUG_ON(rc != BCM_ERR_OK);

    rc = bcmos_module_create(BCMOS_MODULE_ID_NETCONF_SERVER, &netconf_task, &mp);
    BUG_ON(rc != BCM_ERR_OK);

#ifdef NETCONF_MODULE_BBF_POLT_VOMCI
    /* Start TR-451 pOLT subsystem */
    if (startup_opts.tr451_onu_management)
    {
        rc = bcm_tr451_polt_init(&tr451_init_parms);
        BUG_ON(rc != BCM_ERR_OK);
    }
#endif

    /* Connect with sysrepo */
    sr_rc = sr_connect(SR_CONN_DEFAULT, &sr_conn);
    if (sr_rc != SR_ERR_OK)
    {
        bcmos_printf("Can't connect with sysrepo. Error %s\n", sr_strerror(sr_rc));
        return -1;
    }

    sr_rc = sr_session_start(sr_conn, SR_DS_RUNNING, &sr_sess);
    if (sr_rc != SR_ERR_OK)
    {
        bcmos_printf("Unable to create Netopeer session with sysrepod (%s).", sr_strerror(sr_rc));
        return -1;
    }

    /* build libyang context */
    ly_ctx = ly_ctx_new(SR_MODELS_SEARCH_DIR, LY_CTX_ALLIMPLEMENTED);
    if (!ly_ctx)
    {
        bcmos_printf("Unable to create libyang context.");
        return -1;
    }

    /* Start plugin */
    rc = bcm_netconf_modules_init(sr_sess, ly_ctx, &startup_opts);
    if (rc != BCM_ERR_OK)
    {
        /* Let logs a chance to print */
        bcmos_usleep(500000);
        bcmos_printf("NETCONF modules init failed. Error %s\n", bcmos_strerror(rc));
        return -1;
    }

    /* Mark daemon as running */
    if (!do_not_daemonize)
        bcmolt_daemon_init_completed();

    BCMCLI_MAKE_CMD_NOPARM(NULL, "quit", "quit", _cli_quit);

    /* Handle CLI input */
    while (!bcmcli_is_stopped(current_session))
    {
        /* Process user input until EOF or quit command */
        bcmcli_driver(current_session);
        if (feof(stdin) && !do_not_daemonize)
        {
            bcmos_usleep(100000);
            clearerr(stdin);
        }
    }

    /* Cleanup */
    bcm_netconf_shutdown();

    return 0;
}
