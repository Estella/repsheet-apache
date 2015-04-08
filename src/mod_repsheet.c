#include "mod_repsheet.h"

static repsheet_config config;

const char *repsheet_set_enabled(cmd_parms *cmd, void *cfg, const char *arg)
{
  if (strcasecmp(arg, "on") == 0) {
    config.repsheet_enabled = 1;
    return NULL;
  } else if (strcasecmp(arg, "off") == 0) {
    config.repsheet_enabled = 0;
    return NULL;
  } else {
    return "[ModRepsheet] - The RepsheetEnabled directive must be set to On or Off";
  }
}

const char *repsheet_xff_set_enabled(cmd_parms *cmd, void *cfg, const char *arg)
{
  if (strcasecmp(arg, "on") == 0) {
    config.xff_enabled = 1;
    return NULL;
  } else if (strcasecmp(arg, "off") == 0) {
    config.xff_enabled = 0;
    return NULL;
  } else {
    return "[ModRepsheet] - The RepsheetXFFEnabled directive must be set to On or Off";
  }
}

const char *repsheet_set_host(cmd_parms *cmd, void *cfg, const char *arg)
{
  config.redis_host = arg;
  return NULL;
}

const char *repsheet_set_timeout(cmd_parms *cmd, void *cfg, const char *arg)
{
  int timeout = atoi(arg) * 1000;

  if (timeout > 0) {
    config.redis_timeout = timeout;
    return NULL;
  } else {
    return "[ModRepsheet] - The RepsheetRedisTimeout directive must be a number";
  }
}

const char *repsheet_set_port(cmd_parms *cmd, void *cfg, const char *arg)
{
  int port = atoi(arg);

  if (port > 0) {
    config.redis_port = port;
    return NULL;
  } else {
    return "[ModRepsheet] - The RepsheetRedisPort directive must be a number";
  }
}

const char *repsheet_set_redis_expiry(cmd_parms *cmd, void *cfg, const char *arg)
{
  config.redis_expiry = atoi(arg) * 60 * 60;
  return NULL;
}

const char *repsheet_set_user_cookie(cmd_parms *cmd, void *cfg, const char *arg)
{
  config.user_cookie = arg;
  return NULL;
}

static const command_rec repsheet_directives[] =
  {
    AP_INIT_TAKE1("repsheetEnabled",      repsheet_set_enabled,      NULL, RSRC_CONF, "Enable or disable mod_repsheet"),
    AP_INIT_TAKE1("repsheetXFFEnabled",   repsheet_xff_set_enabled,  NULL, RSRC_CONF, "Enable or disable X-Forwarded-For processing"),
    AP_INIT_TAKE1("repsheetRedisTimeout", repsheet_set_timeout,      NULL, RSRC_CONF, "Set the Redis timeout"),
    AP_INIT_TAKE1("repsheetRedisHost",    repsheet_set_host,         NULL, RSRC_CONF, "Set the Redis host"),
    AP_INIT_TAKE1("repsheetRedisPort",    repsheet_set_port,         NULL, RSRC_CONF, "Set the Redis port"),
    AP_INIT_TAKE1("repsheetRedisExpiry",  repsheet_set_redis_expiry, NULL, RSRC_CONF, "Number of hours before records expire"),
    AP_INIT_TAKE1("repsheetUserCookie",   repsheet_set_user_cookie,  NULL, RSRC_CONF, "Set user cookie"),
    { NULL }
  };

static int actor_address(request_rec *r, char *address)
{
# if AP_SERVER_MAJORVERSION_NUMBER == 2 && AP_SERVER_MINORVERSION_NUMBER == 4
  char *connected_address = r->useragent_ip;
# else
  char *connected_address = r->connection->remote_ip;
#endif

  if (config.xff_enabled) {
    const char *xff_header = apr_table_get(r->headers_in, "X-Forwarded-For");
    return remote_address(connected_address, (char*)xff_header, address);
  }
}

static int reset_connection(request_rec *r)
{
  redisContext *context = get_redis_context((char*)config.redis_host, config.redis_port, config.redis_timeout);

  if (context == NULL) {
    return DECLINED;
  } else {
    config.redis_connection = context;
    return OK;
  }
}

static int lookup_user(request_rec *r)
{
  int user_status = OK;
  char user_reason[MAX_REASON_LENGTH];
  const char *cookie_value = NULL;

  if (config.user_cookie) {
    ap_cookie_read(r, config.user_cookie, &cookie_value, 0);
    if (cookie_value) {
      user_status = actor_status(config.redis_connection, cookie_value, USER, user_reason);
    } else {
      ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "Could not locate %s cookie", config.user_cookie);
      return DECLINED;
    }
  }

  if (user_status == DISCONNECTED) {
    ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "The Redis request failed, bypassing further operations");
    return DECLINED;
  } else if (user_status == WHITELISTED) {
    ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "%s is whitelisted by repsheet. Reason: %s", cookie_value, user_reason);
    return DECLINED;
  } else if (user_status == BLACKLISTED) {
    ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "%s was blocked by repsheet. Reason: %s", cookie_value, user_reason);
    return HTTP_FORBIDDEN;
  } else if (user_status == MARKED) {
    ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "%s was found on repsheet. No action taken", cookie_value);
    apr_table_set(r->headers_in, "X-Repsheet", "true");
  }

  return DECLINED;
}

static int lookup_ip(request_rec *r)
{
  int ip_status = OK;
  char ip_reason[MAX_REASON_LENGTH];
  char address[INET6_ADDRSTRLEN];
  int address_result = actor_address(r, address);

  if (address_result == BLACKLISTED) {
    ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "Request was blocked by repsheet. Reason: Invalid X-Forwarded-For");
    return HTTP_FORBIDDEN;
  }

  ip_status = actor_status(config.redis_connection, address, IP, ip_reason);
  if (ip_status == DISCONNECTED) {
    ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "The Redis request failed, bypassing further operations");
    return DECLINED;
  } else if (ip_status == WHITELISTED) {
    ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "%s is whitelisted by repsheet. Reason: %s", address, ip_reason);
    return DECLINED;
  } else if (ip_status == BLACKLISTED) {
    ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "%s was blocked by repsheet. Reason: %s", address, ip_reason);
    return HTTP_FORBIDDEN;
  } else if (ip_status == MARKED) {
    ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "%s was found on repsheet. No action taken", address);
    apr_table_set(r->headers_in, "X-Repsheet", "true");
  }

  return DECLINED;
}

static int lookup(request_rec *r)
{
  if (!config.repsheet_enabled || !ap_is_initial_req(r)) {
    return DECLINED;
  }

  int connection_status = check_connection(config.redis_connection);
  if (connection_status == DISCONNECTED) {
    ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "No Redis connection found, creating a new connection");
    connection_status = reset_connection(r);
    if (connection_status == DECLINED) {
      ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "Unable to establish connection to Redis, bypassing further operations");
      return DECLINED;
    }
  }

  int user_status = lookup_user(r);
  if (user_status != DECLINED) {
    return user_status;
  }

  int ip_status = lookup_ip(r);
  if (ip_status != DECLINED) {
    return ip_status;
  }

  return DECLINED;
}

static int hook_post_config(apr_pool_t *mp, apr_pool_t *mp_log, apr_pool_t *mp_temp, server_rec *s) {
  void *init_flag = NULL;
  int first_time = 0;

  apr_pool_userdata_get(&init_flag, "mod_repsheet-init-flag", s->process->pool);

  if (init_flag == NULL) {
    first_time = 1;
    apr_pool_userdata_set((const void *)1, "mod_repsheet-init-flag", apr_pool_cleanup_null, s->process->pool);
    ap_log_error(APLOG_MARK, APLOG_NOTICE | APLOG_NOERRNO, 0, s, "ModRepsheet for Apache %s (%s) loaded", REPSHEET_VERSION, REPSHEET_URL);
    return OK;
  }

  return OK;
}

static void register_hooks(apr_pool_t *pool)
{
  ap_hook_post_config(hook_post_config, NULL, NULL, APR_HOOK_REALLY_LAST);
  ap_hook_post_read_request(lookup, NULL, NULL, APR_HOOK_LAST);
}

module AP_MODULE_DECLARE_DATA repsheet_module = {
  STANDARD20_MODULE_STUFF,
  NULL,                /* Per-directory configuration handler */
  NULL,                /* Merge handler for per-directory configurations */
  NULL,                /* Per-server configuration handler */
  NULL,                /* Merge handler for per-server configurations */
  repsheet_directives, /* Any directives we may have for httpd */
  register_hooks       /* Our hook registering function */
};
