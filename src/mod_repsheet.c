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

const char *repsheet_set_recorder_enabled(cmd_parms *cmd, void *cfg, const char *arg)
{
  if (strcasecmp(arg, "on") == 0) {
    config.recorder_enabled = 1;
    return NULL;
  } else if (strcasecmp(arg, "off") == 0) {
    config.recorder_enabled = 0;
    return NULL;
  } else {
    return "[ModRepsheet] - The RepsheetRecorder directive must be set to On or Off";
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

const char *repsheet_set_redis_max_length(cmd_parms *cmd, void *cfg, const char *arg)
{
  int length = atoi(arg);

  if (length > 0) {
    config.redis_max_length = length;
    return NULL;
  } else {
    return "[ModRepsheet] - The RepsheetRedisMaxLength directive must be a number";
  }
}

const char *repsheet_set_redis_expiry(cmd_parms *cmd, void *cfg, const char *arg)
{
  config.redis_expiry = atoi(arg) * 60 * 60;
  return NULL;
}

const char *repsheet_set_modsecurity_anomaly_threshold(cmd_parms *cmd, void *cfg, const char *arg)
{
  int threshold = strtol(arg, 0, 10);

  if (threshold > 0) {
    config.modsecurity_anomaly_threshold = threshold;
    return NULL;
  } else {
    return "[ModRepsheet] - The ModSecurity anomaly threshold directive must be a number";
  }
}

const char *repsheet_set_user_cookie(cmd_parms *cmd, void *cfg, const char *arg)
{
  config.user_cookie = arg;
  return NULL;
}

static const command_rec repsheet_directives[] =
  {
    AP_INIT_TAKE1("repsheetEnabled",          repsheet_set_enabled,                       NULL, RSRC_CONF, "Enable or disable mod_repsheet"),
    AP_INIT_TAKE1("repsheetRecorder",         repsheet_set_recorder_enabled,              NULL, RSRC_CONF, "Enable or disable repsheet recorder"),
    AP_INIT_TAKE1("repsheetRedisTimeout",     repsheet_set_timeout,                       NULL, RSRC_CONF, "Set the Redis timeout"),
    AP_INIT_TAKE1("repsheetRedisHost",        repsheet_set_host,                          NULL, RSRC_CONF, "Set the Redis host"),
    AP_INIT_TAKE1("repsheetRedisPort",        repsheet_set_port,                          NULL, RSRC_CONF, "Set the Redis port"),
    AP_INIT_TAKE1("repsheetRedisMaxLength",   repsheet_set_redis_max_length,              NULL, RSRC_CONF, "Last n requests kept per IP"),
    AP_INIT_TAKE1("repsheetRedisExpiry",      repsheet_set_redis_expiry,                  NULL, RSRC_CONF, "Number of hours before records expire"),
    AP_INIT_TAKE1("repsheetAnomalyThreshold", repsheet_set_modsecurity_anomaly_threshold, NULL, RSRC_CONF, "Set block threshold"),
    AP_INIT_TAKE1("repsheetUserCookie",       repsheet_set_user_cookie,                   NULL, RSRC_CONF, "Set user cookie"),
    { NULL }
  };

static const char *actor_address(request_rec *r)
{
# if AP_SERVER_MAJORVERSION_NUMBER == 2 && AP_SERVER_MINORVERSION_NUMBER == 4
  char *connected_address = r->useragent_ip;
# else
  char *connected_address = r->connection->remote_ip;
#endif

  const char *xff_header = apr_table_get(r->headers_in, "X-Forwarded-For");

  return remote_address(connected_address, xff_header);
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

static int act_and_record(request_rec *r)
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

  int user_status = OK;
  const char *cookie_value = NULL;
  ap_cookie_read(r, "user", &cookie_value, 0);
  if (cookie_value) {
    user_status = actor_status(config.redis_connection, cookie_value, USER);
  } else {
    ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "Could not locate %s cookie", config.user_cookie);
  }

  int ip_status = OK;
  const char *address = actor_address(r);
  ip_status = actor_status(config.redis_connection, address, IP);

  if (ip_status == DISCONNECTED) {
    ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "The Redis request failed, bypassing further operations");
    return DECLINED;
  }

  int reason_response;
  char reason_code[MAX_REASON_LENGTH];

  if (ip_status == WHITELISTED) {
    ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "%s is whitelisted by repsheet", address);
    return DECLINED;
  } else if (user_status == WHITELISTED) {
    ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "%s is whitelisted by repsheet", cookie_value);
    return DECLINED;
  }

  if (ip_status == BLACKLISTED) {
    reason_response = blacklist_reason(config.redis_connection, address, reason_code);
    if (reason_response == LIBREPSHEET_OK) {
      ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "%s was blocked by repsheet. Reason: %s", address, reason_code);
    } else {
      ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "%s was blocked by repsheet", address);
    }
    return HTTP_FORBIDDEN;
  } else if (user_status == BLACKLISTED) {
    reason_response = blacklist_reason(config.redis_connection, cookie_value, reason_code);
    if (reason_response == LIBREPSHEET_OK) {
      ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "%s was blocked by repsheet. Reason: %s", cookie_value, reason_code);
    } else {
      ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "%s was blocked by repsheet", cookie_value);
    }
    return HTTP_FORBIDDEN;
  }

  if (ip_status == MARKED) {
    ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "%s was found on repsheet. No action taken", address);
    apr_table_set(r->headers_in, "X-Repsheet", "true");
  } else if (user_status == MARKED) {
    ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "%s was found on repsheet. No action taken", cookie_value);
    apr_table_set(r->headers_in, "X-Repsheet", "true");
  }

  apr_time_exp_t start;
  char timestamp[50];

  apr_time_exp_gmt(&start, r->request_time);
  sprintf(timestamp, "%d/%d/%d %d:%d:%d.%d", (start.tm_mon + 1), start.tm_mday, (1900 + start.tm_year), start.tm_hour, start.tm_min, start.tm_sec, start.tm_usec);

  record(config.redis_connection, timestamp, apr_table_get(r->headers_in, "User-Agent"),
         r->method, r->uri, r->args, config.redis_max_length, config.redis_expiry,
         address);

  return DECLINED;
}

static int process_mod_security(request_rec *r)
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

  char *address = (char*)actor_address(r);

  char *x_waf_score = (char *)apr_table_get(r->headers_in, "X-WAF-Score");
  int anomaly_score = modsecurity_total(x_waf_score);
  if (anomaly_score >= config.modsecurity_anomaly_threshold) {
    blacklist_and_expire(config.redis_connection, address, config.redis_expiry, "ModSecurity Anomaly Threshold");
    ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "%s was blacklisted by Repsheet. ModSecurity anomaly score was %d", address, anomaly_score);
    return HTTP_FORBIDDEN;
  }

  char *waf_events = (char *)apr_table_get(r->headers_in, "X-WAF-Events");

  if (!waf_events) {
    return DECLINED;
  }

  int i, m;
  char **events;

  m = matches(waf_events);

  if (m > 0) {
    events = malloc(m * sizeof(char*));
    for(i = 0; i < m; i++) {
      events[i] = malloc(i * sizeof(char));
    }

    process_mod_security_headers(waf_events, events);

    for(i = 0; i < m; i++) {
      increment_rule_count(config.redis_connection, address, events[i]);
      mark_actor(config.redis_connection, address, IP);
      if (config.redis_expiry > 0) {
        expire(config.redis_connection, address, "detected", config.redis_expiry);
        expire(config.redis_connection, address, "repsheet", config.redis_expiry);
      }
    }
    free(events);
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
  ap_hook_post_read_request(act_and_record, NULL, NULL, APR_HOOK_LAST);
  ap_hook_fixups(process_mod_security, NULL, NULL, APR_HOOK_REALLY_LAST);
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
