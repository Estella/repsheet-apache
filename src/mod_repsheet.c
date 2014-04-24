#include "http_core.h"
#include "http_log.h"

#include "repsheet.h"
#include "mod_repsheet.h"

typedef struct {
  int repsheet_enabled;

  const char *redis_host;
  int redis_port;
  int redis_timeout;
  int redis_expiry;
  int redis_max_length;

} repsheet_config;

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

static const command_rec repsheet_directives[] =
  {
    AP_INIT_TAKE1("repsheetEnabled",        repsheet_set_enabled,          NULL, RSRC_CONF, "Enable or disable mod_repsheet"),
    AP_INIT_TAKE1("repsheetRedisTimeout",   repsheet_set_timeout,          NULL, RSRC_CONF, "Set the Redis timeout"),
    AP_INIT_TAKE1("repsheetRedisHost",      repsheet_set_host,             NULL, RSRC_CONF, "Set the Redis host"),
    AP_INIT_TAKE1("repsheetRedisPort",      repsheet_set_port,             NULL, RSRC_CONF, "Set the Redis port"),
    AP_INIT_TAKE1("repsheetRedisMaxLength", repsheet_set_redis_max_length, NULL, RSRC_CONF, "Last n requests kept per IP"),
    AP_INIT_TAKE1("repsheetRedisExpiry",    repsheet_set_redis_expiry,     NULL, RSRC_CONF, "Number of hours before records expire"),
    { NULL }
  };

static int act(request_rec *r)
{
  if (!ap_is_initial_req(r)) {
    return DECLINED;
  }

  redisContext *context = get_redis_context((char*)config.redis_host, config.redis_port, config.redis_timeout);

  if (context == NULL) {
    return DECLINED;
  }

# if AP_SERVER_MAJORVERSION_NUMBER == 2 && AP_SERVER_MINORVERSION_NUMBER == 4
  char *actor_address = r->useragent_ip;
# else
  char *actor_address = r->connection->remote_ip;
#endif

  if (is_whitelisted(context, actor_address)) {
    ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "%s is whitelisted by repsheet", actor_address);
    redisFree(context);
    return DECLINED;
  } else if (is_blacklisted(context, actor_address)) {
    ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "%s was blocked by repsheet", actor_address);
    redisFree(context);
    return HTTP_FORBIDDEN;
  } else if (is_on_repsheet(context, actor_address)) {
    ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "%s was found on repsheet. No action taken", actor_address);
    apr_table_set(r->headers_in, "X-Repsheet", "true");
  }

  apr_time_exp_t start;
  char timestamp[50];

  apr_time_exp_gmt(&start, r->request_time);
  sprintf(timestamp, "%d/%d/%d %d:%d:%d.%d", (start.tm_mon + 1), start.tm_mday, (1900 + start.tm_year), start.tm_hour, start.tm_min, start.tm_sec, start.tm_usec);

  record(context, timestamp, apr_table_get(r->headers_in, "User-Agent"),
	 r->method, r->uri, r->args, config.redis_max_length, config.redis_expiry,
	 actor_address);

  redisFree(context);

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
  ap_hook_post_read_request(act, NULL, NULL, APR_HOOK_LAST);
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
