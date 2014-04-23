#include "http_core.h"
#include "http_log.h"

#include "repsheet.h"
#include "mod_repsheet.h"

typedef struct {
  int repsheet_enabled;
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

static const command_rec repsheet_directives[] =
  {
    AP_INIT_TAKE1("repsheetEnabled", repsheet_set_enabled, NULL, RSRC_CONF, "Enable or disable mod_repsheet"),
    { NULL }
  };

static int act(request_rec *r)
{
  if (!ap_is_initial_req(r)) {
    return DECLINED;
  }

  redisContext *context = get_redis_context("localhost", 6379, 5);

  if (context == NULL) {
    return DECLINED;
  }

# if AP_SERVER_MAJORVERSION_NUMBER == 2 && AP_SERVER_MINORVERSION_NUMBER == 4
  char *actor_address = r->useragent_ip;
# else
  char *actor_address = r->connection->remote_ip;
#endif

  if (is_whitelisted(context, actor_address)) {
    redisFree(context);
    return DECLINED;
  } else if (is_blacklisted(context, actor_address)) {
    ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "%s was blocked by the repsheet", actor_address);
    redisFree(context);
    return HTTP_FORBIDDEN;
  } else if (is_on_repsheet(context, actor_address)) {
    ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "IP Address %s was found on the repsheet. No action taken", actor_address);
    apr_table_set(r->headers_in, "X-Repsheet", "true");
  }

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
