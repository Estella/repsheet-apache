#ifndef __MOD_REPSHEET_H
#define __MOD_REPSHEET_H

#define REPSHEET_VERSION "0.0.1"
#define REPSHEET_URL "https://getrepsheet.com/"

#include "http_core.h"
#include "http_log.h"
#include "hiredis/hiredis.h"
#include "repsheet.h"

typedef struct {
  int repsheet_enabled;
  int recorder_enabled;

  const char *redis_host;
  int redis_port;
  int redis_timeout;
  int redis_expiry;
  int redis_max_length;
  redisContext *redis_connection;

  int modsecurity_enabled;
  int modsecurity_anomaly_threshold;

  const char *user_cookie;

} repsheet_config;

#endif
