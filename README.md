# Repsheet Apache

## How does it work?

Repsheet works by inspecting requests as they come into the web server
and checking the requesting actor's status in Redis. When a request
comes in, the actor is checked to see if it has been flagged by
Repsheet. If the actor has been flagged, that information is logged
and the header `X-Repsheet: true` will be added to the downstream
request to let the application know that the actor is suspected of
malicious activity. If the actor has been blacklisted, Repsheet
instructs Apache to return a 403.

An actor can be defined by either an IP address or a cookie value. By
default Repsheet looks at the IP address of the requesting actor by
using the directly connected IP address provided by Apache or by
examining the `X-Forwarded-For`. If the `RepsheetUserCookie`
directive is given a value, it will test the value of that cookie in
each request to see if the user has been blacklisted.

Repsheet can also listen to ModSecurity to determine if the actor has
triggered any rules. Repsheet will examine the headers set by
ModSecurity and log any activity that is present. If the
`RepsheetAnomalyThreshold` is set Repsheet will look at the total
anomaly score and blacklist the actor if the request exceeds the
threshold.

## Dependencies

This module requires [hiredis](https://github.com/redis/hiredis) and
[librepsheet](https://github.com/repsheet/librepsheet) >= 2.2.0 for
compilation and [Redis](http://redis.io) for its runtime.

