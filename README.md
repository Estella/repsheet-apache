# mod_repsheet

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

The following dependencies are needed to install mod_repsheet:

* [librepsheet](https://github.com/repsheet/librepsheet) >= 2.2.0
* [hiredis](https://github.com/redis/hiredis)
* [Redis](http://redis.io)


And the following to compile mod_repsheet:

* [librepsheet](https://github.com/repsheet/librepsheet) >= 2.2.0
* [hiredis](https://github.com/redis/hiredis)
* [json-c](https://github.com/json-c/json-c)
* [libcurl](http://curl.haxx.se/)
* [libxml2](http://xmlsoft.org/)
* [libpcre](http://www.pcre.org/)
* [libgeoip](https://github.com/maxmind/geoip-api-c/tree/master/libGeoIP)
* [check](http://check.sourceforge.net/)

#### Installation

Compilation is done via `apxs`. This is one of the simpler ways to
deal with compilation/installation/activation of a module. Repsheet
uses autotools to generate `configure` scripts and make files. If you
want to build from source you will need to have the
[check](http://check.sourceforge.net/) library installed as well as
the dependencies listed above.

```
autogen.sh
./configure
make
sudo make install
```

To activate and configure repsheet you will need to set some
directives. The following list explains what each directive is and
what is does.

* `RepsheetEnabled <On|Off>` - Determines if Repsheet will do any processing
* `RepsheetModSecurityEnabled <On|Off>` - Determines if Repsheet will look for ModSecurity information
* `RepsheetXFFEnabled <On|Off>` - Determines if Repsheet will look for the X-Forwarded-For header to determine remote ip
* `RepsheetGeoIpEnabled <On|Off>` - Determines if Repsheet will look at GeoIP information
* `RepsheetRecorder <On|Off>` - Determines if request information will be stored
* `RepsheetRedisTimeout <n>` - Sets the time (in milliseconds) before the attempt to connect to redis will timeout and fail
* `RepsheetRedisHost <host>` - Sets the host for the Redis connection
* `RepsheetRedisPort <port>` - Sets the port for the Redis connection
* `RepsheetRedisMaxLength <max>` - Number of recorded requests a single IP can have before it is trimmed in Redis
* `RepsheetRedisExpiry <hours>` - Number of hours of inactivity before an entry expires
* `RepsheetAnomalyThreshold <n>` - Maximum ModSecurity total before blacklisting
* `RepsheetUserCookie <name>` - Name of cookie value to examine

Here's a complete example:

```
<IfModule repsheet_module>
  RepsheetEnabled On
  RepsheetModSecurityEnabled On
  RepsheetXFFEnabled On
  RepsheetGeoIpEnabled On
  RepsheetRecorder On
  RepsheetRedisTimeout 5
  RepsheetRedisHost localhost
  RepsheetRedisPort 6379
  RepsheetRedisMaxLength 2
  RepsheetRedisExpiry 24
  RepsheetAnomalyThreshold 20
  RepsheetUserCookie user
</IfModule>
```

## Running the Integration Tests

This project comes with a basic set of integration tests to ensure
that things are working. If you want to run the tests, you will need
to have [Ruby](http://www.ruby-lang.org/en/),
[RubyGems](http://rubygems.org/), and [Bundler](http://bundler.io/)
installed. In order to run the integration tests, use the following
commands:

```sh
bundle install
script/bootstrap
rake
```

The `script/bootstrap` task will take some time. It downloads and
compiles Apache, ModSecurity, and mod_geoip, and then configures
everything to work together. Running `rake` launches some curl based
tests that hit the site and exercise Repsheet, then test that
everything is working as expected.
