configure_repsheet () {
    if [[ -z $(grep RepsheetEnabled build/$APACHE_24_DIR/conf/httpd.conf) ]]; then
        printf "$BLUE * $YELLOW Configuring Repsheet$RESET "

        cat <<EOF >> build/$APACHE_24_DIR/conf/httpd.conf
<IfModule repsheet_module>
  RepsheetEnabled On
  RepsheetRecorder On
  RepsheetFilter On
  RepsheetGeoIP On
  RepsheetProxyHeaders On
  RepsheetAction Notify
  RepsheetPrefix [repsheet]
  RepsheetAnomalyThreshold 20
  RepsheetRedisTimeout 5
  RepsheetRedisHost localhost
  RepsheetRedisPort 6379
  RepsheetRedisMaxLength 2
  RepsheetRedisExpiry 24
</IfModule>
EOF
        printf "."
        printf " $GREEN [Complete] $RESET\n"
    else
        printf "$BLUE * $GREEN Repsheet already configured $RESET\n"
    fi
}
