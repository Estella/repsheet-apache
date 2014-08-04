configure_repsheet () {
    if [[ -z $(grep RepsheetEnabled build/$APACHE_24_DIR/conf/httpd.conf) ]]; then
        printf "$BLUE * $YELLOW Configuring Repsheet$RESET "

        cat <<EOF >> build/$APACHE_24_DIR/conf/httpd.conf
<IfModule repsheet_module>
  RepsheetEnabled On
  RepsheetRecorder On
  RepsheetRedisTimeout 5
  RepsheetRedisHost localhost
  RepsheetRedisPort 6379
  RepsheetRedisMaxLength 2
  RepsheetRedisExpiry 24
  RepsheetAnomalyThreshold 20
  RepsheetUserCookie user
</IfModule>
EOF
        printf "."
        printf " $GREEN [Complete] $RESET\n"
    else
        printf "$BLUE * $GREEN Repsheet already configured $RESET\n"
    fi
}
