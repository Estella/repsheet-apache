install_mod_geoip () {
    if [ ! -d "vendor/geoip" ]; then
        printf "$BLUE * $YELLOW Installing GeoIP$RESET "
        pushd vendor > /dev/null 2>&1
        mkdir geoip
        pushd geoip > /dev/null 2>&1
        curl -s -O http://geolite.maxmind.com/download/geoip/database/GeoLiteCity.dat.gz
        gunzip GeoLiteCity.dat.gz
        cp GeoLiteCity.dat ../../build/$APACHE_24_DIR/conf
        curl -s -O http://www.maxmind.com/download/geoip/api/mod_geoip2/mod_geoip2-latest.tar.gz
        tar xzf mod_geoip2-latest.tar.gz
        printf "."
        pushd mod_geoip2_1.2.8 > /dev/null 2>&1
        ../../../build/$APACHE_24_DIR/bin/apxs -i -a \
	    -L../../../build/$APACHE_24_DIR/lib      \
	    -I../../../build/$APACHE_24_DIR/include/ \
	    -lGeoIP -c mod_geoip.c > install.log 2>&1
        printf "."
        popd > /dev/null 2>&1
        popd > /dev/null 2>&1
        popd > /dev/null 2>&1

        #sed -i.bak '268s/.*/LogFormat "%h %l %u %t \\"%r\\" %>s %b \\"%{GEOIP_COUNTRY_CODE}e %{GEOIP_CITY}e %{GEOIP_REGION_NAME}e %{GEOIP_POSTAL_CODE}e %{GEOIP_LATITUDE}e %{GEOIP_LONGITUDE}e\\"" common/' build/apache/conf/httpd.conf

        cat <<EOF >> build/$APACHE_24_DIR/conf/httpd.conf

<IfModule geoip_module>
  GeoIPEnable On
  GeoIPDBFile $(pwd)/build/apache24/conf/GeoLiteCity.dat
  GeoIPOutput All
</IfModule>
EOF
        printf " $GREEN [Complete] $RESET\n"
    else
        printf "$BLUE * $GREEN GeoIP already installed $RESET\n"
    fi
}
