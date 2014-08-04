MODSECURITY_VERSION=2.8.0

install_mod_security () {
    if [ ! -d "vendor/modsecurity-apache_$MODSECURITY_VERSION" ]; then
        printf "$BLUE * $YELLOW Installing ModSecurity $MODSECURITY_VERSION$RESET "
        pushd vendor > /dev/null 2>&1
        curl -s -O http://www.modsecurity.org/tarball/$MODSECURITY_VERSION/modsecurity-apache_$MODSECURITY_VERSION.tar.gz
        tar xzf modsecurity-apache_$MODSECURITY_VERSION.tar.gz
        printf "."
        pushd modsecurity-apache_$MODSECURITY_VERSION > /dev/null 2>&1
        ./configure --prefix=$BUILDDIR/$APACHE_24_DIR \
            --exec-prefix=$BUILDDIR/$APACHE_24_DIR    \
            --libdir=$BUILDDIR/$APACHE_24_DIR/lib     \
            --with-apxs=$BUILDDIR/$APACHE_24_DIR/bin/apxs #> install.log 2>&1
        printf "."
        make #>> install.log 2>&1
        printf "."
        make install #>> install.log 2>&1
        printf "."
        popd > /dev/null 2>&1
        popd > /dev/null 2>&1
        printf " $GREEN [Complete] $RESET\n"
    else
        printf "$BLUE * $GREEN ModSecurity already installed $RESET\n"
    fi
}

configure_modsecurity () {
    if [[ ! -d "build/$APACHE_24_DIR/conf/modsecurity" ]] ; then
        printf "$BLUE * $YELLOW Configuring ModSecurity$RESET "
        mkdir build/$APACHE_24_DIR/conf/modsecurity
        cp -r modsecurity/* build/$APACHE_24_DIR/conf/modsecurity/

        cat <<EOF >> build/$APACHE_24_DIR/conf/httpd.conf
LoadModule security2_module modules/mod_security2.so

<IfModule security2_module>
  Include conf/modsecurity/*.conf
</IfModule>
EOF

        printf "."
        printf " $GREEN [Complete] $RESET\n"
    else
	printf "$BLUE * $GREEN ModSecurity already configured $RESET\n"
    fi
}
