#!/bin/bash

source script/apache/modsecurity.sh
source script/apache/geoip.sh
source script/apache/repsheet.sh

DIR=$(pwd)
BUILDDIR=$DIR/build
APACHE_24_DIR=apache24
APACHE_24_VERSION=2.4.9

install_apache () {
    if [ ! -d "vendor/httpd-$APACHE_24_VERSION" ]; then
        printf "$BLUE * $YELLOW Installing Apache $APACHE_24_VERSION$RESET "
        pushd vendor > /dev/null 2>&1
        curl -s -O http://mirror.symnds.com/software/Apache//httpd/httpd-2.4.9.tar.gz
        tar xzf httpd-$APACHE_24_VERSION.tar.gz
        printf "."
        pushd httpd-$APACHE_24_VERSION > /dev/null 2>&1
        ./configure --prefix=$BUILDDIR/$APACHE_24_DIR \
            --exec-prefix=$BUILDDIR/$APACHE_24_DIR    \
            --enable-modules=all                      \
            --enable-mods-shared=all                  \
            --enable-so                               \
            --enable-suexec                           \
            --enable-cache                            \
            --enable-disk-cache                       \
            --enable-mem-cache                        \
            --enable-file-cache                       \
            --enable-ssl                              \
            --with-ssl                                \
            --enable-deflate                          \
            --enable-cgid                             \
            --enable-proxy                            \
            --enable-proxy-connect                    \
            --enable-proxy-http                       \
            --enable-proxy-ftp                        \
            --enable-dbd > install.log 2>&1
        printf "."
        make >> install.log 2>&1
        printf "."
        make install >> install.log 2>&1
        printf "."
        popd > /dev/null 2>&1
        popd > /dev/null 2>&1
        printf "."
        printf "$GREEN [Complete] $RESET\n"
    else
        printf "$BLUE * $GREEN Apache already installed $RESET\n"
    fi
}

configure_apache () {
    if [[ -z $(grep localhost build/$APACHE_24_DIR/conf/httpd.conf) ]]; then
        printf "$BLUE * $YELLOW Configuring base Apache install$RESET "

        pushd build/$APACHE_24_DIR/conf > /dev/null 2>&1
        sed -i.bak 's/Listen 80/Listen 8888/' httpd.conf
        sed -i.bak 's/LogLevel warn/LogLevel info/' httpd.conf
        sed -i.bak 's/#ServerName www.example.com:80/ServerName localhost/' httpd.conf
        sed -i.bak '123s/#//' httpd.conf # enable mod_unique_id (for ModSecurity)
        sed -i.bak '142s/#//' httpd.conf # enable mod_slotmem_shm
        popd > /dev/null 2>&1

        printf "."
        printf "$GREEN [Complete] $RESET\n"
    else
        printf "$BLUE * $GREEN Apache already configured $RESET\n"
    fi
}
