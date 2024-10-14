#! /bin/sh
####################################################################
# Startup script for aesdsocket.
# Author: Induja Narayanan <Induja.Narayanan@colorado.edu>
####################################################################


if [ -z "$1" ]; then
    echo "usage: $0 {start|stop}"
    exit 1
fi

case "$1" in
    start)
        echo "Starting aesdsocketserver"
        start-stop-daemon -S -n aesdsocket -a /usr/bin/aesdsocket -- -d
        if [ $? -eq 0 ]; then
            echo "aesdsocketserver started successfully."
        else
            echo "Failed to start aesdsocketserver."
            exit 1
        fi
        ;;
    stop)
        echo "Stopping aesdsocketserver"
        start-stop-daemon -K -n aesdsocket
        if [ $? -eq 0 ]; then
            echo "aesdsocketserver stopped successfully."
        else
            echo "Failed to stop aesdsocketserver."
            exit 1
        fi
        ;;
    *)

esac
exit 0