#! /bin/sh
####################################################################
# Startup script for can-socket.
# Author: Fernando Becerra Tanaka <fernando.becerratanaka@colorado.edu>
# Based on the work of Induja Narayanan <Induja.Narayanan@colorado.edu>
####################################################################


if [ -z "$1" ]; then
    echo "usage: $0 {start|stop}"
    exit 1
fi

case "$1" in
    start)
        echo "Starting can-socket"
        start-stop-daemon -S -n can-socket -a /usr/bin/can-socket -- -d
        if [ $? -eq 0 ]; then
            echo "can-socketserver started successfully."
        else
            echo "Failed to start can-socket."
            exit 1
        fi
        ;;
    stop)
        echo "Stopping can-socket"
        start-stop-daemon -K -n can-socket
        if [ $? -eq 0 ]; then
            echo "can-socketserver stopped successfully."
        else
            echo "Failed to stop can-socket."
            exit 1
        fi
        ;;
    *)

esac
exit 0