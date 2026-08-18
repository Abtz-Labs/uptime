# List available recipes (default)
default:
    @just --list

# Dev server
start *args:
    #!/usr/bin/env bash
    port="3030"
    mode="foreground"
    for arg in {{args}}; do
        if [ "$arg" = "background" ]; then
            mode="background"
        elif [[ "$arg" =~ ^[0-9]+$ ]]; then
            port="$arg"
        fi
    done
    if [ "$mode" = "foreground" ]; then
        php -S 127.0.0.1:$port index.php
    else
        php -S 127.0.0.1:$port index.php > /dev/null 2>&1 &
        echo $! > .server.pid
        echo "Server started on port $port (PID: $(cat .server.pid))"
    fi

# Stop dev server
stop:
    @if [ -f .server.pid ]; then \
        kill $(cat .server.pid) 2>/dev/null && echo "Server stopped" || echo "Server not running"; \
        rm -f .server.pid; \
    else \
        echo "No server running"; \
    fi

# Run test suite
test:
    php test.php
