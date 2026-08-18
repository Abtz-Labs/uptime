# List available recipes (default)
default:
    @just --list

# Dev server
start port="3030" mode="foreground":
    #!/usr/bin/env bash
    # Handle: just start background -> swap args
    if [ "{{port}}" = "background" ]; then
        port=3030
        mode=background
    elif [ "{{port}}" = "fg" ] || [ "{{port}}" = "foreground" ]; then
        port=3030
        mode=foreground
    else
        mode="{{mode}}"
    fi

    if [ "$mode" = "foreground" ]; then
        php -S localhost:$port index.php
    else
        php -S localhost:$port index.php > /dev/null 2>&1 &
        echo $! > .server.pid
        echo "Server started on port $port (PID: $(cat .server.pid))"
    fi

# Stop dev server
stop:
    @if [ -f .server.pid ]; then \
        kill $(cat .server.pid) 2>/dev/null && echo "Server stopped" || echo "Server not running"; \
        rm -f .server.pid; \
    else \
        echo "No server PID file found"; \
    fi

# Run test suite
test:
    php test.php
