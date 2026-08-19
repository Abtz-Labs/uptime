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

# Simulated cron: run checks every N seconds (default: 60)
cron *args:
    #!/usr/bin/env bash
    interval=60
    mode="foreground"
    for arg in {{args}}; do
        if [ "$arg" = "background" ]; then
            mode="background"
        elif [[ "$arg" =~ ^[0-9]+$ ]]; then
            interval="$arg"
        fi
    done
    run() {
        while true; do
            curl -sf http://localhost:3030/?action=run_checks > /dev/null 2>&1 && echo "[$(date '+%H:%M:%S')] checks ran" || echo "[$(date '+%H:%M:%S')] server not reachable"
            sleep "$interval"
        done
    }
    if [ "$mode" = "foreground" ]; then
        run
    else
        run > /dev/null 2>&1 &
        echo $! > .cron.pid
        echo "Cron started (PID: $(cat .cron.pid), every ${interval}s)"
    fi

# Stop simulated cron
stop-cron:
    @if [ -f .cron.pid ]; then \
        kill $(cat .cron.pid) 2>/dev/null && echo "Cron stopped" || echo "Cron not running"; \
        rm -f .cron.pid; \
    else \
        echo "No cron running"; \
    fi
