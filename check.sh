#!/bin/bash

check_vulnerability() {
    local ip="$1"
    local port="$2"
    local timeout="$3"
    
    # Check if port is open
    nc -z -w "$timeout" "$ip" "$port"
    local port_status="$?"

    if [ "$port_status" != 0 ]; then
        echo "$ip:$port closed"
        return
    fi
    
    # Retrieve SSH banner
    banner=$(echo "SSH-2.0-OpenSSH" | nc -w "$timeout" "$ip" "$port")

    # Check for vulnerable versions
    vulnerable_versions=(
        "SSH-2.0-OpenSSH_8.5p1"
        "SSH-2.0-OpenSSH_8.6p1"
        "SSH-2.0-OpenSSH_8.7p1"
        "SSH-2.0-OpenSSH_8.8p1"
        "SSH-2.0-OpenSSH_8.9p1"
        "SSH-2.0-OpenSSH_9.0p1"
        "SSH-2.0-OpenSSH_9.1p1"
        "SSH-2.0-OpenSSH_9.2p1"
        "SSH-2.0-OpenSSH_9.3p1"
        "SSH-2.0-OpenSSH_9.4p1"
        "SSH-2.0-OpenSSH_9.5p1"
        "SSH-2.0-OpenSSH_9.6p1"
        "SSH-2.0-OpenSSH_9.7p1"
    )

    # Check if banner contains any vulnerable version
    for version in "${vulnerable_versions[@]}"; do
        if [[ "$banner" == *"$version"* ]]; then
            echo "$ip:$port vulnerable (running $banner)"
            return
        fi
    done

    echo "$ip:$port not vulnerable (running $banner)"
}

main() {
    if [ $# -eq 0 ]; then
        echo "Usage: $0 <ip> [<ip> ...] [--port=<port>] [--timeout=<timeout>] [--file=<filename>]"
        exit 1
    fi
    
    port=22
    timeout=1.0
    file=""

    # Parse arguments
    while [ $# -gt 0 ]; do
        case "$1" in
            --port=*)
                port="${1#*=}"
                shift
                ;;
            --timeout=*)
                timeout="${1#*=}"
                shift
                ;;
            --file=*)
                file="${1#*=}"
                shift
                ;;
            *)
                ips+=("$1")
                shift
                ;;
        esac
    done

    # Read IPs from file if provided
    if [ -n "$file" ]; then
        if [ ! -f "$file" ]; then
            echo "Error: File '$file' not found."
            exit 1
        fi
        while IFS= read -r ip || [ -n "$ip" ]; do
            ips+=("$ip")
        done < "$file"
    fi

    # Perform vulnerability check for each IP
    for ip in "${ips[@]}"; do
        check_vulnerability "$ip" "$port" "$timeout"
    done
}

main "$@"
