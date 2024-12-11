#!/bin/bash

# File paths
CONFIG_FILE="config.txt"
RULES_V4="rulesV4"
RULES_V6="rulesV6"

# Function to display help
function display_help() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -config   Configure ad-block rules based on the config.txt file"
    echo "  -save     Save current firewall rules to rulesV4 and rulesV6"
    echo "  -load     Load firewall rules from rulesV4 and rulesV6"
    echo "  -list     List all current firewall rules"
    echo "  -reset    Reset all firewall rules to default (accept all)"
    echo "  -help     Display this help message and exit"
}

# Function to check if the given value is a valid IPv4 address
function is_valid_ipv4() {
    local ip=$1
    if [[ $ip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        return 0
    else
        return 1
    fi
}

# Function to check if the given value is a valid IPv6 address
function is_valid_ipv6() {
    local ip=$1
    if [[ $ip =~ ^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$ ]]; then
        return 0
    else
        return 1
    fi
}

# Function to configure iptables/ip6tables rules
function configure_rules() {
    echo "Configuring rules based on $CONFIG_FILE..."
    # Read domains from config.txt and resolve to IP addresses
    while read -r domain; do
        if [[ -n "$domain" ]]; then
            echo "Blocking domain: $domain"
            
            # Resolve IPv4 addresses
            for ip in $(dig +short A "$domain"); do
                if is_valid_ipv4 "$ip"; then
                    echo "Blocking IPv4: $ip"
                    sudo iptables -A INPUT -s "$ip" -j REJECT
                else
                    echo "Invalid IPv4 address or error for domain $domain: $ip"
                fi
            done

            # Resolve IPv6 addresses
            for ip6 in $(dig +short AAAA "$domain"); do
                if is_valid_ipv6 "$ip6"; then
                    echo "Blocking IPv6: $ip6"
                    sudo ip6tables -A INPUT -s "$ip6" -j REJECT
                else
                    echo "Invalid IPv6 address or error for domain $domain: $ip6"
                fi
            done
        fi
    done < "$CONFIG_FILE"
}

# Function to save rules
function save_rules() {
    echo "Saving rules to $RULES_V4 and $RULES_V6..."
    sudo iptables-save > "$RULES_V4"
    sudo ip6tables-save > "$RULES_V6"
    echo "Rules saved."
}

# Function to load rules
function load_rules() {
    echo "Loading rules from $RULES_V4 and $RULES_V6..."
    sudo iptables-restore < "$RULES_V4"
    sudo ip6tables-restore < "$RULES_V6"
    echo "Rules loaded."
}

# Function to list current rules
function list_rules() {
    echo "Listing current IPv4 rules:"
    sudo iptables -L
    echo ""
    echo "Listing current IPv6 rules:"
    sudo ip6tables -L
}

# Function to reset rules to default (accept all)
function reset_rules() {
    echo "Resetting all rules to default (accept all)..."
    sudo iptables -F
    sudo ip6tables -F
    echo "All rules have been reset to default (accept all)."
}

# Check for command-line arguments
if [[ "$#" -eq 0 ]]; then
    display_help
    exit 1
fi

# Parse command-line arguments
case "$1" in
    -config)
        configure_rules
        ;;
    -save)
        save_rules
        ;;
    -load)
        load_rules
        ;;
    -list)
        list_rules
        ;;
    -reset)
        reset_rules
        ;;
    -help)
        display_help
        ;;
    *)
        echo "Invalid option: $1"
        display_help
        exit 1
        ;;
esac
