#!/bin/bash
CONFIG_FILE="config.txt"
RULES_V4="rulesV4"
RULES_V6="rulesV6"

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

#We check for valid ips by checking their structures and the characters
#they contain. Ipv4s are simpler than ipv6s so more characters are used.
#These functions are needed during configuration.
function is_valid_ipv4() {
    local ip=$1
    if [[ $ip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        return 0
    else
        return 1
    fi
}

function is_valid_ipv6() {
    local ip=$1
    if [[ $ip =~ ^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$ ]]; then
        return 0
    else
        return 1
    fi
}

#We read all domains in the config.txt and using iptables commands we reject them
#both ipv4s and ipv6s using the corresponding iptables/ip6tables commands.
#This is one of the slower parts.
function configure_rules() {
    echo "Configuring rules based on $CONFIG_FILE..."
    while read -r domain; do
        if [[ -n "$domain" ]]; then
            echo "Blocking domain: $domain"
            
            for ip in $(dig +short A "$domain"); do
                if is_valid_ipv4 "$ip"; then
                    echo "Blocking IPv4: $ip"
                    sudo iptables -A INPUT -s "$ip" -j REJECT
                else
                    echo "Invalid IPv4 address or error for domain $domain: $ip"
                fi
            done

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

#the functions below are self-explenatory
#they use the iptables/ip6tables to handle 
#-save, -load, -list, -reset
function save_rules() {
    echo "Saving rules to $RULES_V4 and $RULES_V6..."
    sudo iptables-save > "$RULES_V4"
    sudo ip6tables-save > "$RULES_V6"
    echo "Rules saved."
}

function load_rules() {
    echo "Loading rules from $RULES_V4 and $RULES_V6..."
    sudo iptables-restore < "$RULES_V4"
    sudo ip6tables-restore < "$RULES_V6"
    echo "Rules loaded."
}

#One of the slower parts as well
function list_rules() {
    echo "Listing current IPv4 rules:"
    sudo iptables -L
    echo ""
    echo "Listing current IPv6 rules:"
    sudo ip6tables -L
}

function reset_rules() {
    echo "Resetting all rules to default (accept all)..."
    sudo iptables -F
    sudo ip6tables -F
    echo "All rules have been reset to default (accept all)."
}

if [[ "$#" -eq 0 ]]; then
    display_help
    exit 1
fi

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
