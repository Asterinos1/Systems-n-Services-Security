#!/bin/bash

CONFIG_FILE="config.txt"
RULES_V4="rulesV4"
RULES_V6="rulesV6"

# Function to configure adblock rules based on config.txt
config_rules() {
    # Check if config.txt exists
    if [[ ! -f "$CONFIG_FILE" ]]; then
        echo "Error: config.txt file not found."
        exit 1
    fi

    # Flush existing rules
    sudo iptables -F
    sudo ip6tables -F

    # Read each line from config.txt
    while IFS= read -r line || [[ -n "$line" ]]; do
        if [[ "$line" =~ ^#.*$ ]] || [[ -z "$line" ]]; then
            continue  # Ignore comments and empty lines
        fi
        
        # Resolve domain names to IPv4 and IPv6 addresses
        ipv4=$(dig +short A "$line")
        ipv6=$(dig +short AAAA "$line")
        
        # Add iptables rules for IPv4 addresses
        for ip in $ipv4; do
            if [[ -n "$ip" ]]; then  # Only add if the IPv4 address is valid
                sudo iptables -A INPUT -s "$ip" -j REJECT
            fi
        done

        # Add ip6tables rules for IPv6 addresses
        for ip in $ipv6; do
            if [[ -n "$ip" ]]; then  # Only add if the IPv6 address is valid
                sudo ip6tables -A INPUT -s "$ip" -j REJECT
            fi
        done

    done < "$CONFIG_FILE"

    echo "Adblock rules configured successfully."
}


# Function to save the current rules to files
save_rules() {
    sudo iptables-save > "$RULES_V4"
    sudo ip6tables-save > "$RULES_V6"
    echo "Rules saved to $RULES_V4 and $RULES_V6."
}

# Function to load the rules from files
load_rules() {
    if [[ -f "$RULES_V4" && -f "$RULES_V6" ]]; then
        sudo iptables-restore < "$RULES_V4"
        sudo ip6tables-restore < "$RULES_V6"
        echo "Rules loaded from $RULES_V4 and $RULES_V6."
    else
        echo "Error: Rule files not found."
        exit 1
    fi
}

# Function to reset all rules (default accept all)
reset_rules() {
    sudo iptables -F
    sudo ip6tables -F
    echo "Firewall rules reset to default (accept all)."
}

# Function to list all current rules
list_rules() {
    echo "IPv4 Rules:"
    sudo iptables -L
    echo "IPv6 Rules:"
    sudo ip6tables -L
}

# Function to display help
show_help() {
    echo "Usage: $0 [OPTION]"
    echo "Options:"
    echo "  -config     Configure adblock rules from config.txt"
    echo "  -save       Save current firewall rules to rulesV4 and rulesV6"
    echo "  -load       Load firewall rules from rulesV4 and rulesV6"
    echo "  -list       List current firewall rules"
    echo "  -reset      Reset firewall rules to default (accept all)"
    echo "  -help       Display this help message"
}

# Main script execution
case "$1" in
    -config)
        config_rules
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
        show_help
        ;;
    *)
        echo "Invalid option. Use -help for usage information."
        exit 1
        ;;
esac
