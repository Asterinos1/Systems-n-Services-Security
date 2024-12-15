Security of Systems-n-Services (2024-2025)

Assignment06
Students: Asterinos Karalis 2020030107  - Zografoula Ioanna Neamonitaki 2020030088

!!! IMPORTANT !!!
You will need to use sudo for root privileges when running the script.
1) chmod +x firewall.sh
2) sudo ./firewall.sh -help
You can now use the firewall tool as you prefer:

Options:
  -config     Configure firewall rules from config.txt"
  -save       Save current firewall rules to rulesV4 and rulesV6"
  -load       Load firewall rules from rulesV4 and rulesV6"
  -list       List current firewall rules"
  -reset      Reset firewall rules to default (accept all)"
  -help       Display this help message"

!! Warning: the tool will take some time to configure and to list the rules !!

Example usage:

sudo ./firewall.sh -config
sudo ./firewall.sh -save
sudo ./firewall.sh -list

You can now attempt to access one of the domains inside the config.txt and the request
should get denied saying it's blocked by the firewall.
Currently the tool has a few issues regarding the blocking of certain domains in the config.txt using
iptables/ip6tables as they can't be resolved (main issue) and the other issue being that after have configured the firewall,
a few sites remain unblocked. 
