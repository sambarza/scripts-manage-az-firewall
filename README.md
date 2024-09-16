This script can be used check the status, open and close azure sql server firewall rules

Configuration:
- create a `config.json` file with the list of sql server to manage, look to the `config-example.json` file as example

Instruction:
- `az login` (if not logged in Azure)
- `python az-firewall.py -h` to show the commands

Example:
Status for firewall rule ´rule_name´: `python az-firewall.py -n rule_name status`
Open for firewall with rule ´rule_name´: `python az-firewall.py -n rule_name open`
Close for firewall with rule ´rule_name´: `python az-firewall.py -n rule_name close`
