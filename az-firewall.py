#!python3
import asyncio
import json
import sys
import argparse


class SqlServerInfo:

    def __init__(self, sql_server_info) -> None:
        self.subscription = sql_server_info["subscription"]
        self.resource_group = sql_server_info["resource_group"]
        self.sql_server_name = sql_server_info["sql_server_name"]


async def get_public_id():

    cmd = "curl ipinfo.io -s"

    get_ip_process = await asyncio.create_subprocess_shell(
        cmd=cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )

    print(f"Starting to retrieve the current public ip address...", end=" ")
    stdout, stderr = await get_ip_process.communicate()

    if get_ip_process.returncode == 0:
        ip_address = json.loads(stdout.decode())["ip"]
        print(f"{ip_address}\n")
        return ip_address
    else:
        print(f"cannot get the public is address:")
        print(f"{stderr.decode()}")

        sys.exit(4)


def read_config_file(config_filename):

    config_file = open(config_filename, "r")
    return json.loads(config_file.read())


async def open_firewall(
    firewall_rule_name: str, ip_address: str, sql_server_info: SqlServerInfo
):

    cmd = f"""az sql server firewall-rule create \
                --subscription '{sql_server_info.subscription}' \
                --resource-group '{sql_server_info.resource_group}' \
                --server '{sql_server_info.sql_server_name}' \
                --name '{firewall_rule_name}' \
                --start-ip-address '{ip_address}' \
                --end-ip-address '{ip_address}'"""

    open_firewall_process = await asyncio.create_subprocess_shell(
        cmd=cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )

    print(f"Starting opening firewall for server {sql_server_info.sql_server_name}")
    stdout, stderr = await open_firewall_process.communicate()

    if open_firewall_process.returncode == 0:
        print(
            f"...Firewall for server {sql_server_info.sql_server_name} now is open with name {firewall_rule_name}"
        )
    else:
        print(f"Error opening firewall for server {sql_server_info.sql_server_name}:")
        print(f"{stderr.decode()}")

    return open_firewall_process.returncode, stdout, stderr


async def close_firewall(
    firewall_rule_name: str, ip_address: str, sql_server_info: SqlServerInfo
):

    cmd = f"""az sql server firewall-rule delete \
                --subscription '{sql_server_info.subscription}' \
                --resource-group '{sql_server_info.resource_group}' \
                --server '{sql_server_info.sql_server_name}' \
                --name '{firewall_rule_name}'"""

    close_firewall_process = await asyncio.create_subprocess_shell(
        cmd=cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )

    print(f"Starting closing firewall for server {sql_server_info.sql_server_name}")
    stdout, stderr = await close_firewall_process.communicate()

    if close_firewall_process.returncode == 0:
        print(f"...Firewall for server {sql_server_info.sql_server_name} now is closed")
    else:
        print(f"Error closing firewall for server {sql_server_info.sql_server_name}:")
        print(f"{stderr.decode()}")

    return close_firewall_process.returncode, stdout, stderr


def get_rules_for_ip_or_name(firewall_rules, ip_address, firewall_rule_name):

    firewall_rules_for_ip = []

    for firewall_rule in firewall_rules:
        if firewall_rule["startIpAddress"] == ip_address:
            firewall_rules_for_ip.append(firewall_rule)
            continue

        if firewall_rule["name"] == firewall_rule_name:
            firewall_rules_for_ip.append(firewall_rule)
            continue

    return firewall_rules_for_ip


async def firewall_status(
    firewall_rule_name: str, ip_address: str, sql_server_info: SqlServerInfo
):

    cmd = f"""az sql server firewall-rule list \
                --subscription '{sql_server_info.subscription}' \
                --resource-group '{sql_server_info.resource_group}' \
                --server '{sql_server_info.sql_server_name}'"""

    firewall_list_process = await asyncio.create_subprocess_shell(
        cmd=cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )

    print(f"Checking firewall status for server {sql_server_info.sql_server_name}")
    stdout, stderr = await firewall_list_process.communicate()

    if firewall_list_process.returncode == 0:
        firewall_rules = json.loads(stdout.decode())

        firewall_rules_for_ip = get_rules_for_ip_or_name(
            firewall_rules=firewall_rules,
            ip_address=ip_address,
            firewall_rule_name=firewall_rule_name,
        )

        if firewall_rules_for_ip:
            for firewall_rule_for_ip in firewall_rules_for_ip:
                print(
                    f"...Firewall for server {sql_server_info.sql_server_name} is open with name {firewall_rule_for_ip['name']} for ip {firewall_rule_for_ip['startIpAddress']}"
                )
        else:
            print(f"...Firewall for server {sql_server_info.sql_server_name} is closed")
    else:
        print(
            f"Error checking the firewall status for server {sql_server_info.sql_server_name}:"
        )
        print(f"{stderr.decode()}")

    return firewall_list_process.returncode, stdout, stderr


async def command_open_firewall(config, firewall_rule_name, ip_address):

    tasks = []

    for sql_server_info in config["server_list"]:
        tasks.append(
            open_firewall(
                firewall_rule_name=firewall_rule_name,
                ip_address=ip_address,
                sql_server_info=SqlServerInfo(sql_server_info),
            )
        )

    await asyncio.gather(*tasks)


async def command_close_firewall(config, firewall_rule_name, ip_address):

    tasks = []

    for sql_server_info in config["server_list"]:
        tasks.append(
            close_firewall(
                firewall_rule_name=firewall_rule_name,
                ip_address=ip_address,
                sql_server_info=SqlServerInfo(sql_server_info),
            )
        )

    await asyncio.gather(*tasks)


async def command_firewall_status(config, firewall_rule_name, ip_address):

    tasks = []

    for sql_server_info in config["server_list"]:
        tasks.append(
            firewall_status(
                firewall_rule_name=firewall_rule_name,
                ip_address=ip_address,
                sql_server_info=SqlServerInfo(sql_server_info),
            )
        )

    await asyncio.gather(*tasks)


async def main():

    parser = argparse.ArgumentParser(
        description=f"""Manage firewall settings. Server list is read from config file"""
    )
    parser.add_argument(
        "-n",
        "--name",
        required=True,
        type=str,
        help="Name of the firewall rule to add/remove",
    )

    parser.add_argument(
        "-c",
        "--config_filename",
        type=str,
        help="Filename of the config file (see config-example.json for example)",
        default="config.json",
    )

    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # Subcommand 'open'
    parser_open = subparsers.add_parser("open", help="Add firewall rule")
    parser_open.set_defaults(func=command_open_firewall)

    # Subcommand 'close'
    parser_close = subparsers.add_parser("close", help="Remove a firewall rule")
    parser_close.set_defaults(func=command_close_firewall)

    # Subcommand 'status'
    parser_close = subparsers.add_parser("status", help="Check the firewall status")
    parser_close.set_defaults(func=command_firewall_status)

    args = parser.parse_args()

    if args.command:
        ip_address = await get_public_id()
        config = read_config_file(args.config_filename)

        await args.func(config, args.name, ip_address)
    else:
        parser.print_help()


asyncio.run(main())
