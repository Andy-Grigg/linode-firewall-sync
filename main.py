import logging
from ipaddress import IPv4Address, IPv4Network
import os
from pathlib import Path

import requests
from linode_api4 import LinodeClient
import yaml

logger = logging.getLogger()
logger.setLevel(logging.INFO)

sh = logging.StreamHandler()
sh.setLevel(logging.DEBUG)
logger.addHandler(sh)

PAT = os.getenv("PAT")


def main():
    config = Config()
    public_ip = _get_public_ip()
    public_network = IPv4Network((public_ip, 32))
    fwup = FirewallUpdater(PAT, config)
    fwup.update_firewall_with_network(public_network)


def _get_public_ip() -> IPv4Address:
    response = requests.get("https://checkip.amazonaws.com").text.strip()
    logging.debug(f"Response received: '{response}'")
    public_ip = IPv4Address(response)
    logger.info(f"External IP address: {public_ip}")
    return public_ip


class FirewallUpdater:
    def __init__(self, pat: str, config: "Config") -> None:
        self._client = LinodeClient(
            pat,
            base_url="https://api.linode.com/v4beta",  # Required for Firewall API access
        )
        self._config = config

    def update_firewall_with_network(self, ip_network: IPv4Network) -> None:
        firewall = next(f for f in self._client.networking.firewalls() if f.label == self._config.firewall_name)
        rules = firewall.get_rules()
        rule_modified = False
        for rule in rules["inbound"]:
            if rule["label"] == self._config.rule_label:
                rule["addresses"]["ipv4"] = [str(ip_network)]
                rule_modified = True
        if not rule_modified:
            raise ValueError(f"No rule found with name '{self._config.rule_label}'")
        # firewall.update_rules(rules)
        logging.info("Successfully updated firewall")


class Config:
    def __init__(self):
        config_file = Path(__file__).parent / "config.yaml"
        with open(config_file, "r", encoding="utf-8") as f:
            config = yaml.load(f, yaml.Loader)
        self.firewall_name = config["firewall_name"]
        self.rule_label = config["rule_label"]


if __name__ == "__main__":
    main()
