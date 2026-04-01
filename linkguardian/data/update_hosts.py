import requests

files = {
    "hosts.txt": requests.get("https://github.com/StevenBlack/hosts/raw/refs/heads/master/hosts"),
    "tif.txt": requests.get("https://github.com/hagezi/dns-blocklists/raw/refs/heads/main/hosts/tif.txt"),
    "ultimate.txt": requests.get("https://github.com/hagezi/dns-blocklists/raw/refs/heads/main/hosts/ultimate.txt")
}

for i, j in files.items():
    with open(i, mode="wb") as file:
        file.write(j.content)
