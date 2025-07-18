
import pandas as pd
import random

def generate_ip(base, third_range, fourth_range):
    return f"{base}.{random.randint(0, third_range)}.{random.randint(1, fourth_range)}"

# Simulate a pool of IPs to allow for repeats
src_ip_pool = [generate_ip("192.168", 2, 254) for _ in range(50)]
dst_ip_pool = [generate_ip("10.0", 5, 254) for _ in range(80)]

columns = [
    "Name", "Description", "Tags", "Source Zone", "Destination Zone", "Source Address", "Destination Address",
    "Application", "Service", "Action", "Disabled", "Log Setting", "Hit Count"
]

rules = []
for rule_id in range(1, 121):
    num_src_ips = random.randint(1, 4)
    num_dst_ips = random.randint(1, 5)
    src_ips = random.sample(src_ip_pool, num_src_ips)
    dst_ips = random.sample(dst_ip_pool, num_dst_ips)
    # Intentionally add some repeated IPs within the same rule
    if random.random() < 0.2:
        src_ips += [random.choice(src_ips)]
    if random.random() < 0.2:
        dst_ips += [random.choice(dst_ips)]
    rule = {
        "Name": f"Rule_{rule_id}",
        "Description": f"Auto-generated rule {rule_id}",
        "Tags": random.choice(["", "prod", "test", "web"]),
        "Source Zone": random.choice(["trust", "untrust", "dmz"]),
        "Destination Zone": random.choice(["trust", "untrust", "dmz"]),
        "Source Address": ",".join(src_ips),
        "Destination Address": ",".join(dst_ips),
        "Application": random.choice(["web-browsing", "ssl", "dns", "any"]),
        "Service": random.choice(["application-default", "any", "tcp/80", "tcp/443"]),
        "Action": random.choice(["allow", "deny"]),
        "Disabled": random.choice(["yes", "no"]),
        "Log Setting": random.choice(["", "log-forwarding-profile"]),
        "Hit Count": random.randint(10, 10000)
    }
    rules.append(rule)

df = pd.DataFrame(rules, columns=columns)
csv_path = "mock_paloalto_rules.csv"
df.to_csv(csv_path, index=False)
print(f"Mock Palo Alto Firewall rules exported to {csv_path}")