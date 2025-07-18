import pandas as pd
import csv
from collections import defaultdict

# Load the exported Palo Alto CSV
df = pd.read_csv('mock_paloalto_rules.csv')

# To store cleaned rules and report details
cleaned_rules = []
removal_report = []

# Helper to track seen (src, dst) pairs and redundant IPs
seen_src_dst = set()
redundant_ip_rules = defaultdict(list)

previous_rules = []
for idx, row in df.iterrows():
    src_ips = [ip.strip() for ip in str(row['Source Address']).split(',') if ip.strip()]
    dst_ips = [ip.strip() for ip in str(row['Destination Address']).split(',') if ip.strip()]
    src_set = set()
    dst_set = set()
    # Remove duplicate IPs within the same rule
    unique_src_ips = []
    for ip in src_ips:
        if ip not in src_set:
            unique_src_ips.append(ip)
            src_set.add(ip)
        else:
            redundant_ip_rules[row['Name']].append(f"Duplicate source IP {ip} in rule")
    unique_dst_ips = []
    for ip in dst_ips:
        if ip not in dst_set:
            unique_dst_ips.append(ip)
            dst_set.add(ip)
        else:
            redundant_ip_rules[row['Name']].append(f"Duplicate destination IP {ip} in rule")
    # Remove rules that are exact duplicates (same src/dst/app/action)
    rule_key = (tuple(sorted(unique_src_ips)), tuple(sorted(unique_dst_ips)), row['Application'], row['Action'])
    if rule_key in seen_src_dst:
        removal_report.append({
            'Rule Name': row['Name'],
            'Reason': 'Duplicate rule (same src/dst/app/action)'
        })
        continue
    seen_src_dst.add(rule_key)
    # If all IPs in a rule were duplicates, skip rule
    if not unique_src_ips or not unique_dst_ips:
        removal_report.append({
            'Rule Name': row['Name'],
            'Reason': 'All source or destination IPs were duplicates'
        })
        continue
    # If any redundant IPs, note in report
    if redundant_ip_rules[row['Name']]:
        removal_report.append({
            'Rule Name': row['Name'],
            'Reason': '; '.join(redundant_ip_rules[row['Name']])
        })
    # Shadowing detection: check if any previous rule shadows this one
    shadowed = False
    for prev in previous_rules:
        # Check if previous rule's src/dst/app/action/service are supersets or equal
        prev_src = set(prev['Source Address'].split(',')) if prev['Source Address'] else set()
        prev_dst = set(prev['Destination Address'].split(',')) if prev['Destination Address'] else set()
        # Application, Service, and Action must match or be 'any' in previous
        app_match = (prev['Application'] == row['Application']) or (prev['Application'] == 'any')
        svc_match = ('Service' in prev and ('Service' in row) and (prev['Service'] == row['Service'] or prev['Service'] == 'any'))
        act_match = prev['Action'] == row['Action']
        if (set(unique_src_ips).issubset(prev_src)
            and set(unique_dst_ips).issubset(prev_dst)
            and app_match and svc_match and act_match):
            removal_report.append({
                'Rule Name': row['Name'],
                'Reason': f'Shadowed by rule {prev["Name"]}'
            })
            shadowed = True
            break
    if shadowed:
        continue
    # Add cleaned rule and keep for future shadowing checks
    cleaned_rule = row.copy()
    cleaned_rule['Source Address'] = ','.join(unique_src_ips)
    cleaned_rule['Destination Address'] = ','.join(unique_dst_ips)
    cleaned_rules.append(cleaned_rule)
    previous_rules.append(cleaned_rule)

# Save cleaned rules
cleaned_df = pd.DataFrame(cleaned_rules)
cleaned_df.to_csv('cleaned_paloalto_rules.csv', index=False)

# Save removal report
with open('removal_report.csv', 'w', newline='') as f:
    writer = csv.DictWriter(f, fieldnames=['Rule Name', 'Reason'])
    writer.writeheader()
    for entry in removal_report:
        writer.writerow(entry)

print('Cleaning complete. Cleaned rules saved to cleaned_paloalto_rules.csv. Report saved to removal_report.csv.')
