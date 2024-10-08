from scapy.all import *
import os

# Define the live pcap file path
pcap_file = os.path.expanduser('C:\\Users\\hailey\\pcap_files\\live_traffic.pcap')

# Load the pcap file
packets = rdpcap(pcap_file)

# Define the whitelist set
whitelist = set([
    "google.com",
    "microsoft.com",
    "amazon.com",
    "facebook.com",
    "apple.com",
    "twitter.com",
    "linkedin.com",
    "cloudflare.com",
    "github.com",
    "youtube.com",
    "wikipedia.org",
    "bing.com",
    "yahoo.com",
    "baidu.com",
    "reddit.com",
    "netflix.com",
    "spotify.com",
    "whatsapp.com",
    "paypal.com",
    "dropbox.com",
    "zoom.us",
    "slack.com",
    "salesforce.com",
    "adobe.com",
    "ibm.com",
    "oracle.com",
    "intel.com",
    "nvidia.com",
    "skype.com",
    "shopify.com",
    "mailchimp.com"
])

# Define domain categories
domain_categories = {
    "malicious": [
        "malicioussite.com",
        "badsite.com",
        "phishingsite.net",
        "ransomwareattack.com",
        "trojandownload.com",
        "malwaredistribution.net",
        "evilsite.org",
        "hackedwebsite.xyz",
        "keyloggerdownload.com",
        "botnetcontrolserver.com"
    ],
    "suspicious": [
        "unknownsite.org",
        "randomsite.xyz",
        "unverifiedsource.com",
        "suspiciousdomain.info",
        "dodgywebsite.net",
        "untrustedcontent.net",
        "freedownloads.com",
        "suspiciousdownloads.xyz",
        "unfamiliarwebsite.biz",
        "uncertainorigin.org"
    ],
    "tracker": [
        "adtracker.com",
        "analytics.site",
        "trackingpixel.net",
        "behavioralads.org",
        "advertisingnetwork.com",
        "adservice.google.com",
        "trackuserbehavior.com",
        "onlineanalytics.net",
        "useractivitytracker.xyz",
        "webtracker.org"
    ]
}

# Function to check if a query name is suspicious
def is_suspicious_query(query_name):
    if query_name in whitelist:
        return False, "Whitelisted domain"
    
    for category, domains in domain_categories.items():
        if any(domain in query_name for domain in domains):
            return True, f"{category.capitalize()} domain"

    if len(query_name) > 50:
        return True, "Long query name"
    if query_name.count('.') > 5:
        return True, "Too many dots in query name"
    
    return False, ""

# Analyze the packets
suspicious_queries = []
domain_frequency = {}

# TCP anomaly counters
out_of_order_segments = 0
retransmissions = 0
connection_resets = 0
duplicate_acks = 0

for packet in packets:
    if packet.haslayer(DNS):
        dns_layer = packet[DNS]
        if dns_layer.qr == 0:  # DNS query
            query_name = dns_layer.qd.qname.decode()
            query_length = len(query_name)
            query_type = dns_layer.qd.qtype
            is_suspicious, reason = is_suspicious_query(query_name)
            if is_suspicious:
                suspicious_queries.append({
                    "query_name": query_name,
                    "query_length": query_length,
                    "query_type": query_type,
                    "reason": reason
                })
            if query_type not in [1, 28]:
                suspicious_queries.append({
                    "query_name": query_name,
                    "query_length": query_length,
                    "query_type": query_type,
                    "reason": "Unusual query type"
                })
            
            # Update domain frequency
            domain = '.'.join(query_name.split('.')[-2:])
            domain_frequency[domain] = domain_frequency.get(domain, 0) + 1
            if domain_frequency[domain] > 10:
                suspicious_queries.append({
                    "query_name": query_name,
                    "query_length": query_length,
                    "query_type": query_type,
                    "reason": f"Frequent requests to domain '{domain}'"
                })

    if packet.haslayer(TCP):
        tcp_layer = packet[TCP]
        if tcp_layer.flags & 0x04:  # RST flag
            connection_resets += 1
        if packet.haslayer(Raw):
            payload = packet[Raw].load
            if b"out-of-order" in payload:
                out_of_order_segments += 1
            if b"retransmission" in payload:
                retransmissions += 1
            if b"Duplicate ACK" in payload:
                duplicate_acks += 1

# Print the results
if suspicious_queries:
    print("Suspicious DNS queries found:")
    for query in suspicious_queries:
        print(f"Query: {query['query_name']} (Length: {query['query_length']}, Type: {query['query_type']}) - Reason: {query['reason']}")
else:
    print("No suspicious DNS queries found.")

print(f"TCP Anomalies Detected:\nOut-of-Order Segments: {out_of_order_segments}\nRetransmissions: {retransmissions}\nConnection Resets: {connection_resets}\nDuplicate ACKs: {duplicate_acks}")
