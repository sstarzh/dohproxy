import socket
import threading
import dnslib
import requests
import sys

try:
    url = sys.argv[1]
    tenant_id = sys.argv[2]
except:
    print("Please provide a valid URL of DoH server and tenant ID")
    sys.exit()

server_socket = None

def dns_request_handler(data, client_address):
    try:
        # Parse the DNS request using dnslib
        dns_request = dnslib.DNSRecord.parse(data)
        #print(dns_request)
        # Prepare the DNS query in DNS wire format
        dns_query = {
            "questions": [
                {
                    "name": str(dns_request.questions[0].qname),
                    "type": dns_request.questions[0].qtype,
                }
            ],
            "type": 0,  # Regular query
        }
        domain = str(dns_request.questions[0].qname)
        if domain.endswith("."):
            domain = domain[:-1]
        # Convert the DNS query to JSON and send it via DoH POST request
        #doh_server_url = "https://cloudflare-dns.com/dns-query" + "?name=" + domain # Replace with your desired DoH server URL
        doh_server_url = url + "?name=" + domain
        headers = {'Content-Type': 'application/dns-json','x-ns-ext-tenant-id': tenant_id}
        #headers = {'Content-Type': 'application/dns-json'}
        #response = requests.get(doh_server_url, headers=headers)
        response = requests.post(doh_server_url, json=dns_query, headers=headers)
        # Extract the response from the DoH server
        doh_response = response.json()
        doh_name = doh_response.get('Question', [])[0].get('name', [])
        doh_type = doh_response.get('Question', [])[0].get('type', [])
        if doh_type == 1:
            doh_type = "A"
        elif doh_type == 28:
            doh_type = "AAAA"
        else:
            doh_type = "TXT"
        doh_data = doh_response.get('Answer', [])[0].get('data', [])
        doh_ttl = doh_response.get('Answer', [])[0].get('TTL', [])
        print("Name:" + str(doh_name))
        print("Type:" + str(doh_type))
        print("TTL:" + str(doh_ttl))
        print("Data:" + str(doh_data))

        # Prepare the DNS response
        dns_response = dnslib.DNSRecord(dnslib.DNSHeader(id=dns_request.header.id, qr=1, aa=1, ra=1), q=dns_request.q)
        #dns_response.add_answer(dnslib.RR.fromZone(f"{doh_name} {doh_ttl} {doh_type} {doh_data}"))
        if doh_type == "A":
            dns_response.add_answer(dnslib.RR(f"{doh_name}", dnslib.QTYPE.A, rdata=dnslib.A(doh_data), ttl=doh_ttl))
        elif doh_type == "AAAA":
            dns_response.add_answer(dnslib.RR(f"{doh_name}", dnslib.QTYPE.AAAA, rdata=dnslib.AAAA(doh_data), ttl=doh_ttl))
        else:
            dns_response.add_answer(dnslib.RR(f"{doh_name}", dnslib.QTYPE.TXT, rdata=dnslib.TXT(doh_data), ttl=doh_ttl))
        #dns_response.add_answer(dnslib.RR("{doh_name}",
        #print(dns_response)
        # Send the DNS response back to the client
        server_socket.sendto(dns_response.pack(), client_address)

    except Exception as e:
        print(f"Error occurred while processing DNS request: {e}")

def dns_server():
    # Create a UDP socket to listen for DNS requests
    global server_socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind(("0.0.0.0", 8053))

    print("DNS server is running on UDP port 8053...")

    while True:
        data, client_address = server_socket.recvfrom(4096)
        dns_thread = threading.Thread(target=dns_request_handler, args=(data, client_address))
        dns_thread.start()

if __name__ == "__main__":
    dns_server()

