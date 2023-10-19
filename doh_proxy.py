import socket
import threading
import dnslib
import requests
import sys
import requests.adapters


try:
    url = sys.argv[1]
    service_key = sys.argv[2]
except:
    print("Please provide a valid URL of DoH server and DoH service key")
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
        #doh_server_url = url + "/?authorization=" + service_key
        session = requests.Session()
        adapter = requests.adapters.HTTPAdapter(pool_connections=20, pool_maxsize=20)
        session.mount('https://', adapter)
        doh_server_url = url
        headers = {'Content-Type': 'application/dns-message', 'Authorization': 'Bearer '+ service_key}
        response = session.post(doh_server_url, data=data, headers=headers)
        req = response.request
        parsed_req = dnslib.DNSRecord.parse(bytes(req.body))
        print('{}\n{}\r\n{}\r\n\r\n{}'.format(
        '-----------REQUEST-----------',
        req.method + ' ' + req.url,
        '\r\n'.join('{}: {}'.format(k, v) for k, v in req.headers.items()),
        str(dnslib.DNSRecord.parse(bytes(req.body))),
        ))
        print('{}\n{}\r\n{}\r\n\r\n{}'.format(
        '-----------RESPONSE-----------',
        str(response.status_code) + ' ' + response.reason,
        '\r\n'.join('{}: {}'.format(k, v) for k, v in response.headers.items()),
        str(dnslib.DNSRecord.parse(bytes(response.content))),
        ))
        # Extract the response from the DoH server
        doh_response = dnslib.DNSRecord.parse(bytes(response.content))
        doh_response.header.ra = 1
        doh_response.header.rd = parsed_req.header.rd
        doh_response.questions = parsed_req.questions
        print("Response: " + str(doh_response))
        
        # Send the DNS response back to the client
        server_socket.sendto(doh_response.pack(), client_address)

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

