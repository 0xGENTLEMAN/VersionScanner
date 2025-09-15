import socket
import argparse
import threading
import queue
import sys


def print_banner():
    banner = """
888888ba                                        
88    `8b                                       
88     88 dP    dP 88d8b.d8b. .d8888b. 88d888b. 
88     88 88    88 88'`88'`88 88'  `88 88'  `88 
88    .8P 88.  .88 88  88  88 88.  .88 88    88 
8888888P  `88888P' dP  dP  dP `88888P8 dP    dP 
oooooooooooooooooooooooooooooooooooooooooooooooo                                         
    """
    print(banner)

# -----------------------
# Configuration
# -----------------------
MAX_THREADS = 100
TIMEOUT = 1  # seconds

# Queue to hold ports for threading
port_queue = queue.Queue()
open_ports = []

# Lock for printing
print_lock = threading.Lock()

# Common service banners to identify version
SERVICE_BANNERS = {
    21: 'FTP',
    22: 'SSH',
    23: 'Telnet',
    25: 'SMTP',
    53: 'DNS',
    80: 'HTTP',
    110: 'POP3',
    143: 'IMAP',
    443: 'HTTPS',
    3306: 'MySQL',
    3389: 'RDP',
    5900: 'VNC',
}


# -----------------------
# Function to get banner
# -----------------------
def get_banner(sock):
    try:
        sock.settimeout(TIMEOUT)
        banner = sock.recv(1024)
        return banner.decode(errors='ignore').strip()
    except:
        return ""


# -----------------------
# Worker function for threading
# -----------------------
def scan_port(target, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        result = sock.connect_ex((target, port))
        if result == 0:
            banner = get_banner(sock)
            service_name = SERVICE_BANNERS.get(port, "Unknown Service")
            if banner:
                version_info = f"{service_name} - {banner}"
            else:
                version_info = service_name
            with print_lock:
                print(f"Port {port}: Open - {version_info}")
            open_ports.append((port, version_info))
        sock.close()
    except Exception as e:
        pass


# -----------------------
# Main function
# -----------------------
def main():
    print_banner()
    parser = argparse.ArgumentParser(description="Scan all ports and detect service versions.")
    parser.add_argument("--target", required=True, help="Target IP address or hostname")
    args = parser.parse_args()

    target = args.target

    try:
        ip = socket.gethostbyname(target)
        print(f"Starting scan on {target} ({ip})\n")
    except socket.gaierror:
        print("Invalid host")
        sys.exit()

    # Fill the queue with ports
    for port in range(1, 1025):  # First 1024 ports (can extend to 65535)
        port_queue.put(port)

    # Start threads
    threads = []
    for _ in range(MAX_THREADS):
        t = threading.Thread(target=worker, args=(target,))
        t.daemon = True
        t.start()
        threads.append(t)

    # Wait for queue to finish
    port_queue.join()
    print("\nScan completed.")


# -----------------------
# Thread worker wrapper
# -----------------------
def worker(target):
    while not port_queue.empty():
        port = port_queue.get()
        scan_port(target, port)
        port_queue.task_done()


if __name__ == "__main__":
    main()
