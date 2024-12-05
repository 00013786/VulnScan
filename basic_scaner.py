import nmap

def scan_target(target):
    nm = nmap.PortScanner()

    try:
        print(f"Starting scan on target: {target}")
        nm.scan(hosts=target, arguments='-sC -sV --unprivileged -Pn -p- --min-rate=10000 ')  # Here you can enter the NMAP command to scan
        if not nm.all_hosts():
            print("No hosts found. Make sure the target is up and reachable.")
        for host in nm.all_hosts():
            print(f"\nHost: {host} ({nm[host].hostname()})")
            print(f"State: {nm[host].state()}")
            for proto in nm[host].all_protocols():
                print(f"\nProtocol: {proto}")
                lport = nm[host][proto].keys()
                for port in lport:
                    state = nm[host][proto][port]['state']
                    print(f"Port: {port}\tState: {state}")

    except Exception as e:
        print(f"An error occurred: {str(e)}")

if __name__ == "__main__":
    target_ip = input("Enter the target IP address to scan: ")
    scan_target(target_ip)
