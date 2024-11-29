from scapy.all import sniff
import threading
import platform
import getpass
import socket
import sys
import os

def banner():
    print('''
    __      ___    _ _         ___      _    _    _ _   
    \ \    / / |_ (_) |_ ___  | _ \__ _| |__| |__(_) |_ 
     \ \/\/ /| ' \| |  _/ -_) |   / _` | '_ \ '_ \ |  _| 
      \_/\_/ |_||_|_|\__\___| |_|_\__,_|_.__/_.__/_|\__| 
    
   "the quieter you become, the more you are able to hear"
    ''')

def clear():
    os.system('cls' if os.name == 'nt' else 'clear')

def set_title(title):
    if platform.system() == "Windows":
        os.system(f"title {title}")
    else:
        sys.stdout.write(f"\033]0;{title}\007")
        sys.stdout.flush()

def get_username():
    try:
        username = os.getlogin()
    except Exception:
        username = getpass.getuser()
    
    return username

def get_hostname():
    try:
        hostname = socket.gethostname()
    except:
        hostname = "Unknown"
    
    return hostname

def scan_ports(host):
    open_ports = []

    def scan_port(port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((host, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        except socket.error:
            pass

    threads = []
    for port in range(1, 65536):
        thread = threading.Thread(target=scan_port, args=(port,))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    return open_ports

def packet_callback(packet):
    print(packet.summary())

def packet_sniffer(filter_rule=""):
    sniff(filter=filter_rule, prn=packet_callback, store=False)

def main():
    clear()
    banner()
    set_title("White Rabbit by @batubyte")

    while True:
        try:
            command = input(f"[{get_username()}@{get_hostname()}]$ ")

            if command == "help":
                print("""
 Main
 - help, clear, exit
 - calculate <math>
 - shell <command>
 - execute <code>

 Tools
 - portscan <host>
 - packetsniff <rule(optional)>
""")
            elif command == "clear":
                clear()
            elif command.startswith("calculate "):
                expression = command.split(" ", 1)[1]
                result = eval(expression)
                print(f"Result: {result}")
            elif command.startswith("shell "):
                command = command.split(" ", 1)[1]
                os.system(command)
            elif command.startswith("execute "):
                code = command.split(" ", 1)[1]
                exec(code)
            elif command.startswith("portscan "):
                host = command.split(" ", 1)[1]
                ports = scan_ports(host)
                if ports:
                    print(f"Ports: {ports}")
            elif command.startswith("packetsniff"):
                parts = command.split(" ", 1)
                filter_rule = parts[1] if len(parts) > 1 else ""
                packet_sniffer(filter_rule)
            elif command == "exit":
                break
        except Exception as e:
            print(e)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit()
