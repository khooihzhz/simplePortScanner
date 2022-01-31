import socket # use to establish connection
import sys # access system variables
import argparse # library to make arguments easy
import re # part port range

# todo: make a banner for our port scanner
def banner():
    pass

def tcp_scan(host, ports):
    # ---- TCP SCAN ---- [X] Passed Test
    for port in ports: 
        tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try: 
            # Create a new socket
            tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # If port is open, add to list!
            if not tcp.connect_ex((host, port)):
                openPortList.append(str(port) + " " + str(socket.getservbyport(port, "tcp")))
                tcp.close() 
            else:
                closedPortList.append(port)
        except Exception:
            pass
    printPort('TCP')


def udp_scan(host, ports):
    # ---- UDP SCAN ---- [X] Passed Test
    for port in ports:
        # create socket
        try:
            udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) 
            
            # set timeout for packet
            timeout = 5
            udp.settimeout(timeout)
            udp.connect((host, port))
            udp.send(b'Sample UDP packet')
            data, addr = udp.recvfrom(1024)
            # add to open port list 
            #print( f"[+] UDP Port Open: {port} , {data} ")
            openPortList.append(str(port) + ", " + str(data))
        except TimeoutError:
            # uncertain
            #print(f"[+] UDP Port Open:{port} kinda no response or something") # might be open/closed
            uncertainPortList.append(port)
        except:
            # confirm close
            #print(f"[+] UDP Port Closed:{port}")
            closedPortList.append(port)
    printPort('UDP')
    


def parseNumList(string):
    # match string 1-65535
    m = re.match(r'(\d+)(?:-(\d+))?$', string)
    if not m:
        raise argparse.ArgumentTypeError("'" + string + "' is not a range of number. Expected forms like '0-65535' or '80'.")
    start = m.group(1)
    end = m.group(2) or start
    if int(start) > 65535 or int(end) > 65535: 
        # out of range
        raise argparse.ArgumentTypeError("'" + string + "' is out of range. Expected forms like '0-65535' or '80'.")

    return list(range(int(start,10), int(end,10)+1))

def printPort(mode):
    print(f"\nOpened ports in {mode}:\n{', '.join(openPortList)}")
    if (mode == 'UDP'):
        print(f"\nUncertain ports in {mode}:\n{', '.join(uncertainPortList)}")
        print(f"{len(uncertainPortList)} ports are uncertain whether it is opened or closed")
    print(f"{len(openPortList)} ports are opened")
    print(f"{len(closedPortList)} ports are closed\n")

    
if __name__ == '__main__':
    # arguments here
    parser = argparse.ArgumentParser(description='Port Scanner v1.0')
    parser.add_argument('-t', metavar="TARGET", type=str, help='target host')
    parser.add_argument('-p', default='0-65535', metavar="PORT", type=parseNumList, help='port, default(0-65535)')
    parser.add_argument('--mode',
                    default='tcp',
                    const='tcp',
                    nargs='?',
                    choices=['tcp', 'udp'],
                    help='choose tcp or udp (default: %(default)s)')

    args = parser.parse_args()
    host = args.t # target host
    ports = args.p # list of ports
    openPortList = []
    closedPortList = []
    uncertainPortList = []
    
    if args.mode == 'tcp':
        # run tcp scan
        tcp_scan(host, ports)
    else:
        # run udp scan
        udp_scan(host, ports)