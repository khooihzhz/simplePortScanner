import argparse, random, socket, sys

MAX_BYTES = 65535
# file to run udp server
def server(interface, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((interface, port))
    print('Listening at', sock.getsockname())
    while True:
        data, address = sock.recvfrom(MAX_BYTES)
        print(f'server: {data}')
        sock.sendto(b"UDP Response", address)


if __name__ == '__main__':
    server('<attack_machine_ip>', 1060)
