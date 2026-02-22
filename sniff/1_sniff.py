import socket
import os

# Host to listen on (change to your machine's IP address)
HOST = '192.168.1.203'

def main():
    # Detect operating system
    if os.name == 'nt':  # Windows
        socket_protocol = socket.IPPROTO_IP
    else:  # Linux/Unix
        socket_protocol = socket.IPPROTO_ICMP

    # 1. Create a raw socket and bind it to the public interface
    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
    sniffer.bind((HOST, 0))

    # 2. Include the IP headers in the capture
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    # 3. If on Windows, turn on promiscuous mode
    if os.name == 'nt':
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    # 4. Read a single packet
    print(sniffer.recvfrom(65565))

    # 5. If on Windows, turn off promiscuous mode
    if os.name == 'nt':
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)

if __name__ == '__main__':
    main()
