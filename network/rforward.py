import getpass
import sys
import socket
import select
import threading
import paramiko
import argparse


def verbose(s):
    print("[*] " + s)


def handler(chan, host, port):
    sock = socket.socket()
    try:
        sock.connect((host, port))
    except Exception as e:
        verbose(f"Forwarding request to {host}:{port} failed: {e}")
        return

    verbose(f"Connected! Tunnel open {chan.origin_addr} -> {host}:{port}")
    while True:
        r, w, x = select.select([sock, chan], [], [])
        if sock in r:
            data = sock.recv(1024)
            if not data:
                break
            chan.send(data)
        if chan in r:
            data = chan.recv(1024)
            if not data:
                break
            sock.send(data)
    chan.close()
    sock.close()
    verbose(f"Tunnel closed from {chan.origin_addr}")


def reverse_forward_tunnel(server_port, remote_host, remote_port, transport):
    transport.request_port_forward("", server_port)
    while True:
        chan = transport.accept(1000)
        if chan is None:
            continue
        thr = threading.Thread(target=handler, args=(chan, remote_host, remote_port))
        thr.setDaemon(True)
        thr.start()


def parse_options():
    parser = argparse.ArgumentParser(description="Reverse SSH Tunnel with Paramiko")
    parser.add_argument("ssh_host", help="SSH server hostname/IP")
    parser.add_argument("ssh_port", type=int, help="SSH server port")
    parser.add_argument("username", help="SSH username")
    parser.add_argument("remote_host", help="Local host to expose (ex: localhost)")
    parser.add_argument("remote_port", type=int, help="Port local à exposer (ex: 22)")
    parser.add_argument("remote_bind_port", type=int, help="Port à ouvrir sur le serveur")
    parser.add_argument("--keyfile", help="Chemin vers la clé privée")
    parser.add_argument("--readpass", action="store_true", help="Demander le mot de passe")
    return parser.parse_args()


def main():
    options = parse_options()
    password = None

    if options.readpass:
        password = getpass.getpass("Enter SSH password: ")

    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.WarningPolicy())

    verbose(f"Connecting to SSH host {options.ssh_host}:{options.ssh_port}")
    try:
        client.connect(
            options.ssh_host,
            port=options.ssh_port,
            username=options.username,
            key_filename=options.keyfile,
            look_for_keys=True,
            password=password
        )
    except Exception as e:
        print(f"[!] Failed to connect: {e}")
        sys.exit(1)

    verbose(f"Forwarding remote port {options.remote_bind_port} to {options.remote_host}:{options.remote_port}")
    try:
        reverse_forward_tunnel(
            options.remote_bind_port,
            options.remote_host,
            options.remote_port,
            client.get_transport()
        )
    except KeyboardInterrupt:
        print("\n[!] Canceled by user.")
        sys.exit(0)


if __name__ == '__main__':
    main()
