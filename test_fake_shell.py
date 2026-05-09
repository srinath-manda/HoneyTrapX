import socket
import sys
import time

HOST = '127.0.0.1'
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 22  # 22=SSH, 23=Telnet

# Set to None to make it fully interactive: you type commands.
# Set to a list (['ls','whoami',...]) for automatic command sending.
COMMANDS = None


def recv_all(sock, timeout=2.0):
    sock.settimeout(timeout)
    data = b''
    while True:
        try:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk

            # stop if we likely have a shell prompt/banners
            if (
                data.endswith(b'# ')
                or data.endswith(b'$ ')
                or data.endswith(b'login: ')
                or b'Username:' in data
                or b'Password:' in data
                or data.endswith(b'\r\n$ ')
                or data.endswith(b'\n$ ')
            ):
                break
        except Exception:
            break
    return data


def main():
    print(f'[*] Connecting to {HOST}:{PORT}')

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect((HOST, PORT))

    time.sleep(0.2)
    banner = recv_all(s)
    if banner:
        print(banner.decode(errors='ignore'), end='' if banner.endswith(b'\n') else '\n')

    # Honeypot expects:
    # 1) initial input (ignored by honeypot logic, but it recv()s it)
    # 2) Username:
    # 3) Password:
    # Match the honeypot admin/admin gate.
    s.sendall(b'admin\r\n')
    out = recv_all(s)
    if out:
        print(out.decode(errors='ignore'), end='' if out.endswith(b'\n') else '\n')

    s.sendall(b'admin\r\n')
    out = recv_all(s)
    if out:
        print(out.decode(errors='ignore'), end='' if out.endswith(b'\n') else '\n')

    s.sendall(b'admin\r\n')
    out = recv_all(s)
    if out:
        print(out.decode(errors='ignore'), end='' if out.endswith(b'\n') else '\n')

    if COMMANDS is None:
        # Manual mode: behave like a remote shell.
        try:
            while True:
                cmd = input('$ ')
                if not cmd:
                    continue

                s.sendall(cmd.encode() + b'\n')
                out = recv_all(s, timeout=2.5)
                if out:
                    print(out.decode(errors='ignore'), end='' if out.endswith(b'\n') else '\n')

                if cmd.strip().lower() in {'exit', 'quit'}:
                    break
        except (KeyboardInterrupt, EOFError):
            pass
    else:
        # Automatic mode: send a predefined set of commands.
        for cmd in COMMANDS:
            print(f'\n[*] Sending command: {cmd}')
            s.sendall(cmd.encode() + b'\n')
            out = recv_all(s, timeout=2.5)
            if out:
                print(out.decode(errors='ignore'), end='' if out.endswith(b'\n') else '\n')
            time.sleep(0.2)

    s.close()


if __name__ == '__main__':
    main()