#!/usr/bin/env python3
"""
SSH honeypot module
here we implement an ssh honeypot using paramiko
"""
import socket
import threading
import time
from datetime import datetime
import paramiko
import paramiko.common
from colorama import Fore, Style

DEFAULT_BANNER = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"

# from paramiko
class SSHServer(paramiko.ServerInterface):
    def __init__(self, args, logger):
        self.args = args
        self.logger = logger
        self.event = threading.Event()
        self.auth_attempted = False
        self.auth_success = False  # Always False for honeypot

    def check_auth_password(self, username, password):
        self.logger.info(
            f"SSH Password attempt - IP: {self.client_ip}, "
            f"Username: '{username}', Password: '{password}'",
        )
        
        self.auth_attempted = True
        self.username = username
        
        # TEMPORARY SUCCESS to get shell
        return paramiko.AUTH_SUCCESSFUL  
    
    def check_auth_publickey(self, username, key):
        extra = {
            'ip': self.client_ip,
            'port': self.client_port,
            'username': username,
            'key_fingerprint': key.get_fingerprint().hex(),
        }
        
        self.logger.info(
            f"SSH Public key attempt - IP: {self.client_ip}, "
            f"Username: '{username}', Key: {extra['key_fingerprint']}",
            extra=extra
        )
        
        return paramiko.AUTH_FAILED
    
    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
    
    def get_allowed_auths(self, username):
        return "password"

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, 
                                    pixelheight, modes):
        return True

def handle_ssh_client(client_socket, client_address, args, logger, host_key):
    client_ip, client_port = client_address
    
    try:
        extra = {'ip': client_ip, 'port': client_port}
        logger.info(f"SSH Connection from {client_ip}:{client_port}", extra=extra)
        
        transport = paramiko.Transport(client_socket)
        transport.add_server_key(host_key)
        
        transport.local_version = DEFAULT_BANNER
        
        # create server
        server = SSHServer(args, logger)
        server.client_ip = client_ip
        server.client_port = client_port
        
        try:
            transport.start_server(server=server)

            channel = transport.accept(20)
            if channel is not None:
                channel.send("Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)\r\n\r\n")
                channel.send("Last login: Mon Jan  6 14:32:18 2025 from 192.168.1.100\r\n")
                channel.send("honeypot@ubuntu:~$ ")
                
                # wait for cmd but do not execute them
                server.event.wait(10)
                
                # fake res
                fake_responses = {
                    "ls": "Desktop  Documents  Downloads  Music  Pictures  Public  Templates  Videos",
                    "whoami": "honeypot",
                    "pwd": "/home/honeypot",
                    "id": "uid=1000(honeypot) gid=1000(honeypot) groups=1000(honeypot),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),120(lpadmin),132(lxd),133(sambashare)",
                    "uname -a": "Linux ubuntu 5.15.0-91-generic #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux",
                }
                
                # Keep session alive
                timeout = 60  # 1 minute timeout
                start_time = time.time()
                
                # Buffer for command input
                command_buffer = ""

                # read command character by character
                while time.time() - start_time < timeout:
                    if channel.recv_ready():
                        try:
                            data = channel.recv(1).decode('utf-8', errors='ignore')
                            
                            if not data:
                                break
                            
                            char = data
                            
                            # Handle Enter key (carriage return or newline)
                            if char in ['\r', '\n']:
                                command = command_buffer.strip()
                                command_buffer = ""
                                
                                # Echo newline
                                channel.send("\r\n")
                                
                                if command:
                                    logger.info(f"SSH Command received - IP: {client_ip}, Command: '{command}'",
                                                extra={'ip': client_ip, 'command': command})
                                    
                                    # Handle exit commands
                                    if command.lower() in ['exit', 'logout', 'quit']:
                                        channel.send("logout\r\n")
                                        break
                                    
                                    # Get response for command
                                    cmd_lower = command.lower().split()[0] if command else ""
                                    response = fake_responses.get(cmd_lower, f"bash: {command}: command not found")
                                    channel.send(f"{response}\r\n")
                                
                                # Send new prompt
                                channel.send("honeypot@ubuntu:~$ ")
                            
                            # Handle backspace
                            elif char in ['\x7f', '\x08']:  # DEL or BS
                                if command_buffer:
                                    command_buffer = command_buffer[:-1]
                                    # Erase character: backspace + space + backspace
                                    channel.send('\x08 \x08')
                            
                            # Handle Ctrl+C
                            elif char == '\x03':
                                command_buffer = ""
                                channel.send("^C\r\nhoneypot@ubuntu:~$ ")
                            
                            # Handle Ctrl+D (EOF)
                            elif char == '\x04':
                                if not command_buffer:
                                    channel.send("logout\r\n")
                                    break
                            
                            # Regular character
                            elif ord(char) >= 32 or char == '\t':  # Printable characters
                                command_buffer += char
                                channel.send(char)  # Echo the character
                            
                        except Exception as e:
                            logger.debug(f"Error reading from channel: {e}")
                            break
                    
                    # if client disconnected
                    if not transport.is_active():
                        break
                    time.sleep(0.01)  # Small sleep to prevent busy waiting
                    
                channel.close()
        except paramiko.SSHException as e:
            logger.debug(f"SSH negotiation failed: {e}", extra=extra)
        transport.close()
    except Exception as e:
        logger.error(f"Error handling SSH client {client_ip}:{client_port}: {e}", 
                    extra={'ip': client_ip, 'port': client_port, 'error': str(e)})
    
    finally:
        client_socket.close()

def start_ssh_honeypot(args, logger):
    # generate host key if not exists
    import os
    key_path = "ssh_host_key"
    
    if not os.path.exists(key_path):
        from paramiko import RSAKey
        key = RSAKey.generate(2048)
        key.write_private_key_file(key_path)
        logger.info(f"Generated new SSH host key: {key_path}")
    
    host_key = paramiko.RSAKey(filename=key_path)
    
    # create socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server_socket.bind(('0.0.0.0', args.ssh_port))
        server_socket.listen(5) #  max connections
        
        logger.info(f"SSH honeypot started on port {args.ssh_port}")
        
        while True:
            try:
                client_socket, client_address = server_socket.accept()
                client_thread = threading.Thread(
                    target=handle_ssh_client,
                    args=(client_socket, client_address, args, logger, host_key),
                    daemon=True
                )
                client_thread.start()
                
            except KeyboardInterrupt:
                break
            except Exception as e:
                logger.error(f"Error accepting connection: {e}")
    
    except Exception as e:
        logger.error(f"Failed to start SSH honeypot: {e}")
    
    finally:
        server_socket.close()
        logger.info("SSH honeypot stopped")