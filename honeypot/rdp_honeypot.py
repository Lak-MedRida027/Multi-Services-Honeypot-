#!/usr/bin/env python3
"""
RDP (Remote Desktop Protocol) Honeypot Module
"""
import socket
import threading
import struct
import time

class RDPHoneypot:
    def __init__(self, port=3389, logger=None):
        self.port = port
        self.logger = logger
        self.running = False
        
        self.server_name = b"WIN-COMPUTER"
        self.os_major = 10
        self.os_minor = 0
        self.protocol = 0x00080001
    
    def parse_rdp_connection_request(self, data):
        try:
            if b"mstshash" in data:
                start = data.find(b"mstshash") + 9
                end = data.find(b"\x00", start)
                if end != -1:
                    computer = data[start:end].decode('utf-8', errors='ignore')
                    return {"computer": computer}
            
            username_markers = [b"Administrator", b"admin", b"user"]
            for marker in username_markers:
                if marker in data:
                    return {"username_hint": marker.decode()}
                    
        except:
            pass
        
        return {"raw_data": data[:100].hex()}
    
    def create_rdp_connection_response(self):
        response = bytearray()
        
        response.append(0x03)
        response.append(0x00)
        response.extend(b'\x00\x00')
        
        response.append(0x02)
        response.append(0xf0)
        response.append(0x80)
        
        response.extend(b'\x03\x00\x00\x13')
        response.extend(b'\x0e\xd0\x00\x00')
        response.extend(b'\x00\x00\x00')
        response.append(0x02)
        response.extend(b'\x00\x08')
        response.extend(struct.pack('<I', 0x00080001))
        
        length = len(response)
        response[2] = (length >> 8) & 0xFF
        response[3] = length & 0xFF
        
        return bytes(response)
    
    def create_rdp_security_response(self):
        response = bytearray()
        
        response.extend(b'\x03\x00\x00\x27')
        response.extend(b'\x02\xf0\x80')
        response.extend(b'\x64\x00\x05\x03\x00\x47\x00')
        
        response.extend(struct.pack('<H', len(self.server_name)))
        response.extend(self.server_name)
        response.extend(b'\x00' * 20)
        
        return bytes(response)
    
    def handle_rdp_client(self, client_socket, addr):
        client_ip = addr[0]
        
        try:
            self.logger.info(f"RDP connection from {client_ip}")
            
            data = client_socket.recv(4096)
            info = self.parse_rdp_connection_request(data)
            
            log_msg = f"RDP connection attempt - IP: {client_ip}"
            if "computer" in info:
                log_msg += f", Computer: {info['computer']}"
            if "username_hint" in info:
                log_msg += f", Username hint: {info['username_hint']}"
            
            self.logger.info(log_msg)
            
            attack_patterns = [
                b"BlueKeep", b"CVE-2019-0708", b"MS_T120",
                b"rdpwrap", b"shterm", b"hydra", b"ncrack"
            ]
            
            for pattern in attack_patterns:
                if pattern in data:
                    self.logger.warning(f"RDP attack pattern detected - IP: {client_ip}, Pattern: {pattern.decode()}")
            
            response = self.create_rdp_connection_response()
            client_socket.send(response)
            
            time.sleep(0.5)
            
            try:
                data = client_socket.recv(4096)
                if data:
                    security_response = self.create_rdp_security_response()
                    client_socket.send(security_response)
                    
                    self.logger.info(f"RDP additional data from {client_ip}, length: {len(data)}")
                    
                    if b"NTLMSSP" in data:
                        self.logger.warning(f"RDP NTLM authentication attempt from {client_ip}")
                    
            except socket.timeout:
                pass
                
            time.sleep(2)
            
        except Exception as e:
            self.logger.info(f"RDP error with {client_ip}: {e}")
        finally:
            client_socket.close()
            self.logger.info(f"RDP connection closed with {client_ip}")
    
    def start(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(5)
        
        try:
            sock.bind(('0.0.0.0', self.port))
            sock.listen(5)
            
            self.running = True
            
            while self.running:
                try:
                    client, addr = sock.accept()
                    client.settimeout(10)
                    
                    thread = threading.Thread(target=self.handle_rdp_client, args=(client, addr))
                    thread.daemon = True
                    thread.start()
                    
                except socket.timeout:
                    continue
                except:
                    break
                    
        except Exception as e:
            self.logger.error(f"RDP server error: {e}")
        finally:
            sock.close()
            self.logger.info("RDP honeypot stopped")

def start_rdp_honeypot(args, logger):
    rdp = RDPHoneypot(port=args.rdp_port, logger=logger)
    rdp.start()