#!/usr/bin/env python3
"""
MySQL Honeypot Module
"""
import socket
import threading
import struct
import random
import time
import re
from datetime import datetime

class MySQLHoneypot:
    def __init__(self, host='0.0.0.0', port=3306, logger=None):
        self.host = host
        self.port = port
        self.logger = logger
        self.running = False
        
        # Server info
        self.server_version = b"5.7.29-log"
        self.protocol_version = 10
        self.character_set = 0x21 
        self.status_flags = 0x0002
        self.capability_flags = self._get_capability_flags()
        
        # Connection tracking
        self.connection_counter = 0
        self.active_connections = {}
        
        # Fake data
        self.fake_databases = ["information_schema", "mysql", "performance_schema", "sys", "test", "wordpress", "production", "users_db"]
        self.fake_tables = {
            "mysql": ["user", "db", "tables_priv", "columns_priv", "proc_priv"],
            "test": ["users", "products", "orders", "customers", "invoices"],
            "wordpress": ["wp_users", "wp_posts", "wp_options", "wp_comments", "wp_postmeta"],
            "production": ["accounts", "transactions", "payments", "sessions"],
            "users_db": ["user_credentials", "user_profiles", "user_sessions"],
        }
        
        # Attack patterns
        self.sql_patterns = [
            (r"'.*or.*'.*='.*", "SQL Injection (OR bypass)"),
            (r"union.*select", "Union-based SQLi"),
            (r"sleep\s*\(\d+\)", "Time-based SQLi"),
            (r"benchmark\s*\(", "Benchmark-based SQLi"),
            (r"load_file\s*\(.*\)", "File read attempt"),
            (r"into\s+outfile", "File write attempt"),
            (r"into\s+dumpfile", "File dump attempt"),
            (r"xp_cmdshell", "Command execution attempt"),
            (r"exec\s*\(", "Code execution attempt"),
            (r"--\s*$", "SQL comment injection"),
            (r"/\*.*\*/", "SQL comment obfuscation"),
        ]
    
    def _get_capability_flags(self):
        return (
            (1 << 0) |   # CLIENT_LONG_PASSWORD
            (1 << 3) |   # CLIENT_CONNECT_WITH_DB
            (1 << 4) |   # CLIENT_PROTOCOL_41 (CRITICAL!)
            (1 << 5) |   # CLIENT_TRANSACTIONS
            (1 << 6) |   # CLIENT_SECURE_CONNECTION (CRITICAL!)
            (1 << 7) |   # CLIENT_MULTI_RESULTS
            (1 << 8) |   # CLIENT_PS_MULTI_RESULTS
            (1 << 9) |   # CLIENT_PLUGIN_AUTH
            (1 << 10) |  # CLIENT_CONNECT_ATTRS
            (1 << 11) |  # CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA
            (1 << 13) |  # CLIENT_DEPRECATE_EOF
            (1 << 15) |  # CLIENT_SSL (not really, but flag it)
            (1 << 16) |  # CLIENT_MULTI_STATEMENTS
            (1 << 17) |  # CLIENT_PS_MULTI_STATEMENTS
            (1 << 19) |  # CLIENT_SESSION_TRACK
            (1 << 23) |  # CLIENT_CAN_HANDLE_EXPIRED_PASSWORDS
            (1 << 24) |  # CLIENT_OPTIONAL_RESULTSET_METADATA
            (1 << 27)    # CLIENT_QUERY_ATTRIBUTES
        )
    
    def _create_scramble(self):
        return bytes([random.randint(32, 126) for _ in range(20)])
    
    def _create_handshake(self, connection_id):
        scramble = self._create_scramble()
        
        packet = bytearray()
        
        # Protocol version
        packet.append(self.protocol_version)
        
        # Server version
        packet.extend(self.server_version)
        packet.append(0) 
        
        # Connection ID
        packet.extend(struct.pack('<I', connection_id))
        
        # Auth scramble part 1
        packet.extend(scramble[:8])
        packet.append(0) 
        
        # Capability flags
        packet.extend(struct.pack('<H', self.capability_flags & 0xFFFF))
        
        # Character set
        packet.append(self.character_set)
        
        # Status flags
        packet.extend(struct.pack('<H', self.status_flags))
        
        # Capability flags
        packet.extend(struct.pack('<H', (self.capability_flags >> 16) & 0xFFFF))
        
        # Auth plugin data length
        packet.append(0x15)
        
        # Reserved
        packet.extend(b'\x00' * 10)
        
        # Auth scramble part 2
        packet.extend(scramble[8:])
        packet.append(0)
        
        # Auth plugin name
        packet.extend(b'mysql_native_password')
        packet.append(0)
        
        return packet
    
    def _create_packet(self, sequence_id, payload):
        length = len(payload)
        header = struct.pack('<I', length)[:3] + struct.pack('<B', sequence_id)
        return header + payload
    
    def _parse_auth(self, data):
        try:
            if len(data) < 32:
                return {"username": "unknown", "auth_hash": "", "database": ""}
            
            # skip: capabilities(4) + max_packet(4) + charset(1) + reserved(23)
            pos = 4 + 4 + 1 + 23
            
            # extract username 
            username_end = data.find(b'\x00', pos)
            if username_end == -1:
                return {"username": "unknown", "auth_hash": "", "database": ""}
            
            username = data[pos:username_end].decode('utf-8', errors='ignore')
            pos = username_end + 1
            
            # extract auth response
            auth_hash = ""
            if pos < len(data):
                auth_len = data[pos]
                pos += 1
                
                if auth_len > 0 and pos + auth_len <= len(data):
                    auth_hash = data[pos:pos + auth_len].hex()
                    pos += auth_len
            
            # extract database name (if present)
            database = ""
            if pos < len(data):
                db_end = data.find(b'\x00', pos)
                if db_end != -1:
                    database = data[pos:db_end].decode('utf-8', errors='ignore')
            
            return {
                "username": username,
                "auth_hash": auth_hash,
                "database": database
            }
            
        except Exception as e:
            if self.logger:
                self.logger.error(f"Auth parse error: {e}")
            return {"username": "unknown", "auth_hash": "", "database": ""}
    
    def _send_ok(self, sock, seq_id, message="", affected_rows=0):
        ok_packet = bytearray()
        ok_packet.append(0x00)  
        ok_packet.extend(struct.pack('<I', affected_rows)[:3]) 
        ok_packet.extend(b'\x00\x00')  
        ok_packet.extend(struct.pack('<H', self.status_flags)) 
        ok_packet.extend(b'\x00\x00')  
        
        if message:
            ok_packet.extend(message.encode())
        
        sock.send(self._create_packet(seq_id, bytes(ok_packet)))
    
    def _send_error(self, sock, seq_id, error_code, message):
        error_packet = bytearray()
        error_packet.append(0xff)  
        error_packet.extend(struct.pack('<H', error_code))  
        error_packet.append(0x23)  
        error_packet.extend(b'HY000')  
        error_packet.extend(message.encode())  
        
        sock.send(self._create_packet(seq_id, bytes(error_packet)))
    
    def _analyze_query(self, query, client_ip):
        query_lower = query.lower()
        alerts = []
        
        # Check for SQL injection
        for pattern, description in self.sql_patterns:
            if re.search(pattern, query_lower, re.IGNORECASE):
                if self.logger:
                    self.logger.warning(f"[MySQL] SQL Injection from {client_ip}: {description} - Query: {query[:100]}")
                alerts.append(description)
        
        # Check for sensitive operations
        sensitive_ops = [
            ("drop table", "Table deletion attempt"),
            ("drop database", "Database deletion attempt"),
            ("delete from", "Data deletion attempt"),
            ("truncate table", "Table truncation attempt"),
            ("grant ", "Privilege grant attempt"),
            ("revoke ", "Privilege revoke attempt"),
            ("create user", "User creation attempt"),
            ("alter user", "User modification attempt"),
        ]
        
        for pattern, desc in sensitive_ops:
            if pattern in query_lower:
                if self.logger:
                    self.logger.warning(f"[MySQL] Sensitive operation from {client_ip}: {desc} - Query: {query[:100]}")
                alerts.append(desc)
        
        return {
            "type": "attack" if alerts else "normal",
            "alerts": alerts,
            "query": query
        }
    
    def _handle_show_databases(self, sock, seq_id):
        try:
            # Column count packet
            sock.send(self._create_packet(seq_id, b'\x01'))
            
            # Column definition
            col_def = self._create_column_definition(
                catalog='def',
                schema='information_schema',
                table='SCHEMATA',
                org_table='SCHEMATA',
                name='Database',
                org_name='SCHEMA_NAME',
                charset=0x21, 
                length=256,
                field_type=0xfd,  
                flags=0x0001, 
                decimals=0
            )
            sock.send(self._create_packet(seq_id + 1, col_def))
            
            # EOF after column definitions
            sock.send(self._create_packet(seq_id + 2, self._create_eof_packet()))
            
            # Send database rows
            row_seq = seq_id + 3
            for db in self.fake_databases:
                row_data = self._encode_length_encoded_string(db)
                sock.send(self._create_packet(row_seq, row_data))
                row_seq += 1
            
            # Final EOF
            sock.send(self._create_packet(row_seq, self._create_eof_packet()))
            
        except Exception as e:
            if self.logger:
                self.logger.error(f"Error in SHOW DATABASES: {e}")
            self._send_error(sock, seq_id, 1064, "Error processing query")
    
    def _handle_use_database(self, sock, seq_id, db_name):
        self._send_ok(sock, seq_id, "Database changed")
    
    def _handle_show_tables(self, sock, seq_id, db_name=None):
        try:
            # get tables for database
            tables = self.fake_tables.get(db_name, self.fake_tables.get("test", ["users", "products"]))
            
            sock.send(self._create_packet(seq_id, b'\x01'))
            
            # column definition
            col_name = f"Tables_in_{db_name}" if db_name else "Tables_in_test"
            col_def = self._create_column_definition(
                catalog='def',
                schema='information_schema',
                table='TABLES',
                org_table='TABLES',
                name=col_name,
                org_name='TABLE_NAME',
                charset=0x21,
                length=256,
                field_type=0xfd,
                flags=0x0001, 
                decimals=0
            )
            sock.send(self._create_packet(seq_id + 1, col_def))
            
            # EOF after column definitions
            sock.send(self._create_packet(seq_id + 2, self._create_eof_packet()))
            
            # send table rows
            row_seq = seq_id + 3
            for table in tables:
                row_data = self._encode_length_encoded_string(table)
                sock.send(self._create_packet(row_seq, row_data))
                row_seq += 1
            
            # Final EOF
            sock.send(self._create_packet(row_seq, self._create_eof_packet()))
            
        except Exception as e:
            if self.logger:
                self.logger.error(f"Error in SHOW TABLES: {e}")
            self._send_error(sock, seq_id, 1064, "Error processing query")
    
    def _handle_select(self, sock, seq_id, query):
        try:
            query_lower = query.lower()
            
            if "@@version" in query_lower or "version()" in query_lower:
                sock.send(self._create_packet(seq_id, b'\x01'))
                
                col_def = self._create_column_definition(
                    catalog='def',
                    schema='',
                    table='',
                    org_table='',
                    name='@@version',
                    org_name='',
                    charset=0x21,
                    length=60,
                    field_type=0xfd, 
                    flags=0x0001,
                    decimals=0x1f
                )
                sock.send(self._create_packet(seq_id + 1, col_def))
                sock.send(self._create_packet(seq_id + 2, self._create_eof_packet()))
                
                version = "5.7.29-log"
                row_data = self._encode_length_encoded_string(version)
                sock.send(self._create_packet(seq_id + 3, row_data))
                sock.send(self._create_packet(seq_id + 4, self._create_eof_packet()))
                
            elif "user()" in query_lower or "current_user" in query_lower:
                sock.send(self._create_packet(seq_id, b'\x01'))
                
                col_def = self._create_column_definition(
                    catalog='def',
                    schema='',
                    table='',
                    org_table='',
                    name='user()',
                    org_name='',
                    charset=0x21,
                    length=77,
                    field_type=0xfd,
                    flags=0x0001,
                    decimals=0x1f
                )
                sock.send(self._create_packet(seq_id + 1, col_def))
                sock.send(self._create_packet(seq_id + 2, self._create_eof_packet()))
                
                user = "root@localhost"
                row_data = self._encode_length_encoded_string(user)
                sock.send(self._create_packet(seq_id + 3, row_data))
                sock.send(self._create_packet(seq_id + 4, self._create_eof_packet()))
                
            elif "database()" in query_lower:
                sock.send(self._create_packet(seq_id, b'\x01'))
                
                col_def = self._create_column_definition(
                    catalog='def',
                    schema='',
                    table='',
                    org_table='',
                    name='database()',
                    org_name='',
                    charset=0x21,
                    length=256,
                    field_type=0xfd,
                    flags=0x0000,
                    decimals=0x1f
                )
                sock.send(self._create_packet(seq_id + 1, col_def))
                sock.send(self._create_packet(seq_id + 2, self._create_eof_packet()))
                
                db = "NULL"
                row_data = b'\xfb' 
                sock.send(self._create_packet(seq_id + 3, row_data))
                sock.send(self._create_packet(seq_id + 4, self._create_eof_packet()))
                
            elif "select 1" in query_lower or "select '1'" in query_lower:
                sock.send(self._create_packet(seq_id, b'\x01'))
                
                col_def = self._create_column_definition(
                    catalog='def',
                    schema='',
                    table='',
                    org_table='',
                    name='1',
                    org_name='',
                    charset=0x3f, 
                    length=1,
                    field_type=0x08,  
                    flags=0x0081,  
                    decimals=0
                )
                sock.send(self._create_packet(seq_id + 1, col_def))
                sock.send(self._create_packet(seq_id + 2, self._create_eof_packet()))
                
                row_data = self._encode_length_encoded_string("1")
                sock.send(self._create_packet(seq_id + 3, row_data))
                sock.send(self._create_packet(seq_id + 4, self._create_eof_packet()))
                
            else:
                self._send_ok(sock, seq_id, "", 0)
                
        except Exception as e:
            if self.logger:
                self.logger.error(f"Error in SELECT: {e}")
            self._send_error(sock, seq_id, 1064, "Error processing query")
    
    def handle_client(self, client_socket, addr):
        client_ip = addr[0]
        connection_id = self.connection_counter + 1
        self.connection_counter = connection_id
        
        session_id = f"{client_ip}_{connection_id}"
        self.active_connections[session_id] = {
            "ip": client_ip,
            "start_time": datetime.now(),
            "queries": [],
            "database": None,
            "username": None,
        }
        
        try:
            if self.logger:
                self.logger.info(f"[MySQL] Connection from {client_ip} (ID: {connection_id})")
            
            # send handshake
            handshake = self._create_handshake(connection_id)
            client_socket.send(self._create_packet(0, handshake))
            
            # receive authentication
            auth_data = client_socket.recv(4096)
            if not auth_data or len(auth_data) < 4:
                return
            
            # parse auth packet
            auth_seq = auth_data[3]
            auth_payload = auth_data[4:] if len(auth_data) > 4 else b''
            
            # extract credentials
            credentials = self._parse_auth(auth_payload)
            username = credentials['username']
            auth_hash = credentials['auth_hash']
            database = credentials['database']
            
            # store session info
            self.active_connections[session_id]["username"] = username
            self.active_connections[session_id]["database"] = database
            
            # log auth attempt
            if self.logger:
                log_msg = f"[MySQL] Login attempt from {client_ip} | User: {username}"
                if auth_hash:
                    log_msg += f" | Hash: {auth_hash[:32]}..."
                if database:
                    log_msg += f" | DB: {database}"
                self.logger.warning(log_msg)
            
            # send auth OK 
            self._send_ok(client_socket, auth_seq + 1, "", 0)
            
            while True:
                try:
                    client_socket.settimeout(30)
                    
                    data = client_socket.recv(4096)
                    if not data:
                        break
                    
                    if len(data) < 5:
                        continue
                    
                    packet_seq = data[3]
                    command = data[4]
                    
                    if command == 0x03:
                        query = data[5:].decode('utf-8', errors='ignore').strip()
                        
                        if self.logger:
                            self.logger.info(f"[MySQL] Query from {client_ip}: {query[:100]}")
                        
                        analysis = self._analyze_query(query, client_ip)
                        
                        self.active_connections[session_id]["queries"].append({
                            "query": query,
                            "time": datetime.now(),
                            "analysis": analysis
                        })
                        
                        query_lower = query.lower()
                        
                        if query_lower.startswith("show databases"):
                            self._handle_show_databases(client_socket, packet_seq + 1)
                            
                        elif query_lower.startswith("use "):
                            db_name = query[4:].split()[0].strip(';`"\'')
                            self.active_connections[session_id]["database"] = db_name
                            self._handle_use_database(client_socket, packet_seq + 1, db_name)
                            
                        elif query_lower.startswith("show tables"):
                            current_db = self.active_connections[session_id]["database"]
                            self._handle_show_tables(client_socket, packet_seq + 1, current_db)
                            
                        elif query_lower.startswith("select "):
                            self._handle_select(client_socket, packet_seq + 1, query)
                            
                        else:
                            self._send_ok(client_socket, packet_seq + 1, "", 0)
                        
                    elif command == 0x02:  
                        db_name = data[5:].decode('utf-8', errors='ignore')
                        self.active_connections[session_id]["database"] = db_name
                        self._send_ok(client_socket, packet_seq + 1, "Database changed")
                        
                    elif command == 0x01:
                        if self.logger:
                            self.logger.info(f"[MySQL] Client quit: {client_ip}")
                        break
                    
                    else:
                        if self.logger:
                            self.logger.warning(f"[MySQL] Unknown command {command:#04x} from {client_ip}")
                        self._send_error(client_socket, packet_seq + 1, 1064, "Unknown command")
                
                except socket.timeout:
                    if self.logger:
                        self.logger.info(f"[MySQL] Session timeout: {client_ip}")
                    break
                except Exception as e:
                    if self.logger:
                        self.logger.debug(f"[MySQL] Query error: {e}")
                    break
            
            # log session summary
            session = self.active_connections[session_id]
            duration = (datetime.now() - session["start_time"]).total_seconds()
            if self.logger:
                self.logger.info(f"[MySQL] Session ended: {client_ip} | Duration: {duration:.1f}s | Queries: {len(session['queries'])}")
            
        except Exception as e:
            if self.logger:
                self.logger.error(f"[MySQL] Connection error from {client_ip}: {e}")
        finally:
            client_socket.close()
            if session_id in self.active_connections:
                del self.active_connections[session_id]
    
    def _encode_length_encoded_string(self, s):
        if s is None:
            return b'\xfb' 
        
        data = s.encode('utf-8') if isinstance(s, str) else s
        length = len(data)
        
        if length < 251:
            return bytes([length]) + data
        elif length < (1 << 16):
            return b'\xfc' + struct.pack('<H', length) + data
        elif length < (1 << 24):
            return b'\xfd' + struct.pack('<I', length)[:3] + data
        else:
            return b'\xfe' + struct.pack('<Q', length) + data

    def _create_column_definition(self, catalog, schema, table, org_table, 
                                name, org_name, charset, length, 
                                field_type, flags, decimals):
        packet = bytearray()
        
        # all strings must be length encoded
        packet.extend(self._encode_length_encoded_string(catalog))
        packet.extend(self._encode_length_encoded_string(schema))
        packet.extend(self._encode_length_encoded_string(table))
        packet.extend(self._encode_length_encoded_string(org_table))
        packet.extend(self._encode_length_encoded_string(name))
        packet.extend(self._encode_length_encoded_string(org_name))
        
        # fixed length fields
        packet.append(0x0c) 
        packet.extend(struct.pack('<H', charset))
        packet.extend(struct.pack('<I', length))
        packet.append(field_type)
        packet.extend(struct.pack('<H', flags))
        packet.append(decimals)
        packet.extend(b'\x00\x00') 
        
        return bytes(packet)

    def _create_eof_packet(self, warnings=0):
        packet = bytearray()
        packet.append(0xFE)
        packet.extend(struct.pack('<H', warnings))
        packet.extend(struct.pack('<H', self.status_flags))
        return bytes(packet)
    def start(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(1)
        
        try:
            sock.bind((self.host, self.port))
            sock.listen(10)
            
            self.running = True
            
            while self.running:
                try:
                    client, addr = sock.accept()
                    
                    thread = threading.Thread(
                        target=self.handle_client,
                        args=(client, addr),
                        daemon=True
                    )
                    thread.start()
                    
                except socket.timeout:
                    continue
                except KeyboardInterrupt:
                    if self.logger:
                        self.logger.info("[MySQL] Stopping honeypot...")
                    break
                except Exception as e:
                    if self.logger:
                        self.logger.error(f"[MySQL] Accept error: {e}")
                    time.sleep(1)
        
        except Exception as e:
            if self.logger:
                self.logger.error(f"[MySQL] Server error: {e}")
        finally:
            sock.close()
            self.running = False
            if self.logger:
                self.logger.info("[MySQL] Honeypot stopped")
    
    def stop(self):
        self.running = False


def start_mysql_honeypot(args, logger):
    mysql = MySQLHoneypot(port=args.mysql_port, logger=logger)
    mysql.start()