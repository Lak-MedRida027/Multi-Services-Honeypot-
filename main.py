#!/usr/bin/env python3
import sys
import os
import threading
import time
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)

# Add the current directory to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from honeypot.cli import main as cli_main
    from honeypot.logger import setup_logging
    from honeypot.ssh_honeypot import start_ssh_honeypot
    from honeypot.http_honeypot import start_http_honeypot
    from honeypot.mysql_honeypot import start_mysql_honeypot
    from honeypot.rdp_honeypot import start_rdp_honeypot
except ImportError as e:
    print(f"Error: {e}")
    print("Make sure all module files exist in honeypot/ directory")
    sys.exit(1)

def main():
    try:
        # parse cmd line args
        args = cli_main()
        
        # logging setup
        logger = setup_logging()
        
        threads = []
        
        # start ssh honeypot if requested
        if args.ssh:
            ssh_thread = threading.Thread(
                target=start_ssh_honeypot,
                args=(args, logger),
                daemon=True,
                name="SSH-Honeypot"
            )
            ssh_thread.start()
            threads.append(ssh_thread)
            logger.info(f"SSH honeypot started on port {args.ssh_port}")
        
        # start http honeypot if requested
        if args.http:
            http_thread = threading.Thread(
                target=start_http_honeypot,
                args=(args, logger),
                daemon=True,
                name="HTTP-Honeypot"
            )
            http_thread.start()
            threads.append(http_thread)
            logger.info(f"HTTP honeypot started on port {args.http_port} "
                        f"(fake service: WordPress)")
        
        # start mysql honeypot if requested
        if args.mysql:
            mysql_thread = threading.Thread(
                target=start_mysql_honeypot,
                args=(args, logger),
                daemon=True,
                name="MySQL-Honeypot"
            )
            mysql_thread.start()
            threads.append(mysql_thread)
            logger.info(f"MySQL honeypot started on port {args.mysql_port}")
        
        # start rdp honeypot if requested
        if args.rdp:
            rdp_thread = threading.Thread(
                target=start_rdp_honeypot,
                args=(args, logger),
                daemon=True,
                name="RDP-Honeypot"
            )
            rdp_thread.start()
            threads.append(rdp_thread)
            logger.info(f"RDP honeypot started on port {args.rdp_port}")
        
        # Display status message
        print(f"\n{Fore.GREEN}[+] Honeypot system running. Press Ctrl+C to stop.{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Check honeypot.log for captured activity{Style.RESET_ALL}")
        
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[*] Shutting down honeypot system...{Style.RESET_ALL}")
            logger.info("Honeypot system shutdown requested by user")
            
    except Exception as e:
        print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")
        sys.exit(1)

if __name__ == "__main__":
    main()