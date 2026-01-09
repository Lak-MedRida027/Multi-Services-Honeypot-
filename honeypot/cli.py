#!/usr/bin/env python3
"""
Here we read the cmd line args and validate them and print the banner with config
"""
import argparse
import sys
from colorama import init, Fore, Style

# init colorama
init(autoreset=True)

def create_parser():
    parser = argparse.ArgumentParser(
        description='Multi-Service Honeypot System',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
            Examples:
            %(prog)s --ssh
            %(prog)s --http
            %(prog)s --all
            %(prog)s --all --ssh-port 2222 --http-port 8080
            %(prog)s --ssh --mysql 
            %(prog)s --rdp --mysql
            %(prog)s --ssh --http --rdp --mysql 
            """
    )
    
    # modes
    parser.add_argument(
        "--ssh",
        action="store_true",
        help="Start SSH honeypot"
    )
    parser.add_argument(
        "--http",
        action="store_true", 
        help="Start HTTP honeypot (WordPress)"
    )
    parser.add_argument(
        "--mysql",
        action="store_true",
        help="Start MySQL database honeypot"
    )
    parser.add_argument(
        "--rdp",
        action="store_true",
        help="Start RDP honeypot"
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Start all honeypot services"
    )
    
    # configuration
    parser.add_argument(
        "--ssh-port",
        type=int,
        default=2222,
        help="Port for SSH honeypot (default: 2222)"
    )
    parser.add_argument(
        "--http-port", 
        type=int,
        default=8080,
        help="Port for HTTP honeypot (default: 8080)"
    )
    parser.add_argument(
        "--mysql-port",
        type=int,
        default=3306,
        help="MySQL port (default: 3306)"
    )
    parser.add_argument(
        "--rdp-port",
        type=int,
        default=3389,
        help="RDP port (default: 3389)"
    )
    
    return parser

def validate_args(args):
    errors = []
    
    # at least one mode is selected
    services = ['ssh', 'http', 'mysql', 'rdp']
    has_service = any(getattr(args, service) for service in services) or args.all
    
    if not has_service:
        errors.append("You must specify at least one service: --ssh, --http, --mysql, --rdp, or --all")
    
    # ports range check
    port_mapping = [
        ('ssh-port', args.ssh_port),
        ('http-port', args.http_port),
        ('mysql-port', args.mysql_port),
        ('rdp-port', args.rdp_port)
    ]
    
    for name, port in port_mapping:
        if port < 1 or port > 65535:
            errors.append(f"Invalid {name}: {port}. Must be between 1-65535")
    
    return errors

def print_banner():
    banner = f"""{Fore.RED}
    ╔═══════════════════════════════════════════════════════════════════════════╗
    ║                                                                           ║
    ║  ██╗  ██╗ ██████╗ ███╗   ██╗███████╗██╗   ██╗██████╗  ██████╗ ████████╗   ║
    ║  ██║  ██║██╔═══██╗████╗  ██║██╔════╝╚██╗ ██╔╝██╔══██╗██╔═══██╗╚══██╔══╝   ║
    ║  ███████║██║   ██║██╔██╗ ██║█████╗   ╚████╔╝ ██████╔╝██║   ██║   ██║      ║
    ║  ██╔══██║██║   ██║██║╚██╗██║██╔══╝    ╚██╔╝  ██╔═══╝ ██║   ██║   ██║      ║
    ║  ██║  ██║╚██████╔╝██║ ╚████║███████╗   ██║   ██║     ╚██████╔╝   ██║      ║
    ║  ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝      ╚═════╝    ╚═╝      ║
    ║                                                                           ║
    ║                      Multi-Service Honeypot System                        ║
    ║                         Mohammed Rida Lakhdari                            ║
    ║                         University of Batna 2                             ║
    ║                                                                           ║
    ╚═══════════════════════════════════════════════════════════════════════════╝
    {Style.RESET_ALL}"""
    print(banner)


def main():
    parser = create_parser()
    args = parser.parse_args()
    
    # print banner
    print_banner()
    
    # validate args
    errors = validate_args(args)
    if errors:
        print(f"{Fore.RED}Argument errors:{Style.RESET_ALL}")
        for error in errors:
            print(f"  • {error}")
        print(f"\nUse {Fore.CYAN}--help{Style.RESET_ALL} for usage information.")
        sys.exit(1)
    
    # modes
    if args.all:
        modes = ['SSH', 'HTTP', 'MySQL', 'RDP']
        args.ssh = True
        args.http = True
        args.mysql = True
        args.rdp = True
    else:
        modes = []
        if args.ssh:
            modes.append('SSH')
        if args.http:
            modes.append('HTTP')
        if args.mysql:
            modes.append('MySQL')
        if args.rdp:
            modes.append('RDP')
    
    # display config
    print(f"{Fore.GREEN}Configuration:{Style.RESET_ALL}")
    print(f"  • Modes: {', '.join(modes)}")
    if args.ssh:
        print(f"  • SSH Port: {args.ssh_port}")
    if args.http:
        print(f"  • HTTP Port: {args.http_port}")
        print(f"  • HTTP Service: WordPress")
    if args.mysql:
        print(f"  • MySQL Port: {args.mysql_port}")
        print(f"  • MySQL Version: 8.0.29 (fake)")
    if args.rdp:
        print(f"  • RDP Port: {args.rdp_port}")
        print(f"  • RDP Server: Windows Server 2019 (fake)")
    print(f"  • Log Level: INFO")
    print(f"  • Log File: honeypot.log")
    
    print(f"\n{Fore.YELLOW}[*] Starting honeypot system...{Style.RESET_ALL}")
    
    return args

if __name__ == "__main__":
    main()