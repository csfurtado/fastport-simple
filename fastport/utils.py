import socket
import ipaddress

def ip_range_from_cidr(cidr):
    net = ipaddress.IPv4Network(cidr, strict=False)
    return [str(ip) for ip in net.hosts()]

def tcp_banner(ip, port, timeout=0.5):
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            try:
                return s.recv(1024).decode(errors='ignore').strip()
            except:
                return ""
    except:
        return None

def udp_probe(ip, port, timeout=0.5):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(b'ping', (ip, port))
        data, _ = sock.recvfrom(1024)
        return data.decode(errors='ignore').strip()
    except socket.timeout:
        return "open|filtered"
    except:
        return None
    finally:
        sock.close()
        
     
def expand_targets(cidr_or_ip: str):
    """Expande CIDR ou IP único em lista de IPs."""
    return ip_range_from_cidr(cidr_or_ip)
    
def parse_ports(port_str: str):
    """
    Converte uma string como '22,80,443,1000-1010' numa lista de inteiros.
    """
    ports = set()
    for part in port_str.split(','):
        if '-' in part:
            start, end = map(int, part.split('-'))
            ports.update(range(start, end + 1))
        else:
            ports.add(int(part))
    return sorted(ports)


