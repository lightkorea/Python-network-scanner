import nmap
import socket
import struct
import ipaddress
from tqdm import tqdm

# 로컬 IP와 서브넷 마스크를 추출하는 함수
def get_local_ip_and_netmask():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0)
    try:
        s.connect(('10.254.254.254', 1))
        local_ip = s.getsockname()[0]
        netmask = socket.inet_ntoa(struct.pack('!I', 0xFFFFFF00))  # 예시: 서브넷 마스크 255.255.255.0
        return local_ip, netmask
    except Exception as e:
        print(f"Error: {e}")
        return None, None

# 네트워크 스캔 함수
def scan_network():
    local_ip, subnet_mask = get_local_ip_and_netmask()
    
    if not local_ip or not subnet_mask:
        print("[!] 로컬 IP 또는 서브넷 마스크를 가져오는 데 실패했습니다.")
        return
    
    print(f"[*] 네트워크 스캔 시작...")
    print(f"현재 IP: {local_ip}, 서브넷 마스크: {subnet_mask}")

    # IP 주소와 서브넷 마스크를 기반으로 네트워크 주소를 계산
    network = ipaddress.IPv4Network(f'{local_ip}/{subnet_mask}', strict=False)
    print(f"[*] 스캔할 네트워크: {network}")

    # python-nmap을 사용하여 네트워크에서 기기 검색
    try:
        nm = nmap.PortScanner()
        print(f"[!] 네트워크 스캔 중: {str(network)}")
        nm.scan(hosts=str(network), arguments='-sn')  # -sn 옵션으로 Ping Sweep (호스트만 찾기)
        
        # 호스트 목록 출력
        for host in nm.all_hosts():
            print(f"[+] {host} ({nm[host].hostname()})")
        print("[*] 스캔 완료!")
    except Exception as e:
        print(f"[!] 네트워크 스캔 중 오류 발생: {e}")

# 메인 함수
if __name__ == "__main__":
    scan_network()
