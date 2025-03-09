import subprocess
import ipaddress
import platform
import socket
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm

def get_local_ip():
    """
    현재 장치의 로컬 IP 주소를 가져옵니다.
    """
    try:
        local_ip = socket.gethostbyname(socket.gethostname())
        return local_ip
    except socket.error:
        print("[!] 현재 IP 주소를 가져올 수 없습니다.")
        return None

def get_subnet_mask(local_ip):
    """
    로컬 IP 주소를 기반으로 서브넷 마스크를 가져옵니다.
    """
    # 서브넷 마스크 예시
    if local_ip.startswith("192.168"):
        return "255.255.255.0"
    elif local_ip.startswith("10."):
        return "255.255.255.0"
    elif local_ip.startswith("172."):
        return "255.255.0.0"
    else:
        return "255.255.255.0"

def ping_device(ip):
    """
    주어진 IP 주소로 ping을 보냅니다.
    """
    param = "-n" if platform.system().lower() == "windows" else "-c"
    try:
        result = subprocess.run(["ping", param, "1", str(ip)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode == 0:
            return f"[+] {ip} is online"
        else:
            return f"[-] {ip} is offline"
    except Exception as e:
        return f"[!] Error pinging {ip}: {e}"

def scan_network(ip_range):
    """
    네트워크 범위에 있는 모든 장치 스캔
    """
    network = ipaddress.IPv4Network(ip_range, strict=False)
    results = []
    
    # ThreadPoolExecutor를 사용하여 병렬로 ping
    with ThreadPoolExecutor() as executor:
        # tqdm을 사용하여 진행 상태 표시
        for result in tqdm(executor.map(ping_device, network.hosts()), total=len(list(network.hosts())), desc="Scanning"):
            results.append(result)
    
    return results

if __name__ == "__main__":
    print("[*] 네트워크 스캔 시작...")

    # 현재 IP 가져오기
    local_ip = get_local_ip()
    if not local_ip:
        exit(1)

    print(f"현재 IP: {local_ip}")

    # 서브넷 마스크 가져오기
    subnet_mask = get_subnet_mask(local_ip)
    print(f"서브넷 마스크: {subnet_mask}")

    # 네트워크 범위 설정
    network_range = f"{local_ip}/{subnet_mask}"
    print(f"[*] 스캔할 네트워크: {network_range}")

    # 네트워크 스캔
    scan_results = scan_network(network_range)

    print("\n[+] 스캔 결과:")
    for result in scan_results:
        print(result)
