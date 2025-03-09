import asyncio
import socket
import ipaddress
from aiohttp import ClientSession
from tqdm import tqdm

async def get_local_ip():
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
    if local_ip.startswith("192.168"):
        return "255.255.255.0"
    elif local_ip.startswith("10."):
        return "255.255.255.0"
    elif local_ip.startswith("172."):
        return "255.255.0.0"
    else:
        return "255.255.255.0"

async def ping_device(ip, session):
    """
    주어진 IP 주소로 ping을 비동기적으로 보냅니다.
    """
    url = f'http://{ip}'
    try:
        async with session.get(url, timeout=1) as response:
            if response.status == 200:
                return f"[+] {ip} is online"
            else:
                return f"[-] {ip} is offline"
    except Exception:
        return f"[-] {ip} is offline"

async def scan_network(ip_range):
    """
    네트워크 범위에 있는 모든 장치 스캔
    """
    network = ipaddress.IPv4Network(ip_range, strict=False)
    results = []

    async with ClientSession() as session:
        tasks = []
        # IP 주소들에 대해 ping 작업을 비동기적으로 생성
        for ip in network.hosts():
            tasks.append(ping_device(str(ip), session))
        
        # 비동기적으로 ping 작업 실행
        for result in tqdm(await asyncio.gather(*tasks), total=len(list(network.hosts())), desc="Scanning"):
            results.append(result)
    
    return results

if __name__ == "__main__":
    print("[*] 네트워크 스캔 시작...")

    # 현재 IP 가져오기
    local_ip = asyncio.run(get_local_ip())
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
    scan_results = asyncio.run(scan_network(network_range))

    print("\n[+] 스캔 결과:")
    for result in scan_results:
        print(result)
