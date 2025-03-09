import os
import platform
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm

def ping(ip):
    """특정 IP에 ping을 보내 응답 여부 확인"""
    param = "-n 1" if platform.system().lower() == "windows" else "-c 1"
    result = os.system(f"ping {param} -W 1 {ip} > /dev/null 2>&1")
    return ip if result == 0 else None

def get_local_ip():
    """현재 장치의 로컬 IP 주소를 가져옴"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception as e:
        print(f"[!] 로컬 IP를 가져오는 데 실패: {e}")
        return None

def scan_network():
    """네트워크에서 활성화된 기기의 IP 주소 찾기 (진행률 표시)"""
    local_ip = get_local_ip()
    if not local_ip:
        print("[!] 로컬 IP를 확인할 수 없습니다.")
        return []

    network_prefix = ".".join(local_ip.split(".")[:3])  # 192.168.1.XXX 형식으로 변환
    print(f"[*] 네트워크 스캔 중: {network_prefix}.0/24")

    ip_list = [f"{network_prefix}.{i}" for i in range(1, 255)]
    active_devices = []

    with ThreadPoolExecutor(max_workers=100) as executor:
        future_to_ip = {executor.submit(ping, ip): ip for ip in ip_list}
        
        with tqdm(total=len(ip_list), desc="Scanning", unit=" IP") as pbar:
            for future in as_completed(future_to_ip):
                ip = future.result()
                if ip:
                    active_devices.append(ip)
                pbar.update(1)

    return active_devices

def main():
    devices = scan_network()

    if not devices:
        print("[!] 네트워크에서 기기를 찾을 수 없습니다.")
        return

    print("\n[+] 네트워크 기기 목록:")
    for device in devices:
        print(f"IP: {device}")

if __name__ == "__main__":
    main()
