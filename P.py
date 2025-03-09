import socket
import subprocess
from ping3 import ping
from prettytable import PrettyTable
import threading
import time
import re
import ipaddress

# 현재 IP 주소와 서브넷 마스크를 가져오는 함수
def get_local_ip_and_subnet():
    # subprocess를 이용해 ifconfig(혹은 ipconfig) 명령어 실행
    result = subprocess.run(['ifconfig'], capture_output=True, text=True)
    # IP 주소와 서브넷 마스크 추출 (IPv4)
    match = re.search(r"inet (\d+\.\d+\.\d+\.\d+).*netmask (\S+)", result.stdout)
    if match:
        local_ip = match.group(1)
        subnet_mask = match.group(2)
        return local_ip, subnet_mask
    else:
        raise Exception("IP 또는 서브넷 마스크를 찾을 수 없습니다.")

# 네트워크 스캔 함수
def scan_ip(ip):
    global scanned_ips
    response_time = ping(ip, timeout=1)
    if response_time is not None:
        table.add_row([ip, "Active", f"{response_time:.2f} ms"])
    else:
        table.add_row([ip, "Inactive", "N/A"])
    
    # 스캔 완료된 IP 수 증가
    scanned_ips += 1

    # 진행 상황 출력 (퍼센티지)
    percentage = (scanned_ips / total_ips) * 100
    print(f"Scanning: {percentage:.2f}% ({scanned_ips}/{total_ips})", end='\r')

# 네트워크 스캔 범위 설정
def scan_network():
    global total_ips, scanned_ips
    local_ip, subnet_mask = get_local_ip_and_subnet()
    print(f"현재 IP: {local_ip}, 서브넷 마스크: {subnet_mask}")
    
    # 서브넷 범위 계산
    network = ipaddress.IPv4Network(f'{local_ip}/{subnet_mask}', strict=False)
    
    # IP 범위 (네트워크 내 모든 가능한 IP들)
    ip_range = [str(ip) for ip in network.hosts()]
    
    total_ips = len(ip_range)
    scanned_ips = 0

    # 테이블 준비
    table = PrettyTable()
    table.field_names = ["IP Address", "Status", "Response Time (ms)"]

    threads = []
    for ip in ip_range:
        thread = threading.Thread(target=scan_ip, args=(ip,))
        threads.append(thread)
        thread.start()

    # 모든 스레드가 완료될 때까지 기다리기
    for thread in threads:
        thread.join()

    # 결과 출력
    print("\n[*] 스캔 완료.")
    print(table)

# 네트워크 스캔 실행
if __name__ == "__main__":
    print("[*] 네트워크 스캔 시작...")
    start_time = time.time()
    scan_network()
    end_time = time.time()
    print(f"\n[*] 총 스캔 시간: {end_time - start_time:.2f} 초")
