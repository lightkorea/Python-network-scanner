from scapy.all import ARP, Ether, srp
import nmap

def get_local_devices(ip_range="192.168.1.1/24"):
    """
    같은 네트워크에 있는 기기들의 IP와 MAC 주소를 출력
    """
    print(f"[*] 네트워크 스캔 중: {ip_range}")

    # ARP 패킷 생성
    arp_request = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp_request

    # 패킷 전송 및 응답 수집
    result = srp(packet, timeout=3, verbose=False)[0]

    devices = []
    for sent, received in result:
        devices.append({"ip": received.psrc, "mac": received.hwsrc})
    
    return devices

def get_os_info(ip):
    """
    특정 IP의 운영체제를 스캔하여 반환 (Nmap 사용)
    """
    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=ip, arguments="-O")  # OS 스캔 옵션
        os_info = nm[ip]['osmatch'][0]['name'] if nm[ip]['osmatch'] else "알 수 없음"
    except:
        os_info = "OS 정보 없음"

    return os_info

def main():
    # 네트워크 스캔 (IP 범위는 네트워크 환경에 따라 변경)
    ip_range = "192.168.1.1/24"  # 필요에 따라 변경 (ex: 10.0.0.1/24)
    devices = get_local_devices(ip_range)

    if not devices:
        print("[!] 네트워크에서 기기를 찾을 수 없습니다.")
        return

    print("\n[+] 네트워크 기기 목록:")
    for device in devices:
        os_info = get_os_info(device['ip'])
        print(f"IP: {device['ip']}, MAC: {device['mac']}, OS: {os_info}")

if __name__ == "__main__":
    main()
