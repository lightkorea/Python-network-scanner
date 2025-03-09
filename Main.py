import nmap

def scan_network(ip_range="192.168.1.1/24"):
    """
    같은 네트워크에 있는 기기들의 IP, MAC, OS 정보를 가져옴 (Nmap 사용)
    """
    print(f"[*] 네트워크 스캔 중: {ip_range}")

    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=ip_range, arguments="-O")  # OS 정보 포함한 스캔
        devices = []

        for host in nm.all_hosts():
            ip = host
            mac = nm[host]['addresses'].get('mac', '알 수 없음')
            os_info = "알 수 없음"

            # OS 정보 가져오기
            if 'osmatch' in nm[host] and nm[host]['osmatch']:
                os_info = nm[host]['osmatch'][0]['name']

            devices.append({"ip": ip, "mac": mac, "os": os_info})

        return devices
    except Exception as e:
        print(f"[!] 네트워크 스캔 실패: {e}")
        return []

def main():
    ip_range = "192.168.1.1/24"  # 네트워크 환경에 맞게 수정
    devices = scan_network(ip_range)

    if not devices:
        print("[!] 네트워크에서 기기를 찾을 수 없습니다.")
        return

    print("\n[+] 네트워크 기기 목록:")
    for device in devices:
        print(f"IP: {device['ip']}, MAC: {device['mac']}, OS: {device['os']}")

if __name__ == "__main__":
    main()
