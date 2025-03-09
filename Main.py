from scapy.all import arping

def scan_network(ip_range="192.168.1.1/24"):
    """
    같은 네트워크에 있는 기기들의 IP, MAC 주소를 출력 (Scapy arping 사용)
    """
    print(f"[*] 네트워크 스캔 중: {ip_range}")

    try:
        answered, _ = arping(ip_range, timeout=3, verbose=False)
        devices = [{"ip": recv.psrc, "mac": recv.hwsrc} for send, recv in answered]

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
        print(f"IP: {device['ip']}, MAC: {device['mac']}")

if __name__ == "__main__":
    main()
