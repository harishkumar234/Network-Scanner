import argparse
import scapy.all as scapy


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Target IP / IP range.")
    options = parser.parse_args()

    if not options.target:
        parser.error("[-] Please specify a target IP address or IP range. Use --help for more details.")

    return options


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast_mac = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast_mac = arp_request / broadcast_mac
    answered_list = scapy.srp(arp_request_broadcast_mac, timeout=1, verbose=False)[0]

    client_list = []
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        client_list.append(client_dict)
    return client_list


def result_print(results_list):
    print("IP\t\t\tMAC Address\n-----------------------------------")
    for client in results_list:
        print(client["ip"] + "\t\t" + client["mac"])


options = get_arguments()
scan_results = scan(options.target)
result_print(scan_results)

#print(arp_request.summary()) used to print the summary of function
#scapy.ls(scapy.ARP()) used to list the options available in module



