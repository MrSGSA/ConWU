"""One IGDv2 gateway for native-lab's isolated host. All addresses and ports are fixed."""
import http.server
import ipaddress
import os
import re
import socket
import subprocess
import sys
import threading
import xml.etree.ElementTree as xml
from xml.sax.saxutils import escape

GATEWAY = '10.220.1.1'
HOST = '10.220.1.2'
INTERNAL, EXTERNAL = 48000, 51000
SERVICE = 'urn:schemas-upnp-org:service:WANIPConnection:2'
TYPE = 'urn:schemas-upnp-org:device:InternetGatewayDevice:1'


class Gateway(http.server.BaseHTTPRequestHandler):
    owner = ''

    def reply(self, status, body):
        body = body.encode()
        self.send_response(status)
        self.send_header('Content-Type', 'text/xml')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self.reply(200, f'<root><device><serviceList><service><serviceType>{SERVICE}</serviceType>'
                        '<controlURL>/control</controlURL></service></serviceList></device></root>')

    def do_POST(self):
        if self.client_address[0] != HOST or self.path != '/control':
            return self.send_error(403)
        size = int(self.headers['Content-Length'])
        if not 0 < size <= 8192:
            return self.send_error(400)
        body = xml.fromstring(self.rfile.read(size))
        action = self.headers['SOAPAction'].strip('"').split('#')[-1]
        def field(name):
            return body.findtext('.//' + name)
        external = field('NewExternalPort')
        if action == 'GetExternalIPAddress':
            return self.reply(200, '<r><NewExternalIPAddress>192.0.2.1</NewExternalIPAddress></r>')
        if action == 'GetSpecificPortMappingEntry' and external == str(INTERNAL):
            return self.reply(200, '<r><NewPortMappingDescription>Occupied</NewPortMappingDescription></r>')
        if action == 'GetSpecificPortMappingEntry' and external == str(EXTERNAL) and Gateway.owner:
            return self.reply(200, f'<r><NewInternalClient>{HOST}</NewInternalClient>'
                f'<NewInternalPort>{INTERNAL}</NewInternalPort>'
                f'<NewPortMappingDescription>{escape(Gateway.owner)}</NewPortMappingDescription></r>')
        if (action == 'AddAnyPortMapping' and external == '0' and not Gateway.owner
                and field('NewInternalPort') == str(INTERNAL) and field('NewInternalClient') == HOST
                and field('NewProtocol') == 'TCP' and field('NewPortMappingDescription')):
            subprocess.run(['nft', 'add', 'element', 'ip', 'conwu_lab_nat', 'host_ports',
                            '{', str(EXTERNAL), '}'], check=True)
            Gateway.owner = field('NewPortMappingDescription')
            print(f'allocated {EXTERNAL} to {HOST}:{INTERNAL}', flush=True)
            return self.reply(200, f'<AddAnyPortMappingResponse><NewReservedPort>{EXTERNAL}</NewReservedPort></AddAnyPortMappingResponse>')
        if action == 'DeletePortMapping' and external == str(EXTERNAL) and Gateway.owner:
            subprocess.run(['nft', 'delete', 'element', 'ip', 'conwu_lab_nat', 'host_ports',
                            '{', str(EXTERNAL), '}'], check=True)
            Gateway.owner = ''
            print(f'released {EXTERNAL}', flush=True)
            return self.reply(200, '<r/>')
        return self.reply(500, '<Fault><UPnPError><errorCode>714</errorCode></UPnPError></Fault>')


def main():
    namespace = subprocess.check_output(['ip', 'netns', 'identify', str(os.getpid())], text=True).strip()
    if namespace != sys.argv[1] or not re.fullmatch(r'cwru-ra-[0-9a-f]{8}', namespace):
        raise SystemExit('This fixture requires its disposable native-lab host router')
    with http.server.HTTPServer((GATEWAY, 49110), Gateway) as server, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(('', 1900))
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                        ipaddress.ip_address('239.255.255.250').packed + ipaddress.ip_address(GATEWAY).packed)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        while True:
            message, addr = sock.recvfrom(8192)
            if addr[0] == HOST and message.startswith(b'M-SEARCH '):
                sock.sendto(f'HTTP/1.1 200 OK\r\nST: {TYPE}\r\nLOCATION: http://{GATEWAY}:49110/root.xml\r\n\r\n'.encode(), addr)


if __name__ == '__main__':
    main()
