import socketserver
from http.server import BaseHTTPRequestHandler, HTTPServer
import threading
import logging
import base64
import binascii
import re
import argparse

CROSSDOMAIN = '''<?xml version="1.0"?>
<!DOCTYPE cross-domain-policy SYSTEM "http://www.adobe.com/xml/dtds/cross-domain-policy.dtd">
<cross-domain-policy>
   <allow-access-from domain="*" secure="false"/>
</cross-domain-policy>
'''


class Logger():
    logger = logging.getLogger(__name__)
    results_file = "results.txt"

    @staticmethod
    def set_logger(logger):
        Logger.logger = logger

    @staticmethod
    def write_res(result):
        Logger.logger.debug(result)
        with open(Logger.results_file, "a") as rf:
            rf.writelines(str(result) + "\n")


class HttpServer(BaseHTTPRequestHandler, Logger):

    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/xml')
        self.end_headers()
        Logger.logger.debug(self.request)

        self.wfile.write(CROSSDOMAIN.encode())
        self.wfile.flush()
        Logger.logger.info("crossdomain.xml has been sent")

    def do_POST(self):
        Logger.logger.debug(self.request)
        post_length = int(self.headers["Content-Length"])
        Logger.logger.debug("post_length: ".format(post_length))

        full_hello = self.rfile.read(post_length)
        try:
            fhd = base64.b64decode(full_hello)
            all_strings = re.findall(b'([a-zA-Z0-9!:\@\/\.]{4,})', fhd, re.S)
            Logger.write_res((self.client_address, all_strings))
            Logger.logger.info("got TLS cert")
        except binascii.Error:
            Logger.logger.info("Incorrect base64: {} ".format(full_hello))

        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.send_header('Content-Length', 1)
        self.end_headers()
        self.wfile.write(bytes("1".encode("UTF-8")))


class PolicyServer(socketserver.TCPServer, Logger):
    def __init__(self, server, handler, policy_file):
        super(PolicyServer, self).__init__(server, handler)
        policy_file = policy_file or "flashpolicy.xml"
        with open(policy_file) as pf:
            self.policy = pf.read()

        Logger.logger.debug("Reading is completed")


class PolicyHandler(socketserver.BaseRequestHandler, Logger):
    def handle(self):
        Logger.logger.info("User {} connected".format(self.client_address))
        self.data = self.request.recv(1024)
        self.req = self.data.decode('UTF-8')
        if not self.req.startswith("<policy-file-request/>"):
            Logger.logger.info("Wrong request from {}".format(self.client_address))
        else:
            self.request.sendall(bytes(self.server.policy, 'UTF-8'))


def usage():
    parser = argparse.ArgumentParser(description="Certificate checker")
    parser.add_argument("-p", "--porthttp", help="Set a port for the HTTP server")
    parser.add_argument("-f", "--filepolicy", help="Set a path to a file with policy for flash socket")
    parser.add_argument("-v", "--verbose", help="Give me more info", action="store_true")
    args = parser.parse_args()
    return args


def main():
    args = usage()
    host = "0.0.0.0"
    policy_port = 843
    http_port = int(args.porthttp or 8080)
    policy_file= args.filepolicy or 'flashpolicy.xml'
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO)

    logger = logging.getLogger(__name__)
    Logger.set_logger(logger)

    policy_server = PolicyServer((host, policy_port), PolicyHandler, policy_file)
    logger.info('Started a policy_server {} on port {}'.format(host, policy_port))
    http_server = HTTPServer((host, http_port), HttpServer)
    logger.debug(http_server)
    logger.info('Started a http server {} on port {}'.format(host, http_port))

    try:
        logger.debug("try block")
        pt = threading.Thread(target=policy_server.serve_forever)
        logger.debug("{} is created".format(pt))
        ht = threading.Thread(target=http_server.serve_forever)
        logger.debug("{} is created".format(ht))
        pt.daemon = True
        ht.daemon = True
        pt.start()
        ht.start()

        while True:
            pass
    except KeyboardInterrupt:
        print("BB")
        policy_server.server_close()
        http_server.server_close()


if __name__ == '__main__':
    main()
