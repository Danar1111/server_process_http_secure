import os
import socket
import ssl
import multiprocessing
import logging

from http import HttpServer

httpserver = HttpServer()

class ClientHandler(multiprocessing.Process):
    def __init__(self, connection, address):
        super().__init__()
        self.connection = connection
        self.address = address

    def run(self):
        received_data = ""
        while True:
            try:
                data = self.connection.recv(32)
                if data:
                    decoded_data = data.decode()
                    received_data += decoded_data
                    if received_data.endswith('\r\n'):
                        logging.warning(f"Received from client: {received_data}")
                        response = httpserver.proses(received_data)
                        response += "\r\n\r\n".encode()
                        logging.warning(f"Sending to client: {response}")
                        self.connection.sendall(response)
                        received_data = ""
                        self.connection.close()
                else:
                    break
            except OSError:
                pass
        self.connection.close()

class SecureServer(multiprocessing.Process):
    def __init__(self, hostname='testing.net'):
        super().__init__()
        self.clients = []
        self.hostname = hostname
        cert_path = os.path.join(os.getcwd(), 'certs')
        self.ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ssl_context.load_cert_chain(certfile=os.path.join(cert_path, 'domain.crt'),
                                         keyfile=os.path.join(cert_path, 'domain.key'))
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    def run(self):
        self.socket.bind(('0.0.0.0', 8443))
        self.socket.listen(1)
        while True:
            connection, client_address = self.socket.accept()
            try:
                secure_connection = self.ssl_context.wrap_socket(connection, server_side=True)
                logging.warning(f"Connection from {client_address}")
                client_handler = ClientHandler(secure_connection, client_address)
                client_handler.start()
                self.clients.append(client_handler)
            except ssl.SSLError as e:
                logging.error(f"SSL error: {str(e)}")

def main():
    server = SecureServer()
    server.start()

if __name__ == "__main__":
    main()
