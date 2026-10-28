"""Disposable TLS portal stand-in; not a production source or release dependency."""
import argparse
import http.server
import json
import socket
import ssl


def serve(host, port, cert, key, private_socket):
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self,*_):
            pass

        def do_GET(self):
            if self.path == '/portal/' and private_socket:
                status, body = 200, b'rehearsal registration portal'
            elif private_socket:
                try:
                    with socket.socket(socket.AF_UNIX) as peer:
                        peer.settimeout(2)
                        peer.connect(private_socket)
                        peer.sendall(json.dumps({'path':self.path}).encode()+b'\n')
                        status=json.loads(peer.makefile('rb').readline())['status']
                except (OSError,ValueError,KeyError):
                    status=503
                body=b'fixture subscription status'
            else:
                status,body=404,b'unknown token'
            self.send_response(status)
            self.send_header('Content-Length',str(len(body)))
            self.end_headers()
            self.wfile.write(body)
    server=http.server.ThreadingHTTPServer((host,port),Handler)
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert,key)
    server.socket=context.wrap_socket(server.socket,server_side=True)
    server.serve_forever()


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--socket',required=True)
    parser.add_argument('--host',required=True)
    parser.add_argument('--port',required=True,type=int)
    parser.add_argument('--cert',required=True)
    parser.add_argument('--key',required=True)
    parser.add_argument('--origin',required=True)
    args=parser.parse_args()
    serve(args.host,args.port,args.cert,args.key,args.socket)


if __name__=='__main__':
    main()
