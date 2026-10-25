#!/usr/bin/env python3
"""Local-only certificate rotation experiment for pinned sing-box1.14.4."""
import argparse,json,secrets,subprocess,tempfile,threading,time,uuid,os
from pathlib import Path
from verify_native_local import Handler,free_port,process,request
import http.server
from dazzle.metering import NativeAPI


def certificate(directory,index):
    cert,key=directory/f'cert{index}.pem',directory/f'key{index}.pem'
    conf=directory/'openssl.cnf'
    conf.write_text('[req]\ndistinguished_name=dn\nx509_extensions=ext\nprompt=no\n[dn]\nCN=localhost\n[ext]\nsubjectAltName=DNS:localhost\nbasicConstraints=critical,CA:TRUE\nkeyUsage=digitalSignature,keyEncipherment,keyCertSign\nextendedKeyUsage=serverAuth\n')
    subprocess.run(['/usr/bin/openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(key),'-out',str(cert),'-days','1','-config',str(conf)],check=True,capture_output=True)
    key.chmod(0o600)
    return cert,key


def replace(path,data):
    tmp=path.with_suffix('.new');tmp.write_bytes(data);tmp.chmod(0o600);os.replace(tmp,path)


def test(binary,combined):
    with tempfile.TemporaryDirectory(prefix='dazzle-tls-') as tmp:
        root=Path(tmp);root.chmod(0o700)
        cert1,key1=certificate(root,1);cert2,key2=certificate(root,2)
        if combined:
            certpath=keypath=root/'bundle.pem';replace(certpath,cert1.read_bytes()+key1.read_bytes())
        else:
            certpath,keypath=root/'active-cert.pem',root/'active-key.pem'
            replace(certpath,cert1.read_bytes());replace(keypath,key1.read_bytes())
        target=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
        threading.Thread(target=target.serve_forever,daemon=True).start()
        port,apiport,localport=free_port(),free_port(),free_port();secret=secrets.token_urlsafe(36);user=str(uuid.uuid4());password=secrets.token_urlsafe(32)
        server={'log':{'level':'error'},'services':[{'type':'api','listen':'127.0.0.1','listen_port':apiport,'secret':secret,'dashboard':False}],
            'inbounds':[{'type':'tuic','listen':'127.0.0.1','listen_port':port,'users':[{'uuid':user,'password':password}],'zero_rtt_handshake':False,
            'tls':{'enabled':True,'alpn':['h3'],'certificate_path':str(certpath),'key_path':str(keypath)}}],'outbounds':[{'type':'direct'}]}
        def client(trust):
            return {'log':{'level':'error'},'inbounds':[{'type':'mixed','listen':'127.0.0.1','listen_port':localport}],
                'outbounds':[{'type':'tuic','tag':'proxy','server':'127.0.0.1','server_port':port,'uuid':user,'password':password,
                 'tls':{'enabled':True,'server_name':'localhost','alpn':['h3'],'certificate_path':str(trust)}}],'route':{'final':'proxy'}}
        result={}
        try:
            with process(binary,server,root,'server') as worker:
                api=NativeAPI('127.0.0.1',apiport,secret);epoch=api.started_at();pid=worker.pid
                with process(binary,client(cert1),root,'client-before'):
                    result['before']=request(localport,target.server_port).returncode==0
                if combined:replace(certpath,cert2.read_bytes()+key2.read_bytes())
                else:
                    replace(certpath,cert2.read_bytes());replace(keypath,key2.read_bytes())
                time.sleep(1)
                with process(binary,client(cert2),root,'client-after'):
                    result['after_key_rotation']=request(localport,target.server_port).returncode==0
                result['worker_pid_unchanged']=worker.poll() is None and worker.pid==pid
                result['counter_epoch_unchanged']=api.started_at()==epoch
        finally:target.shutdown();target.server_close()
        return result

parser=argparse.ArgumentParser();parser.add_argument('--sing-box',type=Path,required=True);args=parser.parse_args()
result={'combined':test(args.sing_box.resolve(),True),'separate_atomic_files':test(args.sing_box.resolve(),False),'scope':'isolated_loopback_only'}
print(json.dumps(result))
assert result['separate_atomic_files']['before'] and result['separate_atomic_files']['after_key_rotation']
assert result['separate_atomic_files']['worker_pid_unchanged'] and result['separate_atomic_files']['counter_epoch_unchanged']
