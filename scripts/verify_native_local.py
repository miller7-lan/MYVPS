#!/usr/bin/env python3
"""Isolated VLESS REALITY + TUIC5 smoke test. No production credentials/ports.

Requires an explicitly supplied official sing-box 1.14.4 binary and optional
native protobuf dependencies. All listeners are loopback and temporary.
"""
from __future__ import annotations
import argparse
import copy
from contextlib import contextmanager
import http.server
import json
import os
from pathlib import Path
import secrets
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import uuid


def free_port():
    with socket.socket() as tcp, socket.socket(type=socket.SOCK_DGRAM) as udp:
        tcp.bind(("127.0.0.1", 0)); port = tcp.getsockname()[1]
        udp.bind(("127.0.0.1", port))
        return port


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):pass
    def do_GET(self):
        body = b"Dazzle-local-test" * 65536
        self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers()
        try:self.wfile.write(body)
        except (BrokenPipeError,ConnectionResetError):pass
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)


@contextmanager
def process(binary, config, directory, name):
    path = directory / (name + ".json")
    path.write_text(json.dumps(config)); path.chmod(0o600)
    checked = subprocess.run([str(binary), "check", "-c", str(path)], capture_output=True, timeout=15)
    if checked.returncode:
        raise RuntimeError(name + " configuration check failed: " + checked.stderr.decode()[-1000:])
    log = (directory / (name + ".log")).open("wb")
    p = subprocess.Popen([str(binary), "run", "-c", str(path)], stdout=log, stderr=log)
    try:
        time.sleep(.6)
        if p.poll() is not None:
            raise RuntimeError(name + " exited during startup")
        yield p
    finally:
        if p.poll() is None:
            p.terminate()
            try:p.wait(timeout=5)
            except subprocess.TimeoutExpired:p.kill();p.wait()
        log.close()


def request(socks, target, *, post=False):
    args = ["/usr/bin/curl", "-fsS", "--connect-timeout", "4", "--max-time", "12",
            "--socks5-hostname", f"127.0.0.1:{socks}", "--noproxy", "", f"http://127.0.0.1:{target}/"]
    payload = b"upload-check-" * 4096
    if post:args += ["--data-binary", "@-"]
    return subprocess.run(args, input=payload if post else None, capture_output=True,
                          env={"PATH":"/usr/bin:/bin"}, timeout=15)


class SampleObserver:
    """Continuously consume one real SubscribeStatus stream without a writer."""
    def __init__(self, api):
        self.api = api
        self.samples = []
        self.error = None
        self.lock = threading.Lock()
        self.stopping = threading.Event()
        self.thread = threading.Thread(target=self._consume, daemon=True)

    def _consume(self):
        stream = self.api.stream()
        try:
            for sample in stream:
                with self.lock:
                    self.samples.append(sample)
                    if len(self.samples) > 256:
                        raise RuntimeError("Isolated observer sample limit reached")
                if self.stopping.is_set():
                    break
        except Exception as error:
            if not self.stopping.is_set():
                self.error = type(error).__name__
        finally:
            stream.close()

    def start(self):
        self.thread.start()
        return self

    def values(self):
        with self.lock:
            return tuple(self.samples)

    def stop(self):
        self.stopping.set()
        self.thread.join(timeout=self.api.timeout + 2)
        if self.thread.is_alive():
            raise RuntimeError("Isolated native observer did not stop")


def await_observation(observers, predicate, *, timeout=8):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if any(observer.error for observer in observers):
            raise RuntimeError("Isolated native observer failed")
        values = [observer.values() for observer in observers]
        if all(values) and predicate(values):
            return values
        time.sleep(.02)
    raise RuntimeError("Native observations did not reach the required cumulative state")


def monotonic_samples(samples):
    return bool(samples) and all(
        current.epoch == previous.epoch and current.uplink >= previous.uplink and current.downlink >= previous.downlink
        for previous, current in zip(samples, samples[1:]))


def same_totals(values):
    return len({(samples[-1].epoch, samples[-1].uplink, samples[-1].downlink) for samples in values}) == 1


def dual_observer_reconnect(binary, folder, worker, api, observers, client, target_port):
    first, second = observers
    before = await_observation(observers, same_totals)
    before_total = before[0][-1]
    first_count = len(before[0])
    second.stop()
    # Closing one subscription must leave the other one publishing live samples.
    await_observation([first], lambda values: len(values[0]) > first_count)
    with process(binary, client, folder, "client-during-observer-disconnect"):
        local_port = client["inbounds"][0]["listen_port"]
        for post in (False, True):
            response = request(local_port, target_port, post=post)
            if response.returncode or not response.stdout:
                raise RuntimeError("Local traffic failed while one observer was disconnected")
    advanced = await_observation([first], lambda values: values[0][-1].uplink > before_total.uplink and values[0][-1].downlink > before_total.downlink)
    first_before_reconnect_count = len(advanced[0])
    reconnected = SampleObserver(api).start()
    observers.append(reconnected)
    settled = await_observation([first, reconnected], lambda values: same_totals(values) and len(values[0]) > first_before_reconnect_count)
    final_a, final_b = settled[0][-1], settled[1][-1]
    reconnected_first = settled[1][0]
    if (reconnected_first.uplink < before_total.uplink or reconnected_first.downlink < before_total.downlink or
            reconnected_first.epoch != before_total.epoch):
        raise RuntimeError("Reconnecting a status observer reset or regressed cumulative counters")
    sequences = [observer.values() for observer in observers]
    if not all(monotonic_samples(samples) for samples in sequences):
        raise RuntimeError("A concurrent status observer saw cumulative counter regression")
    if worker.poll() is not None or api.started_at() != before_total.epoch:
        raise RuntimeError("Isolated Core changed during observer validation")
    return {"concurrent_status_streams": 2, "disconnected_observer": "second", "reconnected_observer": "second",
            "first_observer_continued": True, "each_observer_monotonic": True,
            "reconnect_preserved_cumulative_totals": True, "observers_agree_on_upload_and_download_totals": True,
            "core_pid_unchanged": True, "counter_epoch_unchanged": True,
            "samples_observed": {"first": len(sequences[0]), "second_before_disconnect": len(sequences[1]), "second_after_reconnect": len(sequences[2])},
            "before_disconnect": {"upload": before_total.uplink, "download": before_total.downlink},
            "after_reconnect": {"upload": final_a.uplink, "download": final_b.downlink}}


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument("--sing-box",type=Path,required=True);args=parser.parse_args()
    binary=args.sing_box.resolve()
    version=subprocess.check_output([str(binary),"version"],text=True).splitlines()[0]
    if version != "sing-box version 1.14.4":raise SystemExit("Pinned1.14.4 binary required")
    from dazzle.metering import NativeAPI
    with tempfile.TemporaryDirectory(prefix="dazzle-native-") as tmp:
        folder=Path(tmp);folder.chmod(0o700)
        cert,key=folder/"cert.pem",folder/"key.pem"
        cert_config = folder / "cert.cnf"
        cert_config.write_text("[req]\ndistinguished_name=dn\nx509_extensions=ext\nprompt=no\n[dn]\nCN=localhost\n[ext]\nsubjectAltName=DNS:localhost\nbasicConstraints=critical,CA:TRUE\nkeyUsage=digitalSignature,keyEncipherment,keyCertSign\nextendedKeyUsage=serverAuth\n")
        subprocess.run(["/usr/bin/openssl","req","-x509","-newkey","rsa:2048","-nodes","-keyout",str(key),"-out",str(cert),"-days","1","-config",str(cert_config)],check=True,capture_output=True)
        key.chmod(0o600)
        target=http.server.ThreadingHTTPServer(("127.0.0.1",0),Handler)
        tls_target=http.server.ThreadingHTTPServer(("127.0.0.1",0),Handler)
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.minimum_version=ssl.TLSVersion.TLSv1_3
        context.load_cert_chain(cert,key);context.set_alpn_protocols(["h2","http/1.1"])
        tls_target.socket=context.wrap_socket(tls_target.socket,server_side=True)
        threads=[]
        for server in (target,tls_target):
            thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start();threads.append(thread)
        proxyport,apiport=free_port(),free_port();api_secret=secrets.token_urlsafe(36)
        raw=subprocess.check_output([str(binary),"generate","reality-keypair"],text=True)
        keys=dict(line.split(":",1) for line in raw.strip().splitlines())
        priv,pub=keys["PrivateKey"].strip(),keys["PublicKey"].strip()
        vless_uuid,tuic_uuid,password=str(uuid.uuid4()),str(uuid.uuid4()),secrets.token_urlsafe(32)
        short=secrets.token_hex(8)
        from dazzle.rendering import worker_template
        config=worker_template({"id":"isolated","port":proxyport},
                {"vless_uuid":vless_uuid,"tuic_uuid":tuic_uuid,"tuic_password":password,"short_id":short},
                reality_private_key=priv,api_secret=api_secret,api_port=apiport)
        config["log"]={"level":"error"}
        for inbound in config["inbounds"]:inbound["listen"]="127.0.0.1"
        reality_tls=config["inbounds"][0]["tls"]
        reality_tls["server_name"]="localhost"
        reality_tls["reality"]["handshake"]={"server":"127.0.0.1","server_port":tls_target.server_port}
        tuic_tls=config["inbounds"][1]["tls"]
        tuic_tls.update({"server_name":"localhost","certificate_path":str(cert),"key_path":str(key)})
        # The lab target is loopback. The deployment template keeps private-IP rejection.
        config["route"]["rules"]=[]
        try:
            with process(binary,config,folder,"server") as worker:
                original_pid = worker.pid
                api=NativeAPI("127.0.0.1",apiport,api_secret)
                observers=[SampleObserver(api).start(), SampleObserver(api).start()]
                try:
                    initial=await_observation(observers, same_totals)
                    baseline=initial[0][-1]
                    if baseline.uplink or baseline.downlink:
                        raise RuntimeError("Fresh worker should have zero payload baseline")
                    results={};client_templates={}
                    for protocol in ("vless","tuic"):
                        localport=free_port()
                        outbound={"type":protocol,"tag":"proxy","server":"127.0.0.1","server_port":proxyport,"uuid":vless_uuid if protocol=="vless" else tuic_uuid}
                        if protocol=="vless":
                            outbound.update({"flow":"xtls-rprx-vision","tls":{"enabled":True,"server_name":"localhost","utls":{"enabled":True,"fingerprint":"chrome"},"reality":{"enabled":True,"public_key":pub,"short_id":short}}})
                        else:
                            outbound.update({"password":password,"congestion_control":"bbr","tls":{"enabled":True,"server_name":"localhost","certificate_path":str(cert),"alpn":["h3"]}})
                        client={"log":{"level":"error"},"inbounds":[{"type":"mixed","listen":"127.0.0.1","listen_port":localport}],"outbounds":[outbound],"route":{"final":"proxy"}}
                        client_templates[protocol]=copy.deepcopy(client)
                        with process(binary,client,folder,"client-"+protocol):
                            for post in (False,True):
                                response=request(localport,target.server_port,post=post)
                                if response.returncode or not response.stdout:
                                    raise RuntimeError(protocol + " local GET/POST failed")
                        # Invalid independent user identity cannot use the same listener.
                        outbound["uuid"]=str(uuid.uuid4())
                        if protocol=="tuic":outbound["password"]=secrets.token_urlsafe(32)
                        with process(binary,client,folder,"unauthorized-"+protocol):
                            denied=request(localport,target.server_port)
                            if denied.returncode==0:raise RuntimeError("Unauthorized "+protocol+" was accepted")
                        observed=await_observation(observers, lambda values: same_totals(values) and
                            values[0][-1].uplink > baseline.uplink and values[0][-1].downlink > baseline.downlink)
                        sample=observed[0][-1]
                        results[protocol]={"authorized_get_post":True,"unauthorized_rejected":True,"upload_increased":True,"download_increased":True}
                        baseline=sample
                    concurrent=dual_observer_reconnect(binary,folder,worker,api,observers,client_templates["tuic"],target.server_port)
                    if worker.pid != original_pid:
                        raise RuntimeError("Core PID changed during isolated validation")
                    report={"core":version,"mode":"isolated_loopback","protocols":results,"integer_metering":True,
                        "dual_native_observers":concurrent,"production_changed":False}
                finally:
                    for observer in observers:
                        observer.stop()
        finally:
            for server in (target,tls_target):server.shutdown();server.server_close()
    report["cleanup"]={"temporary_directory_removed":not folder.exists(), "child_process_contexts_completed":True}
    print(json.dumps(report))
    return 0

if __name__=="__main__":raise SystemExit(main())
