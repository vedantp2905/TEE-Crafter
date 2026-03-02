from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
import socket
import json
import logging
import asyncio
from typing import Dict, Any

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

app = FastAPI(title="Nitro Enclave Host Proxy", version="1.0.0")

import subprocess

def get_enclave_cid() -> int:
    import subprocess
    import json
    import logging
    try:
        out = subprocess.check_output(['nitro-cli', 'describe-enclaves'], text=True)
        data = json.loads(out)
        if data and isinstance(data, list) and len(data) > 0:
            return data[0]['EnclaveCID']
    except Exception as e:
        logging.error(f"Could not auto-detect enclave CID: {e}")
    return 16 # Default or fallback

VSOCK_PORT = 5005
TIMEOUT = 120.0

def _forward_to_enclave(payload_bytes: bytes) -> bytes:
    sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    sock.settimeout(TIMEOUT)
    try:
        cid = get_enclave_cid()
        logging.info(f"[PROXY] Connecting to enclave CID={cid} port={VSOCK_PORT}...")
        sock.connect((cid, VSOCK_PORT))
        logging.info(f"[PROXY] Connected. Sending {len(payload_bytes)} bytes...")
        sock.sendall(payload_bytes)
        sock.shutdown(socket.SHUT_WR)
        logging.info("[PROXY] Payload sent, waiting for response...")
        
        response = bytearray()
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response.extend(chunk)
        logging.info(f"[PROXY] Received {len(response)} bytes from enclave")
        return bytes(response)
    except Exception as e:
        logging.error(f"[PROXY] vsock error: {type(e).__name__}: {e}")
        raise
    finally:
        sock.close()

import boto3

@app.post("/enclave")
async def handle_enclave_request(request: Request):
    """
    Blindly forwards incoming JSON payloads over vsock to the secure enclave
    and returns the enclave's response. The host never reads the plaintext.
    """
    try:
        body_bytes = await request.body()
        if not body_bytes:
            raise HTTPException(status_code=400, detail="Empty request body")
            
        try:
            body_json = json.loads(body_bytes)
        except json.JSONDecodeError:
            raise HTTPException(status_code=400, detail="Body must be valid JSON")
        
        req_keys = list(body_json.keys()) if isinstance(body_json, dict) else f"list[{len(body_json)}]"
        logging.info(f"[PROXY] Incoming request keys: {req_keys}")
            
        session = boto3.Session()
        creds = session.get_credentials()
        region = session.region_name
        if not region:
            import os
            region = os.environ.get('AWS_REGION', 'us-east-2')
            
        if creds:
            creds = creds.get_frozen_credentials()
            body_json["__aws_credentials"] = {
                "access_key": creds.access_key,
                "secret_key": creds.secret_key,
                "token": creds.token,
                "region": region
            }
            logging.info(f"[PROXY] Injected AWS credentials, region={region}")
        else:
            logging.warning("[PROXY] No AWS credentials available!")
        
        body_bytes_with_creds = json.dumps(body_json).encode('utf-8')
        logging.info(f"[PROXY] Forwarding {len(body_bytes_with_creds)} bytes to enclave...")
            
        loop = asyncio.get_event_loop()
        response_bytes = await loop.run_in_executor(None, _forward_to_enclave, body_bytes_with_creds)
        
        if not response_bytes:
            raise HTTPException(status_code=502, detail="Empty response from enclave")
        
        logging.info(f"[PROXY] Enclave response: {len(response_bytes)} bytes")
            
        try:
            resp_data = json.loads(response_bytes.decode('utf-8'))
            if "error" in resp_data:
                logging.error(f"[PROXY] Enclave error response: {json.dumps(resp_data, indent=2)}")
                return JSONResponse(status_code=400, content=resp_data)
            return JSONResponse(status_code=200, content=resp_data)
        except json.JSONDecodeError:
            raw = response_bytes.decode('utf-8', errors='ignore')
            logging.warning(f"[PROXY] Non-JSON enclave response: {raw[:500]}")
            return JSONResponse(status_code=200, content={"raw_response": raw})
            
    except Exception as e:
        logging.error(f"[PROXY] Error proxying to enclave: {e}")
        import traceback
        logging.error(traceback.format_exc())
        raise HTTPException(status_code=500, detail="Internal proxy error")

if __name__ == "__main__":
    import uvicorn
    # Local fallback for testing, but in production it's run via systemd with SSL params
    uvicorn.run("host_proxy:app", host="0.0.0.0", port=443, ssl_keyfile="/etc/nitro_agent/certs/host.key", ssl_certfile="/etc/nitro_agent/certs/host.crt")
