from fastapi import FastAPI, HTTPException, Depends, Header
from pydantic import BaseModel
from typing import Optional, Dict, List
import uvicorn
import os
import base64
import json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import secrets
import logging

app = FastAPI(title="HSM Simulator", description="A simple HSM simulator for Azure Key Vault")

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("hsm-simulator")

# In-memory key storage
key_store = {}

# Master key used for wrapping/unwrapping keys
MASTER_KEY_NAME = "master-key"
MASTER_KEY = os.environ.get("MASTER_KEY", "default-hsm-master-key-do-not-use-in-production")

# Derive a key using PBKDF2
def derive_key(key_material: str, salt: bytes = b'sofa-hsm-simulator'):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 32 bytes = 256 bits
        salt=salt,
        iterations=100000,
    )
    return kdf.derive(key_material.encode())

# Initialize the master key
master_key_bytes = derive_key(MASTER_KEY)
key_store[MASTER_KEY_NAME] = {
    "name": MASTER_KEY_NAME,
    "key": master_key_bytes,
    "version": "current"
}
logger.info(f"Master key initialized: {MASTER_KEY_NAME}")

# Models
class KeyCreateRequest(BaseModel):
    name: str
    key_type: str = "RSA"  # Only supporting "RSA" for simplicity
    key_size: int = 2048   # Default to 2048-bit keys

class KeyResponse(BaseModel):
    name: str
    id: str
    key_type: str
    version: str

class WrapKeyRequest(BaseModel):
    key_name: str
    algorithm: str = "RSA-OAEP-256"
    value: str  # Base64-encoded value to wrap

class WrapKeyResponse(BaseModel):
    kid: str
    value: str  # Base64-encoded wrapped value

class UnwrapKeyRequest(BaseModel):
    key_name: str
    algorithm: str = "RSA-OAEP-256"
    value: str  # Base64-encoded wrapped value

class UnwrapKeyResponse(BaseModel):
    value: str  # Base64-encoded unwrapped value

class EncryptRequest(BaseModel):
    key_name: str
    algorithm: str = "RSA-OAEP-256"
    plaintext: str  # Base64-encoded plaintext

class EncryptResponse(BaseModel):
    kid: str
    value: str  # Base64-encoded ciphertext

class DecryptRequest(BaseModel):
    key_name: str
    algorithm: str = "RSA-OAEP-256"
    ciphertext: str  # Base64-encoded ciphertext

class DecryptResponse(BaseModel):
    value: str  # Base64-encoded plaintext

# Helper functions
def get_key(key_name: str, version: Optional[str] = None):
    """Get a key from the key store."""
    if key_name not in key_store:
        raise HTTPException(status_code=404, detail=f"Key {key_name} not found")
    
    return key_store[key_name]

def encrypt_value(key: bytes, value: bytes) -> bytes:
    """Encrypt a value using AES-GCM."""
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(12)
    ciphertext = aesgcm.encrypt(nonce, value, None)
    return nonce + ciphertext

def decrypt_value(key: bytes, value: bytes) -> bytes:
    """Decrypt a value using AES-GCM."""
    if len(value) < 12:
        raise HTTPException(status_code=400, detail="Invalid ciphertext format")
    
    nonce = value[:12]
    ciphertext = value[12:]
    
    aesgcm = AESGCM(key)
    try:
        return aesgcm.decrypt(nonce, ciphertext, None)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Decryption failed: {str(e)}")

# Routes
@app.get("/")
def read_root():
    return {"status": "HSM Simulator is running"}

@app.get("/keys")
def list_keys():
    """List all keys in the key store."""
    return {
        "keys": [
            {
                "name": name,
                "id": f"https://hsm-simulator:8080/keys/{name}/versions/current",
                "key_type": "RSA",
                "version": "current"
            }
            for name in key_store.keys()
        ]
    }

@app.post("/keys", response_model=KeyResponse)
def create_key(request: KeyCreateRequest):
    """Create a new key in the key store."""
    if request.name in key_store:
        raise HTTPException(status_code=409, detail=f"Key {request.name} already exists")
    
    # Generate a random key
    key_bytes = secrets.token_bytes(32)  # 256-bit key
    
    # Store the key
    key_store[request.name] = {
        "name": request.name,
        "key": key_bytes,
        "version": "current"
    }
    
    logger.info(f"Created new key: {request.name}")
    
    return {
        "name": request.name,
        "id": f"https://hsm-simulator:8080/keys/{request.name}/versions/current",
        "key_type": request.key_type,
        "version": "current"
    }

@app.get("/keys/{key_name}", response_model=KeyResponse)
def get_key_info(key_name: str):
    """Get information about a key."""
    key_data = get_key(key_name)
    
    return {
        "name": key_name,
        "id": f"https://hsm-simulator:8080/keys/{key_name}/versions/current",
        "key_type": "RSA",
        "version": "current"
    }

@app.post("/keys/{key_name}/wrap", response_model=WrapKeyResponse)
def wrap_key(key_name: str, request: WrapKeyRequest):
    """Wrap a key using the specified key."""
    key_data = get_key(key_name)
    key = key_data["key"]
    
    # Decode the value to wrap
    try:
        value_bytes = base64.b64decode(request.value)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid base64 encoding for value")
    
    # Wrap the key
    wrapped_value = encrypt_value(key, value_bytes)
    
    logger.info(f"Wrapped key with {key_name}")
    
    return {
        "kid": f"https://hsm-simulator:8080/keys/{key_name}/versions/current",
        "value": base64.b64encode(wrapped_value).decode()
    }

@app.post("/keys/{key_name}/unwrap", response_model=UnwrapKeyResponse)
def unwrap_key(key_name: str, request: UnwrapKeyRequest):
    """Unwrap a key using the specified key."""
    key_data = get_key(key_name)
    key = key_data["key"]
    
    # Decode the wrapped value
    try:
        wrapped_value = base64.b64decode(request.value)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid base64 encoding for wrapped value")
    
    # Unwrap the key
    try:
        unwrapped_value = decrypt_value(key, wrapped_value)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to unwrap key: {str(e)}")
    
    logger.info(f"Unwrapped key with {key_name}")
    
    return {
        "value": base64.b64encode(unwrapped_value).decode()
    }

@app.post("/keys/{key_name}/encrypt", response_model=EncryptResponse)
def encrypt(key_name: str, request: EncryptRequest):
    """Encrypt data using the specified key."""
    key_data = get_key(key_name)
    key = key_data["key"]
    
    # Decode the plaintext
    try:
        plaintext = base64.b64decode(request.plaintext)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid base64 encoding for plaintext")
    
    # Encrypt the data
    ciphertext = encrypt_value(key, plaintext)
    
    logger.info(f"Encrypted data with {key_name}")
    
    return {
        "kid": f"https://hsm-simulator:8080/keys/{key_name}/versions/current",
        "value": base64.b64encode(ciphertext).decode()
    }

@app.post("/keys/{key_name}/decrypt", response_model=DecryptResponse)
def decrypt(key_name: str, request: DecryptRequest):
    """Decrypt data using the specified key."""
    key_data = get_key(key_name)
    key = key_data["key"]
    
    # Decode the ciphertext
    try:
        ciphertext = base64.b64decode(request.ciphertext)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid base64 encoding for ciphertext")
    
    # Decrypt the data
    try:
        plaintext = decrypt_value(key, ciphertext)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to decrypt data: {str(e)}")
    
    logger.info(f"Decrypted data with {key_name}")
    
    return {
        "value": base64.b64encode(plaintext).decode()
    }

# Health endpoint
@app.get("/health")
def health_check():
    return {"status": "healthy"}

if __name__ == "__main__":
    # Get port from environment or default to 8080
    port = int(os.environ.get("PORT", 8080))
    
    # Start the server
    uvicorn.run(app, host="0.0.0.0", port=port) 