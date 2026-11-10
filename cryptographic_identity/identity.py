import json
import os
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

# Generate Ed25519 key pair
private_key = Ed25519PrivateKey.generate()
public_key = private_key.public_key()

# Store private key locally, never in Git
Path("secrets").mkdir(exist_ok=True)
private_path = Path("secrets/agent_private_key.pem")
private_path.write_bytes(
    private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
)
os.chmod(private_path, 0o600)

# Public key can be included in evidence
public_path = Path("evidence/agent_public_key.pem")
public_path.write_bytes(
    public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
)

message = {
    "sender": "agent-orchestrator-01",
    "recipient": "agent-worker-02",
    "action": "READ_TEST_RECORD"
}

payload = json.dumps(message, sort_keys=True).encode()
signature = private_key.sign(payload)

def verify(data, signed_data):
    try:
        public_key.verify(signed_data, data)
        return True
    except Exception:
        return False

valid_accepted = verify(payload, signature)

tampered_message = {
    **message,
    "action": "DELETE_TEST_RECORD"
}
tampered_payload = json.dumps(
    tampered_message, sort_keys=True
).encode()

tampered_accepted = verify(tampered_payload, signature)

result = {
    "algorithm": "Ed25519",
    "key_pair_generated": True,
    "public_key_file": str(public_path),
    "private_key_file": "secrets/agent_private_key.pem",
    "valid_message_accepted": valid_accepted,
    "tampered_message_rejected": not tampered_accepted,
    "simulation": "LOCAL_CRYPTOGRAPHIC_TEST"
}

Path("evidence/ed25519_results.json").write_text(
    json.dumps(result, indent=2),
    encoding="utf-8"
)

print(json.dumps(result, indent=2))
print("\nPublic key saved:", public_path)
print("Private key stored locally and excluded from Git.")
