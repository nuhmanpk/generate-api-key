import hashlib
import hmac
import uuid
import random
import os
import base64
import re
import time
import datetime
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def generateApiKey(secret, seed, include=None, add_dashes=False, pbkdf2_iterations=10000):
    try:
        current_timestamp = int(time.time())
        now = datetime.datetime.now()
        numeric_representation = int(
            f"{now.year}{now.month:02d}{now.day:02d}{now.hour:02d}{now.minute:02d}{now.second:02d}"
        )
        timestamp_hash = hashlib.sha256(
            str(current_timestamp).encode()).hexdigest()
        numeric_hash = hashlib.sha256(
            str(numeric_representation).encode()).hexdigest()

        if add_dashes:
            message = str(seed).encode()
            if include:
                pos = random.randint(0, 32)
                message = message[:pos] + include.encode() + message[pos:]

            combined_hash = f"{timestamp_hash}{numeric_hash}{message}"

            combined_hash = ''.join(random.sample(
                combined_hash, len(combined_hash)))
            api_key = hmac.new(
                secret.encode(), combined_hash.encode(), hashlib.sha256).hexdigest()
            return str(uuid.uuid5(uuid.NAMESPACE_DNS, api_key))
        else:
            salt = os.urandom(16)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                salt=salt,
                iterations=pbkdf2_iterations,
                length=32
            )
            seed = f'{seed}{current_timestamp}{numeric_hash}'.encode()
            if include:
                pos = random.randint(0, len(seed))
                seed = seed[:pos] + include.encode() + seed[pos:]
            key_bytes = kdf.derive(seed)
            key_base64 = base64.urlsafe_b64encode(key_bytes).decode()
            api_key = re.sub(r'[^a-zA-Z0-9]', '', key_base64)
            return api_key
    except Exception as e:
        print(e)
        return None
