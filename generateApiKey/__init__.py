import hashlib
import hmac
import uuid
import random

def generateApiKey(secret, seed, include=None):
    try:
        message = seed.encode()
        if include:
            pos = random.randint(0, len(seed))
            message = message[:pos] + include.encode() + message[pos:]
        api_key = hmac.new(secret.encode(), message, hashlib.sha256).hexdigest()
        return str(uuid.uuid5(uuid.NAMESPACE_DNS, api_key))
    except:
        return None
