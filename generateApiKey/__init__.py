import hashlib
import hmac
import uuid
import random
import base64
import time
import datetime
import re
from secrets import token_bytes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from .utils import generate_expiration_token

async def generateApiKey(
    secret: str,
    seed: str,
    include: str = None,
    add_dashes: bool = False,
    prefix: str = None,
    length: int = None,
    expiry: int = None
) -> str:
    """
    Generate a secure API key based on a secret, seed, and optional parameters.

    Args:
        secret: The secret key used for hashing.
        seed: A unique identifier used to personalize the key.
        include: An optional string to be included in the key generation process.
        add_dashes: Whether to add dashes to the generated key for improved readability.
        prefix: A string prefix for the API key. Followed by a '-'.
        length: The desired length of the API key. If provided, the key will be trimmed or padded accordingly.
        expiry: Expiry time provided in minutes.

    Returns:
        A unique and secure API key.

    Raises:
        ValueError: If the secret or seed is an empty string.
    """

    if not secret or not seed:
        raise ValueError("Secret and seed cannot be empty strings.")

    current_timestamp = int(time.time())
    now = datetime.datetime.now()
    pbkdf2_iterations = random.randint(1000, 10000)
    numeric_representation = int(
        f"{now.year}{now.month:02d}{now.day:02d}{now.hour:02d}{now.minute:02d}{now.second:02d}"
    )

    timestamp_hash = hashlib.sha256(str(current_timestamp).encode()).hexdigest()
    numeric_hash = hashlib.sha256(str(numeric_representation).encode()).hexdigest()

    if add_dashes:
        message = str(seed).encode()
        if include:
            pos = random.randint(0, 32)
            message = message[:pos] + include.encode() + message[pos:]

        combined_hash = f"{timestamp_hash}{numeric_hash}{message}"
        combined_hash = "".join(random.sample(combined_hash, len(combined_hash)))
        api_key = hmac.new(
            secret.encode(), combined_hash.encode(), hashlib.sha256
        ).hexdigest()
        api_key = str(uuid.uuid5(uuid.NAMESPACE_DNS, api_key))
    else:
        salt = token_bytes(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            salt=salt,
            iterations=pbkdf2_iterations,
            length=32,
        )
        seed = f"{seed}{current_timestamp}{numeric_hash}".encode()
        if include:
            pos = random.randint(0, len(seed))
            seed = seed[:pos] + include.encode() + seed[pos:]

        key_bytes = kdf.derive(seed)
        key_base64 = base64.urlsafe_b64encode(key_bytes).decode()
        api_key = re.sub(r"[^a-zA-Z0-9]", "", key_base64)

    if length:
        if add_dashes:
            # only trim dashes if length is greaterthan 12
            if length > 12:
              api_key = api_key[:length]
        else:
            api_key = api_key[:length]

    if prefix:
        api_key = f"{prefix}-{api_key}"

    if expiry:
        expiration_token = await generate_expiration_token(expiry)    

    return api_key

async def is_token_valid(token: str) -> bool:
    """
    Check if the provided expiration token is still valid.

    Args:
        token: The expiration token.

    Returns:
        True if the token is valid, False otherwise.
    """
    if not token.includes("exp_"):
        return False
    
    expiration_time = int(token.split("_")[1])
    current_time = int(time.time())
    
    return current_time < expiration_time