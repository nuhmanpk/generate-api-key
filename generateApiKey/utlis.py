import time

async def generate_expiration_token(minutes: int) -> str:
        """
        Generate an expiration token based on the provided expiration time in minutes.

        Args:
            minutes: Expiration time in minutes.

        Returns:
            An expiration token.
        """
        expiration_time = int(time.time()) + (minutes * 60)
        return f"exp_{expiration_time}"