import httpx
from app.config import settings

class CryptoClient:
    def __init__(self):
        self.base_url = settings.crypto_service_url

    async def encrypt(self, plaintext: str) -> dict:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.base_url}/api/v1/crypto/encrypt",
                json={"plaintext": plaintext}
            )
            response.raise_for_status()
            return response.json()

    async def decrypt(self, envelope: dict) -> str:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.base_url}/api/v1/crypto/decrypt",
                json=envelope
            )
            response.raise_for_status()
            return response.json()["plaintext"]

    async def decrypt_batch(self, envelopes: list[dict]) -> list[dict]:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.base_url}/api/v1/crypto/decrypt-batch",
                json={"envelopes": envelopes}
            )
            response.raise_for_status()
            return response.json()["results"]

crypto_client = CryptoClient()
