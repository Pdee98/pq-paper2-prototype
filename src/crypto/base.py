from abc import ABC, abstractmethod
from dataclasses import dataclass


def message_to_bytes(message: str | bytes) -> bytes:
    if isinstance(message, bytes):
        return message
    return message.encode("utf-8")


@dataclass(frozen=True)
class BackendInfo:
    name: str
    parameter_set: str
    implementation: str
    language: str = "unspecified"
    signature_size: int | None = None
    public_key_size: int | None = None
    conformance_status: str = "not assessed"


class CryptoBackend(ABC):
    @abstractmethod
    def sign(self, message: str | bytes, signer_id: int) -> bytes:
        pass

    @abstractmethod
    def verify(self, message: str | bytes, signature: bytes, signer_id: int) -> bool:
        pass

    @abstractmethod
    def get_name(self) -> str:
        pass

    @abstractmethod
    def get_signature_size(self) -> int:
        pass

    @abstractmethod
    def get_public_key_size(self) -> int:
        pass

    @abstractmethod
    def get_private_key_size(self) -> int:
        pass

    def prepare_signer(self, signer_id: int) -> None:
        pass

    def get_info(self) -> BackendInfo:
        return BackendInfo(
            name=self.get_name(),
            parameter_set="unspecified",
            implementation=self.__class__.__name__,
        )
