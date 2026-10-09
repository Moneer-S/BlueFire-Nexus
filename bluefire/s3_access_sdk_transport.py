"""Response byte bounds around the official SDK transport, not a new HTTP client."""

from __future__ import annotations

from typing import Any, Callable, Iterator

from .s3_access_contract import S3AccessError

MAX_RESPONSE_BYTES = 64 * 1024
CHUNK_BYTES = 8192


class BoundedSdkBody:
    def __init__(self, raw: Any, checkpoint: Callable[[], None]):
        self.raw, self.checkpoint = raw, checkpoint
        self.total = 0
        self.closed = False

    def read(self, amt: int | None = None, decode_content: bool = False, **kwargs: Any) -> bytes:
        if decode_content or kwargs or (amt is not None and (type(amt) is not int or amt < 0)):
            self.close()
            raise S3AccessError("SDK response read mode is unsupported")
        if amt is None:
            return b"".join(self.stream())
        if self.closed or amt == 0:
            return b""
        try:
            self.checkpoint()
            chunk = self.raw.read(
                min(amt, CHUNK_BYTES, MAX_RESPONSE_BYTES + 1 - self.total), decode_content=False
            )
            self.checkpoint()
            if type(chunk) is not bytes:
                raise S3AccessError("SDK response stream is invalid")
            self.total += len(chunk)
            if self.total > MAX_RESPONSE_BYTES:
                raise S3AccessError("SDK response exceeds its byte allowance")
            if not chunk:
                self.close()
            return chunk
        except Exception:
            self.close()
            raise

    def stream(
        self, amt: int | None = CHUNK_BYTES, decode_content: bool = False
    ) -> Iterator[bytes]:
        size = CHUNK_BYTES if amt is None else amt
        if type(size) is not int or size <= 0:
            self.close()
            raise S3AccessError("SDK response chunk size is invalid")
        while True:
            chunk = self.read(size, decode_content=decode_content)
            if not chunk:
                break
            yield chunk

    def tell(self) -> int:
        return self.total

    def close(self) -> None:
        if not self.closed:
            self.closed = True
            try:
                self.raw.close()
            except Exception:
                pass


class BoundedSdkTransport:
    """Retains SDK TLS/signing/parser behavior while preventing eager body reads.

    Native runtime admission must pin and test this private SDK interface. The
    body cap does not claim to bound TLS/header buffers or replace native limits.
    """

    def __init__(
        self,
        official_session: Any,
        claim_send: Callable[[Any], None],
        checkpoint: Callable[[], None],
    ):
        self.session, self.claim_send, self.checkpoint = official_session, claim_send, checkpoint
        self.bodies: list[BoundedSdkBody] = []

    def send(self, request: Any) -> Any:
        self.checkpoint()
        self.claim_send(request)
        streaming = request.stream_output
        response = None
        try:
            # URLLib3Session otherwise exhausts .content before returning to us.
            request.stream_output = True
            response = self.session.send(request)
            body = BoundedSdkBody(response.raw, self.checkpoint)
            self.bodies.append(body)
            response.raw = body
            self.checkpoint()
            headers = {str(key).lower(): value for key, value in response.headers.items()}
            if headers.get("content-encoding", "identity") != "identity":
                raise S3AccessError("encoded SDK responses are unsupported")
            length = headers.get("content-length")
            if length is not None and (
                not isinstance(length, str)
                or not length.isascii()
                or not length.isdecimal()
                or len(length) > 8
                or int(length) > MAX_RESPONSE_BYTES
            ):
                raise S3AccessError("SDK response length is unsupported")
            if not streaming or response.status_code >= 300:
                _ = response.content
            return response
        except Exception:
            if response is not None:
                try:
                    response.raw.close()
                except Exception:
                    pass
            raise
        finally:
            request.stream_output = streaming

    def close(self) -> None:
        for body in self.bodies:
            body.close()
        self.session.close()
