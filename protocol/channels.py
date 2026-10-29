"""Authenticated handshake state machines (design v2 section 4) and record plumbing.

One state machine shape, two roles:
    Client: INIT -> M1_SENT -> M3_SENT -> ESTABLISHED -> CLOSED | FAILED(reason)
    Server: INIT -> M2_SENT -> ESTABLISHED -> CLOSED | FAILED(reason)

Verification order is FIXED on every authenticated input:
    policy -> trust-store lookup -> signature -> Finished
An attacker-supplied verification key is never reachable: there is no code path
that consumes a vk from the wire (design v2 section 1).

Prototype limitation (documented): Python cannot guarantee memory hygiene;
zeroization below is best-effort defense-in-depth.
"""
from __future__ import annotations

import base64
import hmac
import os
import time
from collections import OrderedDict

from . import keyschedule as ks
from . import records as rec
from .errors import (
    AuthenticationFailure,
    ChannelError,
    HandshakeReplayDetected,
    PolicyViolation,
    SessionExhausted,
    TranscriptBindingError,
    UntrustedIdentity,
)
from .suites import (
    DEFAULT_ALLOWED,
    Suite,
    kem_decapsulate,
    kem_encapsulate,
    kem_generate,
    resolve_suite,
    sig_sign,
    sig_verify,
)
from .tlv import (
    M1_TAGS,
    M2_TAGS,
    M3_TAGS,
    TAG_FIN_C,
    TAG_FIN_S,
    TAG_ID_S,
    TAG_KEM_CT,
    TAG_KEM_PK_C,
    TAG_NONCE_C,
    TAG_NONCE_S,
    TAG_PROTO_VERSION,
    TAG_SIG_C,
    TAG_SIG_S,
    TAG_SUITE_ID,
    encode_message,
    encode_tlv,
    parse_message,
)

STATE_INIT = "INIT"
STATE_M1_SENT = "M1_SENT"
STATE_M2_SENT = "M2_SENT"
STATE_M3_SENT = "M3_SENT"
STATE_ESTABLISHED = "ESTABLISHED"
STATE_CLOSED = "CLOSED"
STATE_FAILED = "FAILED"

_NONCE_LEN = 32


def _len_error(field: str, expected: int) -> TranscriptBindingError:
    return TranscriptBindingError(
        f"{field} length does not match suite parameters (expected {expected})"
    )


class Endpoint:
    """One end of an in-memory wire: outbox frames waiting for delivery."""

    def __init__(self, name: str = "endpoint") -> None:
        self.name = name
        self.outbox: list[bytes] = []

    def send(self, frame: bytes) -> None:
        self.outbox.append(frame)


class BaseChannel:
    role = "base"

    def __init__(
        self,
        *,
        suite_id: str,
        trust_store: dict,
        identity: str,
        sign_sk: object,
        endpoint: Endpoint,
        allowed_suites: frozenset[str] | set[str] = DEFAULT_ALLOWED,
        max_records: int = rec.DEFAULT_MAX_RECORDS,
    ) -> None:
        self._suite_id_cfg = suite_id
        self._suite: Suite | None = None
        self._trust = trust_store
        self.identity = identity
        self._sign_sk = sign_sk
        self._endpoint = endpoint
        self._allowed = frozenset(allowed_suites)
        self._max_records = max_records
        self.state = STATE_INIT
        self.failure_category: str | None = None
        self.failure_detail: str | None = None
        self._inbox: list[bytes] = []
        self._send_key: bytearray | None = None
        self._send_nb: bytes | None = None
        self._recv_key: bytearray | None = None
        self._recv_nb: bytes | None = None
        self._recv_window = rec.ReplayWindow()
        self._send_seq = 0
        self._send_dir = 0
        self._recv_dir = 0
        self.exporter: bytes | None = None
        # transient handshake secrets (best-effort zeroized on terminal states)
        self._kem_sk: object | None = None
        self._m1_frame: bytes | None = None
        self._ss: bytearray | None = None
        self._prk: bytearray | None = None
        self._fk: bytearray | None = None

    # -- introspection -------------------------------------------------------
    @property
    def established(self) -> bool:
        return self.state == STATE_ESTABLISHED

    @property
    def suite_id(self) -> str | None:
        return self._suite.suite_id if self._suite else None

    def _fail(self, exc: ChannelError) -> None:
        self.state = STATE_FAILED
        self.failure_category = exc.category
        self.failure_detail = str(exc)
        self._wipe_secrets()

    def _wipe_secrets(self) -> None:
        ks.zeroize(self._ss, self._prk, self._fk, self._send_key, self._recv_key)
        self._ss = self._prk = self._fk = None
        self._send_key = self._recv_key = None
        self._kem_sk = None
        self._m1_frame = None

    # -- trust store (design v2 section 1) ------------------------------------
    def _trust_lookup(self, identity: str, expected_role: str) -> bytes:
        entry = self._trust.get("identities", {}).get(identity)
        if entry is None:
            raise UntrustedIdentity(f"identity '{identity}' is not pinned in the trust store")
        if entry.get("role") != expected_role:
            raise UntrustedIdentity(
                f"identity '{identity}' has role '{entry.get('role')}', "
                f"expected '{expected_role}'"
            )
        vk_b64 = entry.get("keys", {}).get(self._suite.suite_id)  # type: ignore[union-attr]
        if not vk_b64:
            raise UntrustedIdentity(
                f"no pinned verification key for suite {self._suite.suite_id}"
            )
        return base64.b64decode(vk_b64)

    @staticmethod
    def _check_version(value: bytes) -> None:
        if value != bytes([0x02]):
            raise PolicyViolation(f"unsupported proto_version 0x{value.hex()}")

    # -- record layer (design v2 section 5) ------------------------------------
    def _init_records(self, keys: dict[str, bytes], send_dir: int, recv_dir: int) -> None:
        if send_dir == rec.DIR_C2S:
            self._send_key = bytearray(keys["c2s_key"])
            self._send_nb = keys["nb_c2s"]
            self._recv_key = bytearray(keys["s2c_key"])
            self._recv_nb = keys["nb_s2c"]
        else:
            self._send_key = bytearray(keys["s2c_key"])
            self._send_nb = keys["nb_s2c"]
            self._recv_key = bytearray(keys["c2s_key"])
            self._recv_nb = keys["nb_c2s"]
        self._send_dir = send_dir
        self._recv_dir = recv_dir
        self._recv_window = rec.ReplayWindow()
        self._send_seq = 0
        self.exporter = keys["exporter"]

    def send(self, data: bytes) -> None:
        if self.state != STATE_ESTABLISHED:
            raise ChannelError(f"send() requires ESTABLISHED, state is {self.state}")
        if self._send_seq >= min(self._max_records, rec.SEQ_HARD_CAP):
            raise SessionExhausted("session record cap reached; renegotiate via new handshake")
        frame = rec.encrypt_record(
            self._send_key, self._send_nb, rec.TYPE_APP_DATA, self._send_dir,
            self._send_seq, data,
        )
        self._send_seq += 1
        self._endpoint.send(frame)

    def close(self) -> None:
        """Authenticated close (type 0x02); forged closes fail authentication."""
        if self.state == STATE_ESTABLISHED and self._send_key is not None:
            frame = rec.encrypt_record(
                self._send_key, self._send_nb, rec.TYPE_CLOSE, self._send_dir,
                self._send_seq, b"",
            )
            self._send_seq += 1
            self._endpoint.send(frame)
        self.state = STATE_CLOSED
        self._wipe_secrets()

    def recv(self) -> bytes | None:
        """Pop one decrypted application record; None when nothing pending."""
        if self._inbox:
            return self._inbox.pop(0)
        return None

    def _on_record(self, frame: bytes) -> None:
        _seq, rtype, plaintext = rec.open_record(
            self._recv_key, self._recv_nb, self._recv_window, self._recv_dir, frame
        )
        if rtype == rec.TYPE_CLOSE:
            self.state = STATE_CLOSED
            self._wipe_secrets()
        else:
            self._inbox.append(plaintext)

    # -- dispatch ---------------------------------------------------------------
    def on_frame(self, frame: bytes) -> None:
        """Entry point for every wire frame. Typed failures are recorded on the
        channel (state FAILED + failure_category); the pump never crashes."""
        if self.state in (STATE_FAILED, STATE_CLOSED):
            return  # terminal states ignore late frames
        try:
            self._dispatch(frame)
        except ChannelError as exc:
            self._fail(exc)
        except Exception as exc:  # unexpected bug: still fail closed
            self._fail(ChannelError(f"internal error: {type(exc).__name__}: {exc}"))

    def _dispatch(self, frame: bytes) -> None:  # pragma: no cover - overridden
        raise NotImplementedError


class ClientChannel(BaseChannel):
    """Initiator (Alice). Sends M1, verifies M2, sends M3."""

    role = "client"

    def start(self) -> None:
        if self.state != STATE_INIT:
            raise ChannelError("start() already called")
        try:
            if self._suite_id_cfg not in self._allowed:
                raise PolicyViolation(f"suite {self._suite_id_cfg} not allowed by local policy")
            self._suite = resolve_suite(self._suite_id_cfg.encode(), self._allowed)
            self._kem_sk, kem_pk = kem_generate(self._suite)
            self._m1_frame = encode_message(M1_TAGS, {
                TAG_PROTO_VERSION: bytes([0x02]),
                TAG_SUITE_ID: self._suite.suite_id.encode(),
                0x03: self.identity.encode(),
                TAG_KEM_PK_C: kem_pk,
                0x05: os.urandom(_NONCE_LEN),
            })
            self._endpoint.send(self._m1_frame)
            self.state = STATE_M1_SENT
        except ChannelError as exc:
            self._fail(exc)

    def _dispatch(self, frame: bytes) -> None:
        if self.state == STATE_M1_SENT:
            self._on_m2(frame)
        elif self.state == STATE_ESTABLISHED:
            self._on_record(frame)
        else:
            raise ChannelError(f"unexpected frame in state {self.state}")

    def _on_m2(self, frame: bytes) -> None:
        suite = self._suite
        values = parse_message(frame, M2_TAGS)  # strict: order/dup/trailing (T2)
        self._check_version(values[TAG_PROTO_VERSION])
        echoed = resolve_suite(values[TAG_SUITE_ID], self._allowed)  # policy first (T9)
        if echoed.suite_id != suite.suite_id:
            raise PolicyViolation("server echoed a different suite than local policy chose")

        id_s = values[TAG_ID_S].decode("utf-8", errors="replace")
        self._suite = echoed
        vk_s = self._trust_lookup(id_s, expected_role="server")  # lookup before sig math

        kem_ct = values[TAG_KEM_CT]
        if len(kem_ct) != suite.kem_ct_len:
            raise _len_error("kem_ct", suite.kem_ct_len)
        if len(values[TAG_NONCE_S]) != _NONCE_LEN:
            raise _len_error("nonce_S", _NONCE_LEN)
        sig_s = values[TAG_SIG_S]
        if len(sig_s) != suite.sig_len:
            raise _len_error("sig_S", suite.sig_len)

        ss = kem_decapsulate(suite, self._kem_sk, kem_ct)

        # T2 = M1 exactly as sent || M2 core TLVs rebuilt from received values
        s_core = b"".join([
            encode_tlv(TAG_PROTO_VERSION, values[TAG_PROTO_VERSION]),
            encode_tlv(TAG_SUITE_ID, values[TAG_SUITE_ID]),
            encode_tlv(TAG_ID_S, values[TAG_ID_S]),
            encode_tlv(TAG_KEM_CT, kem_ct),
            encode_tlv(TAG_NONCE_S, values[TAG_NONCE_S]),
        ])
        t2 = self._m1_frame + s_core
        sig_verify(suite, vk_s, ks.CTX_SERVER, t2, sig_s)  # AuthenticationFailure on bad
        sig_s_tlv = encode_tlv(TAG_SIG_S, sig_s)
        t3 = t2 + sig_s_tlv

        th2 = ks.transcript_hash_2(t3)
        self._ss = bytearray(ss)
        self._prk = bytearray(ks.derive_prk(th2, ss))
        self._fk = bytearray(ks.finished_key(bytes(self._prk)))
        expected_fin_s = ks.finished_server(bytes(self._fk), th2)
        if not hmac.compare_digest(expected_fin_s, values[TAG_FIN_S]):
            raise AuthenticationFailure("server Finished (fin_S) verification failed")

        # client signs T3 (covers sig_S) and confirms keys
        sig_c = sig_sign(suite, self._sign_sk, ks.CTX_CLIENT, t3)
        sig_c_tlv = encode_tlv(TAG_SIG_C, sig_c)
        th3 = ks.transcript_hash_3(t3, sig_c_tlv)
        fin_c = ks.finished_client(bytes(self._fk), th3)
        fin_c_tlv = encode_tlv(TAG_FIN_C, fin_c)
        self._endpoint.send(sig_c_tlv + fin_c_tlv)  # M3

        th4 = ks.transcript_hash_4(t3, sig_c_tlv, fin_c_tlv)
        keys = ks.derive_traffic_keys(bytes(self._prk), th4)
        self._init_records(keys, send_dir=rec.DIR_C2S, recv_dir=rec.DIR_S2C)
        self.state = STATE_ESTABLISHED
        ks.zeroize(self._ss, self._prk, self._fk)
        self._ss = self._prk = self._fk = None


class ServerChannel(BaseChannel):
    """Responder (Bob). Verifies M1, sends M2, verifies M3."""

    role = "server"

    def __init__(
        self,
        *,
        handshake_cache_ttl: float = 300.0,
        handshake_cache_size: int = 4096,
        enable_handshake_cache: bool = True,
        handshake_cache: OrderedDict | None = None,
        **kwargs,
    ) -> None:
        super().__init__(**kwargs)
        self._cache_enabled = enable_handshake_cache
        self._cache_ttl = handshake_cache_ttl
        self._cache_size = handshake_cache_size
        # The cache models SERVER-DEPLOYMENT state across connections: pass the
        # same OrderedDict to multiple ServerChannel instances (connections).
        self._cache = handshake_cache if handshake_cache is not None else OrderedDict()
        # per-handshake state (derivation order: each step consumes earlier outputs)
        self._t2: bytes | None = None
        self._sig_s_tlv: bytes | None = None
        self._peer_id: str | None = None

    def _cache_check_and_add(self, id_c: str, nonce_c: bytes) -> None:
        """(id_C, nonce_C) freshness cache: DoS hygiene + early replay rejection.
        NOT the correctness anchor (design v2 section 6)."""
        if not self._cache_enabled:
            return
        key = (id_c, nonce_c)
        now = time.monotonic()
        ts = self._cache.get(key)
        if ts is not None and now - ts <= self._cache_ttl:
            raise HandshakeReplayDetected(f"M1 replay for '{id_c}' (nonce cache hit)")
        self._cache[key] = now
        self._cache.move_to_end(key)
        while len(self._cache) > self._cache_size:
            self._cache.popitem(last=False)

    def _dispatch(self, frame: bytes) -> None:
        if self.state == STATE_INIT:
            self._on_m1(frame)
        elif self.state == STATE_M2_SENT:
            self._on_m3(frame)
        elif self.state == STATE_ESTABLISHED:
            self._on_record(frame)
        else:
            raise ChannelError(f"unexpected frame in state {self.state}")

    def _on_m1(self, frame: bytes) -> None:
        values = parse_message(frame, M1_TAGS)  # strict
        self._check_version(values[TAG_PROTO_VERSION])
        suite = resolve_suite(values[TAG_SUITE_ID], self._allowed)  # policy first (T9)
        self._suite = suite

        id_c = values[0x03].decode("utf-8", errors="replace")
        self._peer_id = id_c
        self._trust_lookup(id_c, expected_role="client")  # before any signature math

        nonce_c = values[TAG_NONCE_C]
        if len(nonce_c) != _NONCE_LEN:
            raise _len_error("nonce_C", _NONCE_LEN)
        self._cache_check_and_add(id_c, nonce_c)  # T8c
        kem_pk = values[TAG_KEM_PK_C]
        if len(kem_pk) != suite.kem_pk_len:
            raise _len_error("kem_pk_C", suite.kem_pk_len)

        ss, kem_ct = kem_encapsulate(suite, kem_pk)

        nonce_s = os.urandom(_NONCE_LEN)
        s_core = b"".join([
            encode_tlv(TAG_PROTO_VERSION, values[TAG_PROTO_VERSION]),
            encode_tlv(TAG_SUITE_ID, values[TAG_SUITE_ID]),
            encode_tlv(TAG_ID_S, self.identity.encode()),
            encode_tlv(TAG_KEM_CT, kem_ct),
            encode_tlv(TAG_NONCE_S, nonce_s),
        ])
        t2 = frame + s_core  # M1 exactly as received || server core
        sig_s = sig_sign(suite, self._sign_sk, ks.CTX_SERVER, t2)
        sig_s_tlv = encode_tlv(TAG_SIG_S, sig_s)
        t3 = t2 + sig_s_tlv

        th2 = ks.transcript_hash_2(t3)
        self._ss = bytearray(ss)
        self._prk = bytearray(ks.derive_prk(th2, ss))
        self._fk = bytearray(ks.finished_key(bytes(self._prk)))
        fin_s = ks.finished_server(bytes(self._fk), th2)

        self._t2 = t2
        self._sig_s_tlv = sig_s_tlv
        self._endpoint.send(encode_message(M2_TAGS, {
            TAG_PROTO_VERSION: values[TAG_PROTO_VERSION],
            TAG_SUITE_ID: values[TAG_SUITE_ID],
            TAG_ID_S: self.identity.encode(),
            TAG_KEM_CT: kem_ct,
            TAG_NONCE_S: nonce_s,
            TAG_SIG_S: sig_s,
            TAG_FIN_S: fin_s,
        }))
        self.state = STATE_M2_SENT

    def _on_m3(self, frame: bytes) -> None:
        suite = self._suite
        values = parse_message(frame, M3_TAGS)
        sig_c = values[TAG_SIG_C]
        if len(sig_c) != suite.sig_len:
            raise _len_error("sig_C", suite.sig_len)

        # trust lookup AGAIN at M3 (design v2 section 4 server path)
        vk_c = self._trust_lookup(self._peer_id, expected_role="client")  # type: ignore[arg-type]

        t3 = self._t2 + self._sig_s_tlv  # type: ignore[operator]
        sig_verify(suite, vk_c, ks.CTX_CLIENT, t3, sig_c)
        sig_c_tlv = encode_tlv(TAG_SIG_C, sig_c)
        th3 = ks.transcript_hash_3(t3, sig_c_tlv)
        expected_fin_c = ks.finished_client(bytes(self._fk), th3)  # type: ignore[arg-type]
        if not hmac.compare_digest(expected_fin_c, values[TAG_FIN_C]):
            raise AuthenticationFailure("client Finished (fin_C) verification failed")
        fin_c_tlv = encode_tlv(TAG_FIN_C, values[TAG_FIN_C])

        th4 = ks.transcript_hash_4(t3, sig_c_tlv, fin_c_tlv)
        keys = ks.derive_traffic_keys(bytes(self._prk), th4)  # type: ignore[arg-type]
        self._init_records(keys, send_dir=rec.DIR_S2C, recv_dir=rec.DIR_C2S)
        self.state = STATE_ESTABLISHED
        self._t2 = None
        self._sig_s_tlv = None
        ks.zeroize(self._ss, self._prk, self._fk)
        self._ss = self._prk = self._fk = None

