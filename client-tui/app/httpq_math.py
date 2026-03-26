import base64
import hashlib

try:
    from .httpq_protocol import HTTPQClientHello
except ImportError:
    from httpq_protocol import HTTPQClientHello


def httpq_transcript_bytes(
    *,
    realm: str,
    client_id: str,
    client_nonce_b64: str,
    server_nonce_b64: str,
    public_key_b64: str,
) -> bytes:
    hello = HTTPQClientHello(client_id=client_id, client_nonce_b64=client_nonce_b64)
    hello.validate()
    return "\n".join(
        [
            "HTTPq/1",
            realm,
            hello.client_id,
            hello.client_nonce_b64,
            server_nonce_b64,
            public_key_b64,
        ]
    ).encode("utf-8")


def sth_message(tree_size: int, root_hash: bytes) -> bytes:
    return "\n".join(
        [
            "KT-LOG/1",
            str(tree_size),
            base64.b64encode(root_hash).decode("ascii"),
        ]
    ).encode("utf-8")


def witness_message(
    *,
    log_id: str,
    tree_size: int,
    root_hash_b64: str,
    signing_public_key_b64: str,
) -> bytes:
    return "\n".join(
        [
            "WITNESS/1",
            log_id,
            str(tree_size),
            root_hash_b64,
            signing_public_key_b64,
        ]
    ).encode("utf-8")


def hash_leaf(leaf: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + leaf).digest()


def hash_node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def merkle_root_from_proof(*, record_bytes: bytes, index: int, proof: list[bytes]) -> bytes:
    current = hash_leaf(record_bytes)
    pos = index
    for sibling in proof:
        if pos % 2 == 0:
            current = hash_node(current, sibling)
        else:
            current = hash_node(sibling, current)
        pos //= 2
    return current


def verify_consistency_proof(
    *,
    old_tree_size: int,
    new_tree_size: int,
    old_root_hash: bytes,
    new_root_hash: bytes,
    proof: list[bytes],
) -> bool:
    if old_tree_size <= 0 or new_tree_size <= 0 or old_tree_size > new_tree_size:
        return False
    if old_tree_size == new_tree_size:
        return old_root_hash == new_root_hash and len(proof) == 0

    fn = old_tree_size - 1
    sn = new_tree_size - 1
    while fn % 2 == 1:
        fn //= 2
        sn //= 2

    if not proof:
        return False

    old_hash = proof[0]
    new_hash = proof[0]
    index = 1

    while fn != 0:
        if index >= len(proof):
            return False
        if fn % 2 == 1:
            old_hash = hash_node(proof[index], old_hash)
            new_hash = hash_node(proof[index], new_hash)
            index += 1
        elif fn < sn:
            new_hash = hash_node(new_hash, proof[index])
            index += 1
        fn //= 2
        sn //= 2

    while sn != 0:
        if index >= len(proof):
            return False
        new_hash = hash_node(new_hash, proof[index])
        index += 1
        sn //= 2

    return old_hash == old_root_hash and new_hash == new_root_hash
