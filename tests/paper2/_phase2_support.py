"""Explicit small workload configurations; no defaults for fee distributions."""


def generator_parameters(**changes):
    value = dict(run_id="generator-check", replicate=0, horizon=3,
        arrivals_valid=dict(kind="poisson", rate=3),
        fee_distribution=dict(name="uniform_int", low=1, high=3),
        amount_distribution=dict(name="constant", value=10),
        senders=["alice", "bob"], initial_balance=1000000000, receiver="merchant",
        scheme=dict(signature_bytes=64, public_key_bytes=32, include_public_key=False,
                    alg_id="model-ed25519", param_set_id="model-ed25519"),
        block_period=1, block_size=10, p_seen=1, arrivals_invalid=dict(kind="poisson", rate=3),
        invalid_kinds=["bit_flip", "random_bytes"])
    value.update(changes)
    return value
