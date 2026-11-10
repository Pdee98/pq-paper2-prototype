"""Author-approved Deviation 8 engineering caps; no scientific guard changes."""
CALIBRATION={'xmss':1200,'ml_dsa_44':1900}
PREPARATION_US=70.7
SERIALISATION_US=208.4
BLOCK_MESSAGE='Run #7 blocked: replay timeouts not finalised; dry-run and timing receipts required'
V5_SECONDS_PER_MESSAGE={'xmss':178.35452754099992/61689,
                        'ml_dsa_44':73.38280058500004/108906}


def presigning(backend,messages):
    import math
    if isinstance(messages,bool) or not isinstance(messages,int) or messages<1:
        raise ValueError('positive exact signed-message count required')
    seconds=V5_SECONDS_PER_MESSAGE[backend]*messages
    return dict(projected_seconds=seconds,cap_seconds=100*math.ceil(2*seconds/100),
                end_to_end_seconds_per_message=V5_SECONDS_PER_MESSAGE[backend],
                includes_key_generation=True,extra_signing_margin=1)


def for_transactions(count):
    if isinstance(count,bool) or not isinstance(count,int) or count<1:raise ValueError('positive exact audited transaction count required')
    return {'preparation':max(30.,2*PREPARATION_US*count/1e6),
            'prototype window':110.,'serialisation':max(60.,2*SERIALISATION_US*count/1e6)}
