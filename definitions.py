# API
ALGORITHM_PLAIN = 0
ALGORITHM_RSA = 1
ALGORITHM_AES = 2

SIGN_LEVEL_ALL = 3
SIGN_LEVEL_ENCRYPTED = 4
SIGN_LEVEL_NONE = 5

HOC_TRUE = 6
HOC_FALSE = 7

USE_TOR = 8
PROXY_STRICT = 9
PROXY_NON_STRICT = 10

Socket_options = {

    # General
    "handshake_on_connect": HOC_TRUE,
    "algorithm": ALGORITHM_PLAIN,
    ""

    # Signatures
    "local_signing_key": "",
    "local_verify_key": "",

    "peer_verify_key": "",

    # Encryption
    "local_private_key": "",
    "local_public_key": "",

    "peer_public_key": "",
    
    "shared_key": "",

    # Anonymity
    "use_tor": 0,
    "continue_proxy_fail": PROXY_STRICT,

    # Authentication
    "sign_level": SIGN_LEVEL_ALL

}
# End

# Protocol
D_HEAD_BEGIN = '-----BEGIN %s-----\n'
D_HEAD_END =   '\n-----END %s-----'
