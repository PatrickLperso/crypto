

if __name__ == "__main__":
    # ================== Test Reduction ==================
    test_reduction()

    # ================== Test Biaised signatures sha1 nonce leading 96 bit 0 ==================
    interface = exemple_signature
    signatures = samples(interface, hash_function_message=sha256, nb_signatures=3, signing_function=signer_ecdsa_sha1_nonce)

    key = challenge(hash_function_message=sha256, signatures = signatures, bit_length_prefix=96, biais=0)
    print(f"\nkey recovered: {key}")

    # ================== Test Biaised signatures sha256 leading 10 bit fixed to 0b1001110101 ==================
    interface = exemple_signature

    biais = int("1001110101", 2)
    signatures = samples(interface, hash_function_message=sha256, nb_signatures=32, signing_function=signer_ecdsa_nonce_with_10_MSB_biaised)

    key = challenge(hash_function_message=sha256, signatures=signatures, bit_length_prefix=10, biais=biais)
    print(f"\nkey recovered: {key}")
