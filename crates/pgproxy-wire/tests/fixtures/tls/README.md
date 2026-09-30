`rsa-pss-sha384.der` is a public, self-signed localhost certificate generated
solely for endpoint digest tests. It uses RSA-PSS with SHA384 signature parameters;
the matching disposable private key was discarded. The digest test parses the
signature parameters and does not validate this fixture's expiry or trust chain.

Generated with OpenSSL `req -x509 -newkey rsa:2048 -sha384 -sigopt
rsa_padding_mode:pss`, then exported as DER. No operational certificates or
credentials belong in this directory.
