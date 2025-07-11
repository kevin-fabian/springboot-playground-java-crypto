# Java Cryptography Best Practices & Sample Algorithms


# Java Cryptography Best Practices & Sample Algorithms
X25519 and Ed25519 are recommended for new systems.
RSA is still widely used but is considered less secure for new applications.
| Algorithm   | Use for Key Exchange? | Use for Signing? | Best Usage                               |
| ----------- | --------------------- | ---------------- | ---------------------------------------- |
| **X25519**  | ✅ Yes                 | ❌ No             | Key exchange (TLS, VPNs, Signal)         |
| **Ed25519** | ❌ No                  | ✅ Yes            | Digital signatures (JWTs, SSH)           |
| **RSA**     | ✅ Yes (Key Transport) | ✅ Yes            | Legacy, but still used in certs and JWTs |

## Recommendation
| Task            | Modern Choice     |
| --------------- |-------------------|
| Key Exchange    | ✅ X25519 (ECC)    |
| Sign/Verify     | ✅ Ed25519         |
| Encrypt/Decrypt | ✅ AES/GCM         |
| MAC/Integrity   | ✅ HMAC / Poly1305 |


## RSA
avoid 1024-bit (deprecated, <80-bit security); 2048-bit is minimum, 4096-bit is future-proof.

## SHA
Default: SHA-256. It’s the sweet spot—secure (128-bit resistance), fast, and universally supported in SSH and JWT.
Higher Security: SHA-512 if you need >128-bit resistance (rarely necessary).
Avoid: SHA-1 and MD5 for anything security-related.
Watch: SHA-3 or BLAKE3 for future-proofing, though they’re not yet mainstream in SSH/JWT