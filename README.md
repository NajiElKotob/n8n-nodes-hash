# n8n-nodes-hash

Hash text, files or JSON in n8n using algorithms the built-in Crypto node does not offer.

## Why this exists

n8n already ships a **Crypto** node, and for MD5, SHA-256, SHA-384, SHA-512 and the SHA3 family it is the right tool. This node exists for everything that falls outside that list: **SHA1** for legacy APIs that still demand it, **SHA-224** and **SHA-512/256**, **RIPEMD-160** for Bitcoin-style address work, **BLAKE2b** and **BLAKE2s**, **SM3** for Chinese regulatory use, and **CRC32** for cheap deduplication keys where a cryptographic hash is wasted effort.

It also adds things the Crypto node has no option for: **base64url** output for URL-safe identifiers, **truncation** for short keys, **salt** with a choice of position, an optional **pepper** applied through HMAC, and hashing a **whole JSON object** with sorted keys so the same record always produces the same hash regardless of field order.

Zero runtime dependencies. Everything comes from Node's built-in `node:crypto`, with CRC32 implemented directly.

## Installation

Settings → Community nodes → Install → `n8n-nodes-hash`

## Parameters

| Parameter       | Description                                                                                |
| --------------- | ------------------------------------------------------------------------------------------ |
| Input Type      | `Text`, `Binary File`, or `JSON Object`                                                    |
| Value           | The text to hash. Shown for Text input.                                                    |
| Binary Property | Name of the binary property holding the file, default `data`. Shown for Binary File input. |
| Algorithm       | One of 14, see below                                                                       |
| Salt            | Optional value joined to the input before hashing                                          |
| Salt Position   | `Prefix` or `Suffix`. Appears once a salt is entered.                                      |
| Pepper Secret   | Optional HMAC key. Masked in the interface but stored in the workflow.                     |

### Algorithms

BLAKE2b-512, BLAKE2s-256, CRC32, MD5, RIPEMD-160, SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/256, SHA1, SHA3-256, SHA3-512, SM3

### Options

| Option            | Default | Description                                                                                       |
| ----------------- | ------- | ------------------------------------------------------------------------------------------------- |
| Encoding          | `Hex`   | `Hex`, `Base64` or `Base64url`. Base64url is URL-safe and unpadded.                               |
| Include Metadata  | off     | Writes algorithm, encoding, input type and salt alongside the hash so the value can be reproduced |
| Output Field Name | `hash`  | Field the hash is written to                                                                      |
| Truncate Length   | `0`     | Characters to keep from the start, `0` keeps the full digest                                      |
| Uppercase         | off     | Uppercases hex output                                                                             |

The input item passes through unchanged, with the hash added as a new field. Binary data passes through untouched, so the node can sit mid-pipeline.

## Things that look like bugs but are not

**Uppercase does nothing for Base64.** Base64 and base64url are case-sensitive alphabets, so uppercasing them would produce a string that decodes to different bytes. The option applies to hex only, silently.

**Binary File hashes the file's bytes, not its text.** Hashing a PDF gives you a checksum of the file itself, not a hash of the words inside it. To hash the text, put an Extract From File node in front and hash its output as Text.

**CRC32 rejects a pepper.** A pepper is applied using HMAC, which needs a cryptographic hash function. CRC32 is an error-detecting checksum, not a hash function, so the combination is refused rather than silently producing something meaningless.

**Truncation increases collisions.** Cutting a hash to 8 characters leaves 32 bits. That is fine for a cache key and not fine for anything where a collision matters.

## Pepper

A **pepper** is a single secret shared across every hash the node produces, unlike a salt which varies per record. It is set in the **Pepper Secret** field, which is masked in the interface.

Masked is not the same as encrypted. The value is stored in the workflow like any other parameter, so it appears in workflow exports, in backups, and in version control if you commit workflows. Treat an exported workflow containing a pepper as a secret in its own right. If that is not acceptable for your use case, use a salt stored alongside your data instead, and accept the weaker guarantee.

When a pepper is set, the node switches from `createHash` to `createHmac`. This is deliberate: `hash(pepper + value)` is vulnerable to length-extension attacks on MD5, SHA1 and SHA-256, and HMAC exists to solve exactly that. The pepper is never written to the output, even with Include Metadata switched on.

Changing the pepper invalidates every hash produced with the previous one. There is no way to recover them.

## Security notes

**MD5, SHA1 and CRC32 are here for compatibility, not security.** MD5 and SHA1 both have practical collision attacks. CRC32 is not a hash function at all. Use them for checksums, cache keys and legacy API signatures, and nothing else.

**The pepper is stored in the workflow.** See the Pepper section above. It is masked in the interface, not encrypted at rest.

**A salt does not make a fast hash safe for passwords.** SHA-256 is designed to be fast, and commodity hardware tries billions of candidates per second whether or not a salt is present. Salting protects against precomputed rainbow tables, and that is all it does. For passwords, use a deliberately slow key derivation function such as scrypt, bcrypt or Argon2. This node does not currently offer one.

## Example uses

**Detect changed records.** Set Input Type to JSON Object, hash each row from your source, and compare against the hash you stored last run. Only rows whose hash changed need to be written. Sorted-key hashing means a reordered payload from the API does not register as a change.

**Verify a download.** Fetch a file with HTTP Request, hash the binary property with SHA-256, and compare against the checksum published by the vendor with an IF node.

**Build short URL-safe IDs.** SHA-256, Base64url encoding, Truncate Length 12. No padding characters, nothing that needs escaping in a URL.

**Pseudonymize personal data.** Hash an email address with a salt so records can still be joined across systems without storing the address itself. Store the salt with the data, or the hashes can never be reproduced.

**Legacy API signatures.** Some payment and telecom APIs still require SHA1 or an HMAC over a concatenated parameter string. Set the algorithm to SHA1 and put the shared secret in the pepper Secret field.

## Compatibility

Requires n8n 1.x on Node.js 20 or later. Tested against n8n 1.x with the community node API version 1.

RIPEMD-160 and SM3 depend on the OpenSSL build behind your n8n instance. On the rare build compiled without them, the node fails with a message naming the algorithm rather than crashing.

## Resources

- [n8n community nodes documentation](https://docs.n8n.io/integrations/#community-nodes)
- [n8n built-in Crypto node](https://docs.n8n.io/integrations/builtin/core-nodes/n8n-nodes-base.crypto/)

## Version history

**0.1.3** — Pepper moved from a credential to a masked node parameter.

**0.1.2** — Contactable author email in package metadata.

**0.1.1** — Initial release. 14 algorithms, three input types, hex/base64/base64url encoding, salt with position, optional pepper via HMAC, truncation, and optional metadata output.

## License

[MIT](LICENSE.md)
