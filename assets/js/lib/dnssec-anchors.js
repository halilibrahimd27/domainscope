/**
 * dnssec-anchors.js — the root zone trust anchors the DNSSEC validator (lib/dnssec.js) starts
 * its chain of trust from: the two root key-signing keys IANA publishes, KSK-2017 (key tag
 * 20326) and KSK-2024 (key tag 38696), as their DS digests with the DNSKEY data next to them.
 *
 * Source: https://data.iana.org/root-anchors/root-anchors.xml (the KeyDigest elements without a
 * validUntil, read 2026-10-08; KSK-2010, key tag 19036, expired on 2019-01-11 and is left out).
 * A root key rollover means a new entry here, from that file and nowhere else.
 *
 * A module of its own so that a test can serve other anchors (an e2e suite answers this file
 * with the anchor of its signed fixture root). DOM-free, no I/O.
 */

/**
 * @typedef {object} TrustAnchor
 * @property {string} zone always '.'
 * @property {string} id IANA's name of the key ('KSK-2017')
 * @property {number} keyTag
 * @property {number} algorithm DNSSEC algorithm number (8: RSA/SHA-256)
 * @property {number} digestType DS digest type (2: SHA-256)
 * @property {string} digest lowercase hex
 * @property {number} flags DNSKEY flags (257: zone key + secure entry point)
 * @property {string} publicKey DNSKEY public key, base64
 * @property {string} validFrom ISO date
 */

/** The IANA root trust anchors in force. @type {ReadonlyArray<TrustAnchor>} */
export const ROOT_ANCHORS = Object.freeze([
  Object.freeze({
    zone: '.',
    id: 'KSK-2017',
    keyTag: 20326,
    algorithm: 8,
    digestType: 2,
    digest: 'e06d44b80b8f1d39a95c0b0d7c65d08458e880409bbc683457104237c7f8ec8d',
    flags: 257,
    publicKey: 'AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=',
    validFrom: '2017-02-02'
  }),
  Object.freeze({
    zone: '.',
    id: 'KSK-2024',
    keyTag: 38696,
    algorithm: 8,
    digestType: 2,
    digest: '683d2d0acb8c9b712a1948b27f741219298d0a450d612c483af444a4c0fb2b16',
    flags: 257,
    publicKey: 'AwEAAa96jeuknZlaeSrvyAJj6ZHv28hhOKkx3rLGXVaC6rXTsDc449/cidltpkyGwCJNnOAlFNKF2jBosZBU5eeHspaQWOmOElZsjICMQMC3aeHbGiShvZsx4wMYSjH8e7Vrhbu6irwCzVBApESjbUdpWWmEnhathWu1jo+siFUiRAAxm9qyJNg/wOZqqzL/dL/q8PkcRU5oUKEpUge71M3ej2/7CPqpdVwuMoTvoB+ZOT4YeGyxMvHmbrxlFzGOHOijtzN+u1TQNatX2XBuzZNQ1K+s2CXkPIZo7s6JgZyvaBevYtxPvYLw4z9mR7K2vaF18UYH9Z9GNUUeayffKC73PYc=',
    validFrom: '2024-07-18'
  })
]);
