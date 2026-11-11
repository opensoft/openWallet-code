// Maintainer-only generator. Never imports the candidate Python implementation.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

// Deliberately restricted to the fixture profile: no floating-point numbers,
// undefined, non-JSON objects or lone surrogates. Object keys use UTF-16 order.
function canonical(value) {
  if (value === null) return 'null';
  if (typeof value === 'string') {
    assert(value.isWellFormed());
    return JSON.stringify(value);
  }
  if (typeof value === 'number') {
    assert(Number.isSafeInteger(value) && value >= 0);
    return String(value);
  }
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  assert(value && Object.getPrototypeOf(value) === Object.prototype);
  return '{' + Object.keys(value).sort().map(
    key => JSON.stringify(key) + ':' + canonical(value[key])).join(',') + '}';
}

function keyFromPublicTestSeed(seedHex) {
  return crypto.createPrivateKey({
    key: Buffer.from('302e020100300506032b657004220420' + seedHex, 'hex'),
    format: 'der', type: 'pkcs8',
  });
}

function publicHex(key) {
  const der = crypto.createPublicKey(key).export({format: 'der', type: 'spki'});
  assert(der.subarray(0, 12).equals(Buffer.from('302a300506032b6570032100', 'hex')));
  return der.subarray(12).toString('hex');
}

function publish(vectors) {
  const filename = path.join(__dirname, 'vectors.json');
  const expected = JSON.stringify(vectors, null, 2) + '\n';
  assert(process.argv.length <= 3 && (!process.argv[2] || process.argv[2] === '--write'));
  if (process.argv[2] === '--write') fs.writeFileSync(filename, expected);
  else assert.equal(fs.readFileSync(filename, 'utf8'), expected);
  console.log('Independent Node/OpenSSL vectors reproduce exactly');
}

const seed = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f';
const key = keyFromPublicTestSeed(seed);
const vectors = [false, true].map(unicode => {
  const unsigned = {
    profile: 'openwallet.challenge-proof.v0', alg: 'Ed25519',
    binding_ref: 'binding:vector:1', wallet_ref: unicode ? 'wallet:é/🚀' : 'wallet:vector',
    key_ref: 'key:vector:1', subject_ref: 'subject:machine:vector',
    custody_ref: 'custody:public-test-only', binding_revision: unicode ? 9007199254740991 : 3,
    challenge_digest: 'sha256:' + (unicode ? 'f' : '1').repeat(64),
  };
  const unsignedCanonical = canonical(unsigned);
  const message = Buffer.concat([Buffer.from('openWallet.challenge-proof.v0\0'), Buffer.from(unsignedCanonical)]);
  const signature = crypto.sign(null, message, key);
  assert(crypto.verify(null, message, crypto.createPublicKey(key), signature));
  const proof = {...unsigned, signature: signature.toString('base64url')};
  return {
    name: unicode ? 'unicode-and-max-safe-revision' : 'ascii',
    public_test_seed_hex: seed, public_key_hex: publicHex(key),
    binding: {
      binding_ref: unsigned.binding_ref, wallet_ref: unsigned.wallet_ref,
      key_ref: unsigned.key_ref, subject_ref: unsigned.subject_ref,
      custody_ref: unsigned.custody_ref, revision: unsigned.binding_revision,
      not_before: 900, expires_at: 1200, revoked: false,
    },
    now: 1000, unsigned_canonical_utf8: unsignedCanonical,
    message_hex: message.toString('hex'), proof, wire_utf8: canonical(proof),
  };
});
publish(vectors);
