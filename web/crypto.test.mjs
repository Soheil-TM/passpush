import { test } from "node:test";
import assert from "node:assert/strict";

const text = new TextEncoder();

function b64url(bytes) {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

async function hkdf(master, info) {
  const key = await crypto.subtle.importKey("raw", master, "HKDF", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({
    name: "HKDF",
    hash: "SHA-256",
    salt: new Uint8Array(32),
    info: text.encode(info),
  }, key, 256);
  return new Uint8Array(bits);
}

test("hkdf split, aad round trip, and tamper failure", async () => {
  const master = crypto.getRandomValues(new Uint8Array(32));
  const encKey = await hkdf(master, "pwpush-v1-enc");
  const authToken = await hkdf(master, "pwpush-v1-auth");
  assert.equal(encKey.length, 32);
  assert.equal(authToken.length, 32);
  assert.notDeepEqual(encKey, authToken);
  assert.notDeepEqual(encKey, master);
  assert.notDeepEqual(authToken, master);

  const id = "abcdefghijklmnopqrstuv";
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = text.encode("correct horse battery");
  const aes = await crypto.subtle.importKey("raw", encKey, "AES-GCM", false, ["encrypt", "decrypt"]);
  const aad = text.encode("v1|" + id);
  const cipher = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: aad }, aes, plaintext));
  const opened = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: nonce, additionalData: aad }, aes, cipher));
  assert.deepEqual(opened, plaintext);

  await assert.rejects(crypto.subtle.decrypt({ name: "AES-GCM", iv: nonce, additionalData: text.encode("v1|other-id") }, aes, cipher));
  const tampered = new Uint8Array(cipher);
  tampered[0] ^= 0xff;
  await assert.rejects(crypto.subtle.decrypt({ name: "AES-GCM", iv: nonce, additionalData: aad }, aes, tampered));

  const authKey = await crypto.subtle.importKey("raw", authToken, "AES-GCM", false, ["decrypt"]);
  await assert.rejects(crypto.subtle.decrypt({ name: "AES-GCM", iv: nonce, additionalData: aad }, authKey, cipher));
  assert.equal(b64url(authToken).length > 0, true);
});
