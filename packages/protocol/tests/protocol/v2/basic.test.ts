import { FIELD_SIZE, toBN, toBuff, toHex } from '@mystikonetwork/utils';
import { ZokratesCliProver } from '@mystikonetwork/zkp-node';
import { MystikoProtocolV2 } from '../../../src';

let testProtocol: MystikoProtocolV2;

beforeAll(() => {
  testProtocol = new MystikoProtocolV2(new ZokratesCliProver());
});

test('test randomBigInt', () => {
  const int1 = testProtocol.randomBigInt(8);
  expect(int1.lt(FIELD_SIZE)).toBe(true);
  const int2 = testProtocol.randomBigInt(16);
  expect(int2.lt(FIELD_SIZE)).toBe(true);
  const int3 = testProtocol.randomBigInt();
  expect(int3.lt(FIELD_SIZE)).toBe(true);
  for (let i = 0; i < 100; i += 1) {
    const bgInt = testProtocol.randomBigInt();
    expect(bgInt.lt(FIELD_SIZE)).toBe(true);
  }
});

test('test randomBytes', () => {
  const bytes1 = testProtocol.randomBytes();
  expect(bytes1.length).toBe(32);
  const bytes2 = testProtocol.randomBytes(16);
  expect(bytes2.length).toBe(16);
  const bytes3 = testProtocol.randomBytes(1);
  expect(bytes3.length).toBe(1);
});

test('test buffToBigInt', () => {
  const buff = toBuff('baadbeef');
  expect(testProtocol.buffToBigInt(buff).toString()).toBe('4022250938');
});

test('test bigIntToBuff', () => {
  expect(() => testProtocol.bigIntToBuff(toBN(4022250938), 1)).toThrow();
  expect(testProtocol.bigIntToBuff(toBN(4022250938), 4).toString('hex')).toBe('baadbeef');
  expect(testProtocol.bigIntToBuff(toBN(4022250938), 6).toString('hex')).toBe('baadbeef0000');
});

test('test secretKeyForVerification', () => {
  expect(() => testProtocol.secretKeyForVerification(toBuff('baadbeef'))).toThrow();
  for (let i = 0; i < 10; i += 1) {
    const rawSecretKey = testProtocol.randomBytes(testProtocol.verifySkSize);
    const sk = testProtocol.secretKeyForVerification(rawSecretKey);
    expect(sk.length).toBe(testProtocol.verifySkSize);
  }
});

test('test publicKeyForVerification', () => {
  expect(() => testProtocol.publicKeyForVerification(toBuff('baadbeef'))).toThrow();
  for (let i = 0; i < 10; i += 1) {
    const rawSecretKey = testProtocol.randomBytes(testProtocol.verifySkSize);
    const pk = testProtocol.publicKeyForVerification(rawSecretKey);
    expect(pk.length).toBe(testProtocol.verifyPkSize);
  }
});

test('test secretKeyForEncryption', () => {
  expect(() => testProtocol.secretKeyForEncryption(toBuff('baadbeef'))).toThrow();
  const rawSecretKey = testProtocol.randomBytes(testProtocol.encSkSize);
  const sk = testProtocol.secretKeyForVerification(rawSecretKey);
  expect(sk.length).toBe(testProtocol.encSkSize);
});

test('test publicKeyForEncryption', () => {
  expect(() => testProtocol.publicKeyForEncryption(toBuff('baadbeef'))).toThrow();
  const rawSecretKey = testProtocol.randomBytes(testProtocol.encSkSize);
  const pk = testProtocol.publicKeyForEncryption(rawSecretKey);
  expect(pk.length).toBe(testProtocol.encPkSize);
});

test('test fullPublicKey', () => {
  const rawSkVerify = testProtocol.randomBytes(testProtocol.verifySkSize);
  const rawSkEnc = testProtocol.randomBytes(testProtocol.encSkSize);
  const pkVerify = testProtocol.publicKeyForVerification(rawSkVerify);
  const pkEnc = testProtocol.publicKeyForEncryption(rawSkEnc);
  expect(() => testProtocol.fullPublicKey(pkVerify, toBuff('baadbeef'))).toThrow();
  expect(() => testProtocol.fullPublicKey(toBuff('baadbeef'), pkEnc)).toThrow();
  const fullPublicKey = testProtocol.fullPublicKey(pkVerify, pkEnc);
  expect(fullPublicKey.length).toBe(testProtocol.verifyPkSize + testProtocol.encPkSize);
});

test('test fullSecretKey', () => {
  const rawSkVerify = testProtocol.randomBytes(testProtocol.verifySkSize);
  const rawSkEnc = testProtocol.randomBytes(testProtocol.encSkSize);
  const skVerify = testProtocol.secretKeyForVerification(rawSkVerify);
  const skEnc = testProtocol.secretKeyForEncryption(rawSkEnc);
  expect(() => testProtocol.fullSecretKey(skVerify, toBuff('baadbeef'))).toThrow();
  expect(() => testProtocol.fullSecretKey(toBuff('baadbeef'), skEnc)).toThrow();
  const fullSecretKey = testProtocol.fullSecretKey(skVerify, skEnc);
  expect(fullSecretKey.length).toBe(testProtocol.verifySkSize + testProtocol.encSkSize);
});

test('test separatedPublicKeys', () => {
  expect(() => testProtocol.separatedPublicKeys(toBuff('baadbeef'))).toThrow();
  const rawSkVerify = testProtocol.randomBytes(testProtocol.verifySkSize);
  const rawSkEnc = testProtocol.randomBytes(testProtocol.encSkSize);
  const pkVerify = testProtocol.publicKeyForVerification(rawSkVerify);
  const pkEnc = testProtocol.publicKeyForEncryption(rawSkEnc);
  const fullPublicKey = testProtocol.fullPublicKey(pkVerify, pkEnc);
  const keys = testProtocol.separatedPublicKeys(fullPublicKey);
  expect(toHex(keys.pkVerify)).toBe(toHex(pkVerify));
  expect(toHex(keys.pkEnc)).toBe(toHex(pkEnc));
});

test('test separatedSecretKeys', () => {
  expect(() => testProtocol.separatedSecretKeys(toBuff('baadbeef'))).toThrow();
  const rawSkVerify = testProtocol.randomBytes(testProtocol.verifySkSize);
  const rawSkEnc = testProtocol.randomBytes(testProtocol.encSkSize);
  const skVerify = testProtocol.secretKeyForVerification(rawSkVerify);
  const skEnc = testProtocol.secretKeyForEncryption(rawSkEnc);
  const fullSecretKey = testProtocol.fullSecretKey(skVerify, skEnc);
  const keys = testProtocol.separatedSecretKeys(fullSecretKey);
  expect(toHex(keys.skVerify)).toBe(toHex(skVerify));
  expect(toHex(keys.skEnc)).toBe(toHex(skEnc));
});

test('test shieldedAddress', () => {
  const rawSkVerify = testProtocol.randomBytes(testProtocol.verifySkSize);
  const rawSkEnc = testProtocol.randomBytes(testProtocol.encSkSize);
  const pkVerify = testProtocol.publicKeyForVerification(rawSkVerify);
  const pkEnc = testProtocol.publicKeyForEncryption(rawSkEnc);
  const shieldedAddress = testProtocol.shieldedAddress(pkVerify, pkEnc);
  expect(testProtocol.isShieldedAddress(shieldedAddress)).toBe(true);
  const keys = testProtocol.publicKeysFromShieldedAddress(shieldedAddress);
  expect(toHex(keys.pkVerify)).toBe(toHex(pkVerify));
  expect(toHex(keys.pkEnc)).toBe(toHex(pkEnc));
});

test('test isShieldedAddress', () => {
  expect(testProtocol.isShieldedAddress('')).toBe(false);
  expect(testProtocol.isShieldedAddress('axeddd#$')).toBe(false);
});

test('test asymmetric encryption/decryption', async () => {
  const rawSecretKey = testProtocol.randomBytes(testProtocol.encSkSize);
  const sk = testProtocol.secretKeyForEncryption(rawSecretKey);
  const pk = testProtocol.publicKeyForEncryption(rawSecretKey);
  const data = toBuff('baadbeefdeadbeef');
  const encryptedData = await testProtocol.encryptAsymmetric(pk, data);
  const decryptedData = await testProtocol.decryptAsymmetric(sk, encryptedData);
  expect(toHex(decryptedData)).toBe(toHex(data));
});

test('test symmetric encryption/decryption', () => {
  const plainText = 'mystiko is awesome';
  const cipherText = testProtocol.encryptSymmetric('P@ssw0rd', plainText);
  expect(testProtocol.decryptSymmetric('P@ssw0rd', cipherText)).toBe(plainText);
});

test('test sha256', () => {
  const data1 = toBuff('baad');
  const data2 = toBuff('beef');
  const data3 = toBuff('baad');
  const hash1 = testProtocol.sha256([data1]);
  const hash2 = testProtocol.sha256([data2]);
  const hash3 = testProtocol.sha256([data3]);
  expect(toHex(hash1)).not.toBe(toHex(hash2));
  expect(toHex(hash1)).toBe(toHex(hash3));
});

test('test poseidonHash', () => {
  const h1 = testProtocol.poseidonHash([toBN(1), toBN(2)]);
  const h2 = testProtocol.poseidonHash([toBN(3), toBN(4)]);
  const h3 = testProtocol.poseidonHash([toBN(1), toBN(2)]);
  expect(h1.toString()).toBe(h3.toString());
  expect(h2.toString()).not.toBe(h3.toString());
});

test('test checksum', () => {
  const hash1 = testProtocol.checkSum('hello world');
  const hash2 = testProtocol.checkSum('Mystiko is awesome', '');
  const hash3 = testProtocol.checkSum('Mystiko is awesome', 'P@ssw0rd');
  const hash4 = testProtocol.checkSum('hello world');
  expect(hash1).not.toBe(hash2);
  expect(hash2).not.toBe(hash3);
  expect(hash4).toBe(hash1);
  expect(hash3).toBe(
    '03b41505aa26437d94831f9bfd24afd4e7eaf33d6aaf368d0' +
      'c77545ad2a958024222badb4d84a17f84ff15297e16199dab' +
      'c88b417ce764624ed5a2443681afcd',
  );
  expect(hash2).toBe(
    '8b9fb4d5f890ea83d09f63af9dee5ba8a53a9f5dedeb9bfd0e6e' +
      'd135d5dca7abbc75d455fe0ee46040828834186543e008401238aeaaab1039f3a5ab37bb1c97',
  );
});
