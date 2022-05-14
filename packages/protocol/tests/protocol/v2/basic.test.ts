import { FIELD_SIZE, toBN, toBuff, toHex } from '@mystikonetwork/utils';
import { ZokratesCliProverFactory, ZokratesCliProverOptions } from '@mystikonetwork/zkp-node';
import { MystikoProtocolV2, ProtocolFactoryV2 } from '../../../src';

let protocol: MystikoProtocolV2;
let factory: ProtocolFactoryV2;

beforeAll(async () => {
  factory = new ProtocolFactoryV2<ZokratesCliProverOptions>(new ZokratesCliProverFactory());
  protocol = await factory.create();
});

test('test randomBigInt', () => {
  const int1 = protocol.randomBigInt(8);
  expect(int1.lt(FIELD_SIZE)).toBe(true);
  const int2 = protocol.randomBigInt(16);
  expect(int2.lt(FIELD_SIZE)).toBe(true);
  const int3 = protocol.randomBigInt();
  expect(int3.lt(FIELD_SIZE)).toBe(true);
  for (let i = 0; i < 100; i += 1) {
    const bgInt = protocol.randomBigInt();
    expect(bgInt.lt(FIELD_SIZE)).toBe(true);
  }
});

test('test randomBytes', () => {
  const bytes1 = protocol.randomBytes();
  expect(bytes1.length).toBe(32);
  const bytes2 = protocol.randomBytes(16);
  expect(bytes2.length).toBe(16);
  const bytes3 = protocol.randomBytes(1);
  expect(bytes3.length).toBe(1);
});

test('test buffToBigInt', () => {
  const buff = toBuff('baadbeef');
  expect(protocol.buffToBigInt(buff).toString()).toBe('4022250938');
});

test('test bigIntToBuff', () => {
  expect(() => protocol.bigIntToBuff(toBN(4022250938), 1)).toThrow();
  expect(protocol.bigIntToBuff(toBN(4022250938), 4).toString('hex')).toBe('baadbeef');
  expect(protocol.bigIntToBuff(toBN(4022250938), 6).toString('hex')).toBe('baadbeef0000');
});

test('test secretKeyForVerification', () => {
  expect(() => protocol.secretKeyForVerification(toBuff('baadbeef'))).toThrow();
  for (let i = 0; i < 10; i += 1) {
    const rawSecretKey = protocol.randomBytes(protocol.verifySkSize);
    const sk = protocol.secretKeyForVerification(rawSecretKey);
    expect(sk.length).toBe(protocol.verifySkSize);
  }
});

test('test publicKeyForVerification', () => {
  expect(() => protocol.publicKeyForVerification(toBuff('baadbeef'))).toThrow();
  for (let i = 0; i < 10; i += 1) {
    const rawSecretKey = protocol.randomBytes(protocol.verifySkSize);
    const pk = protocol.publicKeyForVerification(rawSecretKey);
    expect(pk.length).toBe(protocol.verifyPkSize);
  }
});

test('test secretKeyForEncryption', () => {
  expect(() => protocol.secretKeyForEncryption(toBuff('baadbeef'))).toThrow();
  const rawSecretKey = protocol.randomBytes(protocol.encSkSize);
  const sk = protocol.secretKeyForVerification(rawSecretKey);
  expect(sk.length).toBe(protocol.encSkSize);
});

test('test publicKeyForEncryption', () => {
  expect(() => protocol.publicKeyForEncryption(toBuff('baadbeef'))).toThrow();
  const rawSecretKey = protocol.randomBytes(protocol.encSkSize);
  const pk = protocol.publicKeyForEncryption(rawSecretKey);
  expect(pk.length).toBe(protocol.encPkSize);
});

test('test fullPublicKey', () => {
  const rawSkVerify = protocol.randomBytes(protocol.verifySkSize);
  const rawSkEnc = protocol.randomBytes(protocol.encSkSize);
  const pkVerify = protocol.publicKeyForVerification(rawSkVerify);
  const pkEnc = protocol.publicKeyForEncryption(rawSkEnc);
  expect(() => protocol.fullPublicKey(pkVerify, toBuff('baadbeef'))).toThrow();
  expect(() => protocol.fullPublicKey(toBuff('baadbeef'), pkEnc)).toThrow();
  const fullPublicKey = protocol.fullPublicKey(pkVerify, pkEnc);
  expect(fullPublicKey.length).toBe(protocol.verifyPkSize + protocol.encPkSize);
});

test('test fullSecretKey', () => {
  const rawSkVerify = protocol.randomBytes(protocol.verifySkSize);
  const rawSkEnc = protocol.randomBytes(protocol.encSkSize);
  const skVerify = protocol.secretKeyForVerification(rawSkVerify);
  const skEnc = protocol.secretKeyForEncryption(rawSkEnc);
  expect(() => protocol.fullSecretKey(skVerify, toBuff('baadbeef'))).toThrow();
  expect(() => protocol.fullSecretKey(toBuff('baadbeef'), skEnc)).toThrow();
  const fullSecretKey = protocol.fullSecretKey(skVerify, skEnc);
  expect(fullSecretKey.length).toBe(protocol.verifySkSize + protocol.encSkSize);
});

test('test separatedPublicKeys', () => {
  expect(() => protocol.separatedPublicKeys(toBuff('baadbeef'))).toThrow();
  const rawSkVerify = protocol.randomBytes(protocol.verifySkSize);
  const rawSkEnc = protocol.randomBytes(protocol.encSkSize);
  const pkVerify = protocol.publicKeyForVerification(rawSkVerify);
  const pkEnc = protocol.publicKeyForEncryption(rawSkEnc);
  const fullPublicKey = protocol.fullPublicKey(pkVerify, pkEnc);
  const keys = protocol.separatedPublicKeys(fullPublicKey);
  expect(toHex(keys.pkVerify)).toBe(toHex(pkVerify));
  expect(toHex(keys.pkEnc)).toBe(toHex(pkEnc));
});

test('test separatedSecretKeys', () => {
  expect(() => protocol.separatedSecretKeys(toBuff('baadbeef'))).toThrow();
  const rawSkVerify = protocol.randomBytes(protocol.verifySkSize);
  const rawSkEnc = protocol.randomBytes(protocol.encSkSize);
  const skVerify = protocol.secretKeyForVerification(rawSkVerify);
  const skEnc = protocol.secretKeyForEncryption(rawSkEnc);
  const fullSecretKey = protocol.fullSecretKey(skVerify, skEnc);
  const keys = protocol.separatedSecretKeys(fullSecretKey);
  expect(toHex(keys.skVerify)).toBe(toHex(skVerify));
  expect(toHex(keys.skEnc)).toBe(toHex(skEnc));
});

test('test shieldedAddress', () => {
  const rawSkVerify = protocol.randomBytes(protocol.verifySkSize);
  const rawSkEnc = protocol.randomBytes(protocol.encSkSize);
  const pkVerify = protocol.publicKeyForVerification(rawSkVerify);
  const pkEnc = protocol.publicKeyForEncryption(rawSkEnc);
  const shieldedAddress = protocol.shieldedAddress(pkVerify, pkEnc);
  expect(protocol.isShieldedAddress(shieldedAddress)).toBe(true);
  const keys = protocol.publicKeysFromShieldedAddress(shieldedAddress);
  expect(toHex(keys.pkVerify)).toBe(toHex(pkVerify));
  expect(toHex(keys.pkEnc)).toBe(toHex(pkEnc));
});

test('test isShieldedAddress', () => {
  expect(protocol.isShieldedAddress('')).toBe(false);
  expect(protocol.isShieldedAddress('axeddd#$')).toBe(false);
});

test('test asymmetric encryption/decryption', async () => {
  const rawSecretKey = protocol.randomBytes(protocol.encSkSize);
  const sk = protocol.secretKeyForEncryption(rawSecretKey);
  const pk = protocol.publicKeyForEncryption(rawSecretKey);
  const data = toBuff('baadbeefdeadbeef');
  const encryptedData = await protocol.encryptAsymmetric(pk, data);
  const decryptedData = await protocol.decryptAsymmetric(sk, encryptedData);
  expect(toHex(decryptedData)).toBe(toHex(data));
});

test('test symmetric encryption/decryption', () => {
  const plainText = 'mystiko is awesome';
  const cipherText = protocol.encryptSymmetric('P@ssw0rd', plainText);
  expect(protocol.decryptSymmetric('P@ssw0rd', cipherText)).toBe(plainText);
});

test('test sha256', () => {
  const data1 = toBuff('baad');
  const data2 = toBuff('beef');
  const data3 = toBuff('baad');
  const hash1 = protocol.sha256([data1]);
  const hash2 = protocol.sha256([data2]);
  const hash3 = protocol.sha256([data3]);
  expect(toHex(hash1)).not.toBe(toHex(hash2));
  expect(toHex(hash1)).toBe(toHex(hash3));
});

test('test poseidonHash', () => {
  const h1 = protocol.poseidonHash([toBN(1), toBN(2)]);
  const h2 = protocol.poseidonHash([toBN(3), toBN(4)]);
  const h3 = protocol.poseidonHash([toBN(1), toBN(2)]);
  expect(h1.toString()).toBe(h3.toString());
  expect(h2.toString()).not.toBe(h3.toString());
});

test('test checksum', () => {
  const hash1 = protocol.checkSum('hello world');
  const hash2 = protocol.checkSum('Mystiko is awesome', '');
  const hash3 = protocol.checkSum('Mystiko is awesome', 'P@ssw0rd');
  const hash4 = protocol.checkSum('hello world');
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
