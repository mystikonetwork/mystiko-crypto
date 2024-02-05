import { check, FIELD_SIZE, toBN, toHex, toHexNoPrefix } from '@mystikonetwork/utils';
import createBlakeHash from 'blake-hash';
import BN from 'bn.js';
import bs58 from 'bs58';
import { eddsa, poseidon } from 'circomlibjs';
import cryptojs from 'crypto-js';
import aes from 'crypto-js/aes';
import hmacSHA512 from 'crypto-js/hmac-sha512';
import eccrypto from '@mystikonetwork/eccrypto';
import { ethers } from 'ethers';
import { Scalar } from 'ffjavascript';
import unsafeRandomBytes from 'randombytes';
import { CommitmentInput, CommitmentOutput, DecryptOutput } from '../../interface';

export const VERIFY_PK_SIZE = 32;
export const VERIFY_SK_SIZE = 32;
export const ENC_PK_SIZE = 33;
export const ENC_SK_SIZE = 32;
export const RANDOM_SK_SIZE = 16;
export const AMOUNT_SIZE = 32;
export const MERKLE_TREE_LEVELS = 20;
export const NUM_OF_AUDITORS = 5;
export const AUDITING_THRESHOLD = 3;

const ECIES_IV_LENGTH = 16;
const ECIES_EPHEM_PK_LENGTH = 65;
const ECIES_MAC_LENGTH = 32;
const ECIES_META_LENGTH = ECIES_IV_LENGTH + ECIES_EPHEM_PK_LENGTH + ECIES_MAC_LENGTH;

export function buffToBigInt(buff: Buffer): BN {
  let res = toBN(0);
  for (let i = 0; i < buff.length; i += 1) {
    const byteNumber = toBN(buff[i]);
    res = res.add(byteNumber.shln(8 * i));
  }
  return res;
}

export function bigIntToBuff(bigInt: BN, numBytes: number = 32): Buffer {
  let res = bigInt;
  let index = 0;
  const buff = new Uint8Array(numBytes);
  while (res.gt(toBN(0)) && index < numBytes) {
    buff[index] = Number(res.and(toBN(255)).toString());
    index += 1;
    res = res.shrn(8);
  }
  if (!res.isZero()) {
    throw new Error('Number does not fit in this length');
  }
  return Buffer.from(buff);
}

export function randomBigInt(numBytes?: number): BN {
  let bigInt = toBN(toHexNoPrefix(unsafeRandomBytes(numBytes || 32)), 16);
  if (bigInt.gte(FIELD_SIZE)) {
    bigInt = bigInt.mod(FIELD_SIZE);
  }
  return bigInt;
}

export function randomBytes(numBytes?: number): Buffer {
  return unsafeRandomBytes(numBytes || 32);
}

export function secretKeyForVerification(rawSecretKey: Buffer): Buffer {
  check(rawSecretKey.length === VERIFY_SK_SIZE, `rawSecretKey length does not equal to ${VERIFY_SK_SIZE}`);
  const keyHash = createBlakeHash('blake512').update(rawSecretKey).digest().slice(0, VERIFY_SK_SIZE);
  const sBuffer = eddsa.pruneBuffer(keyHash);
  const skBigInt = Scalar.shr(buffToBigInt(sBuffer).toString(), 3);
  check(FIELD_SIZE.gt(toBN(skBigInt.toString())), 'skBigInt should be less than FIELD_SIZE');
  const sk = bigIntToBuff(toBN(skBigInt.toString()), VERIFY_SK_SIZE);
  check(sk.length === VERIFY_SK_SIZE, `converted secret key length ${sk.length} not equal to ${FIELD_SIZE}`);
  return sk;
}

export function publicKeyForVerification(rawSecretKey: Buffer): Buffer {
  check(rawSecretKey.length === VERIFY_SK_SIZE, `rawSecretKey length does not equal to ${VERIFY_SK_SIZE}`);
  const unpackedPoints = eddsa.prv2pub(rawSecretKey);
  const pkInt = toBN(unpackedPoints[0].toString());
  check(pkInt.lt(FIELD_SIZE), 'first point should be less than FIELD_SIZE');
  const pk = bigIntToBuff(pkInt, VERIFY_PK_SIZE);
  check(pk.length === VERIFY_PK_SIZE, `converted public key length ${pk.length} not equal to ${FIELD_SIZE}`);
  return pk;
}

export function secretKeyForEncryption(rawSecretKey: Buffer): Buffer {
  check(rawSecretKey.length === ENC_SK_SIZE, `rawSecretKey length does not equal to ${ENC_SK_SIZE}`);
  return rawSecretKey;
}

export function publicKeyForEncryption(rawSecretKey: Buffer): Buffer {
  check(rawSecretKey.length === ENC_SK_SIZE, `rawSecretKey length does not equal to ${ENC_SK_SIZE}`);
  const publicKey = eccrypto.getPublicCompressed(rawSecretKey);
  check(publicKey.length === ENC_PK_SIZE, `generate public key length does not equal to ${ENC_PK_SIZE}`);
  return publicKey;
}

export function fullPublicKey(pkVerify: Buffer, pkEnc: Buffer): Buffer {
  check(pkVerify.length === VERIFY_PK_SIZE, `pkVerify length does not equal to ${VERIFY_PK_SIZE}`);
  check(pkEnc.length === ENC_PK_SIZE, `pkEnc length does not equal to ${ENC_PK_SIZE}`);
  return Buffer.concat([pkVerify, pkEnc]);
}

export function fullSecretKey(skVerify: Buffer, skEnc: Buffer): Buffer {
  check(skVerify.length === VERIFY_SK_SIZE, `skVerify length does not equal to ${VERIFY_SK_SIZE}`);
  check(skEnc.length === ENC_SK_SIZE, `skEnc length does not equal to ${ENC_SK_SIZE}`);
  return Buffer.concat([skVerify, skEnc]);
}

export function separatedPublicKeys(longPublicKey: Buffer): { pkEnc: Buffer; pkVerify: Buffer } {
  const expectedSize = VERIFY_PK_SIZE + ENC_PK_SIZE;
  check(longPublicKey.length === expectedSize, `fullPublicKey length does not equal to ${expectedSize}`);
  return {
    pkVerify: longPublicKey.slice(0, VERIFY_PK_SIZE),
    pkEnc: longPublicKey.slice(VERIFY_PK_SIZE),
  };
}

export function separatedSecretKeys(longSecretKey: Buffer): { skVerify: Buffer; skEnc: Buffer } {
  const expectedSize = VERIFY_SK_SIZE + ENC_SK_SIZE;
  check(longSecretKey.length === expectedSize, `fullSecretKey length does not equal to ${expectedSize}`);
  return {
    skVerify: longSecretKey.slice(0, VERIFY_SK_SIZE),
    skEnc: longSecretKey.slice(VERIFY_SK_SIZE),
  };
}

export function shieldedAddress(pkVerify: Buffer, pkEnc: Buffer): string {
  return bs58.encode(fullPublicKey(pkVerify, pkEnc));
}

export function isShieldedAddress(address: string): boolean {
  try {
    const decoded = bs58.decode(address);
    return decoded.length === VERIFY_PK_SIZE + ENC_PK_SIZE;
  } catch {
    return false;
  }
}

export function publicKeysFromShieldedAddress(address: string): { pkEnc: Buffer; pkVerify: Buffer } {
  check(isShieldedAddress(address), `${address} is a invalid address format`);
  return separatedPublicKeys(bs58.decode(address));
}

export function encryptAsymmetric(publicKey: Buffer, plainData: Buffer): Promise<Buffer> {
  return eccrypto
    .encrypt(publicKey, plainData)
    .then((r) => Buffer.concat([r.iv, r.ephemPublicKey, r.mac, r.ciphertext]));
}

export function decryptAsymmetric(secretKey: Buffer, cipherData: Buffer): Promise<Buffer> {
  check(cipherData.length > ECIES_META_LENGTH, 'incorrect cipherData length');
  return eccrypto.decrypt(secretKey, {
    iv: cipherData.slice(0, ECIES_IV_LENGTH),
    ephemPublicKey: cipherData.slice(ECIES_IV_LENGTH, ECIES_IV_LENGTH + ECIES_EPHEM_PK_LENGTH),
    mac: cipherData.slice(ECIES_IV_LENGTH + ECIES_EPHEM_PK_LENGTH, ECIES_META_LENGTH),
    ciphertext: cipherData.slice(ECIES_META_LENGTH),
  });
}

export function encryptSymmetric(password: string, plainText: string): string {
  return aes.encrypt(plainText, password).toString();
}

export function decryptSymmetric(password: string, cipherText: string): string {
  return aes.decrypt(cipherText, password).toString(cryptojs.enc.Utf8);
}

export function sha256(inputs: Buffer[]): BN {
  const merged = Buffer.concat(inputs);
  const result = ethers.utils.sha256(toHex(merged));
  return toBN(toHexNoPrefix(result), 16).mod(FIELD_SIZE);
}

export function poseidonHash(inputs: BN[]): BN {
  check(inputs.length < 7, 'inputs length should be not greater than 6');
  const result = poseidon(inputs);
  const resultNum = toBN(result.toString());
  check(resultNum.lt(FIELD_SIZE), 'resultNum should be less than FIELD_SIZE');
  return resultNum;
}

export function checkSum(data: string, salt?: string): string {
  return hmacSHA512(data, salt || 'mystiko').toString();
}

export function serialNumber(skVerify: Buffer, randomP: BN): BN {
  const nullifierKey = poseidonHash([buffToBigInt(skVerify)]);
  return poseidonHash([randomP, nullifierKey]);
}

export function sigPkHash(sigPk: Buffer, secretKey: Buffer) {
  return poseidonHash([buffToBigInt(secretKey), toBN(sigPk)]);
}

export async function commitment(options: CommitmentInput): Promise<CommitmentOutput> {
  let pkVerify: Buffer;
  let pkEnc: Buffer;
  let randomP: BN = randomBigInt(RANDOM_SK_SIZE);
  let randomR: BN = randomBigInt(RANDOM_SK_SIZE);
  let randomS: BN = randomBigInt(RANDOM_SK_SIZE);
  let amount: BN = options.amount || toBN(0);
  if (typeof options.publicKeys === 'string') {
    const pks = publicKeysFromShieldedAddress(options.publicKeys);
    pkVerify = pks.pkVerify;
    pkEnc = pks.pkEnc;
  } else {
    pkVerify = options.publicKeys.pkVerify;
    pkEnc = options.publicKeys.pkEnc;
  }
  if (options.randomSecrets) {
    randomP = options.randomSecrets.randomP;
    randomR = options.randomSecrets.randomR;
    randomS = options.randomSecrets.randomS;
  }
  if (options.encryptedNote) {
    const { skEnc, encryptedNote } = options.encryptedNote;
    const decryptedNote = await decryptAsymmetric(skEnc, encryptedNote);
    if (decryptedNote.length !== RANDOM_SK_SIZE * 3 + AMOUNT_SIZE) {
      return Promise.reject(new Error('wrong decrypted data from encrypted note, maybe secret key is wrong'));
    }
    randomP = buffToBigInt(decryptedNote.slice(0, RANDOM_SK_SIZE));
    randomR = buffToBigInt(decryptedNote.slice(RANDOM_SK_SIZE, RANDOM_SK_SIZE * 2));
    randomS = buffToBigInt(decryptedNote.slice(RANDOM_SK_SIZE * 2, RANDOM_SK_SIZE * 3));
    amount = buffToBigInt(decryptedNote.slice(RANDOM_SK_SIZE * 3));
  }
  const k = poseidonHash([buffToBigInt(pkVerify), randomP, randomR]);
  const commitmentHash = poseidonHash([k, amount, randomS]);
  const encryptedNote = await encryptAsymmetric(
    pkEnc,
    Buffer.concat([
      bigIntToBuff(randomP, RANDOM_SK_SIZE),
      bigIntToBuff(randomR, RANDOM_SK_SIZE),
      bigIntToBuff(randomS, RANDOM_SK_SIZE),
      bigIntToBuff(amount, AMOUNT_SIZE),
    ]),
  );
  return Promise.resolve({
    commitmentHash,
    amount,
    shieldedAddress: shieldedAddress(pkVerify, pkEnc),
    k,
    randomP,
    randomR,
    randomS,
    encryptedNote,
  });
}

async function decryptNote(
  commitmentLike: { commitmentHash: BN; encryptedNote: Buffer },
  keys: { publicKey: Buffer; secretKey: Buffer }[],
  keyIndex: number,
): Promise<DecryptOutput | undefined> {
  if (keyIndex < keys.length) {
    const { publicKey, secretKey } = keys[keyIndex];
    const { pkVerify, pkEnc } = separatedPublicKeys(publicKey);
    const { skVerify, skEnc } = separatedSecretKeys(secretKey);
    const commitmentOutput = await commitment({
      publicKeys: { pkVerify, pkEnc },
      encryptedNote: { skEnc, encryptedNote: commitmentLike.encryptedNote },
    }).catch(() => undefined);
    if (commitmentOutput !== undefined && commitmentOutput.commitmentHash.eq(commitmentLike.commitmentHash)) {
      const sn = serialNumber(secretKeyForVerification(skVerify), commitmentOutput.randomP);
      return {
        commitment: commitmentOutput,
        shieldedAddress: shieldedAddress(pkVerify, pkEnc),
        serialNumber: sn,
      };
    }
    return decryptNote(commitmentLike, keys, keyIndex + 1);
  }
  return undefined;
}

export async function decryptNotes(
  commitments: { commitmentHash: BN; encryptedNote: Buffer }[],
  keys: { publicKey: Buffer; secretKey: Buffer }[],
): Promise<DecryptOutput[]> {
  const promises: Promise<DecryptOutput | undefined>[] = [];
  commitments.forEach((commitmentLike) => {
    const promise = decryptNote(commitmentLike, keys, 0);
    promises.push(promise);
  });
  const results = await Promise.all(promises);
  const commitmentOutputs: DecryptOutput[] = [];
  results.forEach((result) => {
    if (result !== undefined) {
      commitmentOutputs.push(result);
    }
  });
  return commitmentOutputs;
}
