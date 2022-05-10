/* eslint-disable class-methods-use-this */
import bs58 from 'bs58';
import createBlakeHash from 'blake-hash';
import BN from 'bn.js';
import { eddsa, poseidon } from 'circomlibjs';
import cryptojs from 'crypto-js';
import aes from 'crypto-js/aes';
import hmacSHA512 from 'crypto-js/hmac-sha512';
import eccrypto from 'eccrypto';
import { ethers } from 'ethers';
import { Scalar } from 'ffjavascript';
import unsafeRandomBytes from 'randombytes';
import { Proof } from 'zokrates-js';
import { check, FIELD_SIZE, toBN, toHex, toHexNoPrefix } from '@mystikonetwork/utils';

const ECIES_IV_LENGTH = 16;
const ECIES_EPHEM_PK_LENGTH = 65;
const ECIES_MAC_LENGTH = 32;
const ECIES_META_LENGTH = ECIES_IV_LENGTH + ECIES_EPHEM_PK_LENGTH + ECIES_MAC_LENGTH;

// eslint-disable-next-line import/prefer-default-export
export abstract class MystikoProtocol<CI = any, CO = any, T = any, R = any> {
  public get verifyPkSize(): number {
    return 32;
  }

  public get verifySkSize(): number {
    return 32;
  }

  public get encPkSize(): number {
    return 33;
  }

  public get encSkSize(): number {
    return 32;
  }

  public get randomSkSize(): number {
    return 16;
  }

  public get amountSize(): number {
    return 32;
  }

  public get merkleTreeLevels(): number {
    return 20;
  }

  public buffToBigInt(buff: Buffer): BN {
    let res = toBN(0);
    for (let i = 0; i < buff.length; i += 1) {
      const byteNumber = toBN(buff[i]);
      res = res.add(byteNumber.shln(8 * i));
    }
    return res;
  }

  public bigIntToBuff(bigInt: BN, numBytes: number = 32): Buffer {
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

  public randomBigInt(numBytes?: number): BN {
    let bigInt = toBN(toHexNoPrefix(unsafeRandomBytes(numBytes || 32)), 16);
    if (bigInt.gte(FIELD_SIZE)) {
      bigInt = bigInt.mod(FIELD_SIZE);
    }
    return bigInt;
  }

  public randomBytes(numBytes?: number): Buffer {
    return this.bigIntToBuff(this.randomBigInt(numBytes || 32), numBytes);
  }

  public secretKeyForVerification(rawSecretKey: Buffer): Buffer {
    check(
      rawSecretKey.length === this.verifySkSize,
      `rawSecretKey length does not equal to ${this.verifySkSize}`,
    );
    const keyHash = createBlakeHash('blake512').update(rawSecretKey).digest().slice(0, this.verifySkSize);
    const sBuffer = eddsa.pruneBuffer(keyHash);
    const skBigInt = Scalar.shr(this.buffToBigInt(sBuffer).toString(), 3);
    check(FIELD_SIZE.gt(toBN(skBigInt.toString())), 'skBigInt should be less than FIELD_SIZE');
    const sk = this.bigIntToBuff(toBN(skBigInt.toString()), this.verifySkSize);
    check(
      sk.length === this.verifySkSize,
      `converted secret key length ${sk.length} not equal to ${FIELD_SIZE}`,
    );
    return sk;
  }

  public publicKeyForVerification(rawSecretKey: Buffer): Buffer {
    check(
      rawSecretKey.length === this.verifySkSize,
      `rawSecretKey length does not equal to ${this.verifySkSize}`,
    );
    const unpackedPoints = eddsa.prv2pub(rawSecretKey);
    const pkInt = toBN(unpackedPoints[0].toString());
    check(pkInt.lt(FIELD_SIZE), 'first point should be less than FIELD_SIZE');
    const pk = this.bigIntToBuff(pkInt, this.verifyPkSize);
    check(
      pk.length === this.verifyPkSize,
      `converted public key length ${pk.length} not equal to ${FIELD_SIZE}`,
    );
    return pk;
  }

  public secretKeyForEncryption(rawSecretKey: Buffer): Buffer {
    check(rawSecretKey.length === this.encSkSize, `rawSecretKey length does not equal to ${this.encSkSize}`);
    return rawSecretKey;
  }

  public publicKeyForEncryption(rawSecretKey: Buffer): Buffer {
    check(rawSecretKey.length === this.encSkSize, `rawSecretKey length does not equal to ${this.encSkSize}`);
    const publicKey = eccrypto.getPublicCompressed(rawSecretKey);
    check(
      publicKey.length === this.encPkSize,
      `generate public key length does not equal to ${this.encPkSize}`,
    );
    return publicKey;
  }

  public fullPublicKey(pkVerify: Buffer, pkEnc: Buffer): Buffer {
    check(pkVerify.length === this.verifyPkSize, `pkVerify length does not equal to ${this.verifyPkSize}`);
    check(pkEnc.length === this.encPkSize, `pkEnc length does not equal to ${this.encPkSize}`);
    return Buffer.concat([pkVerify, pkEnc]);
  }

  public fullSecretKey(skVerify: Buffer, skEnc: Buffer): Buffer {
    check(skVerify.length === this.verifySkSize, `skVerify length does not equal to ${this.verifySkSize}`);
    check(skEnc.length === this.encSkSize, `skEnc length does not equal to ${this.encSkSize}`);
    return Buffer.concat([skVerify, skEnc]);
  }

  public separatedPublicKeys(longPublicKey: Buffer): { pkEnc: Buffer; pkVerify: Buffer } {
    const expectedSize = this.verifyPkSize + this.encPkSize;
    check(longPublicKey.length === expectedSize, `fullPublicKey length does not equal to ${expectedSize}`);
    return {
      pkVerify: longPublicKey.slice(0, this.verifyPkSize),
      pkEnc: longPublicKey.slice(this.verifyPkSize),
    };
  }

  public separatedSecretKeys(longSecretKey: Buffer): { skVerify: Buffer; skEnc: Buffer } {
    const expectedSize = this.verifySkSize + this.encSkSize;
    check(longSecretKey.length === expectedSize, `fullSecretKey length does not equal to ${expectedSize}`);
    return {
      skVerify: longSecretKey.slice(0, this.verifySkSize),
      skEnc: longSecretKey.slice(this.verifySkSize),
    };
  }

  public shieldedAddress(pkVerify: Buffer, pkEnc: Buffer): string {
    return bs58.encode(this.fullPublicKey(pkVerify, pkEnc));
  }

  public isShieldedAddress(address: string): boolean {
    try {
      const decoded = bs58.decode(address);
      return decoded.length === this.verifyPkSize + this.encPkSize;
    } catch {
      return false;
    }
  }

  public publicKeysFromShieldedAddress(address: string): { pkEnc: Buffer; pkVerify: Buffer } {
    check(this.isShieldedAddress(address), `${address} is a invalid address format`);
    return this.separatedPublicKeys(bs58.decode(address));
  }

  public encryptAsymmetric(publicKey: Buffer, plainData: Buffer): Promise<Buffer> {
    return eccrypto
      .encrypt(publicKey, plainData)
      .then((r) => Buffer.concat([r.iv, r.ephemPublicKey, r.mac, r.ciphertext]));
  }

  public decryptAsymmetric(secretKey: Buffer, cipherData: Buffer): Promise<Buffer> {
    check(cipherData.length > ECIES_META_LENGTH, 'incorrect cipherData length');
    return eccrypto.decrypt(secretKey, {
      iv: cipherData.slice(0, ECIES_IV_LENGTH),
      ephemPublicKey: cipherData.slice(ECIES_IV_LENGTH, ECIES_IV_LENGTH + ECIES_EPHEM_PK_LENGTH),
      mac: cipherData.slice(ECIES_IV_LENGTH + ECIES_EPHEM_PK_LENGTH, ECIES_META_LENGTH),
      ciphertext: cipherData.slice(ECIES_META_LENGTH),
    });
  }

  public encryptSymmetric(password: string, plainText: string): string {
    return aes.encrypt(plainText, password).toString();
  }

  public decryptSymmetric(password: string, cipherText: string): string {
    return aes.decrypt(cipherText, password).toString(cryptojs.enc.Utf8);
  }

  public sha256(inputs: Buffer[]): BN {
    const merged = Buffer.concat(inputs);
    const result = ethers.utils.sha256(toHex(merged));
    return toBN(toHexNoPrefix(result), 16).mod(FIELD_SIZE);
  }

  public poseidonHash(inputs: BN[]): BN {
    check(inputs.length < 7, 'inputs length should be not greater than 6');
    const result = poseidon(inputs);
    const resultNum = toBN(result.toString());
    check(resultNum.lt(FIELD_SIZE), 'resultNum should be less than FIELD_SIZE');
    return resultNum;
  }

  public checkSum(data: string, salt?: string): string {
    return hmacSHA512(data, salt || 'mystiko').toString();
  }

  public commitmentWithShieldedAddress(shieldedRecipientAddress: string, amount: BN, args?: CI): Promise<CO> {
    const { pkVerify, pkEnc } = this.publicKeysFromShieldedAddress(shieldedRecipientAddress);
    return this.commitment(pkVerify, pkEnc, amount, args);
  }

  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  public zkProveRollup(rollup: R): Promise<Proof> {
    return Promise.reject(new Error('not implemented'));
  }

  public abstract commitmentFromEncryptedNote(
    pkVerify: Buffer,
    pkEnc: Buffer,
    skEnc: Buffer,
    encryptedNote: Buffer,
  ): Promise<CO>;

  public abstract commitment(pkVerify: Buffer, pkEnc: Buffer, amount: BN, args?: CI): Promise<CO>;

  public abstract zkProveTransaction(tx: T): Promise<Proof>;

  public abstract zkVerify(proof: Proof, vkeyFile: string | string[]): Promise<boolean>;
}
