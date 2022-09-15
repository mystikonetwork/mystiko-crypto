/* eslint-disable class-methods-use-this */
import { ECIES } from '@mystikonetwork/ecies';
import { MerkleTree } from '@mystikonetwork/merkle';
import { SecretSharing } from '@mystikonetwork/secret-share';
import {
  check,
  FIELD_SIZE,
  logger as rootLogger,
  toBN,
  toFixedLenHexNoPrefix,
  toHex,
  toHexNoPrefix,
  toString,
} from '@mystikonetwork/utils';
import { ZKProof, ZKProver } from '@mystikonetwork/zkp';
import createBlakeHash from 'blake-hash';
import BN from 'bn.js';
import bs58 from 'bs58';
import { eddsa, poseidon } from 'circomlibjs';
import cryptojs from 'crypto-js';
import aes from 'crypto-js/aes';
import hmacSHA512 from 'crypto-js/hmac-sha512';
import eccrypto from 'eccrypto';
import { ethers } from 'ethers';
import { Scalar } from 'ffjavascript';
import { Logger } from 'loglevel';
import unsafeRandomBytes from 'randombytes';
import { CommitmentInput, CommitmentOutput, MystikoProtocol } from '../../interface';

const ECIES_IV_LENGTH = 16;
const ECIES_EPHEM_PK_LENGTH = 65;
const ECIES_MAC_LENGTH = 32;
const ECIES_META_LENGTH = ECIES_IV_LENGTH + ECIES_EPHEM_PK_LENGTH + ECIES_MAC_LENGTH;

export interface TransactionV2 {
  numInputs: number;
  numOutputs: number;
  inVerifyPks: Buffer[];
  inVerifySks: Buffer[];
  inEncPks: Buffer[];
  inEncSks: Buffer[];
  inCommitments: BN[];
  inPrivateNotes: Buffer[];
  pathIndices: number[][];
  pathElements: BN[][];
  sigPk: Buffer;
  treeRoot: BN;
  publicAmount: BN;
  relayerFeeAmount: BN;
  rollupFeeAmounts: BN[];
  outVerifyPks: Buffer[];
  outAmounts: BN[];
  outCommitments: BN[];
  outRandomPs: BN[];
  outRandomRs: BN[];
  outRandomSs: BN[];
  programFile: string | string[];
  abiFile: string | string[];
  provingKeyFile: string | string[];
  randomAuditingSecretKey?: BN;
  auditorPublicKeys: BN[];
}

export interface RollupV2 {
  tree: MerkleTree;
  newLeaves: BN[];
  programFile: string | string[];
  abiFile: string | string[];
  provingKeyFile: string | string[];
}

export class MystikoProtocolV2 implements MystikoProtocol<TransactionV2, RollupV2> {
  private readonly zkProver: ZKProver;

  private readonly logger: Logger;

  constructor(zkProver: ZKProver) {
    this.zkProver = zkProver;
    this.logger = rootLogger.getLogger('MystikoProtocolV2');
  }

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

  public get numOfAuditors(): number {
    return 5;
  }

  public get auditingThreshold(): number {
    return 3;
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
    return unsafeRandomBytes(numBytes || 32);
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

  public serialNumber(skVerify: Buffer, randomP: BN): BN {
    const nullifierKey = this.poseidonHash([this.buffToBigInt(skVerify)]);
    return this.poseidonHash([randomP, nullifierKey]);
  }

  public sigPkHash(sigPk: Buffer, secretKey: Buffer) {
    return this.poseidonHash([this.buffToBigInt(secretKey), toBN(sigPk)]);
  }

  public async commitment(options: CommitmentInput): Promise<CommitmentOutput> {
    let pkVerify: Buffer;
    let pkEnc: Buffer;
    let randomP: BN = this.randomBigInt(this.randomSkSize);
    let randomR: BN = this.randomBigInt(this.randomSkSize);
    let randomS: BN = this.randomBigInt(this.randomSkSize);
    let amount: BN = options.amount || toBN(0);
    if (typeof options.publicKeys === 'string') {
      const pks = this.publicKeysFromShieldedAddress(options.publicKeys);
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
      const decryptedNote = await this.decryptAsymmetric(skEnc, encryptedNote);
      if (decryptedNote.length !== this.randomSkSize * 3 + this.amountSize) {
        return Promise.reject(
          new Error('wrong decrypted data from encrypted note, maybe secret key is wrong'),
        );
      }
      randomP = this.buffToBigInt(decryptedNote.slice(0, this.randomSkSize));
      randomR = this.buffToBigInt(decryptedNote.slice(this.randomSkSize, this.randomSkSize * 2));
      randomS = this.buffToBigInt(decryptedNote.slice(this.randomSkSize * 2, this.randomSkSize * 3));
      amount = this.buffToBigInt(decryptedNote.slice(this.randomSkSize * 3));
    }
    const k = this.poseidonHash([this.buffToBigInt(pkVerify), randomP, randomR]);
    const commitmentHash = this.poseidonHash([k, amount, randomS]);
    const encryptedNote = await this.encryptAsymmetric(
      pkEnc,
      Buffer.concat([
        this.bigIntToBuff(randomP, this.randomSkSize),
        this.bigIntToBuff(randomR, this.randomSkSize),
        this.bigIntToBuff(randomS, this.randomSkSize),
        this.bigIntToBuff(amount, this.amountSize),
      ]),
    );
    this.logger.debug(
      'commitment generation is done:' +
        `commitmentHash='${toString(commitmentHash)}', ` +
        `randomS='${toString(randomS)}', ` +
        `privateNote='${toHex(encryptedNote)}'`,
    );
    return Promise.resolve({
      commitmentHash,
      amount,
      shieldedAddress: this.shieldedAddress(pkVerify, pkEnc),
      k,
      randomP,
      randomR,
      randomS,
      encryptedNote,
    });
  }

  public async zkProveTransaction(tx: TransactionV2): Promise<ZKProof> {
    this.logger.debug('start generating zkSnark proofs...');
    this.checkTransaction(tx);
    const inRandomPs: BN[] = [];
    const inRandomRs: BN[] = [];
    const inRandomSs: BN[] = [];
    const inAmounts: BN[] = [];
    const serialNumbers: BN[] = [];
    const sigHashes: BN[] = [];
    const decryptPromises: Promise<Buffer>[] = [];
    for (let i = 0; i < tx.numInputs; i += 1) {
      decryptPromises.push(this.decryptAsymmetric(tx.inEncSks[i], tx.inPrivateNotes[i]));
    }
    const decryptPrivateNotes = await Promise.all(decryptPromises);
    for (let i = 0; i < decryptPrivateNotes.length; i += 1) {
      const decryptPrivateNote = decryptPrivateNotes[i];
      check(
        decryptPrivateNote.length === this.randomSkSize * 3 + this.amountSize,
        'decrypted note length is incorrect',
      );
      const randomP = this.buffToBigInt(decryptPrivateNote.slice(0, this.randomSkSize));
      const randomR = this.buffToBigInt(decryptPrivateNote.slice(this.randomSkSize, this.randomSkSize * 2));
      const randomS = this.buffToBigInt(
        decryptPrivateNote.slice(this.randomSkSize * 2, this.randomSkSize * 3),
      );
      const amount = this.buffToBigInt(decryptPrivateNote.slice(this.randomSkSize * 3));
      inRandomPs.push(randomP);
      inRandomRs.push(randomR);
      inRandomSs.push(randomS);
      inAmounts.push(amount);
      serialNumbers.push(this.serialNumber(tx.inVerifySks[i], inRandomPs[i]));
      sigHashes.push(this.sigPkHash(tx.sigPk, tx.inVerifySks[i]));
    }
    const randomAuditingSecretKey = tx.randomAuditingSecretKey || ECIES.generateSecretKey();
    const randomAuditingPublicKey = ECIES.publicKey(randomAuditingSecretKey);
    const unpackedRandomAuditingPublicKey = ECIES.unpackPublicKey(randomAuditingPublicKey);
    const unpackedAuditorPublicKeys = tx.auditorPublicKeys.map((pk) => {
      const unpacked = ECIES.unpackPublicKey(pk);
      return [unpacked.x, unpacked.y];
    });
    const commitmentSecretShares = tx.inCommitments.map((inCommitment) =>
      SecretSharing.split(inCommitment, this.numOfAuditors, this.auditingThreshold),
    );
    const encryptedCommitmentSecretShares = commitmentSecretShares.map(({ shares }) =>
      shares.map((share, index) =>
        ECIES.encrypt(share.y, tx.auditorPublicKeys[index], randomAuditingSecretKey).toString(),
      ),
    );
    const inputs: any[] = [
      tx.treeRoot.toString(),
      serialNumbers.map((bn) => bn.toString()),
      sigHashes.map((bn) => bn.toString()),
      toBN(tx.sigPk).toString(),
      tx.publicAmount.toString(),
      tx.relayerFeeAmount.toString(),
      tx.outCommitments.map((bn) => bn.toString()),
      tx.rollupFeeAmounts.map((bn) => bn.toString()),
      MystikoProtocolV2.isNegX(unpackedRandomAuditingPublicKey.x),
      unpackedRandomAuditingPublicKey.y.toString(),
      unpackedAuditorPublicKeys.map((keys) => MystikoProtocolV2.isNegX(keys[0])),
      unpackedAuditorPublicKeys.map((keys) => keys[1].toString()),
      encryptedCommitmentSecretShares,
      tx.inCommitments.map((bn) => bn.toString()),
      inAmounts.map((bn) => bn.toString()),
      inRandomPs.map((bn) => bn.toString()),
      inRandomRs.map((bn) => bn.toString()),
      inRandomSs.map((bn) => bn.toString()),
      tx.inVerifySks.map((bn) => this.buffToBigInt(bn).toString()),
      tx.inVerifyPks.map((bn) => this.buffToBigInt(bn).toString()),
      tx.pathElements.map((bns) => bns.map((bn) => bn.toString())),
      tx.pathIndices.map((numbers) => numbers.map((n) => n !== 0)),
      tx.outAmounts.map((bn) => bn.toString()),
      tx.outRandomPs.map((bn) => bn.toString()),
      tx.outRandomRs.map((bn) => bn.toString()),
      tx.outRandomSs.map((bn) => bn.toString()),
      tx.outVerifyPks.map((bn) => this.buffToBigInt(bn).toString()),
      unpackedRandomAuditingPublicKey.x.toString(),
      unpackedAuditorPublicKeys.map((keys) => keys[0].toString()),
      randomAuditingSecretKey.toString(),
      commitmentSecretShares.map((share) => share.coefficients.map((co) => co.toString())),
      commitmentSecretShares.map((share) => share.shares.map((s) => s.y.toString())),
    ];
    const proof = await this.zkProver.prove({
      programFile: typeof tx.programFile === 'string' ? [tx.programFile] : tx.programFile,
      abiFile: typeof tx.abiFile === 'string' ? [tx.abiFile] : tx.abiFile,
      provingKeyFile: typeof tx.provingKeyFile === 'string' ? [tx.provingKeyFile] : tx.provingKeyFile,
      inputs,
    });
    this.logger.debug('zkSnark proof is generated successfully');
    return proof;
  }

  public zkProveRollup(rollup: RollupV2): Promise<ZKProof> {
    check(MystikoProtocolV2.isPowerOfTwo(rollup.newLeaves.length), 'newLeaves length should be power of 2');
    const rollupSize = rollup.newLeaves.length;
    const rollupHeight = Math.log2(rollupSize);
    const currentLeafCount = rollup.tree.elements().length;
    check(
      currentLeafCount % rollupSize === 0,
      `cannot rollup ${rollupSize} leaves when the tree has ${currentLeafCount} leaves`,
    );
    const currentRoot = rollup.tree.root();
    rollup.tree.bulkInsert(rollup.newLeaves);
    const newRoot = rollup.tree.root();
    const leafPath = rollup.tree.path(currentLeafCount);
    const pathIndices = MystikoProtocolV2.pathIndicesNumber(leafPath.pathIndices.slice(rollupHeight));
    const pathElements = leafPath.pathElements.slice(rollupHeight);
    const leafHash = MystikoProtocolV2.calcLeaveHash(rollup.newLeaves);
    const inputs = [
      currentRoot.toString(),
      newRoot.toString(),
      leafHash.toString(),
      pathIndices.toString(),
      pathElements.map((bn) => bn.toString()),
      rollup.newLeaves.map((bn) => bn.toString()),
    ];
    return this.zkProver.prove({
      programFile: typeof rollup.programFile === 'string' ? [rollup.programFile] : rollup.programFile,
      abiFile: typeof rollup.abiFile === 'string' ? [rollup.abiFile] : rollup.abiFile,
      provingKeyFile:
        typeof rollup.provingKeyFile === 'string' ? [rollup.provingKeyFile] : rollup.provingKeyFile,
      inputs,
    });
  }

  public async zkVerify(proof: ZKProof, verifyingKeyFile: string | string[]): Promise<boolean> {
    this.logger.debug('start verifying generated proofs...');
    const result = await this.zkProver.verify({
      proof,
      verifyingKeyFile: typeof verifyingKeyFile === 'string' ? [verifyingKeyFile] : verifyingKeyFile,
    });
    this.logger.debug(`proof verification is done, result=${result}`);
    return Promise.resolve(result);
  }

  private checkTransaction(tx: TransactionV2): void {
    check(tx.numInputs === tx.inVerifyPks.length, `inVerifyPks length does not equal to ${tx.numInputs}`);
    check(tx.numInputs === tx.inVerifySks.length, `inVerifySks length does not equal to ${tx.numInputs}`);
    check(tx.numInputs === tx.inEncPks.length, `inEncPks length does not equal to ${tx.numInputs}`);
    check(tx.numInputs === tx.inEncSks.length, `inEncSks length does not equal to ${tx.numInputs}`);
    check(tx.numInputs === tx.inCommitments.length, `inCommitments length does not equal to ${tx.numInputs}`);
    check(
      tx.numInputs === tx.inPrivateNotes.length,
      `inPrivateNotes length does not equal to ${tx.numInputs}`,
    );
    check(tx.numInputs === tx.pathIndices.length, `pathIndices length does not equal to ${tx.numInputs}`);
    check(tx.numInputs === tx.pathElements.length, `pathElements length does not equal to ${tx.numInputs}`);
    check(
      tx.numOutputs === tx.rollupFeeAmounts.length,
      `rollupFeeAmounts length does not equal to ${tx.numOutputs}`,
    );
    check(tx.numOutputs === tx.outVerifyPks.length, `outVerifyPks length does not equal to ${tx.numOutputs}`);
    check(
      tx.numOutputs === tx.outCommitments.length,
      `outCommitments length does not equal to ${tx.numOutputs}`,
    );
    check(tx.numOutputs === tx.outRandomPs.length, `outRandomPs length does not equal to ${tx.numOutputs}`);
    check(tx.numOutputs === tx.outRandomRs.length, `outRandomRs length does not equal to ${tx.numOutputs}`);
    check(tx.numOutputs === tx.outRandomSs.length, `outRandomSs length does not equal to ${tx.numOutputs}`);
    check(tx.numOutputs === tx.outAmounts.length, `outAmounts length does not equal to ${tx.numOutputs}`);
    tx.pathIndices.forEach((pathIndices) => {
      check(
        this.merkleTreeLevels === pathIndices.length,
        `pathIndices length does not equal to ${this.merkleTreeLevels}`,
      );
    });
    tx.pathElements.forEach((pathElements) => {
      check(
        this.merkleTreeLevels === pathElements.length,
        `pathElements length does not equal to ${this.merkleTreeLevels}`,
      );
    });
    check(
      tx.auditorPublicKeys.length === this.numOfAuditors,
      `auditorPublicKeys length does not equal to ${this.numOfAuditors}`,
    );
  }

  private static isPowerOfTwo(aNumber: number): boolean {
    return aNumber !== 0 && (aNumber & (aNumber - 1)) === 0;
  }

  private static pathIndicesNumber(pathIndices: number[]): BN {
    return toBN(pathIndices.slice().reverse().join(''), 2);
  }

  private static calcLeaveHash(leaves: BN[]): BN {
    const leafBuffer = Buffer.concat(leaves.map((leaf) => Buffer.from(toFixedLenHexNoPrefix(leaf), 'hex')));
    return toBN(toHexNoPrefix(ethers.utils.keccak256(leafBuffer)), 16).mod(FIELD_SIZE);
  }

  private static isNegX(x: BN): boolean {
    return x.gt(FIELD_SIZE.shrn(1));
  }
}
