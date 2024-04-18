/* eslint-disable class-methods-use-this */
import { ECIES } from '@mystikonetwork/ecies';
import { MerkleTree } from '@mystikonetwork/merkle';
import { SecretSharing } from '@mystikonetwork/secret-share';
import {
  check,
  detectConcurrency,
  FIELD_SIZE,
  logger as rootLogger,
  toBN,
  toBuff,
  toFixedLenHexNoPrefix,
  toHex,
  toHexNoPrefix,
  toString,
} from '@mystikonetwork/utils';
import { ZKProof, ZKProver } from '@mystikonetwork/zkp';
import BN from 'bn.js';
import { ethers } from 'ethers';
import { Logger } from 'loglevel';
import { createWorkerFactory, terminate } from '@shopify/web-worker';
import { CommitmentInput, CommitmentOutput, DecryptOutput, MystikoProtocol } from '../../interface';
import * as impl from './impl';

const createWorker = createWorkerFactory(() => import('./worker'));

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
  program: Buffer;
  abi: string;
  provingKey: Buffer;
  randomAuditingSecretKey?: BN;
  auditorPublicKeys: BN[];
}

export interface RollupV2 {
  tree: MerkleTree;
  newLeaves: BN[];
  program: Buffer;
  abi: string;
  provingKey: Buffer;
}

export class MystikoProtocolV2 implements MystikoProtocol<TransactionV2, RollupV2> {
  private readonly zkProver: ZKProver;

  private readonly logger: Logger;

  constructor(zkProver: ZKProver) {
    this.zkProver = zkProver;
    this.logger = rootLogger.getLogger('MystikoProtocolV2');
  }

  public get verifyPkSize(): number {
    return impl.VERIFY_PK_SIZE;
  }

  public get verifySkSize(): number {
    return impl.VERIFY_SK_SIZE;
  }

  public get encPkSize(): number {
    return impl.ENC_PK_SIZE;
  }

  public get encSkSize(): number {
    return impl.ENC_SK_SIZE;
  }

  public get randomSkSize(): number {
    return impl.RANDOM_SK_SIZE;
  }

  public get amountSize(): number {
    return impl.AMOUNT_SIZE;
  }

  public get merkleTreeLevels(): number {
    return impl.MERKLE_TREE_LEVELS;
  }

  public get numOfAuditors(): number {
    return impl.NUM_OF_AUDITORS;
  }

  public get auditingThreshold(): number {
    return impl.AUDITING_THRESHOLD;
  }

  public buffToBigInt(buff: Buffer): BN {
    return impl.buffToBigInt(buff);
  }

  public bigIntToBuff(bigInt: BN, numBytes: number = 32): Buffer {
    return impl.bigIntToBuff(bigInt, numBytes);
  }

  public randomBigInt(numBytes?: number): BN {
    return impl.randomBigInt(numBytes);
  }

  public randomBytes(numBytes?: number): Buffer {
    return impl.randomBytes(numBytes);
  }

  public secretKeyForVerification(rawSecretKey: Buffer): Buffer {
    return impl.secretKeyForVerification(rawSecretKey);
  }

  public publicKeyForVerification(rawSecretKey: Buffer): Buffer {
    return impl.publicKeyForVerification(rawSecretKey);
  }

  public secretKeyForEncryption(rawSecretKey: Buffer): Buffer {
    return impl.secretKeyForEncryption(rawSecretKey);
  }

  public publicKeyForEncryption(rawSecretKey: Buffer): Buffer {
    return impl.publicKeyForEncryption(rawSecretKey);
  }

  public fullPublicKey(pkVerify: Buffer, pkEnc: Buffer): Buffer {
    return impl.fullPublicKey(pkVerify, pkEnc);
  }

  public fullSecretKey(skVerify: Buffer, skEnc: Buffer): Buffer {
    return impl.fullSecretKey(skVerify, skEnc);
  }

  public separatedPublicKeys(longPublicKey: Buffer): { pkEnc: Buffer; pkVerify: Buffer } {
    return impl.separatedPublicKeys(longPublicKey);
  }

  public separatedSecretKeys(longSecretKey: Buffer): { skVerify: Buffer; skEnc: Buffer } {
    return impl.separatedSecretKeys(longSecretKey);
  }

  public shieldedAddress(pkVerify: Buffer, pkEnc: Buffer): string {
    return impl.shieldedAddress(pkVerify, pkEnc);
  }

  public isShieldedAddress(address: string): boolean {
    return impl.isShieldedAddress(address);
  }

  public publicKeysFromShieldedAddress(address: string): { pkEnc: Buffer; pkVerify: Buffer } {
    return impl.publicKeysFromShieldedAddress(address);
  }

  public encryptAsymmetric(publicKey: Buffer, plainData: Buffer): Promise<Buffer> {
    return impl.encryptAsymmetric(publicKey, plainData);
  }

  public decryptAsymmetric(secretKey: Buffer, cipherData: Buffer): Promise<Buffer> {
    return impl.decryptAsymmetric(secretKey, cipherData);
  }

  public encryptSymmetric(password: string, plainText: string): string {
    return impl.encryptSymmetric(password, plainText);
  }

  public decryptSymmetric(password: string, cipherText: string): string {
    return impl.decryptSymmetric(password, cipherText);
  }

  public sha256(inputs: Buffer[]): BN {
    return impl.sha256(inputs);
  }

  public poseidonHash(inputs: BN[]): BN {
    return impl.poseidonHash(inputs);
  }

  public checkSum(data: string, salt?: string): string {
    return impl.checkSum(data, salt);
  }

  public serialNumber(skVerify: Buffer, randomP: BN): BN {
    return impl.serialNumber(skVerify, randomP);
  }

  public sigPkHash(sigPk: Buffer, secretKey: Buffer) {
    return impl.sigPkHash(sigPk, secretKey);
  }

  public async commitment(options: CommitmentInput): Promise<CommitmentOutput> {
    const output = await impl.commitment(options);
    this.logger.debug(
      'commitment generation is done:' +
        `commitmentHash='${toString(output.commitmentHash)}', ` +
        `randomS='${toString(output.randomS)}', ` +
        `privateNote='${toHex(output.encryptedNote)}'`,
    );
    return output;
  }

  public async decryptNotes(
    commitments: { commitmentHash: string; encryptedNote: string }[],
    keys: { publicKey: string; secretKey: string }[],
    concurrency?: number,
  ): Promise<DecryptOutput[]> {
    const numGroups = concurrency || detectConcurrency() || 1;
    const groupSize = Math.ceil(commitments.length / numGroups);
    const groups = [];
    for (let i = 0; i < commitments.length; i += groupSize) {
      groups.push(commitments.slice(i, i + groupSize));
    }
    const promises: Promise<DecryptOutput[]>[] = groups.map((group) => {
      const worker = createWorker();
      return worker
        .decryptNotes(group, keys)
        .then((outputs) =>
          outputs.map((output) => ({
            commitment: {
              encryptedNote: toBuff(output.commitment.encryptedNote),
              shieldedAddress: output.commitment.shieldedAddress,
              commitmentHash: toBN(output.commitment.commitmentHash),
              amount: toBN(output.commitment.amount),
              randomP: toBN(output.commitment.randomP),
              randomR: toBN(output.commitment.randomR),
              randomS: toBN(output.commitment.randomS),
              k: toBN(output.commitment.k),
            },
            shieldedAddress: output.shieldedAddress,
            serialNumber: toBN(output.serialNumber),
          })),
        )
        .finally(() => terminate(worker));
    });
    const results = await Promise.all(promises);
    return results.flat();
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
      program: tx.program,
      abi: tx.abi,
      provingKey: tx.provingKey,
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
      program: rollup.program,
      abi: rollup.abi,
      provingKey: rollup.provingKey,
      inputs,
    });
  }

  public async zkVerify(proof: ZKProof, verifyingKey: string): Promise<boolean> {
    this.logger.debug('start verifying generated proofs...');
    const result = await this.zkProver.verify({
      proof,
      verifyingKey,
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
