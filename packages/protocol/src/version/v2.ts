import BN from 'bn.js';
import { ethers } from 'ethers';
import { Proof } from 'zokrates-js';
import {
  check,
  FIELD_SIZE,
  logger,
  MerkleTree,
  toBN,
  toFixedLenHexNoPrefix,
  toHex,
  toHexNoPrefix,
  toString,
} from '@mystikonetwork/utils';
import { MystikoProtocol } from '../base';
import { ZokratesRuntime } from '../runtime';

export interface CommitmentArgsV2 {
  randomP?: BN;
  randomR?: BN;
  randomS?: BN;
}

export interface CommitmentV2 {
  privateNote: Buffer;
  amount: BN;
  shieldedAddress: string;
  randomP: BN;
  randomR: BN;
  randomS: BN;
  commitmentHash: BN;
  k: BN;
}

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
}

export interface RollupV2 {
  tree: MerkleTree;
  newLeaves: BN[];
  programFile: string | string[];
  abiFile: string | string[];
  provingKeyFile: string | string[];
}

export class MystikoProtocolV2 extends MystikoProtocol<
  CommitmentArgsV2,
  CommitmentV2,
  TransactionV2,
  RollupV2
> {
  private readonly runtime: ZokratesRuntime;

  constructor(runtime: ZokratesRuntime) {
    super();
    this.runtime = runtime;
  }

  public serialNumber(skVerify: Buffer, randomP: BN): BN {
    return this.poseidonHash([randomP, this.buffToBigInt(skVerify)]);
  }

  public sigPkHash(sigPk: Buffer, secretKey: Buffer) {
    return this.poseidonHash([this.buffToBigInt(secretKey), toBN(sigPk)]);
  }

  public async commitment(
    pkVerify: Buffer,
    pkEnc: Buffer,
    amount: BN,
    args?: CommitmentArgsV2,
  ): Promise<CommitmentV2> {
    const generatedRandomP = args?.randomP || this.randomBigInt(this.randomSkSize);
    const generatedRandomR = args?.randomR || this.randomBigInt(this.randomSkSize);
    const generatedRandomS = args?.randomS || this.randomBigInt(this.randomSkSize);
    const k = this.poseidonHash([this.buffToBigInt(pkVerify), generatedRandomP, generatedRandomR]);
    const commitmentHash = this.poseidonHash([k, amount, generatedRandomS]);
    const privateNote = await this.encryptAsymmetric(
      pkEnc,
      Buffer.concat([
        this.bigIntToBuff(generatedRandomP, this.randomSkSize),
        this.bigIntToBuff(generatedRandomR, this.randomSkSize),
        this.bigIntToBuff(generatedRandomS, this.randomSkSize),
        this.bigIntToBuff(amount, this.amountSize),
      ]),
    );
    logger.debug(
      'commitment generation is done:' +
        `commitmentHash='${toString(commitmentHash)}', ` +
        `randomS='${toString(generatedRandomS)}', ` +
        `privateNote='${toHex(privateNote)}'`,
    );
    return Promise.resolve({
      commitmentHash,
      amount,
      shieldedAddress: this.shieldedAddress(pkVerify, pkEnc),
      k,
      randomP: generatedRandomP,
      randomR: generatedRandomR,
      randomS: generatedRandomS,
      privateNote,
    });
  }

  public async commitmentFromEncryptedNote(
    pkVerify: Buffer,
    pkEnc: Buffer,
    skEnc: Buffer,
    encryptedNote: Buffer,
  ): Promise<CommitmentV2> {
    const decryptedNote = await this.decryptAsymmetric(skEnc, encryptedNote);
    if (decryptedNote.length !== this.randomSkSize * 3 + this.amountSize) {
      return Promise.reject(new Error('wrong decrypted data from encrypted note, maybe secret key is wrong'));
    }
    const randomP = this.buffToBigInt(decryptedNote.slice(0, this.randomSkSize));
    const randomR = this.buffToBigInt(decryptedNote.slice(this.randomSkSize, this.randomSkSize * 2));
    const randomS = this.buffToBigInt(decryptedNote.slice(this.randomSkSize * 2, this.randomSkSize * 3));
    const amount = this.buffToBigInt(decryptedNote.slice(this.randomSkSize * 3));
    return this.commitment(pkVerify, pkEnc, amount, { randomP, randomR, randomS });
  }

  public async zkProveTransaction(tx: TransactionV2): Promise<Proof> {
    logger.debug('start generating zkSnark proofs...');
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
    const inputs: any[] = [
      tx.treeRoot.toString(),
      serialNumbers.map((bn) => bn.toString()),
      sigHashes.map((bn) => bn.toString()),
      toBN(tx.sigPk).toString(),
      tx.publicAmount.toString(),
      tx.relayerFeeAmount.toString(),
      tx.outCommitments.map((bn) => bn.toString()),
      tx.rollupFeeAmounts.map((bn) => bn.toString()),
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
    ];
    const proof = await this.runtime.prove(tx.programFile, tx.abiFile, tx.provingKeyFile, inputs);
    logger.debug('zkSnark proof is generated successfully');
    return proof;
  }

  public zkProveRollup(rollup: RollupV2): Promise<Proof> {
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
    return this.runtime.prove(rollup.programFile, rollup.abiFile, rollup.provingKeyFile, inputs);
  }

  public async zkVerify(proof: Proof, vkeyFile: string | string[]): Promise<boolean> {
    logger.debug('start verifying generated proofs...');
    const result = await this.runtime.verify(vkeyFile, proof);
    logger.debug(`proof verification is done, result=${result}`);
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
}
