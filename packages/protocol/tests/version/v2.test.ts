import BN from 'bn.js';
import { ethers } from 'ethers';
import { MerkleTree, toBN, toDecimals, toHexNoPrefix } from '@mystikonetwork/utils';
import { CommitmentV2, MystikoProtocolV2, TransactionV2, ZokratesCliRuntime } from '../../src';

async function generateTransaction(
  protocol: MystikoProtocolV2,
  numInputs: number,
  numOutputs: number,
  programFile: string,
  abiFile: string,
  provingKeyFile: string,
): Promise<TransactionV2> {
  const inVerifyPks: Buffer[] = [];
  const inVerifySks: Buffer[] = [];
  const inEncPks: Buffer[] = [];
  const inEncSks: Buffer[] = [];
  const inAmounts: BN[] = [];
  for (let i = 0; i < numInputs; i += 1) {
    const rawVerifySk = protocol.randomBytes(protocol.verifySkSize);
    const rawEncSk = protocol.randomBytes(protocol.encSkSize);
    inVerifySks.push(protocol.secretKeyForVerification(rawVerifySk));
    inVerifyPks.push(protocol.publicKeyForVerification(rawVerifySk));
    inEncSks.push(protocol.secretKeyForEncryption(rawEncSk));
    inEncPks.push(protocol.publicKeyForEncryption(rawEncSk));
    inAmounts.push(toDecimals(200));
  }
  const inCommitmentsPromises: Promise<CommitmentV2>[] = [];
  for (let i = 0; i < numInputs; i += 1) {
    inCommitmentsPromises.push(protocol.commitment(inVerifyPks[i], inEncPks[i], inAmounts[i]));
  }
  const inCommitmentsAll = await Promise.all(inCommitmentsPromises);
  const inCommitments = inCommitmentsAll.map((all) => all.commitmentHash);
  const inPrivateNotes = inCommitmentsAll.map((all) => all.privateNote);
  const merkleTree = new MerkleTree(inCommitments, { maxLevels: protocol.merkleTreeLevels });
  const allPaths: { pathElements: BN[]; pathIndices: number[] }[] = [];
  for (let i = 0; i < inCommitments.length; i += 1) {
    allPaths.push(merkleTree.path(i));
  }
  const pathIndices = allPaths.map((all) => all.pathIndices);
  const pathElements = allPaths.map((all) => all.pathElements);
  const randomWallet = ethers.Wallet.createRandom();
  const sigPk = Buffer.from(toHexNoPrefix(randomWallet.address), 'hex');
  const relayerFeeAmount = toDecimals(10);
  const rollupFeeAmounts: BN[] = [];
  const outAmounts: BN[] = [];
  const outVerifyPks: Buffer[] = [];
  const outEncPks: Buffer[] = [];
  for (let i = 0; i < numOutputs; i += 1) {
    const rawVerifySk = protocol.randomBytes(protocol.verifySkSize);
    const rawEncSk = protocol.randomBytes(protocol.encSkSize);
    const verifyPk = protocol.publicKeyForVerification(rawVerifySk);
    const encPk = protocol.publicKeyForEncryption(rawEncSk);
    outVerifyPks.push(verifyPk);
    outEncPks.push(encPk);
    outAmounts.push(toDecimals(50));
    rollupFeeAmounts.push(toDecimals(10));
  }
  const outCommitmentPromises: Promise<CommitmentV2>[] = [];
  for (let i = 0; i < numOutputs; i += 1) {
    outCommitmentPromises.push(protocol.commitment(outVerifyPks[i], outEncPks[i], outAmounts[i]));
  }
  const outCommitmentsAll = await Promise.all(outCommitmentPromises);
  const outCommitments = outCommitmentsAll.map((all) => all.commitmentHash);
  const outRandomPs = outCommitmentsAll.map((all) => all.randomP);
  const outRandomRs = outCommitmentsAll.map((all) => all.randomR);
  const outRandomSs = outCommitmentsAll.map((all) => all.randomS);
  const publicAmount = inAmounts
    .reduce((a, b) => a.add(b), new BN(0))
    .sub(outAmounts.reduce((a, b) => a.add(b), new BN(0)))
    .sub(rollupFeeAmounts.reduce((a, b) => a.add(b), new BN(0)))
    .sub(relayerFeeAmount);
  return {
    numInputs,
    numOutputs,
    inVerifySks,
    inVerifyPks,
    inEncSks,
    inEncPks,
    inCommitments,
    inPrivateNotes,
    pathIndices,
    pathElements,
    sigPk,
    treeRoot: merkleTree.root(),
    publicAmount,
    relayerFeeAmount,
    rollupFeeAmounts,
    outVerifyPks,
    outCommitments,
    outRandomPs,
    outRandomRs,
    outRandomSs,
    outAmounts,
    programFile,
    abiFile,
    provingKeyFile,
  };
}

let protocol: MystikoProtocolV2;

beforeAll(async () => {
  // eslint-disable-next-line global-require
  const { initialize } = require('zokrates-js/node');
  const zokrates = await initialize();
  const runtime = new ZokratesCliRuntime(zokrates);
  protocol = new MystikoProtocolV2(runtime);
});

test('test commitment', async () => {
  const skVerify = protocol.randomBytes();
  const skEnc = protocol.randomBytes();
  const pkVerify = protocol.publicKeyForVerification(skVerify);
  const pkEnc = protocol.publicKeyForEncryption(skEnc);
  const { privateNote, commitmentHash } = await protocol.commitment(pkVerify, pkEnc, toBN(10));
  const c2 = await protocol.commitmentFromEncryptedNote(pkVerify, pkEnc, skEnc, privateNote);
  expect(c2.commitmentHash.toString()).toBe(commitmentHash.toString());
  const c1: CommitmentV2 | undefined = await protocol
    .commitmentFromEncryptedNote(pkVerify, pkEnc, protocol.randomBytes(), privateNote)
    .then((c3) => (c3.commitmentHash.toString() !== commitmentHash.toString() ? undefined : c3))
    .catch(() => undefined);
  expect(c1).toBe(undefined);
});

test('test Transaction1x0', async () => {
  const tx = await generateTransaction(
    protocol,
    1,
    0,
    'circuits/dist/zokrates/dev/Transaction1x0.program.gz',
    'circuits/dist/zokrates/dev/Transaction1x0.abi.json',
    'circuits/dist/zokrates/dev/Transaction1x0.pkey.gz',
  );
  const proof = await protocol.zkProveTransaction(tx);
  const result = await protocol.zkVerify(proof, 'circuits/dist/zokrates/dev/Transaction1x0.vkey.gz');
  expect(result).toBe(true);
});

test('test Transaction1x1', async () => {
  const tx = await generateTransaction(
    protocol,
    1,
    1,
    'circuits/dist/zokrates/dev/Transaction1x1.program.gz',
    'circuits/dist/zokrates/dev/Transaction1x1.abi.json',
    'circuits/dist/zokrates/dev/Transaction1x1.pkey.gz',
  );
  const proof = await protocol.zkProveTransaction(tx);
  const result = await protocol.zkVerify(proof, 'circuits/dist/zokrates/dev/Transaction1x1.vkey.gz');
  expect(result).toBe(true);
});

test('test Transaction1x2', async () => {
  const tx = await generateTransaction(
    protocol,
    1,
    2,
    'circuits/dist/zokrates/dev/Transaction1x2.program.gz',
    'circuits/dist/zokrates/dev/Transaction1x2.abi.json',
    'circuits/dist/zokrates/dev/Transaction1x2.pkey.gz',
  );
  const proof = await protocol.zkProveTransaction(tx);
  const result = await protocol.zkVerify(proof, 'circuits/dist/zokrates/dev/Transaction1x2.vkey.gz');
  expect(result).toBe(true);
});

test('test Transaction2x0', async () => {
  const tx = await generateTransaction(
    protocol,
    2,
    0,
    'circuits/dist/zokrates/dev/Transaction2x0.program.gz',
    'circuits/dist/zokrates/dev/Transaction2x0.abi.json',
    'circuits/dist/zokrates/dev/Transaction2x0.pkey.gz',
  );
  const proof = await protocol.zkProveTransaction(tx);
  const result = await protocol.zkVerify(proof, 'circuits/dist/zokrates/dev/Transaction2x0.vkey.gz');
  expect(result).toBe(true);
});

test('test Transaction2x1', async () => {
  const tx = await generateTransaction(
    protocol,
    2,
    1,
    'circuits/dist/zokrates/dev/Transaction2x1.program.gz',
    'circuits/dist/zokrates/dev/Transaction2x1.abi.json',
    'circuits/dist/zokrates/dev/Transaction2x1.pkey.gz',
  );
  const proof = await protocol.zkProveTransaction(tx);
  const result = await protocol.zkVerify(proof, 'circuits/dist/zokrates/dev/Transaction2x1.vkey.gz');
  expect(result).toBe(true);
});

test('test Transaction2x2', async () => {
  const tx = await generateTransaction(
    protocol,
    2,
    2,
    'circuits/dist/zokrates/dev/Transaction2x2.program.gz',
    'circuits/dist/zokrates/dev/Transaction2x2.abi.json',
    'circuits/dist/zokrates/dev/Transaction2x2.pkey.gz',
  );
  const proof = await protocol.zkProveTransaction(tx);
  const result = await protocol.zkVerify(proof, 'circuits/dist/zokrates/dev/Transaction2x2.vkey.gz');
  expect(result).toBe(true);
});
