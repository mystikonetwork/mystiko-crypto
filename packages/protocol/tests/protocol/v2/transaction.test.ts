import { ECIES } from '@mystikonetwork/ecies';
import { MerkleTree } from '@mystikonetwork/merkle';
import { toBN, toDecimals, toHexNoPrefix } from '@mystikonetwork/utils';
import { ZokratesNodeProverFactory, ZokratesNodeProverOptions } from '@mystikonetwork/zkp-node';
import BN from 'bn.js';
import { ethers } from 'ethers';
import { CommitmentOutput, MystikoProtocolV2, ProtocolFactoryV2, TransactionV2 } from '../../../src';

let protocol: MystikoProtocolV2;
let factory: ProtocolFactoryV2;

async function generateTransaction(
  p: MystikoProtocolV2,
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
    const rawVerifySk = p.randomBytes(p.verifySkSize);
    const rawEncSk = p.randomBytes(p.encSkSize);
    inVerifySks.push(p.secretKeyForVerification(rawVerifySk));
    inVerifyPks.push(p.publicKeyForVerification(rawVerifySk));
    inEncSks.push(p.secretKeyForEncryption(rawEncSk));
    inEncPks.push(p.publicKeyForEncryption(rawEncSk));
    inAmounts.push(toDecimals(200));
  }
  const inCommitmentsPromises: Promise<CommitmentOutput>[] = [];
  for (let i = 0; i < numInputs; i += 1) {
    inCommitmentsPromises.push(
      p.commitment({
        publicKeys: { pkVerify: inVerifyPks[i], pkEnc: inEncPks[i] },
        amount: inAmounts[i],
      }),
    );
  }
  const inCommitmentsAll = await Promise.all(inCommitmentsPromises);
  const inCommitments = inCommitmentsAll.map((all) => all.commitmentHash);
  const inPrivateNotes = inCommitmentsAll.map((all) => all.encryptedNote);
  const merkleTree = new MerkleTree(inCommitments, { maxLevels: p.merkleTreeLevels });
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
    const rawVerifySk = p.randomBytes(p.verifySkSize);
    const rawEncSk = p.randomBytes(p.encSkSize);
    const verifyPk = p.publicKeyForVerification(rawVerifySk);
    const encPk = p.publicKeyForEncryption(rawEncSk);
    outVerifyPks.push(verifyPk);
    outEncPks.push(encPk);
    outAmounts.push(toDecimals(50));
    rollupFeeAmounts.push(toDecimals(10));
  }
  const outCommitmentPromises: Promise<CommitmentOutput>[] = [];
  for (let i = 0; i < numOutputs; i += 1) {
    outCommitmentPromises.push(
      p.commitment({
        publicKeys: { pkVerify: outVerifyPks[i], pkEnc: outEncPks[i] },
        amount: outAmounts[i],
        randomSecrets: {
          randomP: protocol.randomBigInt(protocol.randomSkSize),
          randomS: protocol.randomBigInt(protocol.randomSkSize),
          randomR: protocol.randomBigInt(protocol.randomSkSize),
        },
      }),
    );
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
  const randomAuditingSecretKey = ECIES.generateSecretKey();
  const auditorPublicKeys: BN[] = [];
  for (let i = 0; i < protocol.numOfAuditors; i += 1) {
    auditorPublicKeys.push(ECIES.publicKey(ECIES.generateSecretKey()));
  }
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
    randomAuditingSecretKey,
    auditorPublicKeys,
  };
}

async function generateCommitments(
  mystikoProtocolV2: MystikoProtocolV2,
  numOfCommitments: number,
): Promise<{ publicKey: Buffer; secretKey: Buffer; commitment: CommitmentOutput }[]> {
  const commitmentPromises: Promise<{
    publicKey: Buffer;
    secretKey: Buffer;
    commitment: CommitmentOutput;
  }>[] = [];
  for (let i = 0; i < numOfCommitments; i += 1) {
    const skVerify = mystikoProtocolV2.randomBytes();
    const skEnc = mystikoProtocolV2.randomBytes();
    const pkVerify = mystikoProtocolV2.publicKeyForVerification(skVerify);
    const pkEnc = mystikoProtocolV2.publicKeyForEncryption(skEnc);
    const promise = mystikoProtocolV2
      .commitment({
        publicKeys: { pkVerify, pkEnc },
        amount: toBN(10),
      })
      .then((commitment) => ({
        publicKey: mystikoProtocolV2.fullPublicKey(pkVerify, pkEnc),
        secretKey: mystikoProtocolV2.fullSecretKey(skVerify, skEnc),
        commitment,
      }));
    commitmentPromises.push(promise);
  }
  const commitments = await Promise.all(commitmentPromises);
  return commitments;
}

beforeAll(async () => {
  factory = new ProtocolFactoryV2<ZokratesNodeProverOptions>(new ZokratesNodeProverFactory());
  protocol = await factory.create();
});

test('test commitment', async () => {
  const skVerify = protocol.randomBytes();
  const skEnc = protocol.randomBytes();
  const pkVerify = protocol.publicKeyForVerification(skVerify);
  const pkEnc = protocol.publicKeyForEncryption(skEnc);
  const { encryptedNote, commitmentHash } = await protocol.commitment({
    publicKeys: { pkVerify, pkEnc },
    amount: toBN(10),
  });
  const c2 = await protocol.commitment({
    publicKeys: protocol.shieldedAddress(pkVerify, pkEnc),
    amount: toBN(10),
    encryptedNote: { skEnc, encryptedNote },
  });
  expect(c2.commitmentHash.toString()).toBe(commitmentHash.toString());
  const c1: CommitmentOutput | undefined = await protocol
    .commitment({
      publicKeys: { pkVerify, pkEnc },
      amount: toBN(10),
      encryptedNote: { skEnc: protocol.randomBytes(), encryptedNote },
    })
    .then((c3) => (c3.commitmentHash.toString() !== commitmentHash.toString() ? undefined : c3))
    .catch(() => undefined);
  expect(c1).toBe(undefined);
});

test('test decryptNote', async () => {
  const commitmentsWithKeys = await generateCommitments(protocol, 100);
  const keys = commitmentsWithKeys.map((c) => ({ publicKey: c.publicKey, secretKey: c.secretKey }));
  const commitments = commitmentsWithKeys.map((c) => c.commitment);
  const shieldedAddresses = commitmentsWithKeys.map((c) => {
    const { pkVerify, pkEnc } = protocol.separatedPublicKeys(c.publicKey);
    return protocol.shieldedAddress(pkVerify, pkEnc);
  });
  const serialNumbers = commitmentsWithKeys.map((c) => {
    const { skVerify } = protocol.separatedSecretKeys(c.secretKey);
    return protocol.serialNumber(skVerify, c.commitment.randomP);
  });
  let decrypted = await protocol.decryptNotes(commitments.slice(0, 35), keys.slice(20, 100));
  expect(decrypted.length).toBe(15);
  for (let i = 20; i < 20 + decrypted.length; i += 1) {
    expect(decrypted[i - 20].commitment.commitmentHash.toString()).toBe(
      commitmentsWithKeys[i].commitment.commitmentHash.toString(),
    );
    expect(decrypted[i - 20].shieldedAddress).toBe(shieldedAddresses[i]);
    expect(decrypted[i - 20].serialNumber.toString()).toBe(serialNumbers[i].toString());
  }
  decrypted = await protocol.decryptNotes(commitments, keys, 4);
  expect(decrypted.length).toBe(100);
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
}, 60000);

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
}, 60000);

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
}, 60000);

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
}, 60000);

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
}, 60000);

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
}, 60000);
