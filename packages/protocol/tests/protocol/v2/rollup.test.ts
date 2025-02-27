import { MerkleTree } from '@mystikonetwork/merkle';
import { readCompressedFile, readFile, toBN } from '@mystikonetwork/utils';
import { ZokratesNodeProverFactory, ZokratesNodeProverOptions } from '@mystikonetwork/zkp-node';
import { MystikoProtocolV2, ProtocolFactoryV2 } from '../../../src';

let protocol: MystikoProtocolV2;
let factory: ProtocolFactoryV2;

beforeAll(async () => {
  factory = new ProtocolFactoryV2<ZokratesNodeProverOptions>(new ZokratesNodeProverFactory());
  protocol = await factory.create();
});

test('test zkProveRollup1', async () => {
  const tree = MerkleTree.fromLeaves([toBN('100'), toBN('200'), toBN('300')], {
    maxLevels: protocol.merkleTreeLevels,
  });
  const proof = await protocol.zkProveRollup({
    tree,
    newLeaves: [toBN('1')],
    program: await readCompressedFile(['circuits/dist/zokrates/dev/Rollup1.program.gz']),
    abi: (await readFile(['circuits/dist/zokrates/dev/Rollup1.abi.json'])).toString(),
    provingKey: await readCompressedFile(['circuits/dist/zokrates/dev/Rollup1.pkey.gz']),
  });
  const verified = await protocol.zkVerify(
    proof,
    (await readCompressedFile(['circuits/dist/zokrates/dev/Rollup1.vkey.gz'])).toString(),
  );
  expect(verified).toBe(true);
  expect(tree.elements().length).toBe(4);
}, 60000);

test('test zkProveRollup2', async () => {
  const tree = MerkleTree.fromLeaves([toBN('100'), toBN('200')], {
    maxLevels: protocol.merkleTreeLevels,
  });
  const proof = await protocol.zkProveRollup({
    tree,
    newLeaves: [toBN('1'), toBN('2')],
    program: await readCompressedFile(['circuits/dist/zokrates/dev/Rollup2.program.gz']),
    abi: (await readFile(['circuits/dist/zokrates/dev/Rollup2.abi.json'])).toString(),
    provingKey: await readCompressedFile(['circuits/dist/zokrates/dev/Rollup2.pkey.gz']),
  });
  const verified = await protocol.zkVerify(
    proof,
    (await readCompressedFile(['circuits/dist/zokrates/dev/Rollup2.vkey.gz'])).toString(),
  );
  expect(verified).toBe(true);
  expect(tree.elements().length).toBe(4);
}, 60000);

test('test zkProveRollup4', async () => {
  const tree = MerkleTree.fromLeaves([toBN('100'), toBN('200'), toBN('300'), toBN('400')], {
    maxLevels: protocol.merkleTreeLevels,
  });
  const proof = await protocol.zkProveRollup({
    tree,
    newLeaves: [toBN('1'), toBN('2'), toBN('3'), toBN('4')],
    program: await readCompressedFile(['circuits/dist/zokrates/dev/Rollup4.program.gz']),
    abi: (await readFile(['circuits/dist/zokrates/dev/Rollup4.abi.json'])).toString(),
    provingKey: await readCompressedFile(['circuits/dist/zokrates/dev/Rollup4.pkey.gz']),
  });
  const verified = await protocol.zkVerify(
    proof,
    (await readCompressedFile(['circuits/dist/zokrates/dev/Rollup4.vkey.gz'])).toString(),
  );
  expect(verified).toBe(true);
  expect(tree.elements().length).toBe(8);
  tree.insert(toBN(5));
  await expect(async () => {
    protocol.zkProveRollup({
      tree,
      newLeaves: [toBN('6'), toBN('7'), toBN('8'), toBN('9')],
      program: await readCompressedFile(['circuits/dist/zokrates/dev/Rollup4.program.gz']),
      abi: (await readFile(['circuits/dist/zokrates/dev/Rollup4.abi.json'])).toString(),
      provingKey: await readCompressedFile(['circuits/dist/zokrates/dev/Rollup4.pkey.gz']),
    });
  }).rejects.toThrow();
}, 60000);

test('test zkProveRollup8', async () => {
  const tree = MerkleTree.fromLeaves(
    [toBN('100'), toBN('200'), toBN('300'), toBN('400'), toBN('500'), toBN('600'), toBN('700'), toBN('800')],
    {
      maxLevels: protocol.merkleTreeLevels,
    },
  );
  const proof = await protocol.zkProveRollup({
    tree,
    newLeaves: [toBN('1'), toBN('2'), toBN('3'), toBN('4'), toBN('5'), toBN('6'), toBN('7'), toBN('8')],
    program: await readCompressedFile(['circuits/dist/zokrates/dev/Rollup8.program.gz']),
    abi: (await readFile(['circuits/dist/zokrates/dev/Rollup8.abi.json'])).toString(),
    provingKey: await readCompressedFile(['circuits/dist/zokrates/dev/Rollup8.pkey.gz']),
  });
  const verified = await protocol.zkVerify(
    proof,
    (await readCompressedFile(['circuits/dist/zokrates/dev/Rollup8.vkey.gz'])).toString(),
  );
  expect(verified).toBe(true);
  expect(tree.elements().length).toBe(16);
}, 60000);

test('test zkProveRollup16', async () => {
  const tree = MerkleTree.fromLeaves(
    [
      toBN('100'),
      toBN('200'),
      toBN('300'),
      toBN('400'),
      toBN('500'),
      toBN('600'),
      toBN('700'),
      toBN('800'),
      toBN('900'),
      toBN('1000'),
      toBN('1100'),
      toBN('1200'),
      toBN('1300'),
      toBN('1400'),
      toBN('1500'),
      toBN('1600'),
    ],
    {
      maxLevels: protocol.merkleTreeLevels,
    },
  );
  const proof = await protocol.zkProveRollup({
    tree,
    newLeaves: [
      toBN('1'),
      toBN('2'),
      toBN('3'),
      toBN('4'),
      toBN('5'),
      toBN('6'),
      toBN('7'),
      toBN('8'),
      toBN('9'),
      toBN('10'),
      toBN('11'),
      toBN('12'),
      toBN('13'),
      toBN('14'),
      toBN('15'),
      toBN('16'),
    ],
    program: await readCompressedFile(['circuits/dist/zokrates/dev/Rollup16.program.gz']),
    abi: (await readFile(['circuits/dist/zokrates/dev/Rollup16.abi.json'])).toString(),
    provingKey: await readCompressedFile(['circuits/dist/zokrates/dev/Rollup16.pkey.gz']),
  });
  const verified = await protocol.zkVerify(
    proof,
    (await readCompressedFile(['circuits/dist/zokrates/dev/Rollup16.vkey.gz'])).toString(),
  );
  expect(verified).toBe(true);
  expect(tree.elements().length).toBe(32);
}, 60000);
