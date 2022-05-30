import { MerkleTree } from '@mystikonetwork/merkle';
import { toBN } from '@mystikonetwork/utils';
import { ZokratesNodeProverFactory, ZokratesNodeProverOptions } from '@mystikonetwork/zkp-node';
import { MystikoProtocolV2, ProtocolFactoryV2 } from '../../../src';

let protocol: MystikoProtocolV2;
let factory: ProtocolFactoryV2;

beforeAll(async () => {
  factory = new ProtocolFactoryV2<ZokratesNodeProverOptions>(new ZokratesNodeProverFactory());
  protocol = await factory.create();
});

test('test zkProveRollup1', async () => {
  const tree = new MerkleTree([toBN('100'), toBN('200'), toBN('300')], {
    maxLevels: protocol.merkleTreeLevels,
  });
  const proof = await protocol.zkProveRollup({
    tree,
    newLeaves: [toBN('1')],
    programFile: 'circuits/dist/zokrates/dev/Rollup1.program.gz',
    abiFile: 'circuits/dist/zokrates/dev/Rollup1.abi.json',
    provingKeyFile: 'circuits/dist/zokrates/dev/Rollup1.pkey.gz',
  });
  const verified = await protocol.zkVerify(proof, 'circuits/dist/zokrates/dev/Rollup1.vkey.gz');
  expect(verified).toBe(true);
  expect(tree.elements().length).toBe(4);
});

test('test zkProveRollup4', async () => {
  const tree = new MerkleTree([toBN('100'), toBN('200'), toBN('300'), toBN('400')], {
    maxLevels: protocol.merkleTreeLevels,
  });
  const proof = await protocol.zkProveRollup({
    tree,
    newLeaves: [toBN('1'), toBN('2'), toBN('3'), toBN('4')],
    programFile: 'circuits/dist/zokrates/dev/Rollup4.program.gz',
    abiFile: 'circuits/dist/zokrates/dev/Rollup4.abi.json',
    provingKeyFile: 'circuits/dist/zokrates/dev/Rollup4.pkey.gz',
  });
  const verified = await protocol.zkVerify(proof, 'circuits/dist/zokrates/dev/Rollup4.vkey.gz');
  expect(verified).toBe(true);
  expect(tree.elements().length).toBe(8);
  tree.insert(toBN(5));
  expect(() => {
    protocol.zkProveRollup({
      tree,
      newLeaves: [toBN('6'), toBN('7'), toBN('8'), toBN('9')],
      programFile: 'circuits/dist/zokrates/dev/Rollup4.program.gz',
      abiFile: 'circuits/dist/zokrates/dev/Rollup4.abi.json',
      provingKeyFile: 'circuits/dist/zokrates/dev/Rollup4.pkey.gz',
    });
  }).toThrow();
});

test('test zkProveRollup16', async () => {
  const tree = new MerkleTree(
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
    programFile: 'circuits/dist/zokrates/dev/Rollup16.program.gz',
    abiFile: 'circuits/dist/zokrates/dev/Rollup16.abi.json',
    provingKeyFile: 'circuits/dist/zokrates/dev/Rollup16.pkey.gz',
  });
  const verified = await protocol.zkVerify(proof, 'circuits/dist/zokrates/dev/Rollup16.vkey.gz');
  expect(verified).toBe(true);
  expect(tree.elements().length).toBe(32);
});
