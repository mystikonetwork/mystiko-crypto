import { readFile } from '@mystikonetwork/utils';
import { ZokratesNodeProver, ZokratesNodeProverFactory } from '../../src';

let factory: ZokratesNodeProverFactory;
let prover: ZokratesNodeProver;

beforeAll(async () => {
  factory = new ZokratesNodeProverFactory();
  prover = await factory.create();
}, 60000);

test('test prove', async () => {
  let proof = await prover.prove({
    program: await readFile(['tests/files/program']),
    abi: (await readFile(['tests/files/abi.json'])).toString(),
    provingKey: await readFile(['tests/files/proving.key']),
    inputs: [true, [[[false]]], '1'],
  });
  expect(
    await prover.verify({
      verifyingKey: (await readFile(['tests/files/verification.key'])).toString(),
      proof,
    }),
  ).toBe(true);
  proof = await prover.prove({
    program: await readFile(['tests/files/program']),
    abi: (await readFile(['tests/files/abi.json'])).toString(),
    provingKey: await readFile(['tests/files/proving.key']),
    inputs: [3, '2', '5'],
  });
  expect(
    await prover.verify({
      verifyingKey: (await readFile(['tests/files/verification.key'])).toString(),
      proof,
    }),
  ).toBe(true);
  proof.inputs[2] = '4';
  expect(
    await prover.verify({
      verifyingKey: (await readFile(['tests/files/verification.key'])).toString(),
      proof,
    }),
  ).toBe(false);
  prover = await factory.create({ zokratesPath: 'zokrates' });
  await expect(
    prover.prove({
      program: await readFile(['tests/files/program']),
      abi: (await readFile(['tests/files/abi.json'])).toString(),
      provingKey: await readFile(['tests/files/proving.key']),
      inputs: [true, 2, '4'],
    }),
  ).rejects.toThrow();
}, 60000);

test('test prove with wasm', async () => {
  prover = await factory.create({ zokratesPath: 'non-existing_zokrates' });
  const proof = await prover.prove({
    program: await readFile(['tests/files/program']),
    abi: (await readFile(['tests/files/abi.json'])).toString(),
    provingKey: await readFile(['tests/files/proving.key']),
    inputs: ['1', '0', '1'],
  });
  expect(
    await prover.verify({
      verifyingKey: (await readFile(['tests/files/verification.key'])).toString(),
      proof,
    }),
  ).toBe(true);
}, 60000);
