import { readFile } from '@mystikonetwork/utils';
import { initialize } from '@mystikonetwork/zokrates-js';
import { ZokratesWasmProver } from '../../src';

let prover: ZokratesWasmProver;

beforeAll(async () => {
  const zokratesProvider = await initialize();
  prover = new ZokratesWasmProver(
    zokratesProvider.withOptions({
      backend: 'bellman',
      scheme: 'g16',
      curve: 'bn128',
    }),
  );
});

test('test prove', async () => {
  const proof = await prover.prove({
    program: await readFile(['tests/files/program']),
    abi: (await readFile(['tests/files/abi.json'])).toString(),
    provingKey: await readFile(['tests/files/proving.key']),
    inputs: ['1', '2', '3'],
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
}, 60000);
