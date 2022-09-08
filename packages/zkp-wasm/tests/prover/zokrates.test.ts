import { ZokratesWasmProver } from '../../src';

let prover: ZokratesWasmProver;

beforeAll(async () => {
  // eslint-disable-next-line global-require
  const { initialize } = require('zokrates-js');
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
    programFile: ['tests/files/program'],
    abiFile: ['tests/files/abi.json'],
    provingKeyFile: ['tests/files/proving.key'],
    inputs: ['1', '2', '3'],
  });
  expect(
    await prover.verify({
      verifyingKeyFile: ['tests/files/verification.key'],
      proof,
    }),
  ).toBe(true);
  proof.inputs[2] = '4';
  expect(
    await prover.verify({
      verifyingKeyFile: ['tests/files/verification.key'],
      proof,
    }),
  ).toBe(false);
});
