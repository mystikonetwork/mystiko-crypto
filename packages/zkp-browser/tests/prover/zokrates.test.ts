import { ZokratesWasmProver, ZokratesWasmProverFactory } from '../../src';

let factory: ZokratesWasmProverFactory;
let prover: ZokratesWasmProver;

beforeAll(async () => {
  factory = new ZokratesWasmProverFactory();
  prover = await factory.create();
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
