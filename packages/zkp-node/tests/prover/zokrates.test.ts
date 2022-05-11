import { ZokratesCliProver, ZokratesCliProverFactory } from '../../src';

let factory: ZokratesCliProverFactory;
let prover: ZokratesCliProver;

beforeAll(async () => {
  factory = new ZokratesCliProverFactory();
  prover = await factory.create();
});

test('test prove', async () => {
  let proof = await prover.prove({
    programFile: ['tests/files/program'],
    abiFile: ['tests/files/abi.json'],
    provingKeyFile: ['tests/files/proving.key'],
    inputs: [true, [[[false]]], '1'],
  });
  expect(
    await prover.verify({
      verifyingKeyFile: ['tests/files/verification.key'],
      proof,
    }),
  ).toBe(true);
  proof = await prover.prove({
    programFile: ['tests/files/program'],
    abiFile: ['tests/files/abi.json'],
    provingKeyFile: ['tests/files/proving.key'],
    inputs: [3, '2', '5'],
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
  prover = await factory.create({ zokratesPath: 'zokrates' });
  await expect(
    prover.prove({
      programFile: ['tests/files/program'],
      abiFile: ['tests/files/abi.json'],
      provingKeyFile: ['tests/files/proving.key'],
      inputs: [true, 2, '4'],
    }),
  ).rejects.toThrow();
});
