import { NopProverFactory } from '../src';

test('test basic', async () => {
  const factory = new NopProverFactory();
  const prover = await factory.create();
  await expect(
    prover.prove({
      programFile: ['program'],
      provingKeyFile: ['provingKey'],
      inputs: ['verifyingKey'],
      abiFile: ['abi'],
    }),
  ).rejects.toThrow();
  expect(
    await prover.verify({
      proof: {
        proof: [],
        inputs: [],
      },
      verifyingKeyFile: ['verifyingKey'],
    }),
  ).toBe(false);
});
