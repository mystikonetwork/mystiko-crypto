import { NopProverFactory } from '../src';

test('test basic', async () => {
  const factory = new NopProverFactory();
  const prover = await factory.create();
  await expect(
    prover.prove({
      program: Buffer.from([]),
      provingKey: Buffer.from([]),
      inputs: ['verifyingKey'],
      abi: 'abi',
    }),
  ).rejects.toThrow();
  expect(
    await prover.verify({
      proof: {
        proof: [],
        inputs: [],
      },
      verifyingKey: 'verifyingKey',
    }),
  ).toBe(false);
});
