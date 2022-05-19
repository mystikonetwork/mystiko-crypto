import { ZokratesBrowserProver, ZokratesBrowserProverFactory } from '../../src';

let factory: ZokratesBrowserProverFactory;
let prover: ZokratesBrowserProver;

beforeAll(async () => {
  factory = new ZokratesBrowserProverFactory();
  prover = await factory.create();
});

test('test prove', () => {
  expect(prover).not.toBe(undefined);
});
