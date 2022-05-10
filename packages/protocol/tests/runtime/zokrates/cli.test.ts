import { ZoKratesProvider } from 'zokrates-js';
import { ZokratesCliRuntime } from '../../../src';

let zokrates: ZoKratesProvider;

beforeAll(async () => {
  // eslint-disable-next-line global-require
  const { initialize } = require('zokrates-js/node');
  zokrates = await initialize();
});

test('test prove', async () => {
  const runtime = new ZokratesCliRuntime(zokrates);
  const proof = await runtime.prove(
    'tests/runtime/zokrates/files/program',
    'tests/runtime/zokrates/files/abi.json',
    'tests/runtime/zokrates/files/proving.key',
    [true, [[[2]]], '3'],
  );
  expect(await runtime.verify('tests/runtime/zokrates/files/verification.key', proof)).toBe(true);
  await expect(
    runtime.prove(
      'tests/runtime/zokrates/files/program',
      'tests/runtime/zokrates/files/abi.json',
      'tests/runtime/zokrates/files/proving.key',
      [true, 2, '4'],
    ),
  ).rejects.toThrow();
});
