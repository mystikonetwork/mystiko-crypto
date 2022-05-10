import { ZoKratesProvider } from 'zokrates-js';
import { ZokratesWasmRuntime } from '../../../src';

let zokrates: ZoKratesProvider;

beforeAll(async () => {
  // eslint-disable-next-line global-require
  const { initialize } = require('zokrates-js/node');
  zokrates = await initialize();
});

test('test prove', async () => {
  const runtime = new ZokratesWasmRuntime(zokrates);
  const proof = await runtime.prove(
    'tests/runtime/zokrates/files/program',
    'tests/runtime/zokrates/files/abi.json',
    'tests/runtime/zokrates/files/proving.key',
    ['1', '2', '3'],
  );
  expect(await runtime.verify('tests/runtime/zokrates/files/verification.key', proof)).toBe(true);
});
