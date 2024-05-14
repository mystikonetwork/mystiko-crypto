import { createWorkerFactory, terminate } from '@shopify/web-worker';
import BN from 'bn.js';
import { MerkleTree } from './merkle';

export * from './merkle';

const createWorker = createWorkerFactory(() => import('./worker'));

export async function createMerkleTreeWithWorker(leaves: BN[] = []): Promise<MerkleTree> {
  const worker = createWorker();
  const data = await worker
    .fromStringLeaves(leaves.map((leaf) => leaf.toString()))
    .finally(() => terminate(worker));
  return MerkleTree.fromStringData(data);
}
