import { toBN } from '@mystikonetwork/utils';
import { MerkleTree, MerkleTreeStringData } from './merkle';

export function fromStringLeaves(leaves: string[]): MerkleTreeStringData {
  const convertedLeaves = leaves.map((leaf) => toBN(leaf));
  const merkleTree = MerkleTree.fromLeaves(convertedLeaves);
  return {
    maxLevels: merkleTree.data.maxLevels,
    capacity: merkleTree.data.capacity,
    zeroElement: merkleTree.data.zeroElement.toString(),
    zeros: merkleTree.data.zeros.map((zero) => zero.toString()),
    layers: merkleTree.data.layers.map((layer) => layer.map((node) => node.toString())),
  };
}
