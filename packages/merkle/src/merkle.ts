import { check, FIELD_SIZE, toBN, toHexNoPrefix } from '@mystikonetwork/utils';
import { ethers } from 'ethers';
import BN from 'bn.js';
import { poseidon } from 'circomlibjs';

export interface MerkleTreeOption {
  maxLevels?: number;
  zeroElement?: BN;
}

export type MerkleTreeData = {
  maxLevels: number;
  capacity: number;
  zeroElement: BN;
  zeros: BN[];
  layers: BN[][];
};

export type MerkleTreeStringData = {
  maxLevels: number;
  capacity: number;
  zeroElement: string;
  zeros: string[];
  layers: string[][];
};

export class MerkleTree {
  public readonly data: MerkleTreeData;

  constructor(data: MerkleTreeData) {
    this.data = data;
  }

  public root(): BN {
    return this.data.layers[this.data.maxLevels].length > 0
      ? this.data.layers[this.data.maxLevels][0]
      : this.data.zeros[this.data.maxLevels];
  }

  public insert(element: BN) {
    check(this.data.layers[0].length + 1 <= this.data.capacity, 'the tree is full');
    this.update(this.data.layers[0].length, element);
  }

  public bulkInsert(elements: BN[]) {
    check(this.data.layers[0].length + elements.length <= this.data.capacity, 'the tree is full');
    for (let i = 0; i < elements.length - 1; i += 1) {
      this.data.layers[0].push(elements[i]);
      let level = 0;
      let index = this.data.layers[0].length - 1;
      while (index % 2 === 1) {
        level += 1;
        index >>= 1;
        this.data.layers[level][index] = MerkleTree.hash2(
          this.data.layers[level - 1][index * 2],
          this.data.layers[level - 1][index * 2 + 1],
        );
      }
    }
    this.insert(elements[elements.length - 1]);
  }

  public update(index: number, element: BN) {
    check(
      index >= 0 && index <= this.data.layers[0].length && index < this.data.capacity,
      `Insert index out of bounds: ${index}`,
    );
    this.data.layers[0][index] = element;
    let currentIndex = index;
    for (let level = 1; level <= this.data.maxLevels; level += 1) {
      currentIndex >>= 1;
      this.data.layers[level][currentIndex] = MerkleTree.hash2(
        this.data.layers[level - 1][currentIndex * 2],
        currentIndex * 2 + 1 < this.data.layers[level - 1].length
          ? this.data.layers[level - 1][currentIndex * 2 + 1]
          : this.data.zeros[level - 1],
      );
    }
  }

  public path(index: number): { pathElements: BN[]; pathIndices: number[] } {
    check(index >= 0 && index <= this.data.layers[0].length, `index out of bounds: ${index}`);
    const pathElements = [];
    const pathIndices = [];
    let currentIndex = index;
    for (let level = 0; level < this.data.maxLevels; level += 1) {
      pathIndices[level] = currentIndex % 2;
      pathElements[level] =
        (currentIndex ^ 1) < this.data.layers[level].length
          ? this.data.layers[level][currentIndex ^ 1]
          : this.data.zeros[level];
      currentIndex >>= 1;
    }
    return {
      pathElements,
      pathIndices,
    };
  }

  public elements(): BN[] {
    return this.data.layers[0].slice();
  }

  public indexOf(element: BN, comparator?: (first: BN, second: BN) => unknown) {
    if (comparator) {
      return this.data.layers[0].findIndex((el) => comparator(element, el));
    }
    return this.data.layers[0].findIndex((value) => value.eq(element));
  }

  public leafAt(index: number): BN {
    check(index >= 0 && index <= this.data.layers[0].length, `index out of bounds: ${index}`);
    return this.data.layers[0][index];
  }

  public static hash2(first: BN, second: BN): BN {
    return toBN(poseidon([first, second]).toString());
  }

  public static calcDefaultZeroElement(): BN {
    // eslint-disable-next-line quotes
    const seedHash = ethers.utils.keccak256(Buffer.from("Welcome To Mystiko's Magic World!", 'ascii'));
    return toBN(toHexNoPrefix(seedHash), 16).mod(FIELD_SIZE);
  }

  public static calcZeros(firstZero: BN, levels: number): BN[] {
    const zeros = [firstZero];
    for (let i = 1; i <= levels; i += 1) {
      zeros.push(MerkleTree.hash2(zeros[i - 1], zeros[i - 1]));
    }
    return zeros;
  }

  public static fromLeaves(
    initialElements: BN[] = [],
    options: MerkleTreeOption = {} as MerkleTreeOption,
  ): MerkleTree {
    const maxLevels = options.maxLevels ? options.maxLevels : 20;
    const capacity = 2 ** maxLevels;
    check(capacity >= initialElements.length, 'it exceeds the maximum allowed capacity');
    const zeroElement = options.zeroElement ? options.zeroElement : MerkleTree.calcDefaultZeroElement();
    const zeros = MerkleTree.calcZeros(zeroElement, maxLevels);
    const layers = [initialElements.slice()];
    const data: MerkleTreeData = {
      maxLevels,
      capacity,
      zeroElement,
      zeros,
      layers,
    };
    for (let level = 1; level <= data.maxLevels; level += 1) {
      data.layers[level] = [];
      for (let i = 0; i < Math.ceil(data.layers[level - 1].length / 2); i += 1) {
        data.layers[level][i] = MerkleTree.hash2(
          data.layers[level - 1][i * 2],
          i * 2 + 1 < data.layers[level - 1].length
            ? data.layers[level - 1][i * 2 + 1]
            : data.zeros[level - 1],
        );
      }
    }
    return new MerkleTree(data);
  }

  public static fromStringData(stringData: MerkleTreeStringData): MerkleTree {
    const data: MerkleTreeData = {
      maxLevels: stringData.maxLevels,
      capacity: stringData.capacity,
      zeroElement: toBN(stringData.zeroElement),
      zeros: stringData.zeros.map((zero) => toBN(zero)),
      layers: stringData.layers.map((layer) => layer.map((element) => toBN(element))),
    };
    return new MerkleTree(data);
  }
}
