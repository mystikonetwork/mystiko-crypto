import { check, FIELD_SIZE, toBN, toHexNoPrefix } from '@mystikonetwork/utils';
import { ethers } from 'ethers';
import BN from 'bn.js';
import { poseidon } from 'circomlibjs';

export interface MerkleTreeOption {
  maxLevels?: number;
  zeroElement?: BN;
}

export class MerkleTree {
  private readonly maxLevels: number;

  private readonly capacity: number;

  private readonly zeroElement: BN;

  private readonly zeros: BN[];

  private readonly layers: BN[][];

  constructor(initialElements: BN[] = [], options: MerkleTreeOption = {} as MerkleTreeOption) {
    this.maxLevels = options.maxLevels ? options.maxLevels : 20;
    this.capacity = 2 ** this.maxLevels;
    check(this.capacity >= initialElements.length, 'it exceeds the maximum allowed capacity');
    this.zeroElement = options.zeroElement ? options.zeroElement : MerkleTree.calcDefaultZeroElement();
    this.zeros = MerkleTree.calcZeros(this.zeroElement, this.maxLevels);
    this.layers = [];
    this.layers[0] = initialElements.slice();
    this.rebuild();
  }

  public root(): BN {
    return this.layers[this.maxLevels].length > 0
      ? this.layers[this.maxLevels][0]
      : this.zeros[this.maxLevels];
  }

  public insert(element: BN) {
    check(this.layers[0].length + 1 <= this.capacity, 'the tree is full');
    this.update(this.layers[0].length, element);
  }

  public bulkInsert(elements: BN[]) {
    check(this.layers[0].length + elements.length <= this.capacity, 'the tree is full');
    for (let i = 0; i < elements.length - 1; i += 1) {
      this.layers[0].push(elements[i]);
      let level = 0;
      let index = this.layers[0].length - 1;
      while (index % 2 === 1) {
        level += 1;
        index >>= 1;
        this.layers[level][index] = MerkleTree.hash2(
          this.layers[level - 1][index * 2],
          this.layers[level - 1][index * 2 + 1],
        );
      }
    }
    this.insert(elements[elements.length - 1]);
  }

  public update(index: number, element: BN) {
    check(
      index >= 0 && index <= this.layers[0].length && index < this.capacity,
      `Insert index out of bounds: ${index}`,
    );
    this.layers[0][index] = element;
    let currentIndex = index;
    for (let level = 1; level <= this.maxLevels; level += 1) {
      currentIndex >>= 1;
      this.layers[level][currentIndex] = MerkleTree.hash2(
        this.layers[level - 1][currentIndex * 2],
        currentIndex * 2 + 1 < this.layers[level - 1].length
          ? this.layers[level - 1][currentIndex * 2 + 1]
          : this.zeros[level - 1],
      );
    }
  }

  public path(index: number): { pathElements: BN[]; pathIndices: number[] } {
    check(index >= 0 && index <= this.layers[0].length, `index out of bounds: ${index}`);
    const pathElements = [];
    const pathIndices = [];
    let currentIndex = index;
    for (let level = 0; level < this.maxLevels; level += 1) {
      pathIndices[level] = currentIndex % 2;
      pathElements[level] =
        (currentIndex ^ 1) < this.layers[level].length
          ? this.layers[level][currentIndex ^ 1]
          : this.zeros[level];
      currentIndex >>= 1;
    }
    return {
      pathElements,
      pathIndices,
    };
  }

  public elements(): BN[] {
    return this.layers[0].slice();
  }

  public indexOf(element: BN, comparator?: (first: BN, second: BN) => unknown) {
    if (comparator) {
      return this.layers[0].findIndex((el) => comparator(element, el));
    }
    return this.layers[0].findIndex((value) => value.eq(element));
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

  private rebuild() {
    for (let level = 1; level <= this.maxLevels; level += 1) {
      this.layers[level] = [];
      for (let i = 0; i < Math.ceil(this.layers[level - 1].length / 2); i += 1) {
        this.layers[level][i] = MerkleTree.hash2(
          this.layers[level - 1][i * 2],
          i * 2 + 1 < this.layers[level - 1].length
            ? this.layers[level - 1][i * 2 + 1]
            : this.zeros[level - 1],
        );
      }
    }
  }
}
