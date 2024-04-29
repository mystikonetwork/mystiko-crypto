import { toBN } from '@mystikonetwork/utils';
import { MerkleTree } from '../src';

test('test calcZeros', () => {
  const firstZero = MerkleTree.calcDefaultZeroElement();
  expect(firstZero.toString()).toBe(
    '4506069241680023110764189603658664710592327039412547147745745078424755206435',
  );
  const zeros = MerkleTree.calcZeros(firstZero, 31);
  expect(zeros[31].toString()).toBe(
    '13202030544264649816737469308990869537826379298057211734249690002947353708909',
  );
});

test('test constructor', () => {
  const tree1 = new MerkleTree();
  expect(tree1.root().toString()).toBe(
    '17749238747541177922260023106539184144732198174810064796938596694265936155259',
  );
  expect(tree1.elements()).toStrictEqual([]);

  const element1 = toBN('12d7aafbf3d4c1852ad3634d69607fc9ea8028f2d5724fcf3b917e71fd2dbff6', 16);
  const element2 = toBN('062c3655c709b4b58142b9b270f5a5b06b8df8921cbbb261a7729eae759e7ec3', 16);
  const tree2 = new MerkleTree([element1, element2]);
  expect(tree2.root().toString()).toBe(
    '21205178834650720622262399337497375208854240907281368468056255721030220387133',
  );
  expect(tree2.elements().map((e) => e.toString())).toStrictEqual([element1.toString(), element2.toString()]);
  expect(tree2.indexOf(element1)).toBe(0);
  expect(tree2.indexOf(element2, (a, b) => a.eq(b))).toBe(1);
  expect(tree2.leafAt(1)).toBe(element2);
  const tree3 = new MerkleTree([], { maxLevels: 1, zeroElement: toBN(0) });
  expect(tree3.root().toString()).toBe(MerkleTree.hash2(toBN(0), toBN(0)).toString());
});

test('test insert', () => {
  const tree = new MerkleTree();
  tree.insert(toBN('12d7aafbf3d4c1852ad3634d69607fc9ea8028f2d5724fcf3b917e71fd2dbff6', 16));
  tree.insert(toBN('062c3655c709b4b58142b9b270f5a5b06b8df8921cbbb261a7729eae759e7ec3', 16));
  expect(tree.root().toString()).toBe(
    '21205178834650720622262399337497375208854240907281368468056255721030220387133',
  );
});

test('test batchInsert', () => {
  const tree = new MerkleTree();
  tree.bulkInsert([
    toBN('12d7aafbf3d4c1852ad3634d69607fc9ea8028f2d5724fcf3b917e71fd2dbff6', 16),
    toBN('062c3655c709b4b58142b9b270f5a5b06b8df8921cbbb261a7729eae759e7ec3', 16),
    toBN('02d18bd99c2ce3d70411809537b64bfbbac5f51a7b7e2eeb8d84346162f9c707', 16),
  ]);
  expect(tree.root().toString()).toBe(
    '10254041194642220426314275741279894727412053938657566062675343387806484605596',
  );
});

test('test update', () => {
  const tree = new MerkleTree([toBN('12d7aafbf3d4c1852ad3634d69607fc9ea8028f2d5724fcf3b917e71fd2dbff6', 16)]);
  tree.update(0, toBN('02d18bd99c2ce3d70411809537b64bfbbac5f51a7b7e2eeb8d84346162f9c707', 16));
  expect(tree.root().toString()).toBe(
    '5919354211942147568484662594760486300826527524526112436647850872711338828514',
  );
});

test('test path', () => {
  const element1 = toBN('12d7aafbf3d4c1852ad3634d69607fc9ea8028f2d5724fcf3b917e71fd2dbff6', 16);
  const element2 = toBN('062c3655c709b4b58142b9b270f5a5b06b8df8921cbbb261a7729eae759e7ec3', 16);
  const element3 = toBN('02d18bd99c2ce3d70411809537b64bfbbac5f51a7b7e2eeb8d84346162f9c707', 16);
  const tree = new MerkleTree([element1, element2, element3], { maxLevels: 2 });
  const defaultZero = MerkleTree.calcDefaultZeroElement();
  const result1 = tree.path(0);
  expect(result1.pathElements).toStrictEqual([element2, MerkleTree.hash2(element3, defaultZero)]);
  expect(result1.pathIndices).toStrictEqual([0, 0]);
  const result2 = tree.path(1);
  expect(result2.pathElements).toStrictEqual([element1, MerkleTree.hash2(element3, defaultZero)]);
  expect(result2.pathIndices).toStrictEqual([1, 0]);
  const result3 = tree.path(2);
  expect(result3.pathElements).toStrictEqual([defaultZero, MerkleTree.hash2(element1, element2)]);
  expect(result3.pathIndices).toStrictEqual([0, 1]);
});
