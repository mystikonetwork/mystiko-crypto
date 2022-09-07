import { check, FIELD_SIZE, toBN, toHexNoPrefix } from '@mystikonetwork/utils';
import BN from 'bn.js';
import randomBytes from 'randombytes';

export type Point = {
  x: BN;
  y: BN;
};

export type SecretShare = {
  numOfShares: number;
  threshold: number;
  shares: Point[];
  coefficients: BN[];
};

export class SecretSharing {
  public static recover(shares: Point[], prime = FIELD_SIZE): BN {
    return SecretSharing.lagrangeInterpolate(toBN(0), shares, prime);
  }

  public static split(secret: BN, numOfShares: number, threshold: number, prime = FIELD_SIZE): SecretShare {
    check(
      numOfShares > 0 && Number.isInteger(numOfShares),
      'numOfShares should be an integer that is greater than 0 and less than 2 ** 13',
    );
    check(
      threshold > 0 && threshold <= numOfShares && Number.isInteger(threshold),
      'threshold should an integer that is greater than 0 and less or equal to numOfShares',
    );
    const coefficients: BN[] = [secret];
    for (let i = 1; i < threshold; i += 1) {
      coefficients.push(SecretSharing.random(prime));
    }
    const shares: Point[] = [];
    for (let i = 0; i < numOfShares; i += 1) {
      const x = toBN(i + 1);
      const y = SecretSharing.evalPoly(coefficients, x, prime);
      shares.push({ x, y });
    }
    return { numOfShares, threshold, coefficients, shares };
  }

  public static random(prime = FIELD_SIZE): BN {
    const bigInt = toBN(toHexNoPrefix(randomBytes(32)), 16);
    return bigInt.mod(prime);
  }

  private static mod(aNumber: BN, prime: BN): BN {
    if (aNumber.gten(0)) {
      return aNumber.mod(prime);
    }
    let remain = aNumber.mod(prime).abs();
    if (!remain.isZero()) {
      remain = prime.sub(remain);
    }
    return remain;
  }

  private static evalPoly(coefficients: BN[], x: BN, prime: BN): BN {
    let accum = toBN(0);
    for (let i = coefficients.length - 1; i >= 0; i -= 1) {
      accum = accum.mul(x);
      accum = accum.add(coefficients[i]);
      accum = SecretSharing.mod(accum, prime);
    }
    return accum;
  }

  private static extendedGCD(a: BN, b: BN): { x: BN; y: BN } {
    let x = toBN(0);
    let lastX = toBN(1);
    let y = toBN(1);
    let lastY = toBN(0);
    let aVal = a;
    let bVal = b;
    while (!bVal.isZero()) {
      const quote = aVal.div(bVal);
      const tempB = SecretSharing.mod(aVal, bVal);
      aVal = bVal;
      bVal = tempB;
      const tempX = lastX.sub(quote.mul(x));
      const tempY = lastY.sub(quote.mul(y));
      lastX = x;
      lastY = y;
      x = tempX;
      y = tempY;
    }
    return { x: lastX, y: lastY };
  }

  private static divMod(num: BN, den: BN, prime: BN): BN {
    const { x } = SecretSharing.extendedGCD(den, prime);
    return x.mul(num);
  }

  private static batchMul(values: BN[]): BN {
    let accum = toBN(1);
    values.forEach((val) => {
      accum = accum.mul(val);
    });
    return accum;
  }

  private static sum(values: BN[]): BN {
    return values.reduce((a, b) => a.add(b));
  }

  private static lagrangeInterpolate(x: BN, points: Point[], prime: BN): BN {
    const k = points.length;
    const distinctXs = new Set(points.map((p) => p.x.toString()));
    check(k === distinctXs.size, 'points must be distinct');
    const nums: BN[] = [];
    const dens: BN[] = [];
    for (let i = 0; i < k; i += 1) {
      const numValues: BN[] = [];
      const denValues: BN[] = [];
      for (let j = 0; j < k; j += 1) {
        if (j !== i) {
          numValues.push(x.sub(points[j].x));
          denValues.push(points[i].x.sub(points[j].x));
        }
      }
      nums.push(SecretSharing.batchMul(numValues));
      dens.push(SecretSharing.batchMul(denValues));
    }
    const den = SecretSharing.batchMul(dens);
    const numValues: BN[] = [];
    for (let i = 0; i < k; i += 1) {
      const num = SecretSharing.mod(nums[i].mul(den).mul(points[i].y), prime);
      numValues.push(SecretSharing.divMod(num, dens[i], prime));
    }
    const num = SecretSharing.sum(numValues);
    return SecretSharing.mod(SecretSharing.divMod(num, den, prime).add(prime), prime);
  }
}
