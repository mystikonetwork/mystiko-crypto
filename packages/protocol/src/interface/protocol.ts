import { ZKProof } from '@mystikonetwork/zkp';
import BN from 'bn.js';

export type CommitmentInput = {
  publicKeys: string | { pkVerify: Buffer; pkEnc: Buffer };
  amount?: BN;
  randomSecrets?: { randomP: BN; randomR: BN; randomS: BN };
  encryptedNote?: { skEnc: Buffer; encryptedNote: Buffer };
};

export type CommitmentOutput = {
  encryptedNote: Buffer;
  shieldedAddress: string;
  commitmentHash: BN;
  amount: BN;
  randomP: BN;
  randomR: BN;
  randomS: BN;
  k: BN;
};

export type CommitmentStringOutput = {
  encryptedNote: string;
  shieldedAddress: string;
  commitmentHash: string;
  amount: string;
  randomP: string;
  randomR: string;
  randomS: string;
  k: string;
};

export type DecryptOutput = { commitment: CommitmentOutput; shieldedAddress: string; serialNumber: BN };
export type DecryptStringOutput = {
  commitment: CommitmentStringOutput;
  shieldedAddress: string;
  serialNumber: string;
};

export interface MystikoProtocol<
  TX = any,
  R = any,
  CI = CommitmentInput,
  CO = CommitmentOutput,
  P = ZKProof,
> {
  get verifyPkSize(): number;
  get verifySkSize(): number;
  get encPkSize(): number;
  get encSkSize(): number;
  get randomSkSize(): number;
  get amountSize(): number;
  get merkleTreeLevels(): number;
  get numOfAuditors(): number;
  get auditingThreshold(): number;
  buffToBigInt(buff: Buffer): BN;
  bigIntToBuff(bigInt: BN, numBytes?: number): Buffer;
  randomBigInt(numBytes?: number): BN;
  randomBytes(numBytes?: number): Buffer;
  secretKeyForVerification(rawSecretKey: Buffer): Buffer;
  publicKeyForVerification(rawSecretKey: Buffer): Buffer;
  secretKeyForEncryption(rawSecretKey: Buffer): Buffer;
  publicKeyForEncryption(rawSecretKey: Buffer): Buffer;
  fullPublicKey(pkVerify: Buffer, pkEnc: Buffer): Buffer;
  fullSecretKey(skVerify: Buffer, skEnc: Buffer): Buffer;
  separatedPublicKeys(longPublicKey: Buffer): { pkEnc: Buffer; pkVerify: Buffer };
  separatedSecretKeys(longSecretKey: Buffer): { skVerify: Buffer; skEnc: Buffer };
  shieldedAddress(pkVerify: Buffer, pkEnc: Buffer): string;
  isShieldedAddress(address: string): boolean;
  publicKeysFromShieldedAddress(address: string): { pkEnc: Buffer; pkVerify: Buffer };
  encryptAsymmetric(publicKey: Buffer, plainData: Buffer): Promise<Buffer>;
  decryptAsymmetric(secretKey: Buffer, cipherData: Buffer): Promise<Buffer>;
  encryptSymmetric(password: string, plainText: string): string;
  decryptSymmetric(password: string, cipherText: string): string;
  sha256(inputs: Buffer[]): BN;
  poseidonHash(inputs: BN[]): BN;
  checkSum(data: string, salt?: string): string;
  commitment(options: CI): Promise<CO>;
  decryptNotes(
    commitments: { commitmentHash: string; encryptedNote: string }[],
    keys: { publicKey: string; secretKey: string }[],
  ): Promise<DecryptOutput[]>;
  serialNumber(skVerify: Buffer, randomP: BN): BN;
  sigPkHash(sigPk: Buffer, secretKey: Buffer): BN;
  zkProveTransaction(tx: TX): Promise<P>;
  zkProveRollup(rollup: R): Promise<P>;
  zkVerify(proof: P, verifyingKeyFile: string | string[]): Promise<boolean>;
}

export interface ProtocolFactory<PO = any> {
  create(options?: PO): Promise<MystikoProtocol>;
}
