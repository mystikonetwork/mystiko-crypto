/* eslint-disable class-methods-use-this */
import { spawn } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { Proof } from 'zokrates-js';
import { readCompressedFile, readJsonFile } from '@mystikonetwork/utils';
import { ZokratesWasmRuntime } from './wasm';

// eslint-disable-next-line import/prefer-default-export
export class ZokratesCliRuntime extends ZokratesWasmRuntime {
  public async prove(
    programFile: string | string[],
    abiFile: string | string[],
    provingKeyFile: string | string[],
    args: any[],
  ): Promise<Proof> {
    const tempFolder: string = ZokratesCliRuntime.createTempDirectory();
    try {
      const program = await ZokratesCliRuntime.copyFile(tempFolder, programFile, 'program');
      const abi = await ZokratesCliRuntime.copyFile(tempFolder, abiFile, 'abi');
      const provingKey = await ZokratesCliRuntime.copyFile(tempFolder, provingKeyFile, 'provingKeyFile');
      const flatArgs = args.flat(100).map(ZokratesCliRuntime.argToString).join(' ');
      const witness = path.join(tempFolder, 'witness');
      const proofFile = path.join(tempFolder, 'proof.json');
      const computeWitnessProcess = spawn(
        'zokrates',
        `compute-witness -s ${abi} -i ${program} -o ${witness} -a ${flatArgs}`.split(' '),
      );
      const computeWitnessPromise: Promise<void> = new Promise((resolve, reject) => {
        computeWitnessProcess.on('exit', (code) => {
          if (code !== 0) {
            reject(new Error(`zokrates compute-witness command failed with exit code ${code}`));
          } else {
            resolve();
          }
        });
      });
      await computeWitnessPromise;
      const generateProofProcess = spawn(
        'zokrates',
        `generate-proof -i ${program} -w ${witness} -p ${provingKey} -j ${proofFile}`.split(' '),
      );
      const generateProofPromise: Promise<void> = new Promise((resolve, reject) => {
        generateProofProcess.on('exit', (code) => {
          if (code !== 0) {
            reject(new Error(`zokrates generate-proof command failed with exit code ${code}`));
          } else {
            resolve();
          }
        });
      });
      await generateProofPromise;
      return (await readJsonFile(proofFile)) as Proof;
    } finally {
      fs.rmSync(tempFolder, { recursive: true, force: true });
    }
  }

  private static createTempDirectory(): string {
    return fs.mkdtempSync(path.join(os.tmpdir(), 'ZokratesCliRuntime'));
  }

  private static async copyFile(tempDir: string, orig: string | string[], dest: string): Promise<string> {
    const buffer = await readCompressedFile(orig);
    fs.writeFileSync(path.join(tempDir, dest), buffer);
    return Promise.resolve(path.join(tempDir, dest));
  }

  private static argToString(arg: any): string {
    if (typeof arg === 'boolean') {
      return arg ? '1' : '0';
    }
    return arg.toString();
  }
}
