import { check, readJsonFile } from '@mystikonetwork/utils';
import { ProveOptions, VerifyOptions, ZKProof } from '@mystikonetwork/zkp';
import { ZokratesWasmProver } from '@mystikonetwork/zkp-wasm';
import { spawn } from 'child_process';
import commandExists from 'command-exists';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { ZoKratesProvider } from '@mystikonetwork/zokrates-js';

function copyFile(tempDir: string, content: Buffer, dest: string): string {
  check(content.length > 0, 'file content cannot be empty');
  fs.writeFileSync(path.join(tempDir, dest), content);
  return path.join(tempDir, dest);
}

function createTempDirectory(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'ZokratesNodeProver'));
}

function inputsToString(arg: any): string {
  if (typeof arg === 'boolean') {
    return arg ? '1' : '0';
  }
  return arg.toString();
}

function spawnProcess(command: string, args: string[]): Promise<string> {
  const process = spawn(command, args);
  let stdout: string = '';
  let stderr: string = '';
  process.stdout.on('data', (data: Buffer) => {
    stdout = `${stdout}\n${data.toString()}`;
  });
  process.stderr.on('data', (data: Buffer) => /* istanbul ignore next */ {
    stderr = `${stderr}\n${data.toString()}`;
  });
  return new Promise<string>((resolve, reject) => {
    process.on('exit', (code) => {
      if (code !== 0) {
        reject(new Error(`${command} ${args.join(' ')} failed!\nstdout:\n${stdout}\nstderr:\n${stderr}`));
      }
      return resolve(`stdout:\n${stdout}\nstderr:\n${stderr}`);
    });
  });
}

export type ZokratesNodeProverOptions = {
  zokratesPath?: string;
};

export class ZokratesNodeProver extends ZokratesWasmProver {
  private readonly zokratesPath: string;

  private cliExists?: boolean;

  constructor(zokratesProvider: ZoKratesProvider, options?: ZokratesNodeProverOptions) {
    super(zokratesProvider);
    this.zokratesPath = options?.zokratesPath || 'zokrates';
  }

  public async prove(options: ProveOptions): Promise<ZKProof> {
    const cliExists = await this.zokratesCliExists();
    if (cliExists) {
      const tempFolder: string = createTempDirectory();
      try {
        const program = copyFile(tempFolder, options.program, 'program');
        const abi = copyFile(tempFolder, Buffer.from(options.abi, 'utf8'), 'abi');
        const provingKey = copyFile(tempFolder, options.provingKey, 'provingKeyFile');
        const flatArgs = options.inputs.flat(100).map(inputsToString).join(' ');
        const witness = path.join(tempFolder, 'witness');
        const circomWitness = path.join(tempFolder, 'circom.wtns');
        const proofFile = path.join(tempFolder, 'proof.json');
        const computeWitnessPromise = spawnProcess(
          this.zokratesPath,
          (
            `compute-witness -s ${abi} -i ${program}` +
            ` -o ${witness} -a ${flatArgs} --circom-witness ${circomWitness}`
          ).split(' '),
        );
        await computeWitnessPromise;
        const generateProofPromise = spawnProcess(
          this.zokratesPath,
          `generate-proof -i ${program} -w ${witness} -p ${provingKey} -j ${proofFile} -b bellman`.split(' '),
        );
        await generateProofPromise;
        return (await readJsonFile(proofFile)) as ZKProof;
      } finally {
        fs.rmSync(tempFolder, { recursive: true, force: true });
      }
    } else {
      return super.prove(options);
    }
  }

  public async verify(options: VerifyOptions): Promise<boolean> {
    const cliExists = await this.zokratesCliExists();
    if (cliExists) {
      const tempFolder: string = createTempDirectory();
      try {
        const verifyingKey = copyFile(tempFolder, Buffer.from(options.verifyingKey, 'utf8'), 'program');
        const proof = path.join(tempFolder, 'proof.json');
        fs.writeFileSync(proof, JSON.stringify(options.proof));
        const verifyResultPromise = spawnProcess(
          this.zokratesPath,
          `verify -j ${proof} -v ${verifyingKey} -b bellman`.split(' '),
        );
        return await verifyResultPromise.then((output) => output.includes('PASSED'));
      } finally {
        fs.rmSync(tempFolder, { recursive: true, force: true });
      }
    } else {
      return super.verify(options);
    }
  }

  private zokratesCliExists(): Promise<boolean> {
    if (this.cliExists === undefined) {
      return commandExists(this.zokratesPath)
        .then(() => {
          this.cliExists = true;
          return this.cliExists;
        })
        .catch(() => {
          this.cliExists = false;
          return this.cliExists;
        });
    }
    return Promise.resolve(this.cliExists);
  }
}
