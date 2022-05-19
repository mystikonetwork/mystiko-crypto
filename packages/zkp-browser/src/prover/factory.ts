import { ZKProverFactory } from '@mystikonetwork/zkp';
import { initialize, ZoKratesProvider } from 'zokrates-js';
import { ZokratesBrowserProver } from './zokrates';

export class ZokratesBrowserProverFactory implements ZKProverFactory {
  // eslint-disable-next-line class-methods-use-this
  public create(): Promise<ZokratesBrowserProver> {
    return initialize().then((provider: ZoKratesProvider) => new ZokratesBrowserProver(provider));
  }
}
