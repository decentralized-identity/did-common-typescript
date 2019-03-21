import DidKey from './crypto/DidKey';
import { KeyExport } from './crypto/KeyExport';
import KeyTypeFactory, { KeyType } from './crypto/KeyType';
import KeyUseFactory, { KeyUse } from './crypto/KeyUse';
import IDidDocument from './IDidDocument';
import IDidDocumentPublicKey from './IDidDocumentPublicKey';
import IDidDocumentServiceDescriptor from './IDidDocumentServiceDescriptor';
import IDidResolver from './IDidResolver';
import IDidResolveResult from './IDidResolveResult';
import HttpResolver, { HttpResolverOptions } from './resolvers/HttpResolver';
import TestResolver from './mocks/TestResolver';

export {
  DidKey,
  KeyUse,
  KeyExport,
  KeyType,
  KeyTypeFactory,
  KeyUseFactory,
  IDidDocument,
  IDidDocumentPublicKey,
  IDidDocumentServiceDescriptor,
  IDidResolver,
  IDidResolveResult,
  HttpResolver,
  HttpResolverOptions
};

export const unitTestExports = {
  TestResolver
};
