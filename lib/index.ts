import DidDocument from './DidDocument';
import IDidDocument from './IDidDocument';
import IDidDocumentPublicKey from './IDidDocumentPublicKey';
import IDidDocumentServiceDescriptor from './IDidDocumentServiceDescriptor';
import IDidResolver from './IDidResolver';
import IDidResolveResult from './IDidResolveResult';
import HttpResolver, { HttpResolverOptions } from './resolvers/HttpResolver';
import TestResolver from './mocks/TestResolver';

export {
  DidDocument,
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
