import FS from "fs";
import path from "path";
import Forge from "node-forge";
const { pki, md } = Forge;
import mkdirp from "mkdirp";
import async from "async";
import ErrnoException = NodeJS.ErrnoException;
import { CACert, ErrorCallback } from "./types";

const CAattrs = [
  {
    name: "commonName",
    value: "NodeMITMProxyCA",
  },
  {
    name: "countryName",
    value: "Internet",
  },
  {
    shortName: "ST",
    value: "Internet",
  },
  {
    name: "localityName",
    value: "Internet",
  },
  {
    name: "organizationName",
    value: "Node MITM Proxy CA",
  },
  {
    shortName: "OU",
    value: "CA",
  },
];

const CAextensions = [
  {
    name: "basicConstraints",
    cA: true,
  },
  {
    name: "keyUsage",
    keyCertSign: true,
    digitalSignature: true,
    nonRepudiation: true,
    keyEncipherment: true,
    dataEncipherment: true,
  },
  {
    name: "extKeyUsage",
    serverAuth: true,
    clientAuth: true,
    codeSigning: true,
    emailProtection: true,
    timeStamping: true,
  },
  {
    name: "nsCertType",
    client: true,
    server: true,
    email: true,
    objsign: true,
    sslCA: true,
    emailCA: true,
    objCA: true,
  },
  {
    name: "subjectKeyIdentifier",
  },
];

const ServerAttrs = [
  {
    name: "countryName",
    value: "Internet",
  },
  {
    shortName: "ST",
    value: "Internet",
  },
  {
    name: "localityName",
    value: "Internet",
  },
  {
    name: "organizationName",
    value: "Node MITM Proxy CA",
  },
  {
    shortName: "OU",
    value: "Node MITM Proxy Server Certificate",
  },
];

const ServerExtensions = [
  {
    name: "basicConstraints",
    cA: false,
  },
  {
    name: "keyUsage",
    keyCertSign: false,
    digitalSignature: true,
    nonRepudiation: false,
    keyEncipherment: true,
    dataEncipherment: true,
  },
  {
    name: "extKeyUsage",
    serverAuth: true,
    clientAuth: true,
    codeSigning: false,
    emailProtection: false,
    timeStamping: false,
  },
  {
    name: "nsCertType",
    client: true,
    server: true,
    email: false,
    objsign: false,
    sslCA: false,
    emailCA: false,
    objCA: false,
  },
  {
    name: "subjectKeyIdentifier",
  },
] as any[];

interface CertFolders {
  baseFolder: string;
  certsFolder: string;
  keysFolder: string;
}

export function getCertFolders(baseCAFolder: string): CertFolders {
  return {
    baseFolder: baseCAFolder,
    certsFolder: path.join(baseCAFolder, "certs"),
    keysFolder: path.join(baseCAFolder, "keys"),
  };
}

function randomSerialNumber() {
  // generate random 16 bytes hex string
  let sn = "";
  for (let i = 0; i < 4; i++) {
    sn += `00000000${Math.floor(Math.random() * 256 ** 4).toString(16)}`.slice(
      -8
    );
  }
  return sn;
}

function loadCA(folders: CertFolders, callback: ErrorCallback<CACert>) {
  async.auto(
    {
      certPEM(callback) {
        FS.readFile(
          path.join(folders.certsFolder, "ca.pem"),
          "utf-8",
          callback
        );
      },
      keyPrivatePEM(callback) {
        FS.readFile(
          path.join(folders.keysFolder, "ca.private.key"),
          "utf-8",
          callback
        );
      },
      keyPublicPEM(callback) {
        FS.readFile(
          path.join(folders.keysFolder, "ca.public.key"),
          "utf-8",
          callback
        );
      },
    },
    (
      err,
      results:
        | { certPEM: string; keyPrivatePEM: string; keyPublicPEM: string }
        | undefined
    ) => {
      if (err) {
        return callback(err);
      }

      const cert = pki.certificateFromPem(results!.certPEM);
      const keys = {
        privateKey: pki.privateKeyFromPem(results!.keyPrivatePEM),
        publicKey: pki.publicKeyFromPem(results!.keyPublicPEM),
      };

      return callback(null, {
        cert,
        keys,
      });
    }
  );
}

function generateCA(folders: CertFolders, callback: ErrorCallback<CACert>) {
  pki.rsa.generateKeyPair({ bits: 2048 }, (err, keys) => {
    if (err) {
      return callback(err);
    }
    const cert = pki.createCertificate();

    cert.publicKey = keys.publicKey;
    cert.serialNumber = randomSerialNumber();
    cert.validity.notBefore = new Date();
    cert.validity.notBefore.setDate(cert.validity.notBefore.getDate() - 1);
    cert.validity.notAfter = new Date();
    cert.validity.notAfter.setFullYear(
      cert.validity.notBefore.getFullYear() + 1
    );

    cert.setSubject(CAattrs);
    cert.setIssuer(CAattrs);
    cert.setExtensions(CAextensions);
    cert.sign(keys.privateKey, md.sha256.create());

    const tasks = [
      FS.writeFile.bind(
        null,
        path.join(folders.certsFolder, "ca.pem"),
        pki.certificateToPem(cert)
      ),
      FS.writeFile.bind(
        null,
        path.join(folders.keysFolder, "ca.private.key"),
        pki.privateKeyToPem(keys.privateKey)
      ),
      FS.writeFile.bind(
        null,
        path.join(folders.keysFolder, "ca.public.key"),
        pki.publicKeyToPem(keys.publicKey)
      ),
    ];

    async.parallel(tasks, (err) => {
      if (err) {
        return callback(err);
      }
      return callback(null, { cert, keys });
    });
  });
}

export function getDefaultCA(
  folders: CertFolders,
  callback: ErrorCallback<CACert>
) {
  const exists = FS.existsSync(path.join(folders.certsFolder, "ca.pem"));

  if (exists) {
    loadCA(folders, callback);
  } else {
    generateCA(folders, callback);
  }
}

export class CA {
  baseCAFolder!: string;
  certsFolder!: string;
  keysFolder!: string;

  CAcert!: Forge.pki.Certificate;
  CAkeys!: Forge.pki.rsa.KeyPair;

  static create(folders: CertFolders, cert: CACert) {
    const ca = new CA();

    ca.baseCAFolder = folders.baseFolder;
    ca.certsFolder = folders.certsFolder;
    ca.keysFolder = folders.keysFolder;

    ca.CAcert = cert.cert;
    ca.CAkeys = cert.keys;

    return ca;
  }

  generateServerCertificateKeys(hosts: string | string[], cb) {
    const self = this;
    if (typeof hosts === "string") {
      hosts = [hosts];
    }
    const mainHost = hosts[0];
    const keysServer = pki.rsa.generateKeyPair(2048);
    const certServer = pki.createCertificate();
    certServer.publicKey = keysServer.publicKey;
    certServer.serialNumber = randomSerialNumber();
    certServer.validity.notBefore = new Date();
    certServer.validity.notBefore.setDate(
      certServer.validity.notBefore.getDate() - 1
    );
    certServer.validity.notAfter = new Date();
    certServer.validity.notAfter.setFullYear(
      certServer.validity.notBefore.getFullYear() + 1
    );
    const attrsServer = ServerAttrs.slice(0);
    attrsServer.unshift({
      name: "commonName",
      value: mainHost,
    });
    certServer.setSubject(attrsServer);
    certServer.setIssuer(this.CAcert.issuer.attributes);
    certServer.setExtensions(
      ServerExtensions.concat([
        {
          name: "subjectAltName",
          altNames: hosts.map((host) => {
            if (host.match(/^[\d.]+$/)) {
              return { type: 7, ip: host };
            }
            return { type: 2, value: host };
          }),
        },
      ])
    );
    certServer.sign(this.CAkeys.privateKey, md.sha256.create());
    const certPem = pki.certificateToPem(certServer);
    const keyPrivatePem = pki.privateKeyToPem(keysServer.privateKey);
    const keyPublicPem = pki.publicKeyToPem(keysServer.publicKey);
    FS.writeFile(
      `${this.certsFolder}/${mainHost.replace(/\*/g, "_")}.pem`,
      certPem,
      (error) => {
        if (error) {
          console.error(
            `Failed to save certificate to disk in ${self.certsFolder}`,
            error
          );
        }
      }
    );
    FS.writeFile(
      `${this.keysFolder}/${mainHost.replace(/\*/g, "_")}.key`,
      keyPrivatePem,
      (error) => {
        if (error) {
          console.error(
            `Failed to save private key to disk in ${self.keysFolder}`,
            error
          );
        }
      }
    );
    FS.writeFile(
      `${this.keysFolder}/${mainHost.replace(/\*/g, "_")}.public.key`,
      keyPublicPem,
      (error) => {
        if (error) {
          console.error(
            `Failed to save public key to disk in ${self.keysFolder}`,
            error
          );
        }
      }
    );
    // returns synchronously even before files get written to disk
    cb(certPem, keyPrivatePem);
  }
}

export default CA;
