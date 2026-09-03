import { createHash, createHmac, getHashes } from "node:crypto";
import type {
  IExecuteFunctions,
  INodeExecutionData,
  INodeType,
  INodeTypeDescription,
  IDataObject,
  INode,
} from "n8n-workflow";
import { NodeConnectionTypes, NodeOperationError } from "n8n-workflow";

/**
 * CRC32 lookup table, built once on first use.
 * CRC32 is not part of node:crypto, and pulling a package for it would add a
 * runtime dependency, which verified community nodes are not allowed to have.
 */
let crcTable: Int32Array | null = null;

function getCrcTable(): Int32Array {
  if (crcTable !== null) return crcTable;

  const table = new Int32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) {
      c = (c & 1) !== 0 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    }
    table[n] = c;
  }
  crcTable = table;
  return crcTable;
}

function crc32(payload: Buffer): Buffer {
  const table = getCrcTable();
  let crc = -1;
  for (let i = 0; i < payload.length; i++) {
    crc = (crc >>> 8) ^ table[(crc ^ payload[i]) & 0xff];
  }
  // >>> 0 forces the signed 32-bit result back into an unsigned range
  const digest = Buffer.alloc(4);
  digest.writeUInt32BE((crc ^ -1) >>> 0, 0);
  return digest;
}

/**
 * JSON.stringify with keys sorted at every level, so two objects with the same
 * content always produce the same string, and therefore the same hash,
 * regardless of the order the fields arrived in.
 */
function stableStringify(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value) ?? "null";
  }

  if (Array.isArray(value)) {
    return `[${value.map(stableStringify).join(",")}]`;
  }

  const source = value as Record<string, unknown>;
  const pairs = Object.keys(source)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${stableStringify(source[key])}`);

  return `{${pairs.join(",")}}`;
}

function digestPayload(
  payload: Buffer,
  algorithm: string,
  pepper: string,
  node: INode,
  itemIndex: number,
): Buffer {
  if (algorithm === "crc32") {
    if (pepper !== "") {
      throw new NodeOperationError(node, "CRC32 cannot be used with a pepper", {
        itemIndex,
        description:
          "A pepper is applied using HMAC, which requires a cryptographic hash. Choose another algorithm or remove the Hash Pepper credential.",
      });
    }
    return crc32(payload);
  }

  // Some Node.js builds are compiled without RIPEMD-160 or SM3. Checking first
  // turns an opaque OpenSSL crash into a message that names the algorithm.
  if (!getHashes().includes(algorithm)) {
    throw new NodeOperationError(
      node,
      `The algorithm "${algorithm}" is not available in this Node.js build`,
      {
        itemIndex,
        description:
          "The OpenSSL library behind this n8n instance was compiled without it. Choose a different algorithm, such as SHA-256.",
      },
    );
  }

  return pepper === ""
    ? createHash(algorithm).update(payload).digest()
    : createHmac(algorithm, pepper).update(payload).digest();
}

export class Hash implements INodeType {
  description: INodeTypeDescription = {
    displayName: "Hash",
    name: "hash",
    icon: { light: "file:hash.svg", dark: "file:hash.dark.svg" },
    group: ["transform"],
    version: [1],
    subtitle: '={{ $parameter["algorithm"] }}',
    description:
      "Hash text, files or JSON with algorithms the built-in Crypto node does not offer",
    defaults: {
      name: "Hash",
    },
    inputs: [NodeConnectionTypes.Main],
    outputs: [NodeConnectionTypes.Main],
    usableAsTool: true,
    properties: [
      {
        displayName: "Input Type",
        name: "inputType",
        type: "options",
        default: "text",
        description:
          "What to hash: a text value, a binary file, or the incoming JSON object",
        options: [
          {
            name: "Binary File",
            value: "binaryFile",
            description: "Hash the raw bytes of an attached file",
          },
          {
            name: "JSON Object",
            value: "jsonObject",
            description:
              "Hash the whole incoming item, with keys sorted so the result is stable",
          },
          {
            name: "Text",
            value: "text",
            description: "Hash a text value, typically from an expression",
          },
        ],
      },
      {
        displayName: "Value",
        name: "value",
        type: "string",
        default: "",
        placeholder: "Text to hash",
        description:
          "The text to hash. Supports expressions, so it can be driven by incoming data.",
        displayOptions: {
          show: {
            inputType: ["text"],
          },
        },
      },
      {
        displayName: "Binary Property",
        name: "binaryProperty",
        type: "string",
        default: "data",
        description:
          "Name of the binary property holding the file. The bytes of the file are hashed, not any text inside it, so hashing a PDF gives the file checksum rather than a hash of its words.",
        displayOptions: {
          show: {
            inputType: ["binaryFile"],
          },
        },
      },
      {
        displayName: "Algorithm",
        name: "algorithm",
        type: "options",
        default: "sha256",
        description:
          "The hash algorithm to use. CRC32, MD5 and SHA1 are for checksums and legacy compatibility only, not for security.",
        options: [
          { name: "BLAKE2b-512", value: "blake2b512" },
          { name: "BLAKE2s-256", value: "blake2s256" },
          { name: "CRC32", value: "crc32" },
          { name: "MD5", value: "md5" },
          { name: "RIPEMD-160", value: "ripemd160" },
          { name: "SHA-224", value: "sha224" },
          { name: "SHA-256", value: "sha256" },
          { name: "SHA-384", value: "sha384" },
          { name: "SHA-512", value: "sha512" },
          { name: "SHA-512/256", value: "sha512-256" },
          { name: "SHA1", value: "sha1" },
          { name: "SHA3-256", value: "sha3-256" },
          { name: "SHA3-512", value: "sha3-512" },
          { name: "SM3", value: "sm3" },
        ],
      },
      {
        displayName: "Salt",
        name: "salt",
        type: "string",
        default: "",
        description:
          "Value joined to the input before hashing. Store it alongside the hash, otherwise the hash can never be reproduced or verified.",
      },
      {
        displayName: "Salt Position",
        name: "saltPosition",
        type: "options",
        default: "prefix",
        description:
          "Where the salt sits relative to the input. This has to match whatever system you are interoperating with, or the hashes will not agree.",
        options: [
          { name: "Prefix", value: "prefix" },
          { name: "Suffix", value: "suffix" },
        ],
        displayOptions: {
          hide: {
            salt: [""],
          },
        },
      },
      {
        displayName: "Pepper Secret",
        name: "pepperSecret",
        type: "string",
        typeOptions: {
          password: true,
        },
        default: "",
        description:
          "Optional secret applied through HMAC rather than plain concatenation. Unlike a salt it is one shared secret and it is never written to the output. It is stored inside the workflow, so treat exported workflows as sensitive.",
      },
      {
        displayName: "Options",
        name: "options",
        type: "collection",
        placeholder: "Add option",
        default: {},
        options: [
          {
            displayName: "Encoding",
            name: "encoding",
            type: "options",
            default: "hex",
            description:
              "How to encode the raw digest bytes. Base64url is URL-safe and unpadded.",
            options: [
              { name: "Base64", value: "base64" },
              { name: "Base64url", value: "base64url" },
              { name: "Hex", value: "hex" },
            ],
          },
          {
            displayName: "Include Metadata",
            name: "includeMetadata",
            type: "boolean",
            default: false,
            description:
              "Whether to output the algorithm, encoding and salt next to the hash, so the value can be reproduced later. The pepper is never included.",
          },
          {
            displayName: "Output Field Name",
            name: "outputFieldName",
            type: "string",
            default: "hash",
            description:
              "Name of the field to write the hash to. Change it to avoid overwriting a field that already exists on the item.",
          },
          {
            displayName: "Truncate Length",
            name: "truncateLength",
            type: "number",
            default: 0,
            typeOptions: {
              minValue: 0,
            },
            description:
              "Number of characters to keep from the start of the encoded hash, or 0 to keep all of it. Shorter hashes collide more often.",
          },
          {
            displayName: "Uppercase",
            name: "uppercase",
            type: "boolean",
            default: false,
            description:
              "Whether to uppercase the result. This applies to hex output only, because Base64 is case-sensitive and uppercasing it would corrupt the value.",
          },
        ],
      },
    ],
  };

  async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
    const items = this.getInputData();
    const returnData: INodeExecutionData[] = [];

    for (let itemIndex = 0; itemIndex < items.length; itemIndex++) {
      try {
        const inputType = this.getNodeParameter(
          "inputType",
          itemIndex,
        ) as string;
        const algorithm = this.getNodeParameter(
          "algorithm",
          itemIndex,
        ) as string;
        const salt = this.getNodeParameter("salt", itemIndex, "") as string;
        const pepper = this.getNodeParameter(
          "pepperSecret",
          itemIndex,
          "",
        ) as string;
        const saltPosition = this.getNodeParameter(
          "saltPosition",
          itemIndex,
          "prefix",
        ) as string;
        const options = this.getNodeParameter("options", itemIndex, {}) as {
          encoding?: BufferEncoding;
          includeMetadata?: boolean;
          outputFieldName?: string;
          truncateLength?: number;
          uppercase?: boolean;
        };

        const encoding = options.encoding ?? "hex";
        const outputFieldName = options.outputFieldName ?? "hash";
        const truncateLength = options.truncateLength ?? 0;

        // 1. Resolve whatever the user pointed at into bytes
        let payload: Buffer;
        if (inputType === "binaryFile") {
          const binaryProperty = this.getNodeParameter(
            "binaryProperty",
            itemIndex,
            "data",
          ) as string;
          this.helpers.assertBinaryData(itemIndex, binaryProperty);
          payload = await this.helpers.getBinaryDataBuffer(
            itemIndex,
            binaryProperty,
          );
        } else if (inputType === "jsonObject") {
          payload = Buffer.from(stableStringify(items[itemIndex].json), "utf8");
        } else {
          payload = Buffer.from(
            this.getNodeParameter("value", itemIndex, "") as string,
            "utf8",
          );
        }

        // 2. Apply the salt
        if (salt !== "") {
          const saltBytes = Buffer.from(salt, "utf8");
          payload =
            saltPosition === "suffix"
              ? Buffer.concat([payload, saltBytes])
              : Buffer.concat([saltBytes, payload]);
        }

        // 3. Digest, then encode
        const digest = digestPayload(
          payload,
          algorithm,
          pepper,
          this.getNode(),
          itemIndex,
        );
        let hash = digest.toString(encoding);

        if (options.uppercase === true && encoding === "hex") {
          hash = hash.toUpperCase();
        }

        if (truncateLength > 0) {
          hash = hash.slice(0, truncateLength);
        }

        const json: IDataObject = {
          ...items[itemIndex].json,
          [outputFieldName]: hash,
        };

        if (options.includeMetadata === true) {
          const metadata: IDataObject = {
            algorithm,
            encoding,
            inputType,
            peppered: pepper !== "",
            salted: salt !== "",
          };

          if (salt !== "") {
            metadata.salt = salt;
            metadata.saltPosition = saltPosition;
          }

          if (truncateLength > 0) {
            metadata.truncateLength = truncateLength;
          }

          json[`${outputFieldName}Meta`] = metadata;
        }

        const outputItem: INodeExecutionData = {
          json,
          pairedItem: { item: itemIndex },
        };

        // Files pass straight through, so the node can sit mid-pipeline
        if (items[itemIndex].binary !== undefined) {
          outputItem.binary = items[itemIndex].binary;
        }

        returnData.push(outputItem);
      } catch (error) {
        if (this.continueOnFail()) {
          returnData.push({
            json: { ...items[itemIndex].json, error: (error as Error).message },
            pairedItem: { item: itemIndex },
          });
          continue;
        }

        // Re-throwing the caught error directly is not allowed, so it is
        // wrapped while keeping the description from digestPayload above
        const cause = error as Error & { description?: string };
        throw new NodeOperationError(this.getNode(), cause, {
          itemIndex,
          description: cause.description,
        });
      }
    }

    return [returnData];
  }
}
