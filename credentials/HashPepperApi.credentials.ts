import type { Icon, ICredentialType, INodeProperties } from "n8n-workflow";

export class HashPepperApi implements ICredentialType {
  name = "hashPepperApi";

  displayName = "Hash Pepper API";

  icon: Icon = {
    light: "file:../nodes/Hash/hash.svg",
    dark: "file:../nodes/Hash/hash.dark.svg",
  };

  documentationUrl =
    "https://github.com/NajiElKotob/n8n-nodes-hash?tab=readme-ov-file#pepper";

  properties: INodeProperties[] = [
    {
      displayName: "Pepper Secret",
      name: "pepperSecret",
      type: "string",
      typeOptions: {
        password: true,
      },
      default: "",
      description:
        "Secret key applied through HMAC rather than plain concatenation, which avoids length-extension attacks. Unlike a salt it is one shared secret, it is never written to the output, and changing it invalidates every hash produced with the previous value.",
    },
  ];
}
