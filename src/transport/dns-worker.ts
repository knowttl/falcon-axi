import { lookup } from "node:dns/promises";

const addresses = await lookup(process.argv[2]!, {
  all: true,
  verbatim: true,
  family: Number(process.argv[3]),
  hints: Number(process.argv[4]),
});
process.stdout.write(JSON.stringify(addresses));
