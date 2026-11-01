import "./delivery.js";
import { mock } from "node:test";

const elapsed = Number(process.env.S03_ELAPSED_MS);
let calls = 0;
mock.method(performance, "now", () => (calls++ === 0 ? 0 : elapsed));
