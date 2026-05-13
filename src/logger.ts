import { configure, getConsoleSink, getLogger } from "@logtape/logtape";
import { getPrettyFormatter } from "@logtape/pretty";

const level = process.env.NODE_ENV === "development" ? "debug" : "info";

const formatter = process.env.NODE_ENV === "development" ? getPrettyFormatter({
  // Show timestamp
  timestamp: "time",  // "time" | "date-time" | "date" | "rfc3339" | etc.

  // Control colors
  colors: true,

  // Category display
  categoryWidth: 3,
  categoryTruncate: false,  // "middle" | "end" | false

  // Word wrapping
  wordWrap: false,  // true | false | number

  // Show properties
  properties: false,
}) : undefined;

await configure({
  sinks: { console: getConsoleSink({
      formatter
    }) },
  loggers: [
    { category: "app", lowestLevel: level, sinks: ["console"] },
    { category: ["logtape", "meta"], lowestLevel: "warning", sinks: ["console"] },
  ],
});

export { getLogger };
