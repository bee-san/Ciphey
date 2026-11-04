// gibberish-or-not's verdicts, as the language panel shows them.

import type { Sensitivity } from "./protocol";

/**
 * The calibrated score from which text counts as language, per sensitivity (gibberish-or-not's
 * `Sensitivity::min_score`): High is the most lenient, Low the strictest, as in Ciphey.
 */
export const THRESHOLDS: Readonly<Record<Sensitivity, number>> = { high: 0.5, medium: 0.75, low: 0.9 };

/** Whether `score` counts as language at `sensitivity`. */
export function isLanguageAt(score: number, sensitivity: Sensitivity): boolean {
  return score >= THRESHOLDS[sensitivity];
}

let names: Intl.DisplayNames | undefined;

/** "English" for "en"; the code itself if the browser doesn't know it. */
export function languageName(code: string): string {
  try {
    names ??= new Intl.DisplayNames(["en"], { type: "language" });
    return names.of(code) ?? code;
  } catch {
    return code;
  }
}

/** "English, French and German" */
export function listNames(items: readonly string[]): string {
  try {
    return new Intl.ListFormat("en", { style: "long", type: "conjunction" }).format(items);
  } catch {
    return items.join(", ");
  }
}
