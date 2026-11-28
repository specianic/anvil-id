// axe-core audit for WCAG 2.2 level A/AA rules (UI-02).
//
// axe covers only what is machine-checkable. Target size of custom controls, focus not obscured
// (2.4.11), accessible authentication (3.3.8) and keyboard operation need explicit assertions
// (specs/keyboard.spec.ts) and the manual checklist in the phase summary.

import AxeBuilder from '@axe-core/playwright';
import { expect, type Page } from '@playwright/test';

export const WCAG_TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'] as const;

export interface A11yOptions {
  /** CSS selectors excluded from the audit (use sparingly, document why at the call site). */
  exclude?: string[];
}

interface AxeViolation {
  id: string;
  impact?: string | null;
  help: string;
  helpUrl: string;
  nodes: Array<{ target: unknown[]; failureSummary?: string }>;
}

export function formatViolations(violations: AxeViolation[]): string {
  return violations
    .map((v) => {
      const nodes = v.nodes
        .map((n) => `    - ${n.target.map(String).join(' ')}\n      ${(n.failureSummary ?? '').replaceAll('\n', '\n      ')}`)
        .join('\n');
      return `[${v.impact ?? 'n/a'}] ${v.id}: ${v.help} (${v.helpUrl})\n${nodes}`;
    })
    .join('\n');
}

/**
 * Waits for running CSS transitions (the console's buttons fade between states, e.g. from disabled
 * back to enabled after a click), so axe measures the settled colours, not a colour halfway through.
 * Only transitions: they always end, unlike an infinite spinner animation.
 */
async function settleTransitions(page: Page): Promise<void> {
  await page.evaluate(() =>
    Promise.race([
      Promise.allSettled(
        document
          .getAnimations()
          .filter((a) => typeof CSSTransition !== 'undefined' && a instanceof CSSTransition)
          .map((a) => a.finished),
      ),
      new Promise((resolve) => setTimeout(resolve, 2000)),
    ]),
  );
}

/** Runs axe with the WCAG 2.0/2.1/2.2 A and AA tags on the current page; fails on any violation. */
export async function expectNoA11yViolations(page: Page, options: A11yOptions = {}): Promise<void> {
  await settleTransitions(page);
  let builder = new AxeBuilder({ page }).withTags([...WCAG_TAGS]);
  for (const selector of options.exclude ?? []) {
    builder = builder.exclude(selector);
  }
  const results = await builder.analyze();
  // Compare the count so the failure message is the readable list, not a JSON diff.
  expect(
    results.violations.length,
    `axe violations on ${page.url()}:\n${formatViolations(results.violations)}`,
  ).toBe(0);
}
