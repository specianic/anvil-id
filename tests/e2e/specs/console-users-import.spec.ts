// ADM-08 / ADM-09 from the console (07-20): an operator uploads a 3-line NDJSON file on the Import
// users page. The dry run shows the per-line report (one bcrypt user with the Openwall test vector,
// marked weak; one PBKDF2 record below the import floors, rejected with `weak_parameters`; one user
// without a password) and creates nothing. The real run creates the two valid users, and the
// imported bcrypt user signs in on the tenant's login page with the old password `U*U`. "Export
// all (NDJSON)" downloads every user without any password hash, and the user page's Export and
// GDPR export download that user's documents.
//
// 07.1-15 (C-M10): a CSV file is converted to NDJSON in the browser and posted to the same import
// endpoint. Malformed CSV is reported with its line numbers before anything is uploaded; the dry
// run says "Would create"; the page links the import docs and offers an example CSV.
//
// Each test runs in a tenant of its own, deleted afterwards, signed in as a console administrator created
// with createConsoleAdmin (its token carries admin:write, which allows exports).
//
// Console test ids (admin-ui, plan 07-20):
// - users list: `import-users-link`, `export-all-users`, `export-scope-missing`
// - import page: `import-form`, `import-file`, `import-file-error`, `import-file-summary`,
//   `import-dry-run`, `import-update`, `import-source`, `import-submit`; report `import-report`
//   (`data-dry-run`), `import-count-{created|updated|unchanged|conflict|rejected|weak}`, rows
//   `import-row` (`data-line`, `data-outcome`, `data-reason`, `data-weak`)
// - user page: `user-export`, `export-user`, `export-user-gdpr`
// - CSV (07.1-15): `import-csv-errors` (items carry `data-line`), `import-docs-link`, `import-example`
//
// Env: ANVIL_URL, SETUP_URL, E2E_STATE_FILE (see tests/e2e/run.sh).

import { readFile } from 'node:fs/promises';
import { expect, test, type Download, type Page } from '@playwright/test';
import { expectNoA11yViolations } from '../fixtures/axe';
import { randomEmail } from '../lib/anvil';
import { openTenantPage, setUpConsoleTenant, type ConsoleTenant } from '../lib/console-v10';
import { signInAtTenant, tenantUsers } from '../lib/upstream';

const tenants: ConsoleTenant[] = [];

test.afterAll(async () => {
  for (const t of tenants) await t.cleanup();
});

/** Openwall crypt_blowfish test vector (public): password `U*U`, cost 5 (below 10, so weak). */
const BCRYPT_PW = 'U*U';
const BCRYPT_HASH = '$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW';

/** Clicks `button`, waits for the download and returns its file name and text. */
async function download(page: Page, testId: string): Promise<{ name: string; text: string }> {
  const [file]: [Download, void] = await Promise.all([
    page.waitForEvent('download'),
    page.getByTestId(testId).click(),
  ]);
  const path = await file.path();
  return { name: file.suggestedFilename(), text: await readFile(path, 'utf8') };
}

test('console: import users with a dry run, sign in with the old bcrypt password, export', async ({ page, browser }) => {
  test.setTimeout(150_000);
  const tenant = await setUpConsoleTenant(browser, page, 'cimp');
  tenants.push(tenant);
  const { token, slug } = tenant;

  const bcryptEmail = randomEmail('imp-bcrypt');
  const weakEmail = randomEmail('imp-weak');
  const plainEmail = randomEmail('imp-plain');
  const ndjson = [
    JSON.stringify({
      email: bcryptEmail,
      email_verified: true,
      claims: { name: 'Imported Bcrypt' },
      password: { scheme: 'bcrypt', hash: BCRYPT_HASH },
    }),
    // 500 iterations is below the PBKDF2 import floor (1,000): refused as weak_parameters.
    JSON.stringify({
      email: weakEmail,
      email_verified: true,
      password: {
        scheme: 'pbkdf2',
        prf: 'sha256',
        iterations: 500,
        salt: { hex: '00112233445566778899aabbccddeeff' },
        hash: { hex: '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff' },
      },
    }),
    JSON.stringify({ email: plainEmail, email_verified: true, claims: { name: 'Imported Plain' } }),
  ].join('\n');
  const file = { name: 'users.ndjson', mimeType: 'application/x-ndjson', buffer: Buffer.from(`${ndjson}\n`) };

  await test.step('the users list links to the import page', async () => {
    await openTenantPage(page, slug, 'users');
    await expect(page.getByTestId('export-all-users')).toBeEnabled();
    await expect(page.getByTestId('export-scope-missing')).toHaveCount(0);
    await page.getByTestId('import-users-link').click();
    await expect(page).toHaveURL((url) => url.pathname === `/console/t/${slug}/users/import`);
    await expect(page.getByRole('heading', { level: 1, name: 'Import users' })).toBeVisible();
    await expectNoA11yViolations(page);
  });

  await test.step('a dry run reports every line and creates nothing', async () => {
    await page.getByTestId('import-file').setInputFiles(file);
    await expect(page.getByTestId('import-file-summary')).toContainText('3 records');
    await expect(page.getByTestId('import-dry-run')).toBeChecked();
    await page.getByTestId('import-source').fill('e2e-legacy');
    await page.getByTestId('import-submit').click();

    const report = page.getByTestId('import-report');
    await expect(report).toHaveAttribute('data-dry-run', 'true');
    await expect(report.getByTestId('import-row')).toHaveCount(3);
    await expect(report.getByTestId('import-count-created')).toHaveText('2');
    await expect(report.getByTestId('import-count-rejected')).toHaveText('1');
    await expect(report.getByTestId('import-count-weak')).toHaveText('1');
    await expect(report.locator('[data-testid="import-row"][data-line="1"]')).toHaveAttribute('data-weak', 'true');
    const refused = report.locator('[data-testid="import-row"][data-line="2"]');
    await expect(refused).toHaveAttribute('data-outcome', 'rejected');
    await expect(refused).toHaveAttribute('data-reason', 'weak_parameters');
    await expect(report.locator('[data-testid="import-row"][data-line="3"]')).toHaveAttribute('data-outcome', 'created');
    // The report never echoes a hash.
    const html = await page.content();
    expect(html).not.toContain('$2a$');
    expect(html).not.toContain('00112233445566778899aabbccddeeff00112233');
    await expectNoA11yViolations(page);

    const emails = (await tenantUsers(token, slug)).map((u) => u.email);
    expect(emails).not.toContain(bcryptEmail);
    expect(emails).not.toContain(plainEmail);
  });

  await test.step('the real run creates the two valid users', async () => {
    await page.getByTestId('import-dry-run').uncheck();
    await page.getByTestId('import-submit').click();
    const report = page.getByTestId('import-report');
    await expect(report).toHaveAttribute('data-dry-run', 'false');
    await expect(report.getByTestId('import-count-created')).toHaveText('2');
    await expect(report.getByTestId('import-count-rejected')).toHaveText('1');

    const emails = (await tenantUsers(token, slug)).map((u) => u.email);
    expect(emails).toContain(bcryptEmail);
    expect(emails).toContain(plainEmail);
    expect(emails).not.toContain(weakEmail);
  });

  await test.step('the imported bcrypt user signs in with the old password', async () => {
    // A separate browser context: the console session stays signed in on `page`.
    const context = await browser.newContext();
    try {
      const userPage = await context.newPage();
      await signInAtTenant(userPage, slug, bcryptEmail, BCRYPT_PW);
    } finally {
      await context.close();
    }
  });

  await test.step('Export all downloads NDJSON with the users and no password hash', async () => {
    await openTenantPage(page, slug, 'users');
    const { name, text } = await download(page, 'export-all-users');
    expect(name).toBe(`${slug}.users.ndjson`);
    const records = text
      .split('\n')
      .filter((line) => line.trim() !== '')
      .map((line) => JSON.parse(line) as { email?: string });
    const emails = records.map((r) => r.email);
    expect(emails).toContain(bcryptEmail);
    expect(emails).toContain(plainEmail);
    expect(text).not.toContain('$2a$');
    expect(text).not.toContain('$argon2');
    expect(text).not.toContain('password_hash');
    await expect(page.getByRole('status').filter({ hasText: `Downloaded ${slug}.users.ndjson.` })).toBeVisible();
  });

  await test.step('the user page offers Export and GDPR export downloads', async () => {
    const user = (await tenantUsers(token, slug)).find((u) => u.email === bcryptEmail);
    if (!user) throw new Error(`imported user ${bcryptEmail} not found`);
    await openTenantPage(page, slug, `users/${user.id}`);
    await expect(page.getByTestId('user-export')).toBeVisible();

    const single = await download(page, 'export-user');
    expect(single.name).toBe(`user-${user.id}.json`);
    expect(single.text).toContain(bcryptEmail);
    expect(single.text).not.toContain('$2a$');
    expect(single.text).not.toContain('$argon2');

    const gdpr = await download(page, 'export-user-gdpr');
    expect(gdpr.name).toBe(`user-${user.id}.gdpr.json`);
    expect(gdpr.text).toContain(bcryptEmail);
    expect(gdpr.text).not.toContain('$argon2');
  });
});

test('console: import users from CSV (line-numbered errors, Would create, then created)', async ({ page, browser }) => {
  test.setTimeout(120_000);
  const tenant = await setUpConsoleTenant(browser, page, 'ccsv');
  tenants.push(tenant);
  const { token, slug } = tenant;
  const ada = randomEmail('csv-ada');
  const grace = randomEmail('csv-grace');

  await test.step('the page links the docs and offers an example CSV', async () => {
    await openTenantPage(page, slug, 'users/import');
    await expect(page.getByRole('heading', { level: 1, name: 'Import users' })).toBeVisible();
    await expect(page.getByTestId('import-docs-link')).toHaveAttribute('href', /IMPORT-EXPORT\.html$/);
    const example = await download(page, 'import-example');
    expect(example.name).toBe('users-example.csv');
    expect(example.text.split(/\r?\n/)[0]).toBe('email,email_verified,claims.name,claims.locale,attributes.department');
  });

  await test.step('malformed CSV is reported with line numbers and nothing is uploaded', async () => {
    const broken = ['email,claims.name,nickname', `${ada},Ada`, `${grace},"Hopper, Grace`].join('\n');
    await page.getByTestId('import-file').setInputFiles({ name: 'broken.csv', mimeType: 'text/csv', buffer: Buffer.from(broken) });
    // An unknown column fails the header row (line 1) before any record is read.
    await expect(page.getByTestId('import-file-error')).toContainText('could not be converted');
    await expect(page.getByTestId('import-csv-errors').locator('li[data-line="1"]')).toContainText('nickname');
    await expect(page.getByTestId('import-submit')).toBeDisabled();
    await expectNoA11yViolations(page);

    const rows = ['email,claims.name', `${ada},Ada,extra`, `${grace},"Hopper, Grace`].join('\n');
    await page.getByTestId('import-file').setInputFiles({ name: 'rows.csv', mimeType: 'text/csv', buffer: Buffer.from(rows) });
    const errors = page.getByTestId('import-csv-errors');
    await expect(errors.locator('li[data-line="2"]')).toContainText('Expected 2 fields');
    await expect(errors.locator('li[data-line="3"]')).toContainText('never closed');
    await expect(page.getByTestId('import-submit')).toBeDisabled();
    expect((await tenantUsers(token, slug)).map((u) => u.email)).not.toContain(ada);
  });

  await test.step('a valid CSV converts; the dry run says Would create; the real run creates', async () => {
    const csv = [
      '\uFEFFemail,email_verified,claims.name,claims.locale',
      `${ada},true,Ada Lovelace,en`,
      `${grace},false,"Hopper, Grace",en`,
      '',
    ].join('\r\n');
    await page.getByTestId('import-file').setInputFiles({ name: 'users.csv', mimeType: 'text/csv', buffer: Buffer.from(csv) });
    await expect(page.getByTestId('import-file-error')).toHaveCount(0);
    await expect(page.getByTestId('import-file-summary')).toContainText('2 records (converted from CSV)');
    await expect(page.getByTestId('import-dry-run')).toBeChecked();
    await page.getByTestId('import-submit').click();

    const report = page.getByTestId('import-report');
    await expect(report).toHaveAttribute('data-dry-run', 'true');
    await expect(report.getByText('Would create', { exact: true }).first()).toBeVisible();
    await expect(report.getByTestId('import-count-created')).toHaveText('2');
    await expect(report.locator('[data-testid="import-row"][data-line="1"]')).toContainText('Would create');
    await expectNoA11yViolations(page);
    expect((await tenantUsers(token, slug)).map((u) => u.email)).not.toContain(ada);

    await page.getByTestId('import-dry-run').uncheck();
    await page.getByTestId('import-submit').click();
    await expect(report).toHaveAttribute('data-dry-run', 'false');
    await expect(report.getByTestId('import-count-created')).toHaveText('2');
    await expect(report.locator('[data-testid="import-row"][data-line="2"]')).toContainText('Created');

    const users = await tenantUsers(token, slug);
    expect(users.map((u) => u.email)).toEqual(expect.arrayContaining([ada, grace]));
  });
});
