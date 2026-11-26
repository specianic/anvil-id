// Password hash profiles of a tenant (07-17 API): the Firebase scrypt parameters that imported
// Firebase password hashes reference by id. The signer key is a write-only secret: it is sent once
// on create and the API never returns it, so the console never shows it.
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, createFileRoute } from "@tanstack/react-router";
import { type FormEvent, useState } from "react";
import { ApiError, api, unwrap } from "@/api/client";
import type { components } from "@/api/schema";
import { ConfirmDialog, Modal } from "@/components/ConfirmDialog";
import { ProblemAlert } from "@/components/ProblemAlert";
import { type FieldErrors, StatusMessage, TextField, fieldErrors } from "@/components/form";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, TableBody, TableCaption, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { formatDateTime } from "@/lib/format";
import { useTenant } from "@/lib/tenant";

type HashProfileView = components["schemas"]["HashProfileView"];
type CreateHashProfile = components["schemas"]["CreateHashProfile"];

/** The only profile kind today. */
const FIREBASE_SCRYPT = "firebase_scrypt";

interface FormValues {
  name: string;
  rounds: string;
  mem_cost: string;
  salt_separator: string;
  signer_key: string;
}

// Firebase's usual defaults (rounds 8, mem_cost 14, separator 0x07); copy the real values from the
// Firebase console's password hash parameters.
const EMPTY_FORM: FormValues = { name: "", rounds: "8", mem_cost: "14", salt_separator: "Bw==", signer_key: "" };

const FORM_FIELDS = new Set(["name", "rounds", "mem_cost", "salt_separator", "signer_key", "kind"]);

/** A whole number from a form field, or NaN (the API refuses it with a field error). */
function whole(value: string): number {
  return /^\d+$/.test(value.trim()) ? Number(value.trim()) : Number.NaN;
}

function profilesQueryKey(tenant: string) {
  return ["password-hash-profiles", tenant] as const;
}

function CreateProfileDialog({ open, onClose, onCreated }: { open: boolean; onClose: () => void; onCreated: (p: HashProfileView) => void }) {
  const tenant = useTenant();
  const [values, setValues] = useState<FormValues>(EMPTY_FORM);
  const [localErrors, setLocalErrors] = useState<FieldErrors>({});
  const set = <K extends keyof FormValues>(key: K, value: FormValues[K]) => setValues((v) => ({ ...v, [key]: value }));

  const create = useMutation({
    mutationFn: async (body: CreateHashProfile) =>
      unwrap(
        await api.POST("/api/admin/v1/tenants/{slug}/password-hash-profiles", {
          params: { path: { slug: tenant } },
          body,
        }),
      ),
    onSuccess: (profile) => {
      // Drop the signer key from memory as soon as it was accepted.
      setValues(EMPTY_FORM);
      onCreated(profile);
    },
    // On a refusal the signer key is cleared too: it is re-entered, never kept around.
    onError: () => setValues((v) => ({ ...v, signer_key: "" })),
  });

  const close = () => {
    setValues(EMPTY_FORM);
    setLocalErrors({});
    create.reset();
    onClose();
  };

  const submit = (e: FormEvent) => {
    e.preventDefault();
    const rounds = whole(values.rounds);
    const memCost = whole(values.mem_cost);
    const local: FieldErrors = {};
    if (Number.isNaN(rounds)) local.rounds = [{ message: "Enter a whole number." }];
    if (Number.isNaN(memCost)) local.mem_cost = [{ message: "Enter a whole number." }];
    if (values.signer_key.trim() === "") local.signer_key = [{ message: "Enter the base64 signer key." }];
    setLocalErrors(local);
    if (Object.keys(local).length > 0) return;
    create.mutate({
      kind: FIREBASE_SCRYPT,
      name: values.name.trim(),
      rounds,
      mem_cost: memCost,
      salt_separator: values.salt_separator.trim(),
      signer_key: values.signer_key.trim(),
    });
  };

  const apiErrors = fieldErrors(create.error);
  const errors: FieldErrors = { ...apiErrors, ...localErrors };
  const otherError =
    create.error &&
    !(create.error instanceof ApiError && create.error.problem.errors.length > 0 && create.error.problem.errors.every((x) => FORM_FIELDS.has(x.field)))
      ? create.error
      : null;

  return (
    <Modal open={open} onClose={close} title="New Firebase hash profile">
      <form onSubmit={submit} noValidate className="space-y-4" aria-label="New Firebase hash profile" data-testid="profile-form">
        <p className="text-muted-foreground text-sm">
          The values from the Firebase console's password hash parameters. Imported Firebase records name this profile
          by its id.
        </p>
        {otherError ? <ProblemAlert error={otherError} /> : null}
        <TextField
          label="Name"
          required
          value={values.name}
          onChange={(e) => set("name", e.target.value)}
          hint="Unique in this tenant, 1-64 characters."
          errors={errors.name}
          autoComplete="off"
          data-testid="profile-name"
        />
        <div className="grid gap-4 sm:grid-cols-2">
          <TextField
            label="Rounds"
            inputMode="numeric"
            value={values.rounds}
            onChange={(e) => set("rounds", e.target.value)}
            errors={errors.rounds}
            data-testid="profile-rounds"
          />
          <TextField
            label="Memory cost"
            inputMode="numeric"
            value={values.mem_cost}
            onChange={(e) => set("mem_cost", e.target.value)}
            hint="Firebase mem_cost."
            errors={errors.mem_cost}
            data-testid="profile-mem-cost"
          />
        </div>
        <TextField
          label="Salt separator"
          value={values.salt_separator}
          onChange={(e) => set("salt_separator", e.target.value)}
          hint="Firebase base64_salt_separator (standard base64)."
          errors={errors.salt_separator}
          autoComplete="off"
          data-testid="profile-salt-separator"
        />
        <TextField
          label="Signer key"
          type="password"
          value={values.signer_key}
          onChange={(e) => set("signer_key", e.target.value)}
          hint="Firebase base64_signer_key. Stored on the server and never shown again."
          errors={errors.signer_key}
          autoComplete="off"
          spellCheck={false}
          data-testid="profile-signer-key"
        />
        <div className="flex justify-end gap-2">
          <Button type="button" variant="outline" onClick={close} disabled={create.isPending}>
            Cancel
          </Button>
          <Button type="submit" disabled={create.isPending} data-testid="profile-submit">
            {create.isPending ? "Creating…" : "Create profile"}
          </Button>
        </div>
      </form>
    </Modal>
  );
}

function PasswordProfilesPage() {
  const tenant = useTenant();
  const queryClient = useQueryClient();
  const [creating, setCreating] = useState(false);
  const [deleting, setDeleting] = useState<HashProfileView | null>(null);
  const [status, setStatus] = useState<string | null>(null);

  const query = useQuery({
    queryKey: profilesQueryKey(tenant),
    queryFn: async ({ signal }) =>
      unwrap(
        await api.GET("/api/admin/v1/tenants/{slug}/password-hash-profiles", {
          params: { path: { slug: tenant } },
          signal,
        }),
      ),
  });

  const remove = useMutation({
    mutationFn: async (profile: HashProfileView) => {
      await api.DELETE("/api/admin/v1/tenants/{slug}/password-hash-profiles/{id}", {
        params: { path: { slug: tenant, id: profile.id } },
      });
      return profile;
    },
    onSuccess: async (profile) => {
      setDeleting(null);
      setStatus(`Profile ${profile.name} deleted.`);
      await queryClient.invalidateQueries({ queryKey: profilesQueryKey(tenant) });
    },
  });

  const inUse = remove.error instanceof ApiError && remove.error.status === 409;

  return (
    <section aria-labelledby="profiles-heading" className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 id="profiles-heading" className="text-xl font-semibold">
          Password hash profiles
        </h1>
        <Button
          size="sm"
          onClick={() => {
            setStatus(null);
            setCreating(true);
          }}
          data-testid="new-profile"
        >
          New profile
        </Button>
      </div>
      <p className="text-muted-foreground text-sm">
        Firebase scrypt parameters for{" "}
        <Link to="/t/$tenant/users/import" params={{ tenant }} className="underline underline-offset-4">
          imported users
        </Link>
        . A user's Firebase hash is replaced by an Argon2id hash at their first sign-in; a profile can be deleted once no
        imported hash references it.
      </p>
      <StatusMessage message={status} />
      {query.isPending ? (
        <div role="status" aria-label="Loading profiles" className="space-y-2">
          <Skeleton className="h-6 w-1/2" />
          <Skeleton className="h-6 w-2/3" />
        </div>
      ) : query.isError ? (
        <ProblemAlert error={query.error} />
      ) : (
        <Table data-testid="profiles-table">
          <TableCaption className="sr-only">Password hash profiles</TableCaption>
          <TableHeader>
            <TableRow>
              <TableHead>Name</TableHead>
              <TableHead>Id</TableHead>
              <TableHead>Kind</TableHead>
              <TableHead>Rounds</TableHead>
              <TableHead>Memory cost</TableHead>
              <TableHead>Salt separator</TableHead>
              <TableHead>Created</TableHead>
              <TableHead>
                <span className="sr-only">Actions</span>
              </TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {query.data.items.length === 0 ? (
              <TableRow>
                <TableCell colSpan={8} className="text-muted-foreground">
                  No profiles yet.
                </TableCell>
              </TableRow>
            ) : (
              query.data.items.map((p) => (
                <TableRow key={p.id} data-testid="profile-row" data-name={p.name}>
                  <TableCell className="font-medium">{p.name}</TableCell>
                  <TableCell>
                    <code className="text-xs break-all">{p.id}</code>
                  </TableCell>
                  <TableCell>{p.kind}</TableCell>
                  <TableCell>{p.rounds}</TableCell>
                  <TableCell>{p.mem_cost}</TableCell>
                  <TableCell>
                    <code className="text-xs">{p.salt_separator}</code>
                  </TableCell>
                  <TableCell>{formatDateTime(p.created_at)}</TableCell>
                  <TableCell className="text-right">
                    <Button
                      variant="outline"
                      size="sm"
                      aria-label={`Delete ${p.name}`}
                      onClick={() => {
                        setStatus(null);
                        remove.reset();
                        setDeleting(p);
                      }}
                    >
                      Delete
                    </Button>
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      )}
      <CreateProfileDialog
        open={creating}
        onClose={() => setCreating(false)}
        onCreated={async (profile) => {
          setCreating(false);
          setStatus(`Profile ${profile.name} created. Use its id ${profile.id} in imported Firebase records.`);
          await queryClient.invalidateQueries({ queryKey: profilesQueryKey(tenant) });
        }}
      />
      <ConfirmDialog
        open={deleting !== null}
        title="Delete this profile?"
        description={
          <div className="space-y-2">
            <p>{`The profile ${deleting?.name ?? ""} is removed.`}</p>
            {inUse && (
              <p className="text-destructive font-medium" data-testid="profile-in-use">
                This profile is in use: imported users whose Firebase hash has not been replaced yet (they have not
                signed in since the import) reference it. It cannot be deleted until none do.
              </p>
            )}
          </div>
        }
        confirmLabel="Delete profile"
        onConfirm={() => deleting && remove.mutate(deleting)}
        onCancel={() => {
          setDeleting(null);
          remove.reset();
        }}
        pending={remove.isPending}
        error={inUse ? null : remove.error}
      />
    </section>
  );
}

export const Route = createFileRoute("/t/$tenant/password-profiles/")({ component: PasswordProfilesPage });
