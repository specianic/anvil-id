// "Add administrator" in the system tenant (C-H2): one guided action that invites a new console
// administrator by email and assigns the `administrator` role (SYSTEM_ADMIN_ROLE, seeded with full
// administrative access). When the address already belongs to a system-tenant user, it offers
// to assign the role to that user instead. Every step goes through the existing admin API; the
// server's refusals are shown as they come.
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { UserPlus } from "lucide-react";
import { type FormEvent, useState } from "react";
import { type UserView, api, unwrap } from "@/api/client";
import { Modal } from "@/components/ConfirmDialog";
import { RoleProblem } from "@/components/RoleForm";
import { NoSmtpWarning, useSmtpAvailable } from "@/components/UserForm";
import { StatusMessage, TextField, fieldErrors } from "@/components/form";
import { Button } from "@/components/ui/button";
import { SYSTEM_TENANT } from "@/lib/tenant";

/** The system tenant's administrator role (anvil-core model/role.rs SYSTEM_ADMIN_ROLE). */
export const ADMINISTRATOR_ROLE = "administrator";

type Outcome = { kind: "invited"; user: UserView } | { kind: "assigned"; user: UserView };

export function AddAdministrator() {
  const queryClient = useQueryClient();
  const smtpAvailable = useSmtpAvailable(SYSTEM_TENANT);
  const [open, setOpen] = useState(false);
  const [email, setEmail] = useState("");
  const [existing, setExisting] = useState<UserView | null>(null);
  const [status, setStatus] = useState<string | null>(null);

  const assignRole = async (user: UserView) => {
    unwrap(
      await api.PUT("/api/admin/v1/tenants/{slug}/users/{user_id}/roles/{name}", {
        params: { path: { slug: SYSTEM_TENANT, user_id: user.id, name: ADMINISTRATOR_ROLE } },
      }),
    );
  };

  const refresh = async (user: UserView) => {
    await Promise.all([
      queryClient.invalidateQueries({ queryKey: ["users", SYSTEM_TENANT] }),
      queryClient.invalidateQueries({ queryKey: ["user-roles", SYSTEM_TENANT, user.id] }),
      queryClient.invalidateQueries({ queryKey: ["role-users", SYSTEM_TENANT] }),
    ]);
  };

  // Step 1: look the address up; invite + assign when it is new, otherwise ask.
  const invite = useMutation({
    mutationFn: async (address: string): Promise<Outcome | { kind: "exists"; user: UserView }> => {
      const found = unwrap(
        await api.GET("/api/admin/v1/tenants/{slug}/users", {
          params: { path: { slug: SYSTEM_TENANT }, query: { email: address } },
        }),
      ).items[0];
      if (found) return { kind: "exists", user: found };
      const user = unwrap(
        await api.POST("/api/admin/v1/tenants/{slug}/users", {
          params: { path: { slug: SYSTEM_TENANT } },
          body: { email: address, invite: true },
        }),
      );
      await assignRole(user);
      return { kind: "invited", user };
    },
    onMutate: () => setStatus(null),
    onSuccess: async (result) => {
      if (result.kind === "exists") {
        setExisting(result.user);
        return;
      }
      await refresh(result.user);
      finish(`Invitation sent to ${result.user.email}. The administrator role is assigned; they can sign in to the console after choosing a password from the email.`);
    },
  });

  // Step 2 (existing user): assign the role.
  const assign = useMutation({
    mutationFn: async (user: UserView): Promise<Outcome> => {
      await assignRole(user);
      return { kind: "assigned", user };
    },
    onMutate: () => setStatus(null),
    onSuccess: async (result) => {
      await refresh(result.user);
      finish(`${result.user.email} is now an administrator.`);
    },
  });

  const reset = () => {
    setEmail("");
    setExisting(null);
    invite.reset();
    assign.reset();
  };

  const finish = (message: string) => {
    setOpen(false);
    reset();
    setStatus(message);
  };

  const close = () => {
    setOpen(false);
    reset();
  };

  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (existing) assign.mutate(existing);
    else invite.mutate(email.trim());
  };

  const server = fieldErrors(invite.error);
  const pending = invite.isPending || assign.isPending;
  const error = invite.error && !server.email ? invite.error : assign.error;

  return (
    <div className="space-y-2">
      <Button variant="outline" size="sm" onClick={() => setOpen(true)} data-testid="add-administrator">
        <UserPlus aria-hidden="true" />
        Add administrator
      </Button>
      <StatusMessage message={status} />
      <Modal open={open} onClose={close} title="Add administrator">
        <form onSubmit={submit} className="space-y-4" noValidate aria-label="Add administrator" data-testid="add-administrator-form">
          <p className="text-muted-foreground text-sm">
            Administrators sign in to this console. The person receives an invitation email to choose a password and is
            given the <code>{ADMINISTRATOR_ROLE}</code> role (full administrative access, unless its permissions were changed under Roles).
          </p>
          <TextField
            label="Email"
            type="email"
            required
            autoComplete="off"
            value={email}
            disabled={existing !== null}
            onChange={(e) => setEmail(e.target.value)}
            errors={server.email}
            data-testid="add-administrator-email"
          />
          {smtpAvailable === false && !existing && <NoSmtpWarning action="The invitation" />}
          {existing && (
            <div className="space-y-1 rounded-md border p-3 text-sm" data-testid="add-administrator-existing">
              <p>
                <Link
                  to="/t/$tenant/users/$userId"
                  params={{ tenant: SYSTEM_TENANT, userId: existing.id }}
                  className="text-link underline underline-offset-4"
                >
                  {existing.email}
                </Link>{" "}
                already has an account in the system tenant
                {existing.status === "blocked" ? " (blocked: unblock it before the role takes effect)" : ""}.
              </p>
              <p className="text-muted-foreground">Assign the {ADMINISTRATOR_ROLE} role to this user instead?</p>
            </div>
          )}
          {error ? <RoleProblem error={error} /> : null}
          <div className="flex justify-end gap-2">
            <Button type="button" variant="outline" onClick={close} disabled={pending}>
              Cancel
            </Button>
            <Button type="submit" disabled={pending || (!existing && email.trim() === "")} data-testid="add-administrator-submit">
              {pending ? "Working…" : existing ? "Assign administrator role" : "Invite administrator"}
            </Button>
          </div>
        </form>
      </Modal>
    </div>
  );
}
