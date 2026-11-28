// Slug suggestion from a display name (C-M12), shared by every console form that creates something
// with a slug (tenants, organizations, connections). Usage:
//
//   const { slug, setSlug, onNameChange } = useSlugFromName();
//   <input value={name} onChange={(e) => { setName(e.target.value); onNameChange(e.target.value); }} />
//   <input value={slug} onChange={(e) => setSlug(e.target.value)} />
//
// The slug follows the name until the admin edits the slug field; from then on it is theirs.
// The server validates the slug; this only suggests one.
import { useCallback, useState } from "react";

/** Longest slug the server accepts (tenant, organization and connection slugs). */
export const SLUG_MAX_LENGTH = 63;

/**
 * A slug suggestion for `name` matching the server's slug syntax (anvil-core validate_slug /
 * validate_org_slug / validate_connection_slug: `a-z`, `0-9` and `-`, starting with a letter or
 * digit, at most 63 characters): lowercase ASCII with accents folded, every other run of characters
 * turned into one '-', no leading or trailing '-'. The minimum length (2 for tenants and
 * organizations, 1 for connections) is left to the server, so a very short name gives a short slug.
 */
export function slugify(name: string): string {
  const folded = name
    .normalize("NFKD")
    .replace(/[̀-ͯ]/g, "")
    .toLowerCase()
    .replace(/ß/g, "ss")
    .replace(/[æ]/g, "ae")
    .replace(/[œ]/g, "oe")
    .replace(/[ø]/g, "o")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
  return folded.slice(0, SLUG_MAX_LENGTH).replace(/-+$/, "");
}

/** Slug state that follows a name field until the admin edits the slug. */
export function useSlugFromName(initial = "") {
  const [slug, setSlugState] = useState(initial);
  // An initial slug (editing, or a prefilled form) counts as chosen by the admin.
  const [edited, setEdited] = useState(initial !== "");

  const setSlug = useCallback((value: string) => {
    setSlugState(value);
    // Clearing the slug field hands it back to the name.
    setEdited(value !== "");
  }, []);

  const onNameChange = useCallback(
    (name: string) => {
      if (!edited) setSlugState(slugify(name));
    },
    [edited],
  );

  return { slug, setSlug, onNameChange };
}
