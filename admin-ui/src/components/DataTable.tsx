import { type ColumnDef, type RowData, tableFeatures, useTable } from "@tanstack/react-table";
import { useCallback, useState } from "react";
import { ProblemAlert } from "@/components/ProblemAlert";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, TableBody, TableCaption, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";

/**
 * Paging, sorting and filtering happen on the server (cursor pagination), so the table needs only
 * the core features: no client-side row models.
 */
export const dataTableFeatures = tableFeatures({});
export type DataTableFeatures = typeof dataTableFeatures;

/**
 * Cursor stack for "Previous"/"Next" over the API's `after` cursors. `after` is the cursor of the
 * current page (undefined on the first page).
 */
export function useCursorPager() {
  const [stack, setStack] = useState<string[]>([]);
  const after = stack.at(-1);
  const next = useCallback((cursor: string) => setStack((s) => [...s, cursor]), []);
  const previous = useCallback(() => setStack((s) => s.slice(0, -1)), []);
  return { after, page: stack.length + 1, hasPrevious: stack.length > 0, next, previous };
}

export type CursorPager = ReturnType<typeof useCursorPager>;

interface DataTableProps<TData extends RowData> {
  /** Accessible name of the table. */
  caption: string;
  columns: ColumnDef<DataTableFeatures, TData, any>[];
  data: readonly TData[] | undefined;
  getRowId: (row: TData) => string;
  isPending: boolean;
  isFetching: boolean;
  error: unknown;
  emptyMessage: string;
  pager: CursorPager;
  nextCursor: string | null | undefined;
}

export function DataTable<TData extends RowData>({
  caption,
  columns,
  data,
  getRowId,
  isPending,
  isFetching,
  error,
  emptyMessage,
  pager,
  nextCursor,
}: DataTableProps<TData>) {
  const table = useTable({
    features: dataTableFeatures,
    columns,
    data: data ?? [],
    getRowId: (row) => getRowId(row),
  });

  if (error) return <ProblemAlert error={error} />;

  const rows = table.getRowModel().rows;
  const columnCount = table.getAllLeafColumns().length;

  return (
    <div className="space-y-3">
      <div className="rounded-md border">
        <Table aria-busy={isFetching}>
          <TableCaption className="sr-only">{caption}</TableCaption>
          <TableHeader>
            {table.getHeaderGroups().map((group) => (
              <TableRow key={group.id}>
                {group.headers.map((header) => (
                  <TableHead key={header.id} scope="col">
                    {header.isPlaceholder ? null : <table.FlexRender header={header} />}
                  </TableHead>
                ))}
              </TableRow>
            ))}
          </TableHeader>
          <TableBody>
            {isPending ? (
              [0, 1, 2].map((i) => (
                <TableRow key={`loading-${i}`}>
                  <TableCell colSpan={columnCount}>
                    <Skeleton className="h-5 w-full" />
                  </TableCell>
                </TableRow>
              ))
            ) : rows.length === 0 ? (
              <TableRow>
                <TableCell colSpan={columnCount} className="text-muted-foreground h-20 text-center">
                  {emptyMessage}
                </TableCell>
              </TableRow>
            ) : (
              rows.map((row) => (
                <TableRow key={row.id}>
                  {row.getAllCells().map((cell) => (
                    <TableCell key={cell.id}>
                      <table.FlexRender cell={cell} />
                    </TableCell>
                  ))}
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </div>
      {isPending && (
        <p role="status" className="sr-only">
          Loading…
        </p>
      )}
      <nav aria-label={`${caption} pages`} className="flex items-center justify-end gap-2">
        <span className="text-muted-foreground mr-auto text-sm" aria-live="polite">
          Page {pager.page}
        </span>
        <Button variant="outline" size="sm" onClick={pager.previous} disabled={!pager.hasPrevious || isFetching}>
          Previous
        </Button>
        <Button
          variant="outline"
          size="sm"
          onClick={() => nextCursor && pager.next(nextCursor)}
          disabled={!nextCursor || isFetching}
        >
          Next
        </Button>
      </nav>
    </div>
  );
}
