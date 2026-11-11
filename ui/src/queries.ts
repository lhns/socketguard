import { useEffect, useMemo } from "react";
import {
  keepPreviousData,
  QueryClient,
  useInfiniteQuery,
  useMutation,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import {
  api,
  onDaemonEvent,
  type ActivityKind,
  type App,
  type AppDetail,
  type ApplyRequest,
  type ChangeOp,
  type NewCredential,
  type NewGroup,
  type NewNetwork,
  type PortGroup,
  type ProtectHostRequest,
  type UpdateTag,
} from "./api";

export function createQueryClient(): QueryClient {
  return new QueryClient({
    // Daemon events (and `daemon_connected` after a reconnect) mark what changed as stale, so data
    // can stay fresh for a while without refetching.
    defaultOptions: { queries: { retry: false, staleTime: 30_000, refetchOnWindowFocus: false } },
  });
}

// ─── Queries ────────────────────────────────────────────────────────────────

export const useStatus = () =>
  useQuery({ queryKey: ["status"], queryFn: api.status, refetchInterval: (q) => (q.state.error ? 5_000 : false) });
export const useApps = () => useQuery({ queryKey: ["apps"], queryFn: api.listApps });
/** The detail before it arrives: what the loaded lists already know (`isPlaceholderData`).
 * Grants, access and counters are empty until the real detail comes. */
function partialDetail(qc: QueryClient, id: string | null): AppDetail | undefined {
  const app = qc.getQueryData<App[]>(["apps"])?.find((a) => a.id === id);
  if (!app) return undefined;
  const portGroups = qc.getQueryData<PortGroup[]>(["portGroups"]) ?? [];
  return { ...app, grants: [], access: [], tags: [], counters: [], port_groups: portGroups.filter((g) => g.apps.includes(app.id)) };
}

export const useApp = (id: string | null) => {
  const qc = useQueryClient();
  return useQuery({
    queryKey: ["app", id],
    queryFn: () => api.getApp(id as string),
    enabled: id !== null,
    placeholderData: () => partialDetail(qc, id),
  });
};
export const usePeers = () => useQuery({ queryKey: ["peers"], queryFn: api.listPeers });
export const useGroups = () => useQuery({ queryKey: ["groups"], queryFn: api.listGroups });
export const useGrants = () => useQuery({ queryKey: ["grants"], queryFn: api.listGrants });
export const useTags = () => useQuery({ queryKey: ["tags"], queryFn: api.listTags });
export const usePortGroups = () => useQuery({ queryKey: ["portGroups"], queryFn: api.listPortGroups });
export const useReservations = () => useQuery({ queryKey: ["reservations"], queryFn: api.listReservations });
/** What can be added on this host. Looked at again whenever the window gets focus: the person
 * may have installed something meanwhile. */
export const useNetworkSetup = () =>
  useQuery({ queryKey: ["networkSetup"], queryFn: api.networkSetup, staleTime: 0, refetchOnWindowFocus: true });
export const useNetworks = () => useQuery({ queryKey: ["networks"], queryFn: api.listNetworks });
export const useSettings = () => useQuery({ queryKey: ["settings"], queryFn: api.getSettings });
export const useShare = (appId: string | null) =>
  useQuery({ queryKey: ["share", appId], queryFn: () => api.shareApp(appId as string), enabled: appId !== null });

/** A list query's data, an empty list while it loads (the same one each render, so it can be a
 * dependency). */
export function useList<T>(query: { data: T[] | undefined }): T[] {
  const data = query.data;
  return useMemo(() => data ?? [], [data]);
}

/** Classify pasted credential text with the daemon's parser (kept while typing). */
export const useParsedCredentials = (text: string) => {
  const t = text.trim();
  return useQuery({
    queryKey: ["parse", t],
    queryFn: () => api.parseCredentials(t),
    enabled: t !== "",
    placeholderData: keepPreviousData,
    staleTime: Infinity,
  });
};

export const ACTIVITY_PAGE = 50;

export interface ActivityFilter {
  kind: ActivityKind | null;
  appId: string | null;
  peerId?: string | null;
}

export function useActivity(filter: ActivityFilter) {
  return useInfiniteQuery({
    queryKey: ["activity", filter],
    initialPageParam: null as number | null,
    queryFn: ({ pageParam }) =>
      api.activity({
        kind: filter.kind,
        app_id: filter.appId,
        peer_id: filter.peerId ?? null,
        before: pageParam,
        limit: ACTIVITY_PAGE,
      }),
    getNextPageParam: (last) =>
      last.length < ACTIVITY_PAGE ? undefined : last[last.length - 1].id,
  });
}

// ─── Push events ────────────────────────────────────────────────────────────

/** Which queries each daemon event makes stale. Only the query of an app that is open refetches
 * (`app`: access, port groups, addresses); the others are marked stale for the next time. An
 * event lists what it changes itself: the daemon sends the events of the things a change
 * cascades to (deleting a peer sends peers_changed and grants_changed). */
export const EVENT_INVALIDATIONS: Record<string, string[][]> = {
  apps_changed: [["apps"], ["app"], ["status"]],
  app_discovered: [["apps"], ["app"], ["status"]],
  peers_changed: [["peers"], ["groups"], ["share"]],
  grants_changed: [["grants"], ["apps"], ["app"], ["share"]],
  tags_changed: [["tags"]],
  port_groups_changed: [["portGroups"], ["app"]],
  reservations_changed: [["reservations"], ["addresses"]],
  addresses_changed: [["addresses"], ["reservations"], ["apps"], ["app"]],
  networks_changed: [["networks"], ["networkSetup"], ["status"]],
  settings_changed: [["settings"], ["status"]],
  activity: [["activity"]],
  daemon_disconnected: [["status"]],
  daemon_connected: [["status"], ["apps"], ["app"], ["peers"], ["groups"], ["grants"], ["tags"], ["portGroups"], ["reservations"], ["addresses"], ["networks"], ["settings"], ["activity"]],
};

// ─── Mutations ──────────────────────────────────────────────────────────────

/** Queries stale after a change. Used by the mutations and by the daemon events. An in-flight
 * fetch is reused: a mutation and the event that follows it fetch a query once. */
function invalidate(qc: QueryClient, keys: string[][]) {
  for (const queryKey of keys) void qc.invalidateQueries({ queryKey }, { cancelRefetch: false });
}

/** The queries the given daemon events make stale (see EVENT_INVALIDATIONS). */
const keysOf = (...events: string[]) => [...new Map(events.flatMap((e) => EVENT_INVALIDATIONS[e]).map((k) => [k[0], k])).values()];

/** Mutations also invalidate directly (the SSE bridge may be down); the event that follows reuses
 * the fetch. */
function useInvalidating<V, R>(fn: (v: V) => Promise<R>, keys: string[][]) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: fn,
    onSuccess: () => invalidate(qc, keys),
  });
}

const PEER_KEYS = keysOf("peers_changed");
/** Deleting a peer or a group, a credential or a member changes grants too. */
const PEER_GRANT_KEYS = keysOf("peers_changed", "grants_changed");
const TAG_KEYS = keysOf("tags_changed", "grants_changed", "apps_changed", "activity");
const RESERVATION_KEYS = keysOf("reservations_changed", "grants_changed", "apps_changed", "activity");
const NETWORK_KEYS = keysOf("networks_changed", "apps_changed", "grants_changed", "settings_changed");
/** A batch can touch anything. */
const CHANGES_KEYS = keysOf(
  "apps_changed", "peers_changed", "grants_changed", "tags_changed", "port_groups_changed", "reservations_changed", "addresses_changed", "activity",
);

export const useDeleteApp = () =>
  useInvalidating((id: string) => api.deleteApp(id), keysOf("apps_changed", "grants_changed", "tags_changed", "activity"));

export const useReleaseReservation = () =>
  useInvalidating((id: string) => api.releaseReservation(id), RESERVATION_KEYS);

/** Many changes at once (ADR 0045). A dry run changes nothing, so it invalidates nothing. */
export function useChanges() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (v: { ops: ChangeOp[]; dryRun: boolean }) => api.changes({ ops: v.ops, dry_run: v.dryRun }),
    onSuccess: (_r, v) => {
      if (v.dryRun) return;
      invalidate(qc, CHANGES_KEYS);
    },
  });
}

export const useRenamePeer = () =>
  useInvalidating((v: { id: string; label: string }) => api.updatePeer(v.id, v.label), PEER_KEYS);
export const useDeletePeer = () =>
  useInvalidating((id: string) => api.deletePeer(id), PEER_GRANT_KEYS);
export const useAddCredential = () =>
  useInvalidating((v: { peerId: string; req: NewCredential }) => api.addCredential(v.peerId, v.req), PEER_GRANT_KEYS);
export const useRemoveCredential = () =>
  useInvalidating(
    (v: { peerId: string; credentialId: string }) => api.removeCredential(v.peerId, v.credentialId),
    PEER_GRANT_KEYS,
  );
export const useGenerateTorKey = () =>
  useInvalidating((peerId: string) => api.generateTorKey(peerId), PEER_GRANT_KEYS);

export const useCreateGroup = () =>
  useInvalidating((req: NewGroup) => api.createGroup(req), PEER_KEYS);
export const useRenameGroup = () =>
  useInvalidating((v: { id: string; label: string }) => api.updateGroup(v.id, v.label), PEER_KEYS);
export const useDeleteGroup = () =>
  useInvalidating((id: string) => api.deleteGroup(id), PEER_GRANT_KEYS);
export const useSetGroupMembers = () =>
  useInvalidating((v: { id: string; peerIds: string[] }) => api.setGroupMembers(v.id, v.peerIds), PEER_GRANT_KEYS);

export const useUpdateTag = () =>
  useInvalidating((v: { id: string; req: UpdateTag }) => api.updateTag(v.id, v.req), TAG_KEYS);
export const useDeleteTag = () =>
  useInvalidating((id: string) => api.deleteTag(id), TAG_KEYS);

export const useAddNetwork = () =>
  useInvalidating((req: NewNetwork) => api.addNetwork(req), NETWORK_KEYS);
export const useDeleteNetwork = () =>
  useInvalidating(
    (v: { id: string; force: boolean; confirmExposed?: boolean }) => api.deleteNetwork(v.id, v.force, v.confirmExposed ?? false),
    NETWORK_KEYS,
  );
/** What stays reachable without the block of network `without` ("all": every network); asked
 * afresh each time a confirmation opens, so it is what is true now. */
export const useExposure = (without: string, enabled = true) =>
  useQuery({ queryKey: ["exposure", without], queryFn: () => api.exposure(without), enabled, staleTime: 0, gcTime: 0 });
export const useSetProtectHost = () =>
  useInvalidating((req: ProtectHostRequest) => api.setProtectHost(req), [["settings"], ["status"]]);
export const useApplyState = () =>
  useInvalidating((req: ApplyRequest) => api.applyState(req), [...CHANGES_KEYS, ...keysOf("settings_changed", "networks_changed")]);
export const useSetEnabled = () =>
  useInvalidating((enabled: boolean) => (enabled ? api.enable() : api.disable()), keysOf("apps_changed", "grants_changed"));

let subscribed = false;

/** Subscribe to the backend's SSE bridge once and keep the query cache fresh. */
export function useDaemonEvents() {
  const qc = useQueryClient();
  useEffect(() => {
    const unlistens: Promise<() => void>[] = Object.entries(EVENT_INVALIDATIONS).map(([name, keys]) =>
      onDaemonEvent(name, () => invalidate(qc, keys)),
    );
    if (!subscribed) {
      subscribed = true;
      api.subscribeEvents().catch(() => {
        subscribed = false;
      });
    }
    return () => {
      for (const u of unlistens) u.then((fn) => fn()).catch(() => {});
    };
  }, [qc]);
}
