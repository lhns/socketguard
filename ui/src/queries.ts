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
  type ApplyRequest,
  type ChangeOp,
  type MergeRequest,
  type NewCredential,
  type NewGroup,
  type NewNetwork,
  type NewPeer,
  type ProtectHostRequest,
  type SplitRequest,
  type UpdateSettings,
  type UpdateTag,
} from "./api";

export function createQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: { queries: { retry: false, staleTime: 5_000, refetchOnWindowFocus: false } },
  });
}

// ─── Queries ────────────────────────────────────────────────────────────────

export const useStatus = () =>
  useQuery({ queryKey: ["status"], queryFn: api.status, refetchInterval: (q) => (q.state.error ? 5_000 : false) });
export const useApps = () => useQuery({ queryKey: ["apps"], queryFn: api.listApps });
export const useApp = (id: string | null) =>
  useQuery({ queryKey: ["app", id], queryFn: () => api.getApp(id as string), enabled: id !== null });
export const usePeers = () => useQuery({ queryKey: ["peers"], queryFn: api.listPeers });
export const useGroups = () => useQuery({ queryKey: ["groups"], queryFn: api.listGroups });
export const useGrants = () => useQuery({ queryKey: ["grants"], queryFn: api.listGrants });
export const useTags = () => useQuery({ queryKey: ["tags"], queryFn: api.listTags });
export const useSocketGroups = () => useQuery({ queryKey: ["socketGroups"], queryFn: api.listSocketGroups });
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

// ─── Mutations ──────────────────────────────────────────────────────────────

/** Mutations also invalidate directly; the SSE event follows and is idempotent. */
function useInvalidating<V, R>(fn: (v: V) => Promise<R>, keys: string[][]) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: fn,
    onSuccess: () => {
      for (const queryKey of keys) void qc.invalidateQueries({ queryKey });
    },
  });
}

const GRANT_KEYS = [["grants"], ["apps"], ["app"], ["activity"]];
const PEER_KEYS = [["peers"], ["groups"], ["grants"], ["app"]];
const GROUP_KEYS = [["groups"], ["peers"], ["grants"], ["app"], ["activity"]];
const TAG_KEYS = [["tags"], ["grants"], ["apps"], ["app"], ["activity"]];
const NETWORK_KEYS = [["networks"], ["status"], ["apps"], ["app"], ["grants"], ["settings"]];
/** A batch can touch anything. */
const CHANGES_KEYS = [["grants"], ["apps"], ["app"], ["peers"], ["groups"], ["tags"], ["socketGroups"], ["status"], ["activity"]];

export const useDeleteApp = () =>
  useInvalidating((id: string) => api.deleteApp(id), [...GRANT_KEYS, ["status"], ["tags"]]);
export const useSplitApp = () =>
  useInvalidating((v: { id: string; req: SplitRequest }) => api.splitApp(v.id, v.req), [["apps"], ["app"]]);
export const useMergeApp = () =>
  useInvalidating((v: { id: string; req: MergeRequest }) => api.mergeApp(v.id, v.req), [["apps"], ["app"]]);

/** Many changes at once (ADR 0045). A dry run changes nothing, so it invalidates nothing. */
export function useChanges() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (v: { ops: ChangeOp[]; dryRun: boolean }) => api.changes({ ops: v.ops, dry_run: v.dryRun }),
    onSuccess: (_r, v) => {
      if (v.dryRun) return;
      for (const queryKey of CHANGES_KEYS) void qc.invalidateQueries({ queryKey });
    },
  });
}

export const useCreatePeer = () =>
  useInvalidating((req: NewPeer) => api.createPeer(req), PEER_KEYS);
export const useRenamePeer = () =>
  useInvalidating((v: { id: string; label: string }) => api.updatePeer(v.id, v.label), PEER_KEYS);
export const useDeletePeer = () =>
  useInvalidating((id: string) => api.deletePeer(id), PEER_KEYS);
export const useAddCredential = () =>
  useInvalidating((v: { peerId: string; req: NewCredential }) => api.addCredential(v.peerId, v.req), PEER_KEYS);
export const useRemoveCredential = () =>
  useInvalidating(
    (v: { peerId: string; credentialId: string }) => api.removeCredential(v.peerId, v.credentialId),
    PEER_KEYS,
  );
export const useGenerateTorKey = () =>
  useInvalidating((peerId: string) => api.generateTorKey(peerId), [...PEER_KEYS, ["share"]]);

export const useCreateGroup = () =>
  useInvalidating((req: NewGroup) => api.createGroup(req), GROUP_KEYS);
export const useRenameGroup = () =>
  useInvalidating((v: { id: string; label: string }) => api.updateGroup(v.id, v.label), GROUP_KEYS);
export const useDeleteGroup = () =>
  useInvalidating((id: string) => api.deleteGroup(id), GROUP_KEYS);
export const useSetGroupMembers = () =>
  useInvalidating((v: { id: string; peerIds: string[] }) => api.setGroupMembers(v.id, v.peerIds), GROUP_KEYS);

export const useUpdateTag = () =>
  useInvalidating((v: { id: string; req: UpdateTag }) => api.updateTag(v.id, v.req), TAG_KEYS);
export const useDeleteTag = () =>
  useInvalidating((id: string) => api.deleteTag(id), TAG_KEYS);

export const useAddNetwork = () =>
  useInvalidating((req: NewNetwork) => api.addNetwork(req), NETWORK_KEYS);
export const useDeleteNetwork = () =>
  useInvalidating((v: { id: string; force: boolean }) => api.deleteNetwork(v.id, v.force), NETWORK_KEYS);
export const useUpdateSettings = () =>
  useInvalidating((req: UpdateSettings) => api.updateSettings(req), [["settings"], ["apps"], ["app"]]);
export const useSetProtectHost = () =>
  useInvalidating((req: ProtectHostRequest) => api.setProtectHost(req), [["settings"], ["status"]]);
export const useApplyState = () =>
  useInvalidating((req: ApplyRequest) => api.applyState(req), [...CHANGES_KEYS, ["settings"], ["networks"]]);
export const useSetEnabled = () =>
  useInvalidating((enabled: boolean) => (enabled ? api.enable() : api.disable()), [["status"], ["apps"], ["app"]]);

// ─── Push events ────────────────────────────────────────────────────────────

/** Which queries each daemon event makes stale. */
export const EVENT_INVALIDATIONS: Record<string, string[][]> = {
  apps_changed: [["apps"], ["app"], ["status"]],
  app_discovered: [["apps"], ["app"], ["status"]],
  peers_changed: [["peers"], ["groups"], ["grants"], ["app"], ["share"]],
  grants_changed: [["grants"], ["apps"], ["app"], ["share"]],
  tags_changed: [["tags"], ["grants"], ["app"]],
  socket_groups_changed: [["socketGroups"], ["grants"], ["apps"], ["app"]],
  networks_changed: [["networks"], ["status"], ["app"]],
  settings_changed: [["settings"], ["status"]],
  activity: [["activity"]],
  daemon_disconnected: [["status"]],
  daemon_connected: [["status"], ["apps"], ["app"], ["peers"], ["groups"], ["grants"], ["tags"], ["socketGroups"], ["networks"], ["settings"], ["activity"]],
};

let subscribed = false;

/** Subscribe to the backend's SSE bridge once and keep the query cache fresh. */
export function useDaemonEvents() {
  const qc = useQueryClient();
  useEffect(() => {
    const unlistens: Promise<() => void>[] = Object.entries(EVENT_INVALIDATIONS).map(([name, keys]) =>
      onDaemonEvent(name, () => {
        for (const queryKey of keys) void qc.invalidateQueries({ queryKey });
      }),
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
