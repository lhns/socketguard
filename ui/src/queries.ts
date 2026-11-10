import { useEffect } from "react";
import {
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
  type NewCredential,
  type NewGrant,
  type NewPeer,
  type ProtectHostRequest,
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
export const useNetworks = () => useQuery({ queryKey: ["networks"], queryFn: api.listNetworks });
export const useSettings = () => useQuery({ queryKey: ["settings"], queryFn: api.getSettings });

export const ACTIVITY_PAGE = 50;

export interface ActivityFilter {
  kind: ActivityKind | null;
  appId: string | null;
}

export function useActivity(filter: ActivityFilter) {
  return useInfiniteQuery({
    queryKey: ["activity", filter],
    initialPageParam: null as number | null,
    queryFn: ({ pageParam }) =>
      api.activity({ kind: filter.kind, app_id: filter.appId, before: pageParam, limit: ACTIVITY_PAGE }),
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

export const useCreateGrant = () =>
  useInvalidating((req: NewGrant) => api.createGrant(req), GRANT_KEYS);
export const useDeleteGrant = () =>
  useInvalidating((id: string) => api.deleteGrant(id), GRANT_KEYS);
export const useReviewApp = () =>
  useInvalidating(
    (v: { id: string; reviewed: boolean }) => api.reviewApp(v.id, v.reviewed),
    [["apps"], ["app"], ["status"], ["activity"]],
  );
export const useCreatePeer = () =>
  useInvalidating((req: NewPeer) => api.createPeer(req), PEER_KEYS);
export const useDeletePeer = () =>
  useInvalidating((id: string) => api.deletePeer(id), PEER_KEYS);
export const useAddCredential = () =>
  useInvalidating((v: { peerId: string; req: NewCredential }) => api.addCredential(v.peerId, v.req), PEER_KEYS);
export const useRemoveCredential = () =>
  useInvalidating(
    (v: { peerId: string; credentialId: string }) => api.removeCredential(v.peerId, v.credentialId),
    PEER_KEYS,
  );
export const useSetProtectHost = () =>
  useInvalidating((req: ProtectHostRequest) => api.setProtectHost(req), [["settings"], ["status"]]);
export const useSetEnabled = () =>
  useInvalidating((enabled: boolean) => (enabled ? api.enable() : api.disable()), [["status"], ["apps"], ["app"]]);

// ─── Push events ────────────────────────────────────────────────────────────

/** Which queries each daemon event makes stale. */
export const EVENT_INVALIDATIONS: Record<string, string[][]> = {
  apps_changed: [["apps"], ["app"], ["status"]],
  app_discovered: [["apps"], ["app"], ["status"]],
  peers_changed: [["peers"], ["groups"], ["grants"], ["app"]],
  grants_changed: [["grants"], ["apps"], ["app"]],
  networks_changed: [["networks"], ["status"], ["app"]],
  settings_changed: [["settings"], ["status"]],
  activity: [["activity"]],
  daemon_disconnected: [["status"]],
  daemon_connected: [["status"], ["apps"], ["app"], ["peers"], ["groups"], ["grants"], ["networks"], ["settings"], ["activity"]],
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
