/**
 * CodeFort Workspace & Local Persistence Manager
 * Ensures each browser device has an isolated, private workspace session
 * and that connected repositories never disappear during serverless cold starts.
 */

export interface RepoItem {
  id: string;
  full_name: string;
  is_connected: boolean;
  policy?: Record<string, any>;
}

export const DEMO_REPO: RepoItem = {
  id: "repo_vulnerable",
  full_name: "codefort-sec/vulnerable-test-repo",
  is_connected: true,
  policy: {
    block_on_critical: true,
    review_on_high: true,
    require_static: true,
    require_dependency: true,
  },
};

const WORKSPACE_KEY = "codefort_workspace_id";
const REPOS_PREFIX = "codefort_repos_";

export function getWorkspaceId(): string {
  if (typeof window === "undefined") return "default";
  let wsId = localStorage.getItem(WORKSPACE_KEY);
  if (!wsId) {
    wsId = "ws_" + Math.random().toString(36).substring(2, 10);
    localStorage.setItem(WORKSPACE_KEY, wsId);
  }
  return wsId;
}

export function getLocalRepos(): RepoItem[] {
  if (typeof window === "undefined") return [DEMO_REPO];
  const wsId = getWorkspaceId();
  try {
    const raw = localStorage.getItem(REPOS_PREFIX + wsId);
    if (!raw) {
      // First-time visit for this workspace: seed with demo repo
      saveLocalRepos([DEMO_REPO]);
      return [DEMO_REPO];
    }
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed) && parsed.length > 0) {
      return parsed;
    }
    return [DEMO_REPO];
  } catch {
    return [DEMO_REPO];
  }
}

export function saveLocalRepos(repos: RepoItem[]): void {
  if (typeof window === "undefined") return;
  const wsId = getWorkspaceId();
  try {
    localStorage.setItem(REPOS_PREFIX + wsId, JSON.stringify(repos));
  } catch (err) {
    console.error("Failed to save local repos:", err);
  }
}

export function addLocalRepo(newRepo: RepoItem): RepoItem[] {
  const current = getLocalRepos();
  const exists = current.some(
    (r) => r.full_name.toLowerCase() === newRepo.full_name.toLowerCase()
  );
  const updated = exists ? current : [newRepo, ...current];
  saveLocalRepos(updated);
  return updated;
}

export function removeLocalRepo(repoId: string, fullName: string): RepoItem[] {
  const current = getLocalRepos();
  const updated = current.filter(
    (r) => r.id !== repoId && r.full_name.toLowerCase() !== fullName.toLowerCase()
  );
  saveLocalRepos(updated);
  return updated;
}

export function restoreDemoRepo(): RepoItem[] {
  const current = getLocalRepos();
  const hasDemo = current.some((r) => r.full_name === DEMO_REPO.full_name);
  const updated = hasDemo ? current : [DEMO_REPO, ...current];
  saveLocalRepos(updated);
  return updated;
}
