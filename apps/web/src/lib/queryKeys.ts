export const assessmentKeys = {
  all: ['assessments'] as const,
  latest: () => ['assessments', 'latest'] as const,
  list: (limit = 100) => ['assessments', 'list', limit] as const,
  dashboard: (assessmentId: string) => ['assessments', 'dashboard', assessmentId] as const,
  workspaces: () => ['assessments', 'workspaces'] as const,
}

export const findingsKeys = {
  list: (assessmentId: string, pageSize = 500) => ['findings', assessmentId, pageSize] as const,
}

export const authKeys = {
  me: () => ['auth', 'me'] as const,
}

export const collectionModuleKeys = {
  all: () => ['collection-modules'] as const,
}
