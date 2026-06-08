import _client from './api'

export const approvalApi = {
  approve: (requestId: string) =>
    _client.post(`/ai-operator/approve/${requestId}`).then((r) => r.data),

  reject: (requestId: string) =>
    _client.post(`/ai-operator/reject/${requestId}`).then((r) => r.data),

  getMemory: (assessmentId: string) =>
    _client.get(`/ai-operator/memory/${assessmentId}`).then((r) => r.data),

  clearMemory: (assessmentId: string) =>
    _client.delete(`/ai-operator/memory/${assessmentId}`).then((r) => r.data),

  listPlaybooks: () =>
    _client.get('/ai-operator/playbooks').then((r) => r.data),

  getTargetCard: (assessmentId: string) =>
    _client.get(`/ai-operator/target-card/${assessmentId}`).then((r) => r.data),
}
