// GET /health — liveness probe used by docker-compose healthchecks
// and the Phase 0 verification step (task 1.9).
//
// Returns { status: 'ok', uptimeSec } where uptimeSec is the integer number
// of seconds the API process has been alive. No auth required; safe for
// Caddy and Prometheus to poll.

import type { FastifyPluginAsync } from 'fastify';

export interface HealthResponse {
  readonly status: 'ok';
  readonly uptimeSec: number;
}

export const healthRoutes: FastifyPluginAsync = async (app) => {
  app.get('/health', async (): Promise<HealthResponse> => {
    return {
      status: 'ok',
      uptimeSec: Math.floor(process.uptime()),
    };
  });
};
