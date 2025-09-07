import { EventEmitter } from 'events'

/**
 * OAuth callback server setup options
 */
export interface OAuthCallbackServerOptions {
  /** Port for the callback server */
  port: number
  /** Path for the callback endpoint */
  path: string
  /** Event emitter to signal when auth code is received */
  events: EventEmitter
  /** Timeout in milliseconds for the auth callback server's long poll */
  authTimeoutMs?: number
  /** Server URL hash to locate per-server auth files (e.g., tokens.json) */
  serverUrlHash: string
  /** Poll interval in milliseconds for token readiness checks */
  tokenReadyPollMs?: number
}
