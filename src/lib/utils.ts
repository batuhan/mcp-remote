import { OAuthClientProvider, UnauthorizedError } from '@modelcontextprotocol/sdk/client/auth.js'
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { SSEClientTransport } from '@modelcontextprotocol/sdk/client/sse.js'
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js'
import { Transport } from '@modelcontextprotocol/sdk/shared/transport.js'
import { OAuthError } from '@modelcontextprotocol/sdk/server/auth/errors.js'
import { OAuthClientInformationFull, OAuthClientInformationFullSchema, OAuthTokens, OAuthTokensSchema } from '@modelcontextprotocol/sdk/shared/auth.js'
import { OAuthCallbackServerOptions } from './types'
import { StaticOAuthClientInformationFull, StaticOAuthClientMetadata } from 'mcp-remote/src/lib/types'
import { getConfigDir, getConfigFilePath, readJsonFile } from 'mcp-remote/src/lib/mcp-auth-config'
import {
  REASON_AUTH_NEEDED,
  REASON_TRANSPORT_FALLBACK,
  TransportStrategy,
  DEBUG as ORIGINAL_DEBUG,
  debugLog,
  log,
  mcpProxy,
  AuthInitializer,
  getServerUrlHash,
  shouldIncludeTool,
  findAvailablePort,
  setupSignalHandlers
} from 'mcp-remote/src/lib/utils'
import express from 'express'
import fs from 'fs'
import { readFile, rm } from 'fs/promises'
import path from 'path'
import { version as MCP_REMOTE_VERSION } from '../../package.json'
import { EnvHttpProxyAgent, fetch, Headers, RequestInit, setGlobalDispatcher } from 'undici'

// Global type declaration for typescript
declare global {
  var currentServerUrlHash: string | undefined
}

// Re-export MCP_REMOTE_VERSION from package.json
export { MCP_REMOTE_VERSION }

const pid = process.pid

// Local DEBUG variable that can be modified
export let DEBUG = ORIGINAL_DEBUG








/**
 * Creates and connects to a remote server with OAuth authentication
 * @param client The client to connect with
 * @param serverUrl The URL of the remote server
 * @param authProvider The OAuth client provider
 * @param headers Additional headers to send with the request
 * @param authInitializer Function to initialize authentication when needed
 * @param transportStrategy Strategy for selecting transport type ('sse-only', 'http-only', 'sse-first', 'http-first')
 * @param recursionReasons Set of reasons for recursive calls (internal use)
 * @returns The connected transport
 */
export async function connectToRemoteServer(
  client: Client | null,
  serverUrl: string,
  authProvider: OAuthClientProvider,
  headers: Record<string, string>,
  authInitializer: AuthInitializer,
  transportStrategy: TransportStrategy = 'http-first',
  authTimeoutMs?: number,
  recursionReasons: Set<string> = new Set(),
): Promise<Transport> {
  log(`[${pid}] Connecting to remote server: ${serverUrl}`)
  const url = new URL(serverUrl)

  // Create transport with eventSourceInit to pass Authorization header if present
  const eventSourceInit = {
    fetch: (url: string | URL, init?: RequestInit) => {
      return Promise.resolve(authProvider?.tokens?.()).then((tokens) =>
        fetch(url, {
          ...init,
          headers: {
            ...(init?.headers instanceof Headers
              ? Object.fromEntries(init?.headers.entries())
              : (init?.headers as Record<string, string>) || {}),
            ...headers,
            ...(tokens?.access_token ? { Authorization: `Bearer ${tokens.access_token}` } : {}),
            Accept: 'text/event-stream',
          } as Record<string, string>,
        }),
      )
    },
  }

  log(`Using transport strategy: ${transportStrategy}`)
  // Determine if we should attempt to fallback on error
  // Choose transport based on user strategy and recursion history
  const shouldAttemptFallback = transportStrategy === 'http-first' || transportStrategy === 'sse-first'

  // Create transport instance based on the strategy
  const sseTransport = transportStrategy === 'sse-only' || transportStrategy === 'sse-first'
  const transport = sseTransport
    ? new SSEClientTransport(url, {
        authProvider,
        requestInit: { headers },
        eventSourceInit,
      })
    : new StreamableHTTPClientTransport(url, {
        authProvider,
        requestInit: { headers },
      })

  try {
    debugLog('Attempting to connect to remote server', { sseTransport })

    if (client) {
      debugLog('Connecting client to transport')
      await client.connect(transport)
    } else {
      debugLog('Starting transport directly')
      await transport.start()
      if (!sseTransport) {
        // Extremely hacky, but we didn't actually send a request when calling transport.start() above, so we don't
        // know if we're even talking to an HTTP server. But if we forced that now we'd get an error later saying that
        // the client is already connected. So let's just create a one-off client to make a single request and figure
        // out if we're actually talking to an HTTP server or not.
        debugLog('Creating test transport for HTTP-only connection test')
        const testTransport = new StreamableHTTPClientTransport(url, { authProvider, requestInit: { headers } })
        const testClient = new Client({ name: 'mcp-remote-fallback-test', version: '0.0.0' }, { capabilities: {} })
        await testClient.connect(testTransport)
      }
    }
    log(`Connected to remote server using ${transport.constructor.name}`)

    return transport
  } catch (error: any) {
    // Check if it's a protocol error and we should attempt fallback
    if (
      error instanceof Error &&
      shouldAttemptFallback &&
      (error.message.includes('405') ||
        error.message.includes('Method Not Allowed') ||
        error.message.includes('404') ||
        error.message.includes('Not Found'))
    ) {
      log(`Received error: ${error.message}`)

      // If we've already tried falling back once, throw an error
      if (recursionReasons.has(REASON_TRANSPORT_FALLBACK)) {
        const errorMessage = `Already attempted transport fallback. Giving up.`
        log(errorMessage)
        throw new Error(errorMessage)
      }

      log(`Recursively reconnecting for reason: ${REASON_TRANSPORT_FALLBACK}`)

      // Add to recursion reasons set
      recursionReasons.add(REASON_TRANSPORT_FALLBACK)

      // Recursively call connectToRemoteServer with the updated recursion tracking
      return connectToRemoteServer(
        client,
        serverUrl,
        authProvider,
        headers,
        authInitializer,
        sseTransport ? 'http-only' : 'sse-only',
        authTimeoutMs,
        recursionReasons,
      )
    } else if (error instanceof UnauthorizedError || (error instanceof Error && error.message.includes('Unauthorized'))) {
      log('Authentication required. Initializing auth...')
      debugLog('Authentication error detected', {
        errorCode: error instanceof OAuthError ? error.errorCode : undefined,
        errorMessage: error.message,
        stack: error.stack,
      })

      // Initialize authentication on-demand
      debugLog('Calling authInitializer to start auth flow')
      const { waitForAuthCode, skipBrowserAuth } = await authInitializer()

      if (skipBrowserAuth) {
        log('Authentication required but skipping browser auth - using shared auth')
      } else {
        log('Authentication required. Waiting for authorization...')
      }

      // Wait for the authorization code from the callback
      debugLog('Waiting for auth code from callback server')
      const code = await waitForAuthCode()
      debugLog('Received auth code from callback server')

      try {
        log('Completing authorization...')
        await transport.finishAuth(code)
        debugLog('Authorization completed successfully')

        if (recursionReasons.has(REASON_AUTH_NEEDED)) {
          const errorMessage = `Already attempted reconnection for reason: ${REASON_AUTH_NEEDED}. Giving up.`
          log(errorMessage)
          debugLog('Already attempted auth reconnection, giving up', {
            recursionReasons: Array.from(recursionReasons),
          })
          throw new Error(errorMessage)
        }

        // Track this reason for recursion
        recursionReasons.add(REASON_AUTH_NEEDED)
        log(`Recursively reconnecting for reason: ${REASON_AUTH_NEEDED}`)
        debugLog('Recursively reconnecting after auth', { recursionReasons: Array.from(recursionReasons) })

        // Recursively call connectToRemoteServer with the updated recursion tracking
        return connectToRemoteServer(client, serverUrl, authProvider, headers, authInitializer, transportStrategy, authTimeoutMs, recursionReasons)

      } catch (authError: any) {
        log('Authorization error:', authError)
        debugLog('Authorization error during finishAuth', {
          errorMessage: authError.message,
          stack: authError.stack,
        })
        throw authError
      }
    } else {
      log('Connection error:', error)
      debugLog('Connection error', {
        errorMessage: error.message,
        stack: error.stack,
        transportType: transport.constructor.name,
      })
      throw error
    }
  }
}

/**
 * Sets up an Express server to handle OAuth callbacks
 * @param options The server options
 * @returns An object with the server, authCode, and waitForAuthCode function
 */
export function setupOAuthCallbackServerWithLongPoll(options: OAuthCallbackServerOptions) {
  let authCode: string | null = null
  const app = express()

  // Create a promise to track when auth is completed
  let authCompletedResolve: (code: string) => void
  const authCompletedPromise = new Promise<string>((resolve) => {
    authCompletedResolve = resolve
  })

  async function areTokensReady(): Promise<boolean> {
    try {
      const tokens = await readJsonFile<OAuthTokens>(options.serverUrlHash, 'tokens.json', OAuthTokensSchema)
      const ready = !!tokens?.access_token
      return ready
    } catch (e) {
      return false
    }
  }

  // Long-polling endpoint
  app.get('/wait-for-auth', async (req, res) => {
    const pollingRequested = req.query.poll !== 'false'

    if (!pollingRequested) {
      // Non-polling request: only report completion if tokens are ready
      if (await areTokensReady()) {
        log('Tokens ready - responding 200 to immediate status check')
        return res.status(200).send('Authentication completed')
      }
      return res.status(202).send('Authentication in progress')
    }
    const deadline = Date.now() + (options.authTimeoutMs || 30000)
    while (Date.now() < deadline) {
      if (authCode && (await areTokensReady())) {
        log('Auth code present and tokens ready - responding 200')
        return res.status(200).send('Authentication completed')
      }
      await new Promise((r) => setTimeout(r, options.tokenReadyPollMs ?? 200))
    }
    return res.status(202).send('Authentication in progress')
  })

  // Optional: direct endpoint to check token readiness (useful for debugging)
  app.get('/tokens-ready', async (_req, res) => {
    if (await areTokensReady()) return res.status(200).send('Tokens ready')
    return res.status(202).send('Tokens not ready')
  })

  // OAuth callback endpoint
  app.get(options.path, (req, res) => {
    const code = req.query.code as string | undefined
    if (!code) {
      res.status(400).send('Error: No authorization code received')
      return
    }

    authCode = code
    log('Auth code received, resolving promise')
    authCompletedResolve(code)

    res.send(`
      Authorization successful!
      You may close this window and return to the CLI.
      <script>
        // If this is a non-interactive session (no manual approval step was required) then
        // this should automatically close the window. If not, this will have no effect and
        // the user will see the message above.
        window.close();
      </script>
    `)

    // Notify main flow that auth code is available
    options.events.emit('auth-code-received', code)
  })

  const server = app.listen(options.port, () => {
    log(`OAuth callback server running at http://127.0.0.1:${options.port}`)
  })

  const waitForAuthCode = (): Promise<string> => {
    return new Promise((resolve) => {
      if (authCode) {
        resolve(authCode)
        return
      }

      options.events.once('auth-code-received', (code) => {
        resolve(code)
      })
    })
  }

  return { server, authCode, waitForAuthCode, authCompletedPromise }
}

/**
 * Sets up an Express server to handle OAuth callbacks
 * @param options The server options
 * @returns An object with the server, authCode, and waitForAuthCode function
 */

async function findExistingClientPort(serverUrlHash: string): Promise<number | undefined> {
  const clientInfo = await readJsonFile<OAuthClientInformationFull>(serverUrlHash, 'client_info.json', OAuthClientInformationFullSchema)
  if (!clientInfo) {
    return undefined
  }

  const localhostRedirectUri = clientInfo.redirect_uris
    .map((uri) => new URL(uri))
    .find(({ hostname }) => hostname === 'localhost' || hostname === '127.0.0.1')
  if (!localhostRedirectUri) {
    throw new Error('Cannot find localhost callback URI from existing client information')
  }

  return parseInt(localhostRedirectUri.port)
}

function calculateDefaultPort(serverUrlHash: string): number {
  // Convert the first 4 bytes of the serverUrlHash into a port offset
  const offset = parseInt(serverUrlHash.substring(0, 4), 16)
  // Pick a consistent but random-seeming port from 3335 to 49151
  return 3335 + (offset % 45816)
}


/**
 * Parses command line arguments for MCP clients and proxies
 * @param args Command line arguments
 * @param usage Usage message to show on error
 * @returns A promise that resolves to an object with parsed serverUrl, callbackPort and headers
 */
export async function parseCommandLineArgs(args: string[], usage: string) {
  // Process headers
  const headers: Record<string, string> = {}
  let i = 0
  while (i < args.length) {
    if (args[i] === '--header' && i < args.length - 1) {
      const value = args[i + 1]
      const match = value.match(/^([A-Za-z0-9_-]+):\s*(.*)$/)
      if (match) {
        headers[match[1]] = match[2]
      } else {
        log(`Warning: ignoring invalid header argument: ${value}`)
      }
      args.splice(i, 2)
      // Do not increment i, as the array has shifted
      continue
    }
    i++
  }

  const serverUrl = args[0]
  const specifiedPort = args[1] ? parseInt(args[1]) : undefined
  const allowHttp = args.includes('--allow-http')

  // Check for debug flag
  const debug = args.includes('--debug')
  if (debug) {
    DEBUG = true
    log('Debug mode enabled - detailed logs will be written to ~/.mcp-auth/')
  }

  const enableProxy = args.includes('--enable-proxy')
  if (enableProxy) {
    // Use env proxy
    setGlobalDispatcher(new EnvHttpProxyAgent())
    log('HTTP proxy support enabled - using system HTTP_PROXY/HTTPS_PROXY environment variables')
  }

  // Parse transport strategy
  let transportStrategy: TransportStrategy = 'http-first' // Default
  const transportIndex = args.indexOf('--transport')
  if (transportIndex !== -1 && transportIndex < args.length - 1) {
    const strategy = args[transportIndex + 1]
    if (strategy === 'sse-only' || strategy === 'http-only' || strategy === 'sse-first' || strategy === 'http-first') {
      transportStrategy = strategy as TransportStrategy
      log(`Using transport strategy: ${transportStrategy}`)
    } else {
      log(`Warning: Ignoring invalid transport strategy: ${strategy}. Valid values are: sse-only, http-only, sse-first, http-first`)
    }
  }

  // Parse host
  let host = 'localhost' // Default
  const hostIndex = args.indexOf('--host')
  if (hostIndex !== -1 && hostIndex < args.length - 1) {
    host = args[hostIndex + 1]
    log(`Using callback hostname: ${host}`)
  }

  let staticOAuthClientMetadata: StaticOAuthClientMetadata = null
  const staticOAuthClientMetadataIndex = args.indexOf('--static-oauth-client-metadata')
  if (staticOAuthClientMetadataIndex !== -1 && staticOAuthClientMetadataIndex < args.length - 1) {
    const staticOAuthClientMetadataArg = args[staticOAuthClientMetadataIndex + 1]
    if (staticOAuthClientMetadataArg.startsWith('@')) {
      const filePath = staticOAuthClientMetadataArg.slice(1)
      staticOAuthClientMetadata = JSON.parse(await readFile(filePath, 'utf8'))
      log(`Using static OAuth client metadata from file: ${filePath}`)
    } else {
      staticOAuthClientMetadata = JSON.parse(staticOAuthClientMetadataArg)
      log(`Using static OAuth client metadata from string`)
    }
  }

  // parse static OAuth client information, if provided
  // defaults to OAuth dynamic client registration
  let staticOAuthClientInfo: StaticOAuthClientInformationFull = null
  const staticOAuthClientInfoIndex = args.indexOf('--static-oauth-client-info')
  if (staticOAuthClientInfoIndex !== -1 && staticOAuthClientInfoIndex < args.length - 1) {
    const staticOAuthClientInfoArg = args[staticOAuthClientInfoIndex + 1]
    if (staticOAuthClientInfoArg.startsWith('@')) {
      const filePath = staticOAuthClientInfoArg.slice(1)
      staticOAuthClientInfo = JSON.parse(await readFile(filePath, 'utf8'))
      log(`Using static OAuth client information from file: ${filePath}`)
    } else {
      staticOAuthClientInfo = JSON.parse(staticOAuthClientInfoArg)
      log(`Using static OAuth client information from string`)
    }
  }

  // Parse resource to authorize
  let authorizeResource = '' // Default
  const resourceIndex = args.indexOf('--resource')
  if (resourceIndex !== -1 && resourceIndex < args.length - 1) {
    authorizeResource = args[resourceIndex + 1]
    log(`Using authorize resource: ${authorizeResource}`)
  }

  // Parse ignored tools
  const ignoredTools: string[] = []
  let j = 0
  while (j < args.length) {
    if (args[j] === '--ignore-tool' && j < args.length - 1) {
      const toolName = args[j + 1]
      ignoredTools.push(toolName)
      log(`Ignoring tool: ${toolName}`)
      args.splice(j, 2)
      // Do not increment j, as the array has shifted
      continue
    }
    j++
  }

  // Parse auth timeout
  let authTimeoutMs = 30000 // Default 30 seconds
  const authTimeoutIndex = args.indexOf('--auth-timeout')
  if (authTimeoutIndex !== -1 && authTimeoutIndex < args.length - 1) {
    const timeoutSeconds = parseInt(args[authTimeoutIndex + 1], 10)
    if (!isNaN(timeoutSeconds) && timeoutSeconds > 0) {
      authTimeoutMs = timeoutSeconds * 1000
      log(`Using auth callback timeout: ${timeoutSeconds} seconds`)
    } else {
      log(`Warning: Ignoring invalid auth timeout value: ${args[authTimeoutIndex + 1]}. Must be a positive number.`)
    }
  }

  if (!serverUrl) {
    log(usage)
    process.exit(1)
  }

  const url = new URL(serverUrl)
  const isLocalhost = (url.hostname === 'localhost' || url.hostname === '127.0.0.1') && url.protocol === 'http:'

  if (!(url.protocol == 'https:' || isLocalhost || allowHttp)) {
    log('Error: Non-HTTPS URLs are only allowed for localhost or when --allow-http flag is provided')
    log(usage)
    process.exit(1)
  }
  const serverUrlHash = getServerUrlHash(serverUrl)

  // Set server hash globally for debug logging
  global.currentServerUrlHash = serverUrlHash

  debugLog(`Starting mcp-remote with server URL: ${serverUrl}`)

  const defaultPort = calculateDefaultPort(serverUrlHash)

  // Use the specified port, or the existing client port or fallback to find an available one
  const [existingClientPort, availablePort] = await Promise.all([findExistingClientPort(serverUrlHash), findAvailablePort(defaultPort)])
  let callbackPort: number

  if (specifiedPort) {
    if (existingClientPort && specifiedPort !== existingClientPort) {
      log(
        `Warning! Specified callback port of ${specifiedPort}, which conflicts with existing client registration port ${existingClientPort}. Deleting existing client data to force reregistration.`,
      )
      await rm(getConfigFilePath(serverUrlHash, 'client_info.json'))
    }
    log(`Using specified callback port: ${specifiedPort}`)
    callbackPort = specifiedPort
  } else if (existingClientPort) {
    log(`Using existing client port: ${existingClientPort}`)
    callbackPort = existingClientPort
  } else {
    log(`Using automatically selected callback port: ${availablePort}`)
    callbackPort = availablePort
  }

  if (Object.keys(headers).length > 0) {
    log(`Using custom headers: ${JSON.stringify(headers)}`)
  }
  // Replace environment variables in headers
  // example `Authorization: Bearer ${TOKEN}` will read process.env.TOKEN
  for (const [key, value] of Object.entries(headers)) {
    headers[key] = value.replace(/\$\{([^}]+)}/g, (match, envVarName) => {
      const envVarValue = process.env[envVarName]

      if (envVarValue !== undefined) {
        log(`Replacing ${match} with environment value in header '${key}'`)
        return envVarValue
      } else {
        log(`Warning: Environment variable '${envVarName}' not found for header '${key}'.`)
        return ''
      }
    })
  }

  return {
    serverUrl,
    callbackPort,
    headers,
    transportStrategy,
    host,
    debug,
    staticOAuthClientMetadata,
    staticOAuthClientInfo,
    authorizeResource,
    ignoredTools,
    authTimeoutMs,
  }
}
