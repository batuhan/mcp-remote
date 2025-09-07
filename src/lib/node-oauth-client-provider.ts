import open from 'open'
import { OAuthClientProvider } from '@modelcontextprotocol/sdk/client/auth.js'
import {
  OAuthClientInformationFull,
  OAuthClientInformationFullSchema,
  OAuthTokens,
  OAuthTokensSchema,
} from '@modelcontextprotocol/sdk/shared/auth.js'
import type { OAuthProviderOptions, StaticOAuthClientMetadata } from './types'
import { readJsonFile, writeJsonFile, readTextFile, writeTextFile, deleteConfigFile } from './mcp-auth-config'
import { StaticOAuthClientInformationFull } from './types'
import { getServerUrlHash, log, debugLog, MCP_REMOTE_VERSION } from './utils'
import { sanitizeUrl } from 'strict-url-sanitise'
import { randomUUID } from 'node:crypto'

/**
 * Implements the OAuthClientProvider interface for Node.js environments.
 * Handles OAuth flow and token storage for MCP clients.
 */
export class NodeOAuthClientProvider implements OAuthClientProvider {
  private serverUrlHash: string
  private callbackPath: string
  private clientName: string
  private clientUri: string
  private softwareId: string
  private softwareVersion: string
  private staticOAuthClientMetadata: StaticOAuthClientMetadata
  private staticOAuthClientInfo: StaticOAuthClientInformationFull
  private authorizeResource: string | undefined
  private _state: string

  /**
   * Creates a new NodeOAuthClientProvider
   * @param options Configuration options for the provider
   */
  constructor(readonly options: OAuthProviderOptions) {
    this.serverUrlHash = getServerUrlHash(options.serverUrl)
    this.callbackPath = options.callbackPath || '/oauth/callback'
    this.clientName = options.clientName || 'MCP CLI Client'
    this.clientUri = options.clientUri || 'https://github.com/modelcontextprotocol/mcp-cli'
    this.softwareId = options.softwareId || '2e6dc280-f3c3-4e01-99a7-8181dbd1d23d'
    this.softwareVersion = options.softwareVersion || MCP_REMOTE_VERSION
    this.staticOAuthClientMetadata = options.staticOAuthClientMetadata
    this.staticOAuthClientInfo = options.staticOAuthClientInfo
    this.authorizeResource = options.authorizeResource
    this._state = randomUUID()
  }

  get redirectUrl(): string {
    return `http://${this.options.host}:${this.options.callbackPort}${this.callbackPath}`
  }

  get clientMetadata() {
    return {
      redirect_uris: [this.redirectUrl],
      token_endpoint_auth_method: 'none',
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      client_name: this.clientName,
      client_uri: this.clientUri,
      software_id: this.softwareId,
      software_version: this.softwareVersion,
      ...this.staticOAuthClientMetadata,
    }
  }

  state(): string {
    return this._state
  }

  /**
   * Gets the client information if it exists
   * @returns The client information or undefined
   */
  async clientInformation(): Promise<OAuthClientInformationFull | undefined> {
    debugLog('🔍 CLIENT_INFORMATION CALLED', {
      serverUrlHash: this.serverUrlHash,
      hasStaticInfo: !!this.staticOAuthClientInfo,
      caller: new Error().stack?.split('\n')[2],
    })
    if (this.staticOAuthClientInfo) {
      debugLog('📦 RETURNING STATIC CLIENT INFO', {
        client_id: this.staticOAuthClientInfo.client_id,
      })
      return this.staticOAuthClientInfo
    }
    const clientInfo = await readJsonFile<OAuthClientInformationFull>(
      this.serverUrlHash,
      'client_info.json',
      OAuthClientInformationFullSchema,
    )
    debugLog('📄 CLIENT INFO FROM DISK', {
      found: !!clientInfo,
      client_id: clientInfo?.client_id,
    })
    return clientInfo
  }

  /**
   * Saves client information
   * @param clientInformation The client information to save
   */
  async saveClientInformation(clientInformation: OAuthClientInformationFull): Promise<void> {
    debugLog('💾 SAVE_CLIENT_INFORMATION', {
      client_id: clientInformation.client_id,
      serverUrlHash: this.serverUrlHash,
      caller: new Error().stack?.split('\n')[2],
    })
    await writeJsonFile(this.serverUrlHash, 'client_info.json', clientInformation)
    debugLog('✅ CLIENT INFO SAVED', { client_id: clientInformation.client_id })
  }

  /**
   * Gets the OAuth tokens if they exist
   * @returns The OAuth tokens or undefined
   */
  async tokens(): Promise<OAuthTokens | undefined> {
    const tokenCallId = randomUUID().substring(0, 8)
    debugLog('🔑 TOKENS() CALLED', {
      tokenCallId,
      serverUrlHash: this.serverUrlHash,
      caller: new Error().stack?.split('\n').slice(2, 4).join(' <- '),
    })

    const tokens = await readJsonFile<OAuthTokens>(this.serverUrlHash, 'tokens.json', OAuthTokensSchema)

    if (tokens) {
      const timeLeft = tokens.expires_in || 0

      // Alert if expires_in is invalid
      if (typeof tokens.expires_in !== 'number' || tokens.expires_in < 0) {
        debugLog('⚠️ WARNING: Invalid expires_in detected while reading tokens ⚠️', {
          tokenCallId,
          expiresIn: tokens.expires_in,
          tokenObject: JSON.stringify(tokens),
          stack: new Error('Invalid expires_in value').stack,
        })
      }

      debugLog('🎫 TOKENS FOUND', {
        tokenCallId,
        hasAccessToken: !!tokens.access_token,
        accessTokenPrefix: tokens.access_token?.substring(0, 10) + '...',
        hasRefreshToken: !!tokens.refresh_token,
        expiresIn: `${timeLeft} seconds`,
        isExpired: timeLeft <= 0,
        expiresInValue: tokens.expires_in,
      })
    } else {
      debugLog('🚫 NO TOKENS FOUND', { tokenCallId })
    }

    return tokens
  }

  /**
   * Saves OAuth tokens
   * @param tokens The tokens to save
   */
  async saveTokens(tokens: OAuthTokens): Promise<void> {
    const saveId = randomUUID().substring(0, 8)
    const timeLeft = tokens.expires_in || 0

    // Alert if expires_in is invalid
    if (typeof tokens.expires_in !== 'number' || tokens.expires_in < 0) {
      debugLog('⚠️ WARNING: Invalid expires_in detected in tokens ⚠️', {
        saveId,
        expiresIn: tokens.expires_in,
        tokenObject: JSON.stringify(tokens),
        stack: new Error('Invalid expires_in value').stack,
      })
    }

    debugLog('💾 SAVE_TOKENS CALLED', {
      saveId,
      serverUrlHash: this.serverUrlHash,
      hasAccessToken: !!tokens.access_token,
      accessTokenPrefix: tokens.access_token?.substring(0, 10) + '...',
      hasRefreshToken: !!tokens.refresh_token,
      expiresIn: `${timeLeft} seconds`,
      expiresInValue: tokens.expires_in,
      caller: new Error().stack?.split('\n')[2],
    })

    await writeJsonFile(this.serverUrlHash, 'tokens.json', tokens)
    debugLog('✅ TOKENS SAVED TO DISK', { saveId })
  }

  /**
   * Redirects the user to the authorization URL
   * @param authorizationUrl The URL to redirect to
   */
  async redirectToAuthorization(authorizationUrl: URL): Promise<void> {
    if (this.authorizeResource) {
      authorizationUrl.searchParams.set('resource', this.authorizeResource)
    }

    log(`\nPlease authorize this client by visiting:\n${authorizationUrl.toString()}\n`)

    debugLog('🌐 REDIRECT_TO_AUTHORIZATION', {
      url: authorizationUrl.toString(),
      hasResource: !!this.authorizeResource,
      resource: this.authorizeResource,
      state: authorizationUrl.searchParams.get('state'),
      redirect_uri: authorizationUrl.searchParams.get('redirect_uri'),
      response_type: authorizationUrl.searchParams.get('response_type'),
      client_id: authorizationUrl.searchParams.get('client_id'),
      code_challenge: authorizationUrl.searchParams.get('code_challenge')?.substring(0, 10) + '...',
      code_challenge_method: authorizationUrl.searchParams.get('code_challenge_method'),
    })

    try {
      await open(sanitizeUrl(authorizationUrl.toString()))
      log('Browser opened automatically.')
    } catch (error) {
      log('Could not open browser automatically. Please copy and paste the URL above into your browser.')
      debugLog('Failed to open browser', error)
    }
  }

  /**
   * Saves the PKCE code verifier
   * @param codeVerifier The code verifier to save
   */
  async saveCodeVerifier(codeVerifier: string): Promise<void> {
    debugLog('🔐 SAVE_CODE_VERIFIER', {
      serverUrlHash: this.serverUrlHash,
      verifierLength: codeVerifier.length,
      verifierPrefix: codeVerifier.substring(0, 10) + '...',
    })
    await writeTextFile(this.serverUrlHash, 'code_verifier.txt', codeVerifier)
    debugLog('✅ CODE VERIFIER SAVED', { serverUrlHash: this.serverUrlHash })
  }

  /**
   * Gets the PKCE code verifier
   * @returns The code verifier
   */
  async codeVerifier(): Promise<string> {
    debugLog('🔍 READING CODE VERIFIER', {
      serverUrlHash: this.serverUrlHash,
      caller: new Error().stack?.split('\n')[2],
    })
    const verifier = await readTextFile(this.serverUrlHash, 'code_verifier.txt', 'No code verifier saved for session')
    debugLog('🔐 CODE VERIFIER RESULT', {
      found: !!verifier,
      verifierLength: verifier?.length,
      verifierPrefix: verifier?.substring(0, 10) + '...',
    })
    return verifier
  }

  /**
   * Invalidates the specified credentials
   * @param scope The scope of credentials to invalidate
   */
  async invalidateCredentials(scope: 'all' | 'client' | 'tokens' | 'verifier'): Promise<void> {
    debugLog('🗑️ INVALIDATE_CREDENTIALS', {
      scope,
      serverUrlHash: this.serverUrlHash,
      caller: new Error().stack?.split('\n')[2],
    })

    switch (scope) {
      case 'all':
        await Promise.all([
          deleteConfigFile(this.serverUrlHash, 'client_info.json'),
          deleteConfigFile(this.serverUrlHash, 'tokens.json'),
          deleteConfigFile(this.serverUrlHash, 'code_verifier.txt'),
        ])
        debugLog('All credentials invalidated')
        break

      case 'client':
        await deleteConfigFile(this.serverUrlHash, 'client_info.json')
        debugLog('Client information invalidated')
        break

      case 'tokens':
        await deleteConfigFile(this.serverUrlHash, 'tokens.json')
        debugLog('OAuth tokens invalidated')
        break

      case 'verifier':
        await deleteConfigFile(this.serverUrlHash, 'code_verifier.txt')
        debugLog('Code verifier invalidated')
        break

      default:
        throw new Error(`Unknown credential scope: ${scope}`)
    }
  }
}
