/**
 * GitHub Copilot OAuth + Session Token Manager.
 *
 * Flow:
 *   1. Device-code OAuth flow → persistent OAuth token
 *   2. Exchange OAuth token → short-lived Copilot session token (~25 min)
 *   3. Auto-refresh session token before expiry
 *
 * The Copilot chat API at https://api.githubcopilot.com/chat/completions
 * is OpenAI-compatible, so ChatOpenAI from LangChain works with it.
 */

const COPILOT_CLIENT_ID = "Iv1.b507a08c87ecfe98";
const OAUTH_TOKEN_KEY = "copilot-oauth-token";
const SESSION_REFRESH_MARGIN = 2 * 60; // refresh 2 min before expiry

const DialogBox = acode.require("dialogBox");

/**
 * Use cordova-plugin-advanced-http for all HTTP requests because:
 * - Acode WebView origin is https://localhost
 * - GitHub OAuth endpoints (github.com/login/*) don't send CORS headers
 * - cordova.plugin.http makes native Java HTTP calls, bypassing CORS entirely
 */
function nativeRequest(method, url, data, headers = {}) {
  return new Promise((resolve, reject) => {
    const http = cordova.plugin.http;
    // Set serializer to json for POST with body, raw otherwise
    http.setDataSerializer(data ? "json" : "utf8");

    const success = (response) => {
      try {
        const json = typeof response.data === "string"
          ? JSON.parse(response.data)
          : response.data;
        resolve(json);
      } catch (e) {
        reject(new Error(`${method} ${url}: invalid JSON response: ${response.data}`));
      }
    };

    const failure = (response) => {
      // cordova-plugin-advanced-http puts the response body in response.error
      let json;
      try {
        json = JSON.parse(response.error);
      } catch (_) {
        json = null;
      }
      // For OAuth polling, GitHub returns 4xx with { error: "authorization_pending" }
      if (json && json.error) {
        resolve(json);
        return;
      }
      const msg = response.error || `HTTP ${response.status}`;
      const err = new Error(`${method} ${url}: ${msg}`);
      err.status = response.status;
      reject(err);
    };

    const reqHeaders = { Accept: "application/json", ...headers };

    if (method === "POST") {
      http.post(url, data || {}, reqHeaders, success, failure);
    } else {
      http.get(url, {}, reqHeaders, success, failure);
    }
  });
}

async function postJSON(url, data, headers = {}) {
  return nativeRequest("POST", url, data, headers);
}

async function getJSON(url, headers = {}) {
  return nativeRequest("GET", url, null, headers);
}

/**
 * Perform OAuth device-code flow.
 * Shows a dialog with the user code + verification URL.
 * Returns the OAuth access token.
 */
export async function deviceCodeFlow() {
  // Step 1: request device code
  const codeResp = await postJSON("https://github.com/login/device/code", {
    client_id: COPILOT_CLIENT_ID,
    scope: "read:user",
  });

  const { device_code, user_code, verification_uri, interval: pollInterval = 5, expires_in = 900 } = codeResp;

  // Show dialog with code
  return new Promise((resolve, reject) => {
    let timer = null;
    let closed = false;

    const dlg = DialogBox(
      "GitHub Copilot 授权",
      `<div style="text-align:center;padding:12px;">
        <p style="margin-bottom:8px;">请在浏览器中访问：</p>
        <p style="font-size:1.1em;"><a href="${verification_uri}" style="color:var(--link-text-color);" onclick="window.open('${verification_uri}');return false;">${verification_uri}</a></p>
        <p style="margin:12px 0 4px;">输入授权码：</p>
        <p style="font-size:1.6em;font-weight:bold;letter-spacing:4px;font-family:monospace;">${user_code}</p>
        <p style="margin-top:12px;font-size:0.85em;color:var(--secondary-text-color);">等待授权中…（${Math.floor(expires_in / 60)} 分钟内有效）</p>
      </div>`,
      "取消",
    );

    dlg.onhide = () => {
      closed = true;
      if (timer) clearInterval(timer);
      reject(new Error("用户取消了授权"));
    };

    let interval = pollInterval;
    const deadline = Date.now() + expires_in * 1000;

    timer = setInterval(async () => {
      if (closed || Date.now() > deadline) {
        clearInterval(timer);
        if (!closed) {
          dlg.hide();
          reject(new Error("授权超时"));
        }
        return;
      }
      try {
        const tokenResp = await postJSON("https://github.com/login/oauth/access_token", {
          client_id: COPILOT_CLIENT_ID,
          device_code,
          grant_type: "urn:ietf:params:oauth:grant-type:device_code",
        });

        if (tokenResp.access_token) {
          clearInterval(timer);
          closed = true;
          dlg.hide();
          resolve(tokenResp.access_token);
          return;
        }

        const error = tokenResp.error || "";
        if (error === "slow_down") {
          interval += 5;
        } else if (error === "expired_token") {
          clearInterval(timer);
          closed = true;
          dlg.hide();
          reject(new Error("授权码已过期，请重试"));
        } else if (error !== "authorization_pending") {
          clearInterval(timer);
          closed = true;
          dlg.hide();
          reject(new Error(`授权失败: ${error}`));
        }
      } catch (e) {
        // network error, just retry
      }
    }, interval * 1000);
  });
}

/**
 * Exchange OAuth token for a Copilot session token.
 * Returns { token, expires_at }.
 */
export async function getCopilotSessionToken(oauthToken) {
  const data = await getJSON("https://api.github.com/copilot_internal/v2/token", {
    Authorization: `token ${oauthToken}`,
  });
  return {
    token: data.token,
    expiresAt: data.expires_at || (Date.now() / 1000 + 25 * 60),
  };
}

/**
 * List models available on GitHub Copilot.
 */
export async function listCopilotModels(sessionToken) {
  const data = await getJSON("https://api.githubcopilot.com/models", {
    Authorization: `Bearer ${sessionToken}`,
    "Copilot-Integration-Id": "vscode-chat",
  });
  const models = Array.isArray(data) ? data : data.data || data.models || [];
  return models
    .filter((m) => m && m.id)
    .map((m) => m.id);
}

/**
 * Manages persistent OAuth token + auto-refreshing session token.
 */
export class CopilotTokenManager {
  constructor() {
    this._oauthToken = null;
    this._sessionToken = null;
    this._expiresAt = 0;
    // Auto-load cached OAuth token on construction
    this.loadCachedOAuthToken();
  }

  /** Load cached OAuth token from localStorage. */
  loadCachedOAuthToken() {
    const cached = localStorage.getItem(OAUTH_TOKEN_KEY);
    if (cached) {
      this._oauthToken = cached;
      return true;
    }
    return false;
  }

  /** Save OAuth token to localStorage. */
  saveOAuthToken(token) {
    this._oauthToken = token;
    localStorage.setItem(OAUTH_TOKEN_KEY, token);
  }

  /** Clear all tokens (on logout / re-auth). */
  clearTokens() {
    this._oauthToken = null;
    this._sessionToken = null;
    this._expiresAt = 0;
    localStorage.removeItem(OAUTH_TOKEN_KEY);
  }

  /** Get a valid session token, refreshing if needed. */
  async getSessionToken() {
    if (!this._oauthToken) {
      throw new Error("未授权 GitHub Copilot，请先登录");
    }
    const now = Date.now() / 1000;
    if (this._sessionToken && now < this._expiresAt - SESSION_REFRESH_MARGIN) {
      return this._sessionToken;
    }
    try {
      const { token, expiresAt } = await getCopilotSessionToken(this._oauthToken);
      this._sessionToken = token;
      this._expiresAt = expiresAt;
      return token;
    } catch (e) {
      if (e.status === 401) {
        this.clearTokens();
        throw new Error("GitHub OAuth token 已失效，请重新授权");
      }
      throw e;
    }
  }

  /** Perform device-code auth and save token. */
  async authorize() {
    const oauthToken = await deviceCodeFlow();
    this.saveOAuthToken(oauthToken);
    // Verify it works by getting a session token
    await this.getSessionToken();
    return true;
  }

  get isAuthorized() {
    return !!this._oauthToken;
  }
}
