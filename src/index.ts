
import { FetchCertsHandler } from "./handler/keycloak/fetchCerts.handler";
import { GetJwtPublicKeyHandler } from "./handler/keycloak/getJwtPublicKey.handler";
import { CheckAccessTokenExpiryHandler, RequestAccessTokenFromRefreshTokenHandler } from "./handler/keycloak/requestAccessToken.handler";
import { CheckRefreshTokenExpiredHandler, RequestAccessAndRefreshTokenHandler } from "./handler/keycloak/requestRefreshToken.handler";
import { VerifyJwtHandler } from "./handler/keycloak/verifyJwt.handler";
import { createChain } from "./utils/handler";

export class KeycloakClient {
  private realm: string | undefined;
  private url: string | undefined;
  private username: string | undefined;
  private password: string | undefined;
  private client_id: string | undefined;

  private access_token: string | undefined;
  private refresh_token: string | undefined;
  private expires_in: number = 0;
  private refresh_expires_in: number = 0;
  private access_token_init = 0;
  private refresh_token_init = 0;

  private jwt_algo: string = "RS256";
  private certs: any[] = [];
  private certs_fetched_at = 0;
  private certs_fetch_wait_time = 1800;
  private jwt_public_key: string = "";
  
  constructor(params: any) {
    this.realm = params.realm;
    this.url = params.serverUrl;
    this.username = params.username;
    this.password = params.password;
    this.client_id = params.client_id;

    if (params.jwtAlgo) {
      this.jwt_algo = params.jwtAlgo;
    }
  }

  getKeycloakUrl() {
    return `${this.url}/realms/${this.realm}`;
  }

  getCredentials() {
    return {
      username: this.username,
      password: this.password,
      client_id: this.client_id,
      realm: this.realm,
    };
  }

  setExpiresIn(expires_in: number) {
    this.expires_in = expires_in;
  }
  setRefreshTokenExpiresIn(expires_in: number) {
    this.refresh_expires_in = expires_in;
  }
  setAccessTokenInit(init: number) {
    this.access_token_init = init;
  }
  setRefreshTokenInit(init: number) {
    this.refresh_token_init = init;
  }

  setAccessToken(token: string) {
    this.access_token = token;
  }

  setRefreshToken(token: string) {
    this.refresh_token = token;
  }

  getJwtAlgo(){
    return this.jwt_algo
  }
  setJwtAlgo(alog: string){
    this.jwt_algo = alog
  }
  setCertFetchedAt(fetched_at: number) {
    this.certs_fetched_at = fetched_at;
  }
  setCerts(certs: any[]) {
    this.certs = certs;
  }
  setPublicKey(publicKey: string) {
    this.jwt_public_key = publicKey;
  }

  isCertRequired() {
    const et = Date.now() - this.certs_fetched_at;
    return et > this.certs_fetch_wait_time;
  }

  isAccessTokenExpired() {
    const et = Date.now() - this.expires_in;
    return et > this.access_token_init;
  }

  isRefreshTokenExpired() {
    const et = Date.now() - this.refresh_expires_in;
    return et > this.refresh_token_init;
  }

  async getAccessToken() {
    const { success, message } = await createChain([
      new CheckAccessTokenExpiryHandler(this),
      new RequestAccessTokenFromRefreshTokenHandler(this),
    ]).handle({});
    if (!success) {
      throw new Error(message || "Failed to get access token");
    }
    return this.access_token;
  }

  async getRefreshToken() {
    const { success, message } = await createChain([
      new CheckRefreshTokenExpiredHandler(this),
      new RequestAccessAndRefreshTokenHandler(this),
    ]).handle({});
    if (!success) {
      throw new Error(message || "Failed to get refresh token");
    }

    return this.refresh_token;
  }

  async getCerts() {
    const { success, message } = await createChain([
      new FetchCertsHandler(this),
    ]).handle({});
    if (!success) {
      throw new Error(message || "Failed to get certs");
    }
    return this.certs;
  }

  async getJwtPublicKey() {
    const { success, message } = await createChain([
      new GetJwtPublicKeyHandler(this),
    ]).handle({});
    if (!success) {
      throw new Error(message || "Failed to get jwt public key");
    }
    return this.jwt_public_key;
  }

  async verifyJwt(token: string) {
    const { success, message, data } = await createChain([
      new VerifyJwtHandler(this),
    ]).handle({ token });
    if (!success) {
      throw new Error(message || "Could not verify jwt");
    }
    return data.decoded;
  }

  async createRealm() {
    return await this.getAccessToken();
  }
}