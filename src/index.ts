import {
  FetchCerts,
  GetJwtPublicKey,
  RequestAccessAndRefreshToken,
  RequestAccessTokenFromRefreshToken,
  VerifyJwt,
} from "./handler/keycloak.handler";
import { createChain } from "./utils/handler";

export class KeycloakClient {
  private realm: string | undefined;
  private url: string | undefined;
  private username: string | undefined;
  private password: string | undefined;
  private client_id: string | undefined;

  public init_success: boolean = false;
  private access_token: string | undefined;
  private refresh_token: string | undefined;
  private expires_in: number = 0;
  private refresh_expires_in: number = 0;
  private access_token_init = 0;
  private refresh_token_init = 0;

  public jwt_algo: string = "RS256";
  private certs: any[] = [];
  private certs_fetched_at = 0;
  private certs_fetch_wait_time = 1800;
  private jwt_public_key: string = "";
  constructor(params: any) {
    this.realm = params.realm;
    this.url = params.url;
    this.username = params.username;
    this.password = params.password;
    this.client_id = params.client_id;

    if (params.jwtAlgo) {
      this.jwt_algo = params.jwtAlgo;
    }
  }

  async init() {
    return await createChain([new RequestAccessAndRefreshToken(this)]).handle(
      {}
    );
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
    await createChain([new RequestAccessTokenFromRefreshToken(this)]).handle(
      {}
    );

    return this.access_token;
  }

  async getRefreshToken() {
    await createChain([new RequestAccessAndRefreshToken(this)]).handle({});

    return this.refresh_token;
  }

  async getCerts() {
    await createChain([new FetchCerts(this)]).handle({});
    return this.certs;
  }

  async getJwtPublicKey() {
    await createChain([new GetJwtPublicKey(this)]).handle({});
    return this.jwt_public_key;
  }

  async verifyJwt(token: string) {
    return await createChain([new VerifyJwt(this)]).handle({ token });
  }

  async createRealm() {
    return await this.getAccessToken();
  }
}
