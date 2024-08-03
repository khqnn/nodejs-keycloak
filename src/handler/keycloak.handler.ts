import jwt from "jsonwebtoken";
import axios from "axios";
import qs from "querystring";

import { BaseHandler } from "../utils/handler";
import { KeycloakClient } from "..";

export class TestHandler extends BaseHandler {
  async handle(params: any) {
    const nextHandlerResponse = await this.callNextHandler(params);
    return nextHandlerResponse;
  }
}

export class VerifyJwt extends BaseHandler {
  constructor(private kcClient: KeycloakClient) {
    super();
  }

  async handle(params: any) {
    const { token } = params;

    try {
      const publicKey = await this.kcClient.getJwtPublicKey();
      const algo: any = this.kcClient.jwt_algo;
      const decoded = jwt.verify(token, publicKey, {
        algorithms: [algo],
      });

      params.decoded = decoded;
    } catch (error) {
      return { success: false, code: 400, data: [], message: String(error) };
    }

    const nextHandlerResponse = await this.callNextHandler(params);
    nextHandlerResponse.data["decoded"] = params.decoded;
    return nextHandlerResponse;
  }
}

export class FetchCerts extends BaseHandler {
  constructor(private kcClient: KeycloakClient) {
    super();
  }

  async handle(params: any) {
    const kcUrl = this.kcClient.getKeycloakUrl();
    const url = `${kcUrl}/protocol/openid-connect/certs`;

    if (this.kcClient.isCertRequired()) {
      try {
        const response = await axios.get(url);
        this.kcClient.setCerts(response.data.keys);
        this.kcClient.setCertFetchedAt(Date.now());
      } catch (error) {
        this.kcClient.setCerts([]);
        return {
          success: false,
          code: 400,
          data: [],
          message: "could not fetch certs",
        };
      }
    }

    const nextHandlerResponse = await this.callNextHandler(params);
    return nextHandlerResponse;
  }
}

export class GetJwtPublicKey extends BaseHandler {
  constructor(private kcClient: KeycloakClient) {
    super();
  }

  async handle(params: any) {
    const certs = await this.kcClient.getCerts();
    const cert = certs.find((cert: any) => cert.alg == this.kcClient.jwt_algo);
    if (!cert) {
      return { success: false, code: 404, data: [], message: "cert not found" };
    }

    const publicKey = `-----BEGIN CERTIFICATE-----\n${cert.x5c[0]}\n-----END CERTIFICATE-----`;
    this.kcClient.setPublicKey(publicKey);

    const nextHandlerResponse = await this.callNextHandler(params);
    return nextHandlerResponse;
  }
}

export class RequestAccessTokenFromRefreshToken extends BaseHandler {
  constructor(private kcClient: KeycloakClient) {
    super();
  }

  async handle(params: any) {
    const refreshToken = await this.kcClient.getRefreshToken();

    if (this.kcClient.isAccessTokenExpired()) {
      const creds = this.kcClient.getCredentials();
      const kcUrl = this.kcClient.getKeycloakUrl();
      const tokenUrl = `${kcUrl}/protocol/openid-connect/token`;

      const data = qs.stringify({
        grant_type: "refresh_token",
        client_id: creds.client_id,
        refresh_token: refreshToken,
      });

      const config = {
        method: "post",
        maxBodyLength: Infinity,
        url: tokenUrl,
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
        data: data,
      };

      const response: any = await new Promise((resolve, reject) => {
        axios
          .request(config)
          .then((response) => {
            resolve({ success: true, code: 200, data: response.data });
          })
          .catch((error) => {
            resolve({ success: false, code: 400, message: error.message });
          });
      });

      if (response.success) {
        this.kcClient.setAccessToken(response.data.access_token);
        this.kcClient.setRefreshToken(response.data.refresh_token);
        this.kcClient.setExpiresIn(response.data.expires_in);
        this.kcClient.setRefreshTokenExpiresIn(
          response.data.refresh_expires_in
        );
        this.kcClient.setAccessTokenInit(Date.now());
        this.kcClient.setRefreshTokenInit(Date.now());
      }

      return response;
    }

    const nextHandlerResponse = await this.callNextHandler(params);
    return nextHandlerResponse;
  }
}

export class RequestAccessAndRefreshToken extends BaseHandler {
  constructor(private kcClient: KeycloakClient) {
    super();
  }
  async handle(params: any) {
    const creds = this.kcClient.getCredentials();
    const kcUrl = this.kcClient.getKeycloakUrl();
    const tokenUrl = `${kcUrl}/protocol/openid-connect/token`;

    if (this.kcClient.isRefreshTokenExpired()) {
      const data = qs.stringify({
        grant_type: "password",
        username: creds.username,
        password: creds.password,
        client_id: creds.client_id,
      });

      const config = {
        method: "post",
        maxBodyLength: Infinity,
        url: tokenUrl,
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
        data: data,
      };

      const response: any = await new Promise((resolve, reject) => {
        axios
          .request(config)
          .then((response) => {
            resolve({ success: true, code: 200, data: response.data });
          })
          .catch((error) => {
            resolve({ success: false, code: 400, message: error.message });
          });
      });

      if (!response.success) {
        return response;
      }

      this.kcClient.setAccessToken(response.data.access_token);
      this.kcClient.setRefreshToken(response.data.refresh_token);
      this.kcClient.setExpiresIn(response.data.expires_in);
      this.kcClient.setRefreshTokenExpiresIn(response.data.refresh_expires_in);
      this.kcClient.setAccessTokenInit(Date.now());
      this.kcClient.setRefreshTokenInit(Date.now());
    }
    const nextHandlerResponse = await this.callNextHandler(params);
    return nextHandlerResponse;
  }
}
