import axios from "axios";
import qs from "querystring";

import { KeycloakClient } from "../..";
import { BaseHandler } from "../../utils/handler";

export class CheckRefreshTokenExpiredHandler extends BaseHandler {
  constructor(private kcClient: KeycloakClient) {
    super();
  }
  async handle(params: any) {
    const creds = this.kcClient.getCredentials();
    const kcUrl = this.kcClient.getKeycloakUrl();
    const tokenUrl = `${kcUrl}/protocol/openid-connect/token`;

    if (!this.kcClient.isRefreshTokenExpired()) {
      return { success: true, code: 200, data: [], message: 'refresh token is valid' }
    }
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

    params.config = config

    const nextHandlerResponse = await this.callNextHandler(params);
    return nextHandlerResponse;
  }
}

export class RequestAccessAndRefreshTokenHandler extends BaseHandler {
  constructor(private kcClient: KeycloakClient) {
    super();
  }
  async handle(params: any) {
    const { config } = params

    try {
      const response = await axios.request(config)
      this.kcClient.setAccessToken(response.data.access_token);
      this.kcClient.setRefreshToken(response.data.refresh_token);
      this.kcClient.setExpiresIn(response.data.expires_in);
      this.kcClient.setRefreshTokenExpiresIn(response.data.refresh_expires_in);
      this.kcClient.setAccessTokenInit(Date.now());
      this.kcClient.setRefreshTokenInit(Date.now());
    } catch (error) {
      this.kcClient.setAccessToken("");
      this.kcClient.setRefreshToken("");
      return { success: false, code: 400, message: 'server request failed for refresh token', data: [] }
    }

    const nextHandlerResponse = await this.callNextHandler(params);
    return nextHandlerResponse;
  }
}
