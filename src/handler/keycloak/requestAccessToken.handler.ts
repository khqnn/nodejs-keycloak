import axios from "axios";
import qs from "querystring";

import { KeycloakClient } from "../..";
import { BaseHandler } from "../../utils/handler";


export class CheckAccessTokenExpiryHandler extends BaseHandler {
  constructor(private kcClient: KeycloakClient) {
    super();
  }

  async handle(params: any) {
    let refreshToken
    try {
      refreshToken = await this.kcClient.getRefreshToken() || ""
    } catch (error) {
      return { success: false, code: 400, data: [], message: 'Failed to get refresh token' }
    }

    if (!this.kcClient.isAccessTokenExpired()) {
      return { success: true, code: 200, data: [], message: 'access token is valid' }
    }

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

    params.config = config

    const nextHandlerResponse = await this.callNextHandler(params);
    return nextHandlerResponse;
  }
}


export class RequestAccessTokenFromRefreshTokenHandler extends BaseHandler {
  constructor(private kcClient: KeycloakClient) {
    super();
  }

  async handle(params: any) {

    const {config} = params

      try {
        const response = await axios.request(config)
        this.kcClient.setAccessToken(response.data.access_token);
        this.kcClient.setRefreshToken(response.data.refresh_token);
        this.kcClient.setExpiresIn(response.data.expires_in);
        this.kcClient.setRefreshTokenExpiresIn(
          response.data.refresh_expires_in
        );
        this.kcClient.setAccessTokenInit(Date.now());
        this.kcClient.setRefreshTokenInit(Date.now());
      } catch (error) {
        this.kcClient.setAccessToken("");
        this.kcClient.setRefreshToken("");

        return { success: false, code: 400, data: [], message: 'Server request failed for access token' }
      }


    const nextHandlerResponse = await this.callNextHandler(params);
    return nextHandlerResponse;
  }
}