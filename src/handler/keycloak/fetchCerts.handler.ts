import axios from "axios";
import { KeycloakClient } from "../..";
import { BaseHandler } from "../../utils/handler";

export class FetchCertsHandler extends BaseHandler {
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