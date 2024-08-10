import { KeycloakClient } from "../..";
import { BaseHandler } from "../../utils/handler";

export class GetJwtPublicKeyHandler extends BaseHandler {
    constructor(private kcClient: KeycloakClient) {
      super();
    }
  
    async handle(params: any) {
      let certs: any[] = []
      try {
        certs = await this.kcClient.getCerts();
      } catch (error) {
        return { success: false, code: 400, data: [], message: "failed to fetch certs: " + String(error) };        
      }

      const jwtAlgo = this.kcClient.getJwtAlgo()
      const cert = certs.find((cert: any) => cert.alg == jwtAlgo);
      if (!cert) {
        return { success: false, code: 404, data: [], message: "cert not found" };        
      }
  
      const publicKey = `-----BEGIN CERTIFICATE-----\n${cert.x5c[0]}\n-----END CERTIFICATE-----`;
      this.kcClient.setPublicKey(publicKey);
  
      const nextHandlerResponse = await this.callNextHandler(params);
      return nextHandlerResponse;
    }
  }