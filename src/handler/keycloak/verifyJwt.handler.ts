import { KeycloakClient } from "../..";
import { BaseHandler } from "../../utils/handler";
import jwt from "jsonwebtoken";

export class VerifyJwtHandler extends BaseHandler {
    constructor(private kcClient: KeycloakClient) {
      super();
    }
  
    async handle(params: any) {
      const { token } = params;

      let publicKey
      try {
        publicKey = await this.kcClient.getJwtPublicKey() || ""        
      } catch (error) {
        return { success: false, code: 400, data: [], message: "could not get jwt public key for verification" };
      }
  
      try {
        const algo: any = this.kcClient.getJwtAlgo();
        const decoded = jwt.verify(token, publicKey, {
          algorithms: [algo],
        });
  
        params.decoded = decoded;
      } catch (error) {
        console.log(error);
        
        return { success: false, code: 400, data: [], message: String(error) };
      }
  
      const nextHandlerResponse = await this.callNextHandler(params);
      nextHandlerResponse.data["decoded"] = params.decoded;
      return nextHandlerResponse;
    }
  }
  