
import { BaseHandler } from "../utils/handler";

export class TestHandler extends BaseHandler {
  async handle(params: any) {
    const nextHandlerResponse = await this.callNextHandler(params);
    return nextHandlerResponse;
  }
}
