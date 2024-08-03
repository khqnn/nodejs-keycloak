export abstract class BaseHandler {
  nextHandler?: BaseHandler;

  async callNextHandler(
    params: any
  ): Promise<{
    success: boolean;
    code: number;
    data: any;
    message: string | null;
  }> {
    if (this.nextHandler) {
      return await this.nextHandler.handle(params);
    }
    return { success: true, code: 200, data: {}, message: "" };
  }

  abstract handle(
    params: any
  ): Promise<{
    success: boolean;
    code: number;
    data: any;
    message: string | null;
  }>;
}

export const createChain = (handlers: BaseHandler[]) => {
  const n = handlers.length;
  for (let i = 1; i < n; i++) {
    handlers[i - 1].nextHandler = handlers[i];
  }

  return handlers[0];
};
