export class HttpError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly retryable = false,
    readonly requiredActionId: string | null = null,
  ) {
    super(message);
    this.name = "HttpError";
  }
}
