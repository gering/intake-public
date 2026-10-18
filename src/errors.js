export class IntakeError extends Error {
  constructor(code, status = 400) {
    super(code);
    this.code = code;
    this.status = status;
  }
}

export function unavailable() {
  return new IntakeError('ticket_unavailable', 400);
}

export function assertNonRoot() {
  if (process.getuid?.() === 0) {
    throw new IntakeError('non_root_user_required');
  }
}
