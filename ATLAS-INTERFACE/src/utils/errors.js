// Turns a backend error code into text a person can act on. Falls back to the server's own message.
export function describeAuthError(err) {
  switch (err?.code) {
    case 'invalid_credentials': return 'Incorrect username or password.';
    case 'invalid_mfa': return 'That one-time code was not accepted. Check the code and try again.';
    case 'mfa_required': return 'Enter the 6-digit code from your authenticator app.';
    case 'account_locked': {
      const mins = Math.ceil((err.details?.retry_after_seconds ?? 900) / 60);
      return `Too many failed attempts. This account is locked; try again in about ${mins} minute${mins === 1 ? '' : 's'}.`;
    }
    case 'rate_limited': return `Too many requests. Wait ${err.details?.retry_after_seconds ?? err.retryAfter ?? 'a few'} seconds and try again.`;
    case 'network': return err.message;
    case 'timeout': return 'The server did not answer in time. Try again.';
    default: return err?.message || 'Sign-in failed.';
  }
}

// Messages for errors a user can cause while editing data.
export function describeActionError(err) {
  switch (err?.code) {
    case 'authorization_edit_forbidden': return 'Only an approver or administrator can change authorization details.';
    case 'insufficient_target_permission': return 'Only the person who registered this target, or an administrator, can change it.';
    case 'forbidden': return 'Your role does not allow this action.';
    case 'not_found': return 'This item does not exist, or you do not have access to it.';
    case 'conflict': return 'An item with the same name already exists.';
    case 'authorization_required': return 'The target has no valid authorization record. Add or renew it before activating an assessment.';
    case 'scope_required': return 'Add at least one permitted scope rule before activating.';
    case 'invalid_transition': return 'That status change is not allowed from the current status.';
    case 'invalid_scope_rule': return err.message;
    case 'insufficient_assessment_permission': return 'Your permission on this assessment does not allow this action.';
    case 'owner_immutable': return 'The owner’s access cannot be changed or removed.';
    case 'scope_violation': return err.message;
    case 'session_expired': return 'Your session expired. Please sign in again.';
    default: return err?.message || 'Something went wrong.';
  }
}
