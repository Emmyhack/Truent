import { TRIAL_DAYS } from '@/lib/plans'

/**
 * Fields every newly created account gets, whichever provider created it
 * (email, wallet, Civic). The trial is real: `effectivePlan` grants the
 * trial plan until this date, then the account falls to Free — never locked.
 */
export function newUserDefaults(now = new Date()) {
  return { trialEndsAt: new Date(now.getTime() + TRIAL_DAYS * 86_400_000) }
}
