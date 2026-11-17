export interface SpendableCredit {
  id: string
}

/**
 * Spend the oldest credit whose conditional update wins. A concurrent request
 * may consume the first candidate after it was read; in that case continue to
 * the next candidate instead of incorrectly reporting quota exhaustion.
 */
export async function spendFirstAvailable<T extends SpendableCredit>(
  credits: readonly T[],
  trySpend: (credit: T) => Promise<boolean>,
): Promise<T | null> {
  for (const credit of credits) {
    if (await trySpend(credit)) return credit
  }
  return null
}
