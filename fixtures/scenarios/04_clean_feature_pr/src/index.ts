export function calculateTax(amount: number, rate: number): number {
  if (amount < 0 || rate < 0) {
    throw new Error("Invalid parameters");
  }
  return amount * rate;
}
