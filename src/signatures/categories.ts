/**
 * Categories used to group signatures in reports and referenced by verdict
 * rules as `category:<NAME>` terms.
 */
export enum Category {
  SYMMETRIC = 'SYMMETRIC',
  ASYMMETRIC = 'ASYMMETRIC',
  HASH = 'HASH',
  ENCODING = 'ENCODING',
  CHECKSUM = 'CHECKSUM'
}
