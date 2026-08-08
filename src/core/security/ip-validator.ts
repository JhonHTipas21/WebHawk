/**
 * @file ip-validator.ts
 * @description IP validation against allowed CIDR ranges.
 */

import ipaddr from 'ipaddr.js';

export class IpValidator {
  /**
   * Checks if a given IP address string falls within any of the provided CIDR ranges.
   *
   * @param ipString - The IP address to check (IPv4 or IPv6)
   * @param cidrRanges - Array of CIDR strings (e.g. ['192.168.1.0/24', '2001:db8::/32'])
   * @returns true if the IP is valid and falls within one of the ranges, false otherwise.
   */
  static isIpInCidrRanges(ipString: string, cidrRanges: string[]): boolean {
    if (!ipString || !ipaddr.isValid(ipString)) {
      return false;
    }

    try {
      const ip = ipaddr.parse(ipString);

      return cidrRanges.some((cidr) => {
        try {
          const parsedCidr = ipaddr.parseCIDR(cidr);
          return ip.match(parsedCidr);
        } catch {
          // Ignore invalid CIDR configurations to prevent crashing the check
          return false;
        }
      });
    } catch {
      return false;
    }
  }
}
