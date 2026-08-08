/**
 * @file ip-validator.spec.ts
 * @description Unit tests for IP validation using CIDR ranges.
 */

import { describe, it, expect } from 'vitest';
import { IpValidator } from '../../src/core/security/ip-validator.js';

describe('IpValidator', () => {
  describe('isIpInCidrRanges', () => {
    it('should return true for a valid IPv4 inside the CIDR range', () => {
      expect(IpValidator.isIpInCidrRanges('192.168.1.50', ['192.168.1.0/24'])).toBe(true);
    });

    it('should return false for a valid IPv4 outside the CIDR range', () => {
      expect(IpValidator.isIpInCidrRanges('192.168.2.50', ['192.168.1.0/24'])).toBe(false);
    });

    it('should return true for a valid IPv6 inside the CIDR range', () => {
      expect(IpValidator.isIpInCidrRanges('2001:db8::1234', ['2001:db8::/32'])).toBe(true);
    });

    it('should return false for a valid IPv6 outside the CIDR range', () => {
      expect(IpValidator.isIpInCidrRanges('2001:db9::1234', ['2001:db8::/32'])).toBe(false);
    });

    it('should handle multiple CIDR ranges', () => {
      const ranges = ['10.0.0.0/8', '192.168.1.0/24'];
      expect(IpValidator.isIpInCidrRanges('192.168.1.100', ranges)).toBe(true);
      expect(IpValidator.isIpInCidrRanges('10.5.5.5', ranges)).toBe(true);
      expect(IpValidator.isIpInCidrRanges('172.16.0.5', ranges)).toBe(false);
    });

    it('should return false for invalid IP strings', () => {
      expect(IpValidator.isIpInCidrRanges('invalid-ip', ['192.168.1.0/24'])).toBe(false);
      expect(IpValidator.isIpInCidrRanges('', ['192.168.1.0/24'])).toBe(false);
      expect(IpValidator.isIpInCidrRanges('256.256.256.256', ['192.168.1.0/24'])).toBe(false);
    });

    it('should not crash and return false for invalid CIDR ranges', () => {
      expect(IpValidator.isIpInCidrRanges('192.168.1.50', ['invalid-cidr'])).toBe(false);
      expect(IpValidator.isIpInCidrRanges('192.168.1.50', ['192.168.1.0/24', 'invalid-cidr'])).toBe(true);
    });
  });
});
