import { BigNumber, BigNumber_ONE, BigNumber_ZERO, Modulus } from './bignum';
import { BigNumber_extGCD } from './extgcd';

BigNumber.ZERO = BigNumber_ZERO;
BigNumber.ONE = BigNumber_ONE;

BigNumber.extGCD = BigNumber_extGCD;

export { BigNumber, Modulus };
