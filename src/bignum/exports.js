import {BigNumber_constructor, BigNumber_ONE, BigNumber_ZERO} from './bignum';
import {BigNumber_extGCD} from './extgcd';
import "./prime";

export var BigNumber = BigNumber_constructor;
BigNumber.ZERO = BigNumber_ZERO;
BigNumber.ONE  = BigNumber_ONE;

BigNumber.extGCD = BigNumber_extGCD;

export { Modulus } from "./modulus";
