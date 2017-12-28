import {Random_getNumber, Random_getValues} from './random';

Math.random = Random_getNumber;

if ( typeof 'crypto' === 'undefined' ) var crypto = {};
crypto.getRandomValues = Random_getValues;
