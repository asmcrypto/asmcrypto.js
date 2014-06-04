global.Math.random = Random_getNumber;

if ( global.crypto === undefined ) global.crypto = {};
global.crypto.getRandomValues = Random_getValues;
