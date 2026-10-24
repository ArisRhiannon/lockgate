'use strict';
module.exports = { ...require('./lockfile'), ...require('./analyze'), ...require('./report'), RULES: require('./rules').RULES };
