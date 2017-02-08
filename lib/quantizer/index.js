var Quantizer;

module.exports = Quantizer = (function() {
  function Quantizer() {}

  Quantizer.prototype.initialize = function(pixels, opts) {};

  Quantizer.prototype.getQuantizedColors = function() {};

  return Quantizer;

})();

module.exports.MMCQ = require('./mmcq');
