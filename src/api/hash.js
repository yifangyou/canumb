var crypto = require('crypto');
var _      = require('underscore');
var base85 = require('base85');
var fs      = require('fs');

var errors = require('../lib/errors.js');

var hashes = [
  'sha1',
  'sha224',
  'sha256',
  'sha384',
  'sha512',
  'mdc2',
  'md4',
  'md5',
  'ripemd',
  'ripemd160',
  'whirlpool'
];

function apiBodyHandler(request, response, next)
{
  var self = this;
  var bp = require('restify').bodyParser({
    'mapParams' : false,
    'multipartFileHandler' : function(part) {
      self.hasher = crypto.createHash(request.params.algorithm);
      part.on('data', function(data) {
        self.hasher.update(data);
      });
    }
  });

  /* No need to reimplement the body parser */
  bp[0](request, response, function() {
    bp[1](request, response, next);
  });
}

function api(request, response, next)
{
  if (-1 === hashes.indexOf(request.params.algorithm)) {
    throw new errors.InvalidArgument("Unsupported algorithm: '" + request.params.algorithm);
  }

  var dataProvider;
  if (/^application\/json/.test(request.headers['content-type']) ||
      /^application\/x-www-form-urlencoded/.test(request.headers['content-type'])) {
    if (typeof request.body !== 'object' || request.body.data === undefined) {
      throw new errors.MissingArgument('No data provided.');
    }

    dataProvider = function(datacb, donecb) {
      datacb(request.body.data);
      donecb();
    };
  }

  if (/^multipart\/form-data/.test(request.headers['content-type'])) {
    if (typeof request.body === 'object' && request.body.data !== undefined) {
      /* multipart, but not a file upload. The data is in request.body */
      dataProvider = function(datacb, donecb) {
        datacb(request.body.data);
        donecb();
      };
    } else if (this.hasher) {
      /* The hashing was performed during the upload by apiBodyHandler */
      dataProvider = function(datacb, donecb) {
        donecb();
      };
    } else {
      throw new errors.MissingArgument('No data provided.');
    }
  }

  if (!dataProvider && !this.hasher) {
    throw new errors.MissingArgument('Data must be sent with \'application/json\' or \'multipart/form-data\'');
  }

  var self = this;
  var finished = function() {
    var hashBuffer = self.hasher.digest();
    response.send({
      'hex'    : hashBuffer.toString('hex'),
      'base64' : hashBuffer.toString('base64')
    });
    self.hasher = null;
    return next();
  };

  if (!this.hasher) {
    this.hasher = crypto.createHash(request.params.algorithm);
  }

  dataProvider(_.bind(this.hasher.update, this.hasher), finished);
}

exports.api = 'hash';

exports.method = 'post';

exports.rest = [
  {
    'name'        : 'algorithm',
    'description' : 'The algorithm with which supplied data should be hashed.',
    'valid'       : hashes
  }
];

exports.doc = {};

exports.doc.input = [
  {
    'name'        : 'data',
    'type'        : 'string',
    'description' : 'The data to hash. May be sent as a file.'
  }
]

exports.doc.description = 'Hashes data using a specified algorithm.';

exports.doc.errors = [
  {
    'type' : errors.InvalidArgument,
    'description' : 'Thrown if the algorithm is invalid.'
  },
  {
    'type' : errors.MissingArgument,
    'description' : 'Thrown if no data to hash is supplied.'
  },
  {
    'type' : errors.InternalServerError,
    'description' : 'Thrown if an unknown error occurs when transferring data as a file.'
  }
];

var ctx = {};

exports.entry = [
  _.bind(apiBodyHandler, ctx),
  _.bind(api, ctx)
];
