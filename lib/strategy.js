'use strict';

var passport = require('passport-strategy')
    , auth_hdr = require('./auth_header')
    , util = require('util')
    , url = require('url')  
    , _ = require('lodash');
/**
 * Strategy constructor
 *
 * @param options
 *          algorithms: (REQUIRED) object defining the configuration of for validating
 *          the JWT token per every algorithm i.e {"RS256": { ... options ... }
 *          jwtFromRequest: (REQUIRED) Function that accepts a reqeust as the only parameter and returns the either JWT as a string or null
 *          RS256.issuer: If defined issuer will be verified against this value
 *          RS256.audience: If defined audience will be verified against this value
 *          RS256.ignoreExpiration: if true do not validate the expiration of the token.
 *          RS256.passReqToCallback: If true the, the verify callback will be called with args (request, jwt_payload, done_callback).
 * @param verify - Verify callback with args (jwt_payload, done_callback) if passReqToCallback is false,
 *                 (request, jwt_payload, done_callback) if true.
 */
function MultiJwtStrategy(options, verify) {
    passport.Strategy.call(this);
    this.name = 'jwt';
    this._verify = verify;
    if (!this._verify) {
        throw new TypeError('MultiJwtStrategy requires a verify callback');
    }
    this._jwtFromRequest = options.jwtFromRequest;
    if (!this._jwtFromRequest) {
        throw new TypeError('MultiJwtStrategy requires a function to retrieve jwt from requests (see option jwtFromRequest)');
    }
    this._passReqToCallback = options.passReqToCallback;
    this._verifOpts = {};
    if (options.algorithms) {
        this._verifOpts.algorithms = options.algorithms;
    }
};
util.inherits(MultiJwtStrategy, passport.Strategy);
/**
 * Allow for injection of JWT Verifier.
 *
 * This improves testability by allowing tests to cleanly isolate failures in the JWT Verification
 * process from failures in the passport related mechanics of authentication.
 *
 * Note that this should only be replaced in tests.
 */
MultiJwtStrategy.JwtVerifier = require('./verify_jwt');
/**
 * Authenticate request based on JWT obtained from header or post body
 */
MultiJwtStrategy.prototype.authenticate = function(req, options) {
    var self = this;
    var token = self._jwtFromRequest(req);
    if (!token) {
        return self.fail(new Error("No auth token"));
    }
    var decodedToken;
    try {
        decodedToken = jws.decode(token, {});
    } catch(err) {
        return this.fail(new Error("Invalid token type"));
    }
    if(decodedToken === null)
        return this.fail(new Error("Invalid token type"));

    if(!_.has(decodedToken,'header') || !_.has(decodedToken.header,'alg'))
        return this.fail(new Error("Invalid token type"));
    
    if(!_.has(this._verifOpts.algorithms, decodedToken.header.alg))
        return this.fail(new Error("Invalid algorithm"));
    
    var options  =  this._verifOpts.algorithms[decodedToken.header.alg];
    options.algorithms = [decodedToken.header.alg];
    var secretOrKey = options.secretOrKey;
    delete options.secretOrKey;
    // Verify the JWT
    MultiJwtStrategy.JwtVerifier(token, secretOrKey, options, function(jwt_err, payload) {
        if (jwt_err) {
            return self.fail(jwt_err);
        } else {
            // Pass the parsed token to the user
            var verified = function(err, user, info) {
                if(err) {
                    return self.error(err);
                } else if (!user) {
                    return self.fail(info);
                } else {
                    return self.success(user, info);
                }
            };
            try {
                if (self._passReqToCallback) {
                    self._verify(req, payload, verified);
                } else {
                    self._verify(payload, verified);
                }
            } catch(ex) {
                self.error(ex);
            }
        }
    });
};

module.exports = MultiJwtStrategy;
