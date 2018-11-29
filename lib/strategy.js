// Load modules.
var OAuth2Strategy = require('passport-oauth2')
var querystring = require('querystring')
var util = require('util')
var uid = require('uid2')

function Strategy (options, verify) {
  options = options || {}
  options.authorizationURL = options.authorizationURL || options.sandbox ? 'https://testu2.staff.xdf.cn/i/u7/index.aspx' : 'https://account.wps.cn/oauthLogin'
  options.tokenURL = options.tokenURL || options.sandbox ? 'https://testu2.staff.xdf.cn/apis/oauth.ashx' : 'https://account.wps.cn/oauthapi/token'
  options.scopeSeparator = options.scopeSeparator || ','
  options.customHeaders = options.customHeaders || {}

  if (!options.customHeaders['User-Agent']) {
    options.customHeaders['User-Agent'] = options.userAgent || 'passport-xindongfang'
  }

  OAuth2Strategy.call(this, options, verify)
  this.name = 'xindongfang'
  this._userProfileURL = options.userProfileURL || options.sandbox ? 'https://testu2.staff.xdf.cn/apis/oauth.ashx' : 'https://account.wps.cn/oauthapi/user'

  this._oauth2.getAuthorizeUrl = function (params) {
    params = params || {}
    params['scope'] = 'snsapi_login'
    params['client_id'] = this._clientId
    return this._baseSite + this._authorizeUrl + '?' + querystring.stringify(params)
  }
  this._oauth2.getOAuthAccessToken = function (code, params, callback) {
    params = params || {}
    params['client_id'] = this._clientId
    params['client_secret'] = this._clientSecret
    params['method'] = 'GetAccessToken'
    params['code'] = code
    params['state'] = uid(24)
    var post_data = querystring.stringify(params)

    this._request('POST', this._getAccessTokenUrl(), {'content-type': 'application/x-www-form-urlencoded'}, post_data, null, function (error, data, response) {
      if (error) {
        callback(error)
      } else {
        var results, data
        try {
          results = JSON.parse(data)
          if (results.Status == 1) {
            data = JSON.parse(results.Data)
          } else {
            return callback(results.Message)
          }
        } catch (e) {
          return callback(e)
        }
        var access_token = data['access_token']
        var refresh_token = data['refresh_token']
        callback(null, results.Data, refresh_token, data); // callback results =-=
      }
    })
  }
}

// Inherit from `OAuth2Strategy`.
util.inherits(Strategy, OAuth2Strategy)

Strategy.prototype.userProfile = function (data, done) {
  try {
    var json = JSON.parse(data)
    return done(null, json)
  } catch (ex) {
    return done(new Error('Failed to parse user profile'))
  }
}

// Expose constructor.
module.exports = Strategy
