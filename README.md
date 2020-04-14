# passport-apple-id

[Passport](http://passportjs.org/) strategy for authenticating with [Apple ID](https://appleid.apple.com/) using the OAuth 2.0 API.

This module lets you authenticate using ["Sign in with Apple"](https://developer.apple.com/sign-in-with-apple/) in your Node.js applications.
By plugging into [Passport](http://passportjs.org/), Apple ID authentication can be easily and unobtrusively integrated into any application
or framework that supports [Connect](http://www.senchalabs.org/connect/)-style middleware, including [Express](http://expressjs.com/).

## Install

```bash
$ npm install @mix/passport-apple-id
```

## Usage

#### Create an Application

Before using `@mix/passport-apple-id`, you must register an application with Apple.
If you have not already done so, a new project can be created in the [Apple Developer Portal](https://developer.apple.com/).
Your application will be issued a team ID, a client ID, a private key, and a key ID, which need to be provided to the strategy.
You will also need to configure a redirect URI which matches the routes in your application.

#### Configure Strategy

The "Sign in with Apple" authentication strategy authenticates users using an Apple ID account and OAuth 2.0 tokens.
The team ID, client ID, private key, and key ID are obtained when creating an application are supplied as options when creating the strategy.
The strategy supports an *optional* `verify` callback:
  * If omitted, the authenticated user's Apple profile is accessible from the `passport.authenticate` callback.
  * If provided, it should be a [`passport-oauth2` Strategy `verify` callback](http://www.passportjs.org/packages/passport-oauth2/)

```javascript
const AppleSignInStrategy = require('@mix/passport-apple-id').Strategy;

passport.use('apple', new AppleSignInStrategy({
    teamID: APPLE_TEAM_ID,
    clientID: APPLE_CLIENT_ID,
    keyID: APPLE_KEY_ID,
    privateKey: APPLE_PRIVATE_KEY,
    callbackURL: 'https://www.example.com/auth/apple/callback'
  },
  function(accessToken, refreshToken, profile, done) {
    User.findOrCreate({ appleId: profile.id }, function (err, user) {
      return done(err, user);
    });
  }
));
```

#### Authenticate Requests

Use `passport.authenticate`, specifying the `'apple'` strategy, to authenticate requests.

For example, as route middleware in an [Express](http://expressjs.com/) application:

```javascript
app.get('/auth/apple',
  passport.authenticate('apple', {
    scope: [ 'name', 'email' ]
  })
);

app.get('/auth/apple/callback',
  passport.authenticate('apple', {
    failureRedirect: '/login'
  }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/');
  }
);
```

## Examples

Developers using the popular [Express](http://expressjs.com/) web framework can refer to an
[example](https://github.com/passport/express-4.x-facebook-example) as a starting point for their own web applications.
The example shows how to authenticate users using Facebook.  However, because both Facebook and Apple ID use OAuth 2.0, the code is similar.
Simply replace references to Facebook with corresponding references to "Sign in with Apple".

## License

[The Apache 2.0 License](http://opensource.org/licenses/Apache-2.0)

Copyright (c) 2020 Mix Tech, Inc. <[https://mix.com](http://mix.com)>
