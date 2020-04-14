interface StrategyOptions {
  // AppleSignInStrategy-specific options
  clientID: string;
  keyID: string;
  privateKey: string;
  teamID: string;
  // OAuth2Strategy URLs
  authorizationURL?: string;
  callbackURL: string;
  tokenURL?: string;
  // OAuth2Strategy options
  passReqToCallback?: boolean,
  skipUserProfile?: boolean,
  scope?: string[] | string
}
