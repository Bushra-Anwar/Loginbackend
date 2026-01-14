const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const User = require("../models/User");
const bcrypt = require("bcryptjs");

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "/api/auth/google/callback"
    },
    async (accessToken, refreshToken, profile, done) => {
      const email = profile.emails[0].value;

      let user = await User.findOne({ email });

      if (!user) {
        // 🔐 dummy encrypted password
        const hash = await bcrypt.hash(profile.id, 10);

        user = await User.create({
          name: profile.displayName,
          email,
          password: hash,
          isVerified: true
        });
      }

      done(null, user);
    }
  )
);
