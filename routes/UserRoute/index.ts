import { Request, Response, Router } from "express";
import { check, validationResult } from "express-validator";
import nodemailer from "nodemailer";
import { decode } from "js-base64";
import bcrypt, { hash } from "bcryptjs";
import bs58 from 'bs58';
import nacl from 'tweetnacl';
import Joi from 'joi';
import jwt from "jsonwebtoken";
import axios from "axios";
import User from "../../model/UserModel";
import NonceModel from "../../model/NonceModel";
import { PublicKey, Transaction } from '@solana/web3.js';
import { authMiddleware, AuthRequest, verifyNonceMiddleware } from "../../middleware";
import crypto from 'crypto'
import passport from "passport";
import { JWT_SECRET } from "../../config";
// import dotenv from "dotenv";
import qs from "qs";
import { frontUrl } from "../../utils/api";
import { defaultLogger, authLogger, errorLogger, logLogger } from "../../utils/logger";
import { EMAIL_HOST, EMAIL_PASS, EMAIL_SERVICE, EMAIL_USER, EMAIL_PORT } from "../../utils/config";
import generateToken from "../../utils/generateToken";
import { sleep } from "../../utils/sleep";
// dotenv.config();

const discordClientId = '';
const discordClientSecret = '';
const discordRedirectUri = '';
const googleClientId = '';
const googleClientSecret = '';
const googleRedirectUri = '';


async function validateUsername(username: string) {
  const user = await User.findOne({ username });
  if (user) return false;
  return true;
}

// Create a new instance of the Express Router
const UserRouter = Router();

// @route    GET api/users
// @desc     Get user by token
// @access   Private
UserRouter.get("/", authMiddleware, async (req: AuthRequest, res: Response) => {
  try {
    const user = await User.findById(req.user.id).select([
      "-password",
      "-mnemonic",
      "-role",
      "-referrerlId",
    ]);
    res.json(user);
  } catch (err: any) {
    errorLogger.error('Error during authentication, ', err.message);
    return res.status(500).send({ error: err });
  }
});

// @route    GET api/users/username
// @desc     Is username available
// @access   Public
UserRouter.get("/username", async (req, res) => {
  try {
    const { username } = req.query;
    const isValid = await validateUsername(username as string);
    return res.json({ isValid });
  } catch (error: any) {
    errorLogger.error('Error during username validation, ', error);
    return res.status(500).send({ error });
  }
});

// @route    POST api/users/signup
// @desc     Register user
// @access   Public
UserRouter.post(
  "/signup",
  check("username", "Username is required").notEmpty(),
  check("email", "Please include a valid email").isEmail(),
  check("password", "Please enter a password with 12 or more characters").isLength({ min: 12 }),
  async (req: Request, res: Response) => {
    try {
      const transporter = nodemailer.createTransport({
        service: EMAIL_SERVICE,
        auth: {
          user: EMAIL_USER,
          pass: EMAIL_PASS,
        },
      });

      interface Payload {
        data: string;
      }

      // Provide a secret key type, it can generally be a string or a buffer
      const secretKey: string = "ourSecretKey";

      // Define the payload
      const payloadMail: Payload = {
        data: "Token Data",
      };

      // Generate the JWT token with a specified expiry time
      const tokenMail: string = jwt.sign(payloadMail, secretKey, {
        expiresIn: "10m",
      });

      const mailConfigurations = {
        // It should be a string of sender/server email
        from: EMAIL_USER,

        to: req.body.email,

        // Subject of Email
        subject: "Email Verification",

        // This would be the text of email body
        html: `<!doctype html>
        <html>
        
        <head>
          <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
        </head>
        
        <body style="font-family: sans-serif;">
          <div style="display: block; margin: auto; max-width: 600px;" class="main">
            <div style="display: flex; justify-content: center;">
              <h1 style="font-size: 20px; font-weight: bold; margin-top: 20px">Email Verification</h1>
            </div>
            <p>You have created an account on our system. Please verify your account by clicking the link below. You must verify the email address to use your account.</p>
            <div style="display: flex; justify-content: center;">
              <a href="${frontUrl}/${req.body.email}/verify/${tokenMail}" target="_blank">Email Verification</a>
            </div>
          </div>
          
          <style>
            .main {
              background-color: white;
            }
        
            a:link,
            a:visited {
              background-color: #008800;
              margin-top: 30px;
              color: white;
              padding: 14px 25px;
              text-align: center;
              text-decoration: none;
              display: inline-block;
            }
        
            a:hover,
            a:active {
              background-color: green;
            }
          </style>
        </body>
        
        </html>`,
      };

      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ error: errors.array() });
      }

      const { username, email, password, encodedReferrer } = req.body;

      const userExists = await User.findOne({ email });
      if (userExists) {
        return res.status(400).json({ error: "User already exists" });
      }

      let referrerId: string | null = null;
      if (encodedReferrer) {
        const referrerEmail = decode(encodedReferrer);
        const referrer = await User.findOne({ email: referrerEmail });
        referrerId = referrer?._id.toString() || null;
      }

      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(password, salt);

      const user = new User({
        username,
        email,
        password: hashedPassword,
        verified: false,
        account: 1
      });

      user
        .save()
        .then((response) => {
          transporter.sendMail(
            mailConfigurations,
            function (error: any, info: any) {
              if (error) {
                errorLogger.error('Error when sending email, ', error);
                return res.json({ success: false, mail: "Can't send email!" });
              } else {
                logLogger.debug("Email Sent Successfully");
                return res.json({ success: true });
              }
            }
          );
        })
        .catch((err) => {
          errorLogger.error('Error when user signing up, ', err);
          return res.json({ success: false, mail: "Can't regist user!" });
        });
    } catch (error: any) {
      errorLogger.error('Error when user signing up, ', error);
      return res.status(500).send({ error });
    }
  }
);

// @route    GET api/users/discordLogin
// @desc     Login by discord
// @access   Public
UserRouter.get(
  "/discordLogin",
  async (req, res) => {
    const { code } = req.query;
    if (!code) {
      return res.status(400).send('No code provided');
    }
    try {
      // Exchange code for access token
      const tokenResponse = await axios.post(
        'https://discord.com/api/oauth2/token',
        qs.stringify({
          client_id: discordClientId,
          client_secret: discordClientSecret,
          grant_type: 'authorization_code',
          code,
          redirect_uri: discordRedirectUri,
        }),
        {
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
          },
        }
      );
      const { access_token, token_type } = tokenResponse.data;
      // Use the access token to fetch the user's Discord profile
      const userResponse = await axios.get('https://discord.com/api/users/@me', {
        headers: {
          Authorization: `${token_type} ${access_token}`,
        },
      });
      // const userId = userResponse.data;
      if (userResponse.data) {
        const userId = userResponse.data.id; // Extract user ID
        const username = userResponse.data.username; // Extract username
        const email = userResponse.data.email; // Extract email 

        let user = await User.findOne({ discordId: userId });
        if (!user) {
          const newUser = new User({
            verified: true,
            discordId: userId,
            username: username,
            account: 3
          })

          await newUser.save();
          user = await User.findOne({ discordId: userId });
        }



        const payload = {
          user: {
            _id: user?._id,
            discordId: userId,
            verified: true,
            username: username,
            account: 3
          },
        };

        jwt.sign(
          payload,
          JWT_SECRET,
          { expiresIn: "5 days" },
          (err, token) => {
            if (err) {
              return res.status(400).json({ success: false, error: "jwt error" });
            } else {
              res.redirect(`https://solana-vibe-station.vercel.app/signin?discord_token=${token}`);
            }
          }
        );

      } else {
        console.error('No user data received');
      }

    } catch (error) {
      console.error('Error during Discord OAuth2 process:', error);
      return res.status(500).send('Authentication failed');
    }
  }
);

// @route    POST api/users/googleLogin
// @desc     Login by Google
// @access   Public
UserRouter.post(
  "/googleLogin",
  async (req, res) => {
    const googleId = req.body.userInfo.id;
    const email = req.body.userInfo.email as string;
    const verified = req.body.userInfo.verified_email;
    const username = email.split('@')[0];
    // Check if googleId is arrived
    if (!googleId) {
      return res.status(400).send('No code provided');
    }

    try {
      // Check if user already exists in the database
      let user = await User.findOne({ googleId: googleId, account: 2 });

      if (!user) {
        // If the user doesn't exist, create a new user
        const newUser = new User({
          verified: verified,
          googleId: googleId,
          username: username,
          account: 2
        });
        await newUser.save(); // Save the new user to the database
        user = await User.findOne({ googleId: googleId })
      }

      const payload = {
        user: {
          _id: user?._id,
          googleId: googleId,
          verified: verified,
          username: username,
          account: 2
        },
      };

      jwt.sign(
        payload,
        JWT_SECRET,
        { expiresIn: "5 days" },
        (err, token) => {
          if (err) {
            return res.status(400).json({ success: false, error: "jwt error" });
          } else {
            return res.json({
              success: true,
              authToken: token,
            });
          }
        }
      );

    } catch (error) {
      console.error('User registration failed', error);
      return res.status(500).send('User registration failed');
    }
  }
);

// @route    POST api/users/getNonce
// @desc     Get noce by wallet
// @access   Public
UserRouter.post(
  "/getNonce",
  check("publicKey", "Wallet must be string").notEmpty().isString(),
  async (req, res) => {
    const { body } = req;

    // If nonce is there, remove it
    try {
      await NonceModel.deleteMany({ wallet: body.publicKey }).exec()
    } catch (e) {
      return res.sendStatus(500)
    }

    const nonce = crypto.randomBytes(8).toString('hex');

    const nonceObject = new NonceModel({
      wallet: body.publicKey,
      nonce: nonce,
      authorized: true
    })

    try {
      await nonceObject.save();
    } catch (e) {
      res.sendStatus(500)
    }

    res.status(200).json({ nonce: nonce })
  }
);

// @route    POST api/users/walletLogin
// @desc     Login by signature
// @access   Public
UserRouter.post(
  "/walletLogin",
  check("publicKey", "Wallet is required").notEmpty().isString(),
  check("signature", "Signature is required").notEmpty().isString(),
  check("nonce", "Nonce is required").notEmpty().isString(),
  verifyNonceMiddleware,
  async (req, res) => {
    const { body } = req;

    const foundNonce = await NonceModel.findOne({ wallet: body.publicKey }).exec();
    if (!foundNonce) {
      console.log("Can not find nonce.")
      return res.status(400).json({ error: "Can not find nonce." })
    }

    try {
      // const signatureUint8 = bs58.decode(body.signature);
      // const msgUint8 = new TextEncoder().encode(`confirming will allow to access this site ${foundNonce.nonce}`);
      // const pubKeyUint8 = bs58.decode(body.publicKey);
      // const isValidSignature = nacl.sign.detached.verify(msgUint8, signatureUint8, pubKeyUint8);
      // Convert the signature array to Uint8Array

      const signatureUint8 = new Uint8Array(body.signature);
      const msgUint8 = new TextEncoder().encode(`Verify wallet for Solana Vibe Station\nNonce: ${body.nonce}`);
      const pubKeyUint8 = bs58.decode(body.publicKey);
      const isValidSignature = nacl.sign.detached.verify(msgUint8, signatureUint8, pubKeyUint8);

      if (!isValidSignature) {
        console.log("Invalid signature")
        return res.status(400).json({ error: "Invalid signature" })
      }

    } catch (e) {
      console.log("Error while verifying signature.\n", e);
      return res.status(400).json({ error: "Verifying error" });
    }

    try {
      let user = await User.findOne({ wallet: body.publicKey });
      if (!user) {
        const newUser = new User({
          verified: true,
          wallet: body.publicKey,
          account: 4
        });
        await newUser.save(); // Save the new user to the database
        user = await User.findOne({ wallet: body.publicKey })
      } else {
        await User.findOneAndUpdate(
          { wallet: body.publicKey },
          { verified: true },
          { new: true }
        );
      }

      try {
        const payload = {
          user: {
            _id: user?._id,
            wallet: body.publicKey,
            verified: true,
            account: 4
          },
        };

        jwt.sign(
          payload,
          JWT_SECRET,
          { expiresIn: "5 days" },
          (err, token) => {
            if (err) {
              return res.status(400).json({ success: false, error: "jwt error" });
            } else {
              return res.json({
                success: true,
                authToken: token,
              });
            }
          }
        );
      } catch (err) {
        console.log('error during jwt, error: ', err);
        return res.status(500).json({ error: 'error during jwt, error: ' });
      }
    } catch (err) {
      console.log('error during user data create or update, error: ', err);
      return res.status(500).json({ error: "error during user data create or update, error: " });
    }
  }
);

// @route    POST api/users/verify
// @desc     Is user verified
// @access   Public
UserRouter.post("/verify", async (req, res) => {
  try {
    const { token } = req.body;

    // Verifying the JWT token
    jwt.verify(token, "ourSecretKey", (err: any, decode: any) => {
      if (err) {
        errorLogger.error('Error during jwt verification, ', err);
        defaultLogger.debug('error location 1');
        return res
          .status(400)
          .json({ success: false, error: "Email verification failed!" });
      } else {
        User.findOneAndUpdate(
          { email: req.body.email },
          { $set: { verified: true } },
          { new: true }
        )
          .then(response => {
            logLogger.debug('User verified successfully');
            return res.json({
              success: true,
              mail: "Email verification successed!",
            });
          })
          .catch(error => {
            errorLogger.error('User verification failed');
            defaultLogger.debug('error location 2');
            return res.status(400).json({ success: false, error: "Email verification failed!" });
          })
      }
    });
  } catch (error: any) {
    errorLogger.error('Error during jwt verification, ', error);
    defaultLogger.debug('error location 3');
    return res.status(500).send({ error });
  }
});

// @route    Post api/users/forgotPassword
// @desc     Is user verified
// @access   Public
UserRouter.post("/forgotPassword", async (req, res) => {
  try {
    const email = req.body.email;

    User.findOne({ email: email })
      .then((data) => {
        if (data) {
          const transporter = nodemailer.createTransport({
            service: EMAIL_SERVICE,
            auth: {
              user: EMAIL_USER,
              pass: EMAIL_PASS,
            },
          });

          interface Payload {
            data: string;
          }

          // Provide a secret key type, it can generally be a string or a buffer
          const secretKey: string = "ourSecretKey";

          // Define the payload
          const payloadMail: Payload = {
            data: "Reset Data",
          };

          // Generate the JWT token with a specified expiry time
          const tokenMail: string = jwt.sign(payloadMail, secretKey, {
            expiresIn: "10m",
          });

          const mailConfigurations = {
            // It should be a string of sender/server email
            from: EMAIL_USER,

            to: email,

            // Subject of Email
            subject: "Reset Password",

            // This would be the text of email body
            html: `<!doctype html>
            <html>
            
            <head>
              <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
            </head>
            
            <body style="font-family: sans-serif;">
              <div style="display: block; margin: auto; max-width: 600px;" class="main">
                <div style="display: flex; justify-content: center;">
                  <h1 style="font-size: 20px; font-weight: bold; margin-top: 20px">Reset Password</h1>
                </div>
                <p>We received your request to reset your account password.</p>
                <p>Click the button below to create your new password. Your password will not be reset if no action is taken and your old password will continue to work</p>
                <div style="display: flex; justify-content: center;">
                  <a href="${frontUrl}/${email}/reset-password/${tokenMail}" target="_blank">Reset Password</a>
                </div>
              </div>
              
              <style>
                .main {
                  background-color: white;
                }
            
                a:link,
                a:visited {
                  background-color: #008800;
                  margin-top: 30px;
                  color: white;
                  padding: 14px 25px;
                  text-align: center;
                  text-decoration: none;
                  display: inline-block;
                }
            
                a:hover,
                a:active {
                  background-color: green;
                }
              </style>
            </body>
            
            </html>`,
          };

          transporter.sendMail(
            mailConfigurations,
            function (error: any, info: any) {
              if (error) {
                errorLogger.error('Error when sending message, ', error);
                return res.json({ success: false, mail: "Can't send email!" });
              } else {
                logLogger.debug("Email Sent Successfully");
                return res.json({
                  success: true,
                  mail: "Email verification link sent!",
                });
              }
            }
          );
        } else {
          return res.json({ success: false, mail: "Can't find email!" });
        }
      })
      .catch((err) => {
        errorLogger.error("Can't find corect user");
        return res.json({ success: false, mail: "Can't find user!" });
      });
  } catch (error: any) {
    errorLogger.error('Error when sending message, ', error);
    return res.status(500).send({ error });
  }
});

// @route    Post api/users/resetPassword
// @desc     Is user verified
// @access   Public
UserRouter.post("/resetPassword", async (req, res) => {
  try {
    const email = req.body.email;
    const token = req.body.token;
    const newPassword = req.body.password;

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(newPassword, salt);

    const data = await User.findOne({ email: email });

    if (!data) {
      return res.json({ success: false, mail: "Can't find user!" });
    }

    jwt.verify(token, "ourSecretKey", (err: any, decode: any) => {
      if (err) {
        errorLogger.error('Error during jwt verification, ', err);
        return res.status(400).json({
          success: false,
          error:
            "Reset password failed because email verification failure!",
        });
      } else {
        User.findOneAndUpdate(
          { email: email },
          {
            $set: {
              email: email,
              password: hashedPassword,
              username: data.username,
              verified: true,
            },
          },
          { new: true }
        )
          .then((data) => {
            return res.json({
              success: true,
              mail: "Reset password successed!",
            });
          })
          .catch((errors) => {
            errorLogger.error('Error when updating password, ', errors);
            return res
              .status(400)
              .json({ error: "Reset password failed!" });
          });
      }
    });
  } catch (error: any) {
    errorLogger.error('Reset password error, ', error);
    return res.status(500).send({ error });
  }
});

// @route    Post api/users/updatePassword
// @desc     Is user verified
// @access   Public
UserRouter.post("/updatePassword",
  check("email", "Please include a valid email").isEmail(),
  check("oldPassword", "Old password is required").exists().isString(),
  check("newPassword", "New password is required").exists().isString(),
  authMiddleware,
  async (req, res) => {
    try {
      const email = req.body.email;
      const oldPassword = req.body.oldPassword;
      const newPassword = req.body.newPassword;

      // This is password compare part
      let user = await User.findOne({ email: email, account: 1 });
      if (!user) {
        return res.status(400).json({ sucess: false, error: "Invalid Email" });
      }

      const isMatch = await bcrypt.compare(oldPassword, user.password ? user.password : '');

      if (!isMatch) {
        errorLogger.error('Incorrect password');
        return res.status(400).json({ sucess: false, error: "Incorrect password" });
      }

      // This is part for new password
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(newPassword, salt);

      const data = await User.findOne({ email: email, account: 1 });

      if (!data) {
        return res.json({ success: false, error: "Can't find user!" });
      }

      User.findOneAndUpdate(
        { email: email },
        {
          $set: {
            password: hashedPassword
          },
        },
        { new: true }
      )
        .then((data) => {
          return res.json({
            success: true
          });
        })
        .catch((err) => {
          res.status(400).json({ success: false, error: "Update password failed!" });
        })

    } catch (error: any) {
      errorLogger.error('Reset password error, ', error);
      return res.status(500).send({ error });
    }
  });

// @route    POST api/users/login
// @desc     Authenticate user & get token
// @access   Public
UserRouter.post(
  "/login",
  check("email", "Please include a valid email").isEmail(),
  check("password", "Password is required").exists(),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ sucess: false, error: errors.array() });
    }

    const { email, password } = req.body;

    try {

      try {
        let user = await User.findOne({ email: email, account: 1 });
        if (!user) {
          return res.status(400).json({ sucess: false, error: "Invalid Email" });
        }

        const isMatch = await bcrypt.compare(password, user.password ? user.password : '');

        if (!isMatch) {
          errorLogger.error('Incorrect password');
          return res.status(400).json({ sucess: false, error: "Incorrect password" });
        }

        if (!user.verified) {
          return res.status(400).json({ sucess: false, error: "Unverified member" });
        }

        authLogger.info('User login --> ', "email: ", user.email, ", username: ", user.username, ', IP address: ', req.socket.localAddress);

        const payload = {
          user: {
            _id: user._id,
            email: user.email,
            verified: user.verified,
            username: user.username,
            role: user.role,
            account: 1,
          },
        };

        jwt.sign(
          payload,
          JWT_SECRET,
          { expiresIn: "5 days" },
          (err, token) => {
            if (err) {
              return res.status(400).json({ sucess: false, error: "Incorrect password" });
            } else {
              return res.json({
                success: true,
                authToken: token,
              });
            }
          }
        );

      } catch (error: any) {
        errorLogger.error('Error fetching user, ', error);

        if (error.name === 'CastError') {
          return res.status(400).json({ success: false, message: "Invalid user ID format", details: error.message });
        } else if (error.name === 'ValidationError') {
          return res.status(400).json({ success: false, message: "Validation Error", details: error.errors });
        } else if (error.name === 'MongoError') {
          return res.status(500).json({ success: false, message: "Database Error", details: error.message });
        } else {
          return res.status(500).json({ success: false, message: "Unknown Error", details: error.message });
        }
      }

    } catch (error: any) {
      errorLogger.error('Sign in error, ', error);
      return res.status(500).send({ success: false, error: error });
    }
  }
);

// @route    POST api/users/profile
// @desc     Get user profile
// @access   Private
UserRouter.post(
  "/profile",
  check("account", "Account type is required").exists(),
  check("userInfo", "User info is necessary").exists(),
  authMiddleware,
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ sucess: false, error: errors.array() });
    }

    const account: string = req.body.account;
    const userInfo: string = req.body.userInfo;

    try {

      try {
        if (account === '1') {
          const user = await User.findOne({ email: userInfo });

          return res.json({
            _id: user?._id,
            email: user?.email,
            username: user?.username,
            verified: user?.verified,
            role: user?.role
          });
        }

        if (account === '2') {
          const user = await User.findOne({ googleId: userInfo });
          return res.json({
            _id: user?._id,
            googleId: user?.googleId,
            username: user?.username,
            verified: user?.verified,
            role: user?.role
          });
        }

        if (account === '3') {
          const user = await User.findOne({ discordId: userInfo });
          return res.json({
            _id: user?._id,
            discordId: user?.discordId,
            username: user?.username,
            verified: user?.verified,
            role: user?.role
          });
        }

        if (account === '4') {
          const user = await User.findOne({ wallet: userInfo });
          return res.json({
            _id: user?._id,
            wallet: user?.wallet,
            verified: user?.verified,
            role: user?.role
          });
        }

      } catch (error: any) {
        errorLogger.error('Error fetching user, ', error);

        if (error.name === 'CastError') {
          return res.status(400).json({ success: false, error: "Invalid user ID format", details: error.message });
        } else if (error.name === 'ValidationError') {
          return res.status(400).json({ success: false, error: "Validation Error", details: error.errors });
        } else if (error.name === 'MongoError') {
          return res.status(500).json({ success: false, error: "Database Error", details: error.message });
        } else {
          return res.status(500).json({ success: false, error: "Unknown Error", details: error.message });
        }
      }

    } catch (error: any) {
      errorLogger.error('Profile edit error, ', error);
      return res.status(500).send({ success: false, error: error });
    }
  }
);

// @route    POST api/users/updateUser
// @desc     Update user profile
// @access   Private
UserRouter.post(
  "/updateUser",
  check("account", "Account type is required").exists(),
  check("userInfo", "User info is necessary").exists(),
  check("username", "Username info is necessary").exists().isString(),
  authMiddleware,
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ sucess: false, error: errors.array() });
    }

    const account: string = (req.body.account).toString();
    const userInfo: string = req.body.userInfo;
    const username: string = req.body.username;

    try {
      try {
        if (account === '1') {
          const user = await User.findOneAndUpdate(
            { email: userInfo },
            {
              $set: {
                username: username
              },
            },
            { new: true }
          );

          const payload = {
            user: {
              _id: user?._id,
              email: user?.email,
              verified: user?.verified,
              username: user?.username,
              role: user?.role,
              account: 1,
            },
          };

          jwt.sign(
            payload,
            JWT_SECRET,
            { expiresIn: "5 days" },
            (err, token) => {
              if (err) {
                return res.status(400).json({ sucess: false, error: "Error happened during jwt sign" });
              } else {
                return res.json({
                  success: true,
                  authToken: token,
                });
              }
            }
          );
        }

        if (account === '2') {
          const user = await User.findOneAndUpdate(
            { googleId: userInfo },
            {
              $set: {
                username: username
              },
            },
            { new: true }
          );
          const payload = {
            user: {
              _id: user?._id,
              googleId: user?.googleId,
              verified: user?.verified,
              username: user?.username,
              role: user?.role,
              account: 2,
            },
          };

          jwt.sign(
            payload,
            JWT_SECRET,
            { expiresIn: "5 days" },
            (err, token) => {
              if (err) {
                return res.status(400).json({ sucess: false, error: "Error happened during jwt sign" });
              } else {
                return res.json({
                  success: true,
                  authToken: token,
                });
              }
            }
          );
        }

        if (account === '3') {
          const user = await User.findOneAndUpdate(
            { discordId: userInfo },
            {
              $set: {
                username: username
              },
            },
            { new: true }
          );
          const payload = {
            user: {
              _id: user?._id,
              discordId: user?.discordId,
              verified: user?.verified,
              username: user?.username,
              role: user?.role,
              account: 3,
            },
          };

          jwt.sign(
            payload,
            JWT_SECRET,
            { expiresIn: "5 days" },
            (err, token) => {
              if (err) {
                return res.status(400).json({ sucess: false, error: "Error happened during jwt sign" });
              } else {
                return res.json({
                  success: true,
                  authToken: token,
                });
              }
            }
          );
        }



      } catch (error: any) {
        errorLogger.error('Error fetching user, ', error);

        if (error.name === 'CastError') {
          return res.status(400).json({ success: false, error: "Invalid user ID format", details: error.message });
        } else if (error.name === 'ValidationError') {
          return res.status(400).json({ success: false, error: "Validation Error", details: error.errors });
        } else if (error.name === 'MongoError') {
          return res.status(500).json({ success: false, error: "Database Error", details: error.message });
        } else {
          return res.status(500).json({ success: false, error: "Unknown Error", details: error.message });
        }
      }

    } catch (error: any) {
      errorLogger.error('Profile edit error, ', error);
      return res.status(500).send({ success: false, error: error });
    }
  }
);

export default UserRouter;
