/**
 * Module for the AccountController.
 *
 * @author Emilia Hansson <eh222yn@student.lnu.se>
 * @version 1.0.0
 */

import jwt from 'jsonwebtoken'
import { Account } from '../models/account.js'
import createError from 'http-errors'

/**
 * Encapsulates a controller.
 */
export class AccountsController {
  /**
   * Authenticates a user.
   *
   * @param {object} req Express request object.
   * @param {object} res Express response object.
   * @param {Function} next Express next middleware function.
   */
  async login (req, res, next) {
    try {
      const account = await Account.authenticate(req.body.username, req.body.password)

      const payload = {
        sub: account.username,
        given_name: account.firstName,
        family_name: account.lastName,
        email: account.email
      }

      const accessToken = jwt.sign(payload, process.env.ACCESS_TOKEN_SECRET, {
        algorithm: 'HS256',
        expiresIn: process.env.ACCESS_TOKEN_LIFE
      })

      res
        .status(201)
        .json({
          access_token: accessToken
        })
    } catch (error) {
      const err = createError(401)
      err.cause = error
      next(err)
    }
  }
}
